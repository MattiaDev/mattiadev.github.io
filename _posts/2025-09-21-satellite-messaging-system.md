---
title: Satellite Messaging System
date: 2025-09-21 05:30:00
description: From Ctrl+Space Quals CTF 2025 - A not so easy reversing journey
tags: [rev]
categories: [CTF]
media_subpath: /assets/2025-ctrl-space
---

Nice intro about Ctrl+Space CTF.

## The Challenge

The challenge description was the following:
![Description](desc.png)
_Description_
We are given two files: a `server` executable binary and a `capture.pcap` capture.

The `capture.pcap` is quite small, but after opening it in Wireshark there is not much helpful information in it: only two tcp streams are available and the content seems gibberish.

Time to have a look at the binary file in Ghidra.
The `main` function is simply a while loop that accepts new connects and dispatches the handling of the client to a function renamed to `srv::serve_client(socket_fd)`.

Midway through `srv::serve_client` there are two very similar calls.
![Weird calls](crypt_setup_call.png)
_Calls_

A bit of reversing reveals the purpose: initialising an encryption and decryption objects using the supplied `key` and `cipher_id`.
Interestingly the `initialization_vector` is always `0x0` and the operation mode is always ECB.
This could explain why the packet capture makes no sense at all!
![crypto::init_cipher](crypt_setup.png)
_crypto::init_cipher_

Going back to `srv::serve_client`, you can notice that the key is taken from a global location plus an offset.
Cross-referecing which other function operates on that data as well we trace back to `FUN_00423165()` at line 29.
This is the raw decompilation from Ghidra:
![crypto::init_keys](crypt_key_pre.png)
_crypto::init_keys pre_
And this is after some cleanup and a few ad-hoc struct:
![crypto::init_keys](crypt_key_post.png)
_crypto::init_keys post_

Basically, it seems that `crypto30_array` (which is initally empty in memory) is populated with fields from `crypto40_array`, including the actual key for the cipher.
From this array a key is chosen, allegedly by getting the offset from the client.
The interesting bit is that, by looking at the program logic, the cipher should always be AES 256.

Now that it's clear that some encryption is going on, and that we have potential access to the keys used for it, it's time to understand better how the server communicates.
You could investigate deeper `srv::serve_client`, but a faster way is to cross-reference the `send` function and see where it is used.
We notice that it's actually used in one function only, and here is the reversing outcome:
![srv::send_encrypted_if_possible](send_encrypted.png)
_srv::send_encrypted_if_possible_
This function has a weird behaviour: it encrypts the packet before sending only if the ciphers have been already setup, otherwise it will the the packet in clear.
This means that we might have both encrypted and unencrypted content in the PCAP file (even tough a fir look showed mostly garbage data).

As the overall behaviour of the program remains unclear it's worth investigating more deeply one of the function we have already identified: `let_client_choose_key?`.
Inside we have a lot of calls to other functions, but one of them caught my attention:
![asn_hint](asn1_hint.png)
_asn1_hint_
And made me wander, what is this `asn1` that is mentioned here together with encoding and buffers?
A quick search revealed that ASN.1 - Abstract Syntax Notation One - is a language to define data structures that can be serialized and deserialized in a cross-platform way. [Wikipedia](https://en.wikipedia.org/wiki/ASN.1) says it's used in telecommunications, including satellites!

> To be completly transparent this was not so obvious, and I spent a lot of time looking at tons of different functions.
> Some included hints at this notation, by using words like SEQUENCE, tags, and so on.. but it was actually when I went back to this function that I realized that ASN1 could be the encoding name.
{: .prompt-info }

The Wikipedia page also included an example of encoding..
```
30 13 02 01 05 16 0e 41 6e 79 62 6f 64 79 20 74 68 65 72 65 3f
```
..which is very very similar to the beginning of the two TCP streams in the PCAP file!
![wireshark](wireshark.png)
_wireshark_
Ok, they're not identical, but the first three rows in each stream look very close to the example!

Copying the first line into the first ASN.1 online decode I could find ([this one](https://lapo.it/asn1js/#MDGAAQGBAQSCAQKDBGjMYqKEII6yXlkdoTYlCYQ1DKrpO75yWCujSAs3Z2cH2xpkbksN)), revealed a meaningful content!
![decoder](decoder.png)
_decoder_
Even though, the actual content of the messages remained unclear.
More over I was (as expected) only able to decode the first three packets.
The rest unfortunately appeared to be encrypted.. but wait! We know the keys! We just need to find the right one.

So we have the array of structures containing the keys:
![Key Array](keyarray.png)
_Key Array_
We only need to try all of them and see if one returns meaningful text!

I tried all of them on the encrypted portion of the stream and the 5th key returned the most promising results.
By using this script:
```python
import asn1
from Crypto.Cipher import AES

key5 = [ 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81, 0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8
, 0x09, 0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe,
 0x0f ]

with open('tc0_hex.txt', 'r') as f:
    c = f.read()

bc = c.replace(' ','').replace('\n','')
c = bytes.fromhex(bc)

cip = AES.new(bytes(key5), AES.MODE_ECB)
dec = cip.decrypt(c)
d = asn1.Decoder()
d.start(dec)
while True:
    try:
        print(d.read())
    except:
        break
```
I was trying to decode all stream content after the first three plaintext ASN.1 packets.
This is the output:
```
(Tag(nr=<Numbers.Sequence: 0x10>, typ=<Types.Constructed: 0x20>, cls=<Classes.Universal: 0x00>), [b'\x00', [[b'\x12', b'\x01', b'\x00', b'', b'\x00']], b'\xc5\xa2\x01\xef\xf5>p\xfe\xefo\xca\x91\xb2A2\x8ba\xf0\x96AW\xce\xd9w2h\xe8\xbb\xca\x88\x17\xe4'])
(Tag(nr=<Numbers.ObjectDescriptor: 0x07>, typ=<Types.Primitive: 0x00>, cls=<Classes.Universal: 0x00>), b'\x07\x07\x07\x07\x070B')
(Tag(nr=0, typ=<Types.Primitive: 0x00>, cls=<Classes.Context: 0x80>), b'\x00')
(Tag(nr=1, typ=<Types.Constructed: 0x20>, cls=<Classes.Context: 0x80>), [[b'\x0c', b'\x02', b'\x08', b's=SAFETY', b'e\x8e\xbf\xe2']])
(Tag(nr=2, typ=<Types.Primitive: 0x00>, cls=<Classes.Context: 0x80>), b"S\xdft~\xd3@\x93\x84\xf8\xaf\x9d\x12\x1f\x18\xf7I)s\xe3\x9f\x97'K\x97\x15e5\xa83\xc0\xec\xfa")
(Tag(nr=<Numbers.UTF8String: 0x0c>, typ=<Types.Primitive: 0x00>, cls=<Classes.Universal: 0x00>), '\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c0C')
(Tag(nr=0, typ=<Types.Primitive: 0x00>, cls=<Classes.Context: 0x80>), b'\x00')
(Tag(nr=1, typ=<Types.Constructed: 0x20>, cls=<Classes.Context: 0x80>), [[b'\n', b'\x03', b'\x08', b's=CAMERA', b'\x00\xf4o\x05\xa8']])
(Tag(nr=2, typ=<Types.Primitive: 0x00>, cls=<Classes.Context: 0x80>), b'.\xbe\xcc\xa2\xadb\r\x88\x88\xa9[\xc5\x07\xc3HGA,^l\xfe\xe0K\x93\xcfx\x81\xaedK\xb6\x9e')
(Tag(nr=<Numbers.EmbeddedPDV: 0x0b>, typ=<Types.Primitive: 0x00>, cls=<Classes.Universal: 0x00>), b'\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b0P')
(Tag(nr=0, typ=<Types.Primitive: 0x00>, cls=<Classes.Context: 0x80>), b'\x00')
(Tag(nr=1, typ=<Types.Constructed: 0x20>, cls=<Classes.Context: 0x80>), [[b'\x08', b'\x04', b'\x15', b'n=SPEED;v=LIGHT_SPEED', b'\x00\xf7\xee\xda\x0b']])
(Tag(nr=2, typ=<Types.Primitive: 0x00>, cls=<Classes.Context: 0x80>), b'\xc1\x8a\xe7\xce\xfb]\xd44\xb7\xbd\x89i"\xb2\xbd.60\xd7\x1d\xcf\xb0w{\xec\xfc\x87wx\x8c\x84n')
(Tag(nr=<Numbers.Time: 0x0e>, typ=<Types.Primitive: 0x00>, cls=<Classes.Universal: 0x00>), b'\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e0_')
(Tag(nr=0, typ=<Types.Primitive: 0x00>, cls=<Classes.Context: 0x80>), b'\x00')
(Tag(nr=1, typ=<Types.Constructed: 0x20>, cls=<Classes.Context: 0x80>), [[b'\x18', b'\x05', b'$', b'la=25.000000;lo=-71.000000;al=100000', b'\x00\xc8\x1bzq']])
(Tag(nr=2, typ=<Types.Primitive: 0x00>, cls=<Classes.Context: 0x80>), b'<C\xeb\xfb\xb4\x16Uj\xbe\xf1\xd2\xe0\xac\xfa\xc9d\xd4\xa2I\xf9Od\xaa\xa0p\x82\xfc\xb0\x1b\xcd\xf1\x1f')
```
It makes sense in a lot of ways: words like SAFETY, CAMERA, SPEED, are not random.
However, the decoding was terminating prematurely, and sure enough there was no flag in this output (and the same was for the second stream).

This is the moment where I realized I was deceived by Wireshark and it's stream representation.
I started looking at individual packets and I found one that was suspiciously big.
I tryed the same operation on that and here is the results:
```
[b'\x01', [[[b' ', b'\x1e', b'\x13', b'k=5;i=11;v=100;s=48', b'Z]\xb6\x1a'], [b' ', b'=', b'\x12', b'k=5;i=42;v=52;s=48', b'd\xc5\xf3\x82'], [b' ', b'\x16', b'\x11', b'k=5;i=3;v=99;s=48', b']x\x97\xc6'], [b' ', b'A', b'\x13', b'k=5;i=46;v=103;s=48', b'\x00\xb5~\x9e('], [b' ', b'1', b'\x13', b'k=5;i=30;v=114;s=48', b'\x00\x9cB\x06\x9c'], [b' ', b'9', b'\x12', b'k=5;i=38;v=95;s=48', b'(W\x18E'], [b' ', b"'", b'\x13', b'k=5;i=20;v=103;s=48', b'\x00\xfa\xa6\xe4\x15'], [b' ', b'3', b'\x13', b'k=5;i=32;v=116;s=48', b'=\xb19\x08'], [b' ', b'2', b'\x12', b'k=5;i=31;v=48;s=48', b'\x00\x8eST\xde'], [b' ', b'"', b'\x12', b'k=5;i=15;v=99;s=48', b'x:\x0b\xa6'], [b' ', b'\x14', b'\x12', b'k=5;i=1;v=112;s=48', b'\x13H\x9a\x81'], [b' ', b'\x1b', b'\x12', b'k=5;i=8;v=102;s=48', b'(\x96\xab\xa4'], [b' ', b' ', b'\x13', b'k=5;i=13;v=100;s=48', b'\x00\xb6f(\x85'], [b' ', b'!', b'\x12', b'k=5;i=14;v=51;s=48', b'\x00\x92G<\x7f'], [b' ', b'\x1c', b'\x11', b'k=5;i=9;v=49;s=48', b'\x00\xde\x00\xae\x82'], [b' ', b'+', b'\x13', b'k=5;i=24;v=115;s=48', b'\x00\x89\x8e7\xc3'], [b' ', b'\x1d', b'\x13', b'k=5;i=10;v=110;s=48', b'g\x8f\xf1\xc1'], [b' ', b'@', b'\x13', b'k=5;i=45;v=110;s=48', b'\x00\xe2\x035\xc2'], [b' ', b'/', b'\x12', b'k=5;i=28;v=95;s=48', b'\x00\xb3\xf2T*'], [b' ', b'>', b'\x13', b'k=5;i=43;v=120;s=48', b'<\xd6\x8a\xbf'], [b' ', b':', b'\x13', b'k=5;i=39;v=114;s=48', b'\x01\xeb<\r'], [b' ', b'\x1f', b'\x12', b'k=5;i=12;v=95;s=48', b'&\xc3\xde^'], [b' ', b')', b'\x12', b'k=5;i=22;v=99;s=48', b'&\x9f\xcc\xd5'], [b' ', b'&', b'\x13', b'k=5;i=19;v=110;s=48', b'\x00\xfa&\xcbP'], [b' ', b'*', b'\x13', b'k=5;i=23;v=117;s=48', b'\x00\xb0\xde\x7fG'], [b' ', b'.', b'\x13', b'k=5;i=27;v=109;s=48', b'/\xa5.\xfc'], [b' ', b'\x15', b'\x11', b'k=5;i=2;v=97;s=48', b'\x00\xa6\xfc)v'], [b' ', b'\x17', b'\x12', b'k=5;i=4;v=101;s=48', b'\x00\xab\x08\x94\x8b'], [b' ', b'-', b'\x12', b'k=5;i=26;v=48;s=48', b'<\xcd\r2'], [b' ', b'(', b'\x12', b'k=5;i=21;v=95;s=48', b'\x00\xc8\xbfj\xaf'], [b' ', b'6', b'\x12', b'k=5;i=35;v=48;s=48', b">\x8a'\\"], [b' ', b'4', b'\x12', b'k=5;i=33;v=48;s=48', b'\x00\xd6?\xed\x1f'], [b' ', b'\x18', b'\x12', b'k=5;i=5;v=123;s=48', b'\x00\xea\xfah\xc6'], [b' ', b'0', b'\x13', b'k=5;i=29;v=112;s=48', b'\n$\x06\x95'], [b' ', b'?', b'\x12', b'k=5;i=44;v=49;s=48', b'@\xc0\xc2\xb6'], [b' ', b'%', b'\x13', b'k=5;i=18;v=105;s=48', b'\x00\x979\x1d8'], [b' ', b'B', b'\x13', b'k=5;i=47;v=125;s=48', b'o\x1d s'], [b' ', b'$', b'\x13', b'k=5;i=17;v=100;s=48', b'\x00\xb5`\x13\xfa'], [b' ', b'#', b'\x12', b'k=5;i=16;v=48;s=48', b'KS\xdf\xc2'], [b' ', b'7', b'\x13', b'k=5;i=36;v=108;s=48', b'\x00\xa2\xcah\xb3'], [b' ', b'\x1a', b'\x11', b'k=5;i=7;v=95;s=48', b'\x00\x9ac$?'], [b' ', b'\x13', b'\x12', b'k=5;i=0;v=115;s=48', b'\x00\x95\xe8\xe6V'], [b' ', b'5', b'\x12', b'k=5;i=34;v=99;s=48', b'U\x8fJ\xf9'], [b' ', b'<', b'\x13', b'k=5;i=41;v=108;s=48', b'\x00\xab!\x87d'], [b' ', b';', b'\x12', b'k=5;i=40;v=51;s=48', b'\x00\xba=8\xed'], [b' ', b'\x19', b'\x11', b'k=5;i=6;v=49;s=48', b'M\xf8ZD'], [b' ', b'8', b'\x12', b'k=5;i=37;v=53;s=48', b'\x00\xaaVe\xea'], [b' ', b',', b'\x13', b'k=5;i=25;v=116;s=48', b'\x00\x94\xbf\t\x02']]], b'\xd2\x12\xbf\x10\xf5\xad\xd8\xb5\x11{\xb81\x15\xe54/1\x84i#\x8b\x18M\xbc\xe0\xcc\x0cE\xbf\xe4\x19\x9b']
```
A big mess! But if you look closely you'll start to notice a pattern.. a bunch of i=X,v=Y.
Could that be index and value of the characters of the flag?

A quick python script to test the idea, and sure enough we got the flag:
```
space{1_f1nd_d3c0ding_cust0m_pr0t0c0l5_r3l4x1ng}
```

## Bonus - Global Vtable?

ToDo

## Bonus - Variadic Function Decompilation

ToDo
