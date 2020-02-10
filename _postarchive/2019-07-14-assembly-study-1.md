---
layout: post
cover: 'assets/images/cover8.jpg'
navigation: true
title: movs, scas, stos, .. 어셈블리 명령어 정리
date: 2019-07-14
tags: 공부
subclass: 'post'
logo: 'assets/images/ghost.png'
author: lanphere
categories: lanphere
disqus: true
---

> movsb, movsw, movsd: **src에 있는 데이터(1, 2, 4바이트)를 dest에 저장**

이 세 명령어는 내부적으로 edi, esi레지스터를 각각 destination, source 레지스터로
사용한다. 또한 이 명령어들은 edi, esi값을 점차적으로 업데이트하는데 이 때 direction flag(DF)를
사용한다. 만약 DF가 0이면 edi, esi레지스터는 movsb(movsw, movsd) 명령어가 실행될 때마다
점점 감소한다(DF가 1이면 증가).

따라서 movsb, movsw, movsd 명령어는 데이터의 길이를 컴파일 시간에 알 수 있을 때
문자열(혹은 메모리)을 비교하는 함수를 짤 때 사용된다. 종종 rep 명령어와 같이 쓰인다.
rep는 ecx레지스터가 0인 동안에 뒤에 오는 명령어를 반복하는 명령어이다.
```
01: 6A 08 push 8 ; 스택에 8을 넣는다.
02: ...
03: 59 pop ecx  ; ecx = 8;
04: ...
05: BE 00 44 61 00 mov esi, offset _src_mem
06: BF C0 43 61 00 mov edi, offset _dest_mem
; ecx에 있는 값 만큼 movsd를 반복(32바이트 복사)
07: F3 A5 rep movsd
```

위 어셈블리 코드는 아래 코드랑 같다.
```
memcpy(_src_mem, _dest_mem, 32);
```

movsb(movsw, movsd)와 비슷한 명령어로 scas, stos 명령어가 있다. movs와 마찬가지로
scas또한 데이터의 크기에 따라 scasb, scasw, scasd 명령어로 나뉜다.

> scasb: **edi주소에 있는 1바이트와 al 레지스터에 있는 값을 비교한 후 Z Flag를 설정**

scasb와 rep를 이용해서 strlen() 함수를 아래와 같이 구현할 수 있다.
```
01: 30 C0 xor al, al ; al 레지스터를 0으로 초기화
02: 89 FB mov ebx, edi ; 문자열 주소를 ebx 레지스터에 백업
03: F2 AE repne scasb ; 문자열에서 NULL 바이트를 찾을 때 까지 비교
; edi는 NULL 바이트가 있는 문자열의 주소이므로
; 이 연산 후 edi는 문자열의 길이와 같다.
04: 29 DF sub edi, ebx
```

scas가 edi주소에 있는 데이터와 eax(ax, al) 레지스터에 있는 데이터를 **비교(cmp)**했다면,
stos는 **edi주소에 eax(ax, al) 레지스터에 있는 데이터를 저장(store)**한다.
따라서 stos는 가령 memset 함수를 구현하는 데 사용할 수 있다.

추가적으로 stos 명령어와 반대로 lods 명령어가 있다.
> lods: **esi주소에 있는 데이터를 읽어와서 eax(ax, al) 레지스터에 저장**