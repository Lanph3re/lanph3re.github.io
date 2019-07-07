---
layout: post
cover: 'assets/images/cover8.jpg'
navigation: true
title: 어셈블리어로 Hello World 출력하기
date: 2019-06-26
tags: 공부
subclass: 'post'
logo: 'assets/images/ghost.png'
author: lanphere
categories: lanphere
disqus: true
---

우리가 C언어로 소스코드를 작성하고 컴파일을 하면 먼저 작성한 소스코드는
컴파일러에 의해 어셈블리어로 변환된 후,
이어서 어셈블러에 의해 기계어로 변환되는 과정을 거친다.

하지만 C언어대신 어셈블리어로 직접 소스코드를 작성하고
어셈블러를 이용해서 실행파일을 만들 수도 있다.

C 컴파일러가 gcc를 비롯해 다양한 컴파일러가 있는 것처럼 어셈블러도 다양하지만
이 글에서는 **nasm**을 이용해보자. nasm은 아래 명령어로 설치할 수 있다.

> sudo apt install nasm (또는 sudo apt-get install nasm)

설치가 됐다면 이제 간단하게 어셈블리어로 Hello World를 출력하는 소스코드를 작성해보자.
텍스트 에디터를 열고 파일이름은 hello.asm으로 만들어주자.

C언어에서는 흔히 가장 먼저 실행되는 함수는 main이라고 배웠지만 더 낮은 레벨인 어셈블리어에서,
특히 리눅스에서는 _start라는 이름의 Procedure를 먼저 실행한다.

어셈블러에게 _start라는 Routine이 존재한다는 것을 알려줘야 한다.
```
global _start
```
프로세스는 기계어가 저장되는 text영역과
컴파일 시간에 결정되는 문자열(printf("Hello World"); 에서 "Hello World"같은 것들)과
전역변수 등이 저장되는 data영역, 그 외 stack, heap영역 등이 있다.

C언어에서 문자열을 출력할 땐 puts, printf 같은 함수를 사용하지만 그런 C 라이브러리 함수 대신
리눅스의 시스템 호출(System call)을 이용해서 표준 출력, 즉 모니터에 문자열을 출력해볼 것이다.

시스템 호출이란 운영체제 내의 커널이 유저에게 제공하는 서비스의 인터페이스이다. 사용자는 직접 모니터에
무언가를 출력하는 것이 아니라, 시스템 호출을 통해서 커널에게 출력을 해줘! 라는 부탁을 하고
시스템 호출을 받은 커널은 사용자를 대신해서 작업을 수행한다.

시스템 호출은 운영체제마다 다 다르며, 가능한 시스템 호출의 종류와 호출 방법도 각기 다르다.
64비트 리눅스에서의 시스템 호출에 대한 정보는 https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/에서 확인할 수 있다.

리눅스에서 무언가를 출력하기 위해선 write 시스템 호출을 사용한다.
write 시스템 호출을 이용해서 터미널에 "Hello World!\n"를 출력하기 위해
1. rax = 1 (사용하는 시스템 호출이 write라는 것을 뜻함)
2. rdi = 1 (값을 출력할 파일의 descriptor, 1은 표준 출력)
3. rsi = "Hello World!\n" 문자열의 주소
4. rdx = 14(NULL 바이트를 제외한 문자열의 길이)

위 4개의 조건을 만족하도록 각 레지스터에 적절한 값을 넣어주고, syscall 명령어를 실행하면
우리가 원하는 write 시스템 호출을 실행할 수 있다.

어셈블리어 명령어들을 작성하기 위해 section을 선언해야한다.
text section을 선언하기 위해서 `section .text`라 입력하고 _start Procedure를
선언하기 위해 `_start:`와 같이 뒤에 :를 붙여주고, 아래에 어셈블리어를 작성한다.
```
section .text
_start:
    mov rax, 1
    mov rdi, 1
    mov rsi, message
    mov rdx, 14
    syscall
    mov rax, 60
    xor rdi, rdi
    syscall
```
첫 번째 syscall 다음 세 줄은 프로세스가 정상 종료하도록 exit 시스템 호출을 하는 부분이니
자세한건 exit 시스템 호출을 알아보면 된다.

message는 "Hello World!\n"를 담고 있는 변수 이름인데 이 또한 선언을 해주어야한다.
문자열은 data영역에 저장되므로 data영역을 선언해주고 문자열을 지정해준다.
```
section .data
message: db "Hello, World!", 10 (10은 개행문자, '\n'의 아스키 코드 값)
```
소스코드를 다 작성했다면 실행파일을 만들어야 한다.
처음에 nasm을 이용해서 목적파일을 만들고, 링킹까지 해주면 실행파일이 생성된다.
> nasm -felf hello.asm  
> ld -o hello hello.o