---
layout: post
cover: 'assets/images/cover8.jpg'
navigation: true
title: Rust로 PEViewer 프로젝트 계획
date: 2019-06-26
tags: 공부 주저리
subclass: 'post'
logo: 'assets/images/ghost.png'
author: lanphere
categories: lanphere
disqus: true
---

최근에 **Rust**에 관심이 생겼다. Firefox 브라우저를 만든 Mozila에서
개발한 언어인데, 코드의 안정성을 상당한 수준으로 보장해준다.
몇 가지 특징이라면

1. Garbage Collector를 사용하지 않으면서 메모리 관리
    - 컴파일러가 메모리 해제 함수를 알아서 삽입
2. 소유권 개념을 통한 메모리 접근 제어
    - 같은 객체를 가리키는 포인터가 여러 개 존재하지 않도록 제한
3. Integer Overflow, Out of Index 접근을 허용하지 않는다.

등이 있다.

```
fn main() {
    let s1 = String::from("hello");

    let (s2, len) = calculate_length(s1);

    println!("The length of '{}' is {}.", s2, len);
}

fn calculate_length(s: String) -> (String, usize) {
    let length = s.len(); // len() returns the length of a String

    (s, length)
}
```

평소 C언어랑 Python을 자주 보다 Rust를 보니 코드가 꽤 신기하게 생겼다.
뭐랄까 C계열 언어와 파이썬, 자바스크립트 등을 섞은 듯한 느낌이다. 여러모로 관심이 생겨서
이번 방학 때 한 번 공부해보고 싶은 생각이 들었다. 프로그래밍 언어도 언어이기 때문에
글로 배우는 것보다 직접 써보면서 배워야 한다는 생각에 어떤 프로젝트를 해볼까 생각 중
PE Viewer를 만들어 보기로 했다!

간단하게 CLI로 만들 생각이다. C로 만든다면 훨씬 수월하게 만들 수 있겠지만 전적으로 새 언어를 공부한다는 데서
의미가 있는 것이기 때문이다. PE 구조도 공부를 다시 해야한다.
PE구조와 더불어서 Rust에 대해서도 포스팅을 할 수 있을 듯 하고 프로젝트 코드도 GitHub와 글을 통해서 공유할 생각이다.