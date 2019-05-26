---
layout: post
cover: 'assets/images/cover8.jpg'
navigation: True
title: 'Visual Studio Code 유용한 단축키 정리'
date: 2019-05-26
tags: 개발
subclass: 'post'
logo: 'assets/images/ghost.png'
author: lanphere
categories: lanphere
disqus: true
---

이번 포스팅에는 Visual Studio Code에서 자주 쓰는 단축키를 정리해봤다.
외우면 좋은 단축키는 많지만 기능이 겹치치 않는 선에서 적당히 필요하다고 생각하는 것만 정리했다.
익혀두고 적응하면 확실히 코딩할 때 간결하고 빠르게 작업할 수 있는 것 같다!

### 코드 이동 - Alt + 상/하 방향키
![pic_1](/files/vscode-shortcuts/alt_direc_up_down.gif)
옮기고 싶은 코드 위에 커서를 두고 Alt + 상/하 방향키를 누르면 코드를 위나 아래로 이동시킬 수 있다.
커서를 여러 개 두거나(다중 커서) 코드 여러 줄을 드래그 하면 여러 줄을 한 번에 옮기는 것도 가능하다.

### 코드 복사 - Shift + Alt + 상/하 방향키
![pic_2](/files/vscode-shortcuts/shift_alt_up_down.gif)
복사하고 싶은 코드 위에 커서를 둔 상태에서 Shift + Alt + 상/하 방향키를 누르면 해당 코드를 위나 아래에 복사할 수 있다.
Ctrl + C, V를 누른 거랑 사실 동일하긴 하지만 위에서 설명한 코드 이동이랑 단축키가 비슷해서 같이 활용을 많이 하는 편이다.
유용한 단축키 중에 하나! 코드 이동이랑 마찬가지로 코드 여러 줄을 복사할 수도 있다.

### 다중 커서 - Ctrl + Alt + 상/하 방향키
![pic_3](/files/vscode-shortcuts/ctrl_alt_up_down.gif)
말 그대로 커서를 여러 개 만들 수 있는 단축 키이다. Ctrl + Alt를 누르고 위나 아래 방향키를 누르면 해당 커서 위나 아래에
커서가 추가 된다. 바로 곧이어 설명할 블록 드래그의 마우스 버전이랄까 활용 빈도가 낮긴 하지만 필요할 땐 유용하게 쓰는 단축키이다.

### 블록 드래그 - Shift + Alt + 드래그
![pic_4](/files/vscode-shortcuts/shift_alt_drag.gif)
언젠가 문득 여러 줄의 글이 있을 때 모든 줄의 앞부분(혹은 뒷부분)만 드래그를 동시에 할 수 없을까 생각한 적이 있었다.
없으면 구현을 해볼까 하는 생각을 했었는데 역시나 Visual Studio Code에 이미 있는 기능이었다.

### 같은 단어 동시에 수정하기 - Ctrl + Shift + l
![pic_5](/files/vscode-shortcuts/ctrl_shift_l.gif)
코드 상에 있는 여러 단어를 동시에 수정할 때 쓰는 단축키이다.

그 외에도 Visual Studio Code 단축키 설정을 잘 살펴보면 유용하게 쓸 수 있는 단축키들이 많고,
기능은 있지만 단축키가 설정돼 있지 않은 것들도 많긴 하다. 마지막으로 위에서 언급한 단축키 외 자주 쓰이는 것들을 정리하고 마무리한다.

기능                  | 단축키
---------------------|--------
블록주석(해제)         | Shift + Alt + a
해당 한 줄 삭제        | Ctrl + Shift + k
해당 블록 접기/펴기    | Ctrl + Shift + [, ]
탭, 거꾸로 탭         | Ctrl + [, ]
커서 아래에 빈 행 삽입 | Ctrl + Enter
커서 위에 빈 행 삽입   | Ctrl + Shift + Enter