---
layout: post
cover: 'files/redblacktree-with-c++-1/pic_1.png'
navigation: true
title: '자료구조) C++로 레드 블랙 트리 삽입&삭제 구현 - 1'
date: 2019-02-18
tags: c++ 자료구조
subclass: 'post'
logo: 'assets/images/ghost.png'
author: lanphere
categories: lanphere
disqus: true
---

스스로 레드 블랙 트리를 구현해보면서 개념을 정리해봤다. 자료는 학교 알고리즘 수업시간의 강의자료를 참고했다.

>  레드 블랙 트리?

레드 블랙 트리는 자식이 2개고 균형잡힌 트리이다. 즉 균형잡힌 이진 트리이다(Balanced Binary Search Tree).
일반적인 이진 트리의 경우 최악의 경우 연산의 시간복잡도가 N이 되기 때문에 전체 트리의 높이를 최소화하는게 좋다.

다시 말하면 두 자식이 루트인 서브 트리의 높이가 비슷할 수록 좋다.
그래서 레드 블랙 트리랑 비슷한 트리로 AVL 트리라는 것도 있다. 마찬가지로 균형잡힌 이진 트리이다.

트리를 균형있게 만들면 연산에 대해서 평균적으로 Log N의 시간복잡도를 가지게 된다.
![concept-pic](/files/redblacktree-with-c++-1/pic_1.png)

> 레드 블랙 트리의 특징

레드 블랙 트리는 개념적으로 각 트리 노드가 빨강, 혹은 검정색을 가진다고 가정한다.
왜 빨강이랑 검정인진 모르겠다. 블랙 앤 화이트가 될 수도 있고 레드 블루일 수도 있지 않았을까 하는 생각을 해본다..
기본적으로 아래와 같은 특징이 있다.

1. 루트 노드의 색은 검정이다.
2. 트리의 끝(리프 노드의 자식, NULL 포인터)에도 노드가 있다고 개념적으로 가정하고, 그 노드의 색은 검정이다.
3. 임의의 색이 빨강인 노드의 자식 노드의 색은 검정이다.
  - 다시 말해 빨강색 노드가 연속으로 올 수 없다.
4. 루트 노드에서 특정 리프 노드까지의 경로에 있는 색이 검정인 노드의 수는 모두 같다.

두 번째 조건이 왜 있는 지 처음엔 몰랐다가 구현을 직접 해보면서 중요성을 꺠달았다.
노드 삭제를 구현할 때 주변 노드의 색상을 고려해야하는 데, 이 때 두 번째 조건이 쓰인다.

> 레드 블랙 트리 - 삽입

레드 블랙 트리에서 노드를 삽입하는 과정은 기본적으로 일반적인 이진 탐색 트리와 같다.
루트의 값과 삽입하려는 노드의 값을 비교한 후 루트의 값보다 작으면 왼쪽, 크면 오른쪽에 삽입한다.
다만 이후에 노드의 색과 관련해서 레드 블랙트리의 특성을 만족시켜야하기 때문에 트리 구조를 재조정하는 과정이 필요하다.

삽입한 노드가 트리의 첫 노드이면(루트) 색을 검정으로 칠하고 삽입을 종료한다.
만약 첫 노드가 아니면 색을 일단 빨강으로 칠하고, 부모 노드의 색을 확인한다.
만약 부모 노드의 색이 빨강이면 레드 블랙 트리의 세 번째 특징, 연속으로 색이 빨강인 노드가 올 수 없다는 규칙에 의해 트리를 재조정해야한다.
![concept-pic](/files/redblacktree-with-c++-1/pic_2.JPG)

재조정을 할 때 부모 노드의 형제노드, 즉 삼촌 노드의 색에 따라 두 가지 경우의 수가 있다. 본 글에서는 p가 부모노드의 왼쪽 자식인 경우에만 다뤘다. 오른쪽 자식인 경우는
완벽하게 대칭이기 때문이다.

1) s가 빨강
 - p와 s의 색을 검정으로 칠함
 - 부모의 부모노드(p^2)의 색을 빨강으로 칠함
   - p^2가 루트면 p^2의 색을 다시 검정으로 칠함
   - p^2가 루트가 아니면 p^2의 부모 노드의 색을 다시 확인하고, 재귀적으로 처리
  
  ![concept-pic](/files/redblacktree-with-c++-1/pic_3.JPG)
2-1) s가 검정이고 x가 p의 오른쪽 자식
  - p를 중심으로 왼쪽 회전 --> 2.2)로 이동
  
  ![concept-pic](/files/redblacktree-with-c++-1/pic_4.JPG)

2-2) x가 p의 왼쪽 자식
  - p^2를 중심으로 오른쪽 회전
  - p와 p^2의 색을 바꿈

  ![concept-pic](/files/redblacktree-with-c++-1/pic_5.JPG)

코드는 [https://github.com/Lanph3re/Red-Black-Tree](https://github.com/Lanph3re/Red-Black-Tree)에 있다.
```
void RedBlackTree::Insert(int val) {
  TreeNode *new_node = new TreeNode(val);
  TreeNode *parent = this->root_;
  this->count_++;

  if (!parent) {
    this->root_ = new_node;
    new_node->color_ = BLACK;
    new_node->parent_ = new_node;
    return;
  }

  while (true) {
    if (val < parent->val_) {
      // if given value is less than the value of the current parent node
      if (parent->left_child_) {
        parent = parent->left_child_;
      } else {
        parent->left_child_ = new_node;
        new_node->color_ = RED;
        new_node->parent_ = parent;

        _InsertColorCheck(new_node);
        return;
      }
    } else {
      // if given value is more than the value of the current parent node
      if (parent->right_child_) {
        parent = parent->right_child_;
      } else {
        parent->right_child_ = new_node;
        new_node->color_ = RED;
        new_node->parent_ = parent;

        _InsertColorCheck(new_node);
        return;
      }
    }
  }
}

void RedBlackTree::_InsertColorCheck(TreeNode *node) {
  TreeNode *parent = node->parent_, *grand_parent = node->parent_->parent_,
           *uncle;

  if (parent->color_ == RED) {
    // Two reds in a row
    uncle = grand_parent->right_child_ == parent ? grand_parent->left_child_
                                                 : grand_parent->right_child_;
    if (uncle && uncle->color_ == RED) {
      parent->color_ = uncle->color_ = BLACK;
      grand_parent->color_ = RED;

      if (grand_parent == this->root_) {
        grand_parent->color_ = BLACK;
      } else {
        _InsertColorCheck(grand_parent);
      }
    } else {
      // if uncle->color_ == BLACK
      // and if the parent node is the left child of the grand parent node
      if (parent == grand_parent->left_child_) {
        // and node is the right child of parent node
        if (node == parent->right_child_) {
          _RotateLeft(parent);
          _RotateRight(grand_parent);
          grand_parent->color_ = RED;
          node->color_ = BLACK;
        } else {
          _RotateRight(grand_parent);
          grand_parent->color_ = RED;
          parent->color_ = BLACK;
        }
      } else {
        // and if the parent node is the right child of the grand parent node
        // and node is the left child of parent node
        if (node == parent->left_child_) {
          _RotateRight(parent);
          _RotateLeft(grand_parent);
          grand_parent->color_ = RED;
          node->color_ = BLACK;
        } else {
          _RotateLeft(grand_parent);
          grand_parent->color_ = RED;
          parent->color_ = BLACK;
        }
      }
    }
  }

  return;
}
```





