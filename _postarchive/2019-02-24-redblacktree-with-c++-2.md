---
layout: post
cover: 'files/redblacktree-with-c++-1/pic_1.png'
navigation: true
title: '자료구조) C++로 레드 블랙 트리 삽입&삭제 구현 - 2'
date: 2019-02-24
tags: c++ 자료구조
subclass: 'post'
logo: 'assets/images/ghost.png'
author: lanphere
categories: lanphere
disqus: true
---

> 레드 블랙 트리 - 삭제

삽입을 구현하는 건 생각보다 오래 안 걸렸는데 삭제를 구현할 때 꽤나 고생했다.
기본적으로 삽입과 마찬가지로 삭제또한 이진 탐색 트리와 비슷하다.
레드 블랙 트리에서는 **삭제 노드의 자식이 없거나 하나**인 경우만 생각하자.

삭제 노드의 자식이 둘이면 오른쪽 서브 트리에서 값이 가장 작은 원소의 값을
가져와서 원래 삭제하려는 노드의 값에 넣는다. 그리고 값을 가져온 노드를 삭제한다.
이렇게 생각하면 **임의의 노드를 삭제한다는 것은 항상 자식이 없거나 하나인 노드를 삭제**하는 경우로 바꿀 수 있다.

실제로 삭제한 노드를 m, 그 자식 노드를 x라 하자.
- m의 색이 빨강이면 문제가 없다.
  - 왜냐면 그 노드를 삭제 한다고 해서 레드 블랙 트리의 특성을 위반하지 않기 때문이다.
  - 연속으로 색이 빨강인 노드가 올 일도 없고, 경로까지의 검정 노드의 수가 변하지도 않는다.
- m의 색이 검정이라도 (유일한) 자식 x의 색이 빨강이면 문제가 없다.
  - m을 삭제하고 x를 검정으로 칠하면 문제 없다.
- 자식 노드가 없으면 x는 NIL노드(검정 노드)
![concept-pic](/files/redblacktree-with-c++-2/pic_1.JPG)
삽입과 마찬가지로 삭제하는 노드 m은 부모 노드의 왼쪽 자식이라 가정하자.

위에서 삭제하려는 노드m을 삭제하면 그 자리를 자식 노드 x가 차지하게 된다.
이 때 삭제한 노드와 그 자식 노드의 색이 모두 검정인 경우, 검정인 노드가 삭제되면서
경로 상의 검정 노드의 수가 줄어든다(black height가 줄어든다고도 한다).
이는 레드 블랙 트리 특성을 위반하는 것이기 때문에 재조정을 해야한다.

> 레드 블랙 트리 재조정 경우의 수

1. 부모 노드의 색만 빨강이고 주변의 모든 노드의 색이 검정인 경우
  - p와 s의 색을 바꿈
  - l, r로 가는 경로 상의 검정 노드의 수는 유지하면서 x로 가는 경로 상의 검정 노드 수를 증가시킴으로써 문제 해결
  ![concept-pic](/files/redblacktree-with-c++-2/pic_2.JPG)
2. x, s의 색이 검정이고 r의 색이 빨강인 경우
  - p를 중심으로 왼쪽 회전
  - p와 s의 색을 바꿈
  - r의 색을 검정으로 칠함
  ![concept-pic](/files/redblacktree-with-c++-2/pic_3.JPG)
3. x, s, r의 색이 검정이고 l의 색이 빨강인 경우
  - s를 중심으로 오른쪽 회전
  - l과 s의 색을 바꿈
  - 두 번째 경우로 이동
  ![concept-pic](/files/redblacktree-with-c++-2/pic_4.JPG)
4. 모든 노드의 색이 검정
  - s의 색을 빨강으로 칠함
  - s를 지나가는 경로에서도 검정 노드의 수가 부족해짐
  - p에 대해서 다시 재귀적으로 처리
  ![concept-pic](/files/redblacktree-with-c++-2/pic_5.JPG)
5. s의 색만 빨강이고 나머지 노드의 색이 모두 검정인 경우
  - p를 중심으로 왼쪽 회전
  - p와 s의 색을 바꿈
  - 처음 세 가지 경우 중 하나로 이동
  ![concept-pic](/files/redblacktree-with-c++-2/pic_6.JPG)

코드는 [https://github.com/Lanph3re/Red-Black-Tree](https://github.com/Lanph3re/Red-Black-Tree)에 있다.
```
void RedBlackTree::Delete(int val) {
  TreeNode *parent = this->root_;

  while (parent) {
    if (parent->val_ == val) {
      break;
    } else if (val < parent->val_) {
      parent = parent->left_child_;
    } else {
      parent = parent->right_child_;
    }
  }

  if (!parent) return;

  this->count_--;
  RedBlackTree::_Delete(parent);

  return;
}

void RedBlackTree::_Delete(TreeNode *node) {
  if (this->count_ == 0) {
    delete this->root_;
    this->root_ = NULL;
    return;
  }

  if (node->left_child_ && node->right_child_) {
    TreeNode *temp;

    for (temp = node->right_child_; temp->left_child_; temp = temp->left_child_)
      ;

    node->val_ = temp->val_;
    _Delete(temp);

    return;
  }

  // if node has a child or no children
  TreeNode *parent = node->parent_;
  TreeNode *child = node->left_child_ ? node->left_child_ : node->right_child_;
  bool is_left_child = node == parent->left_child_;

  if (node == parent) {
    this->root_ = child;
    if (child) child->parent_ = child;
  } else if (node == parent->left_child_) {
    parent->left_child_ = child;
    if (child) child->parent_ = parent;
  } else {
    parent->right_child_ = child;
    if (child) child->parent_ = parent;
  }

  if (node->color_ == BLACK) {
    if (child && child->color_ == RED) {
      child->color_ = BLACK;
    } else {
      // if (node->color_ == BLACK)
      // and if (child->color_ == BLACK)
      // problem in the number of black nodes, need to be reconstruct the three
      _DeleteColorCheck(child, parent, is_left_child);
    }
  }

  delete node;
  return;
}

void RedBlackTree::_DeleteColorCheck(TreeNode *node, TreeNode *parent,
                                     bool is_left_child) {
  TreeNode *uncle = is_left_child ? parent->right_child_ : parent->left_child_;
  bool is_parent_red = parent->color_ == RED;
  bool is_uncle_red = uncle ? uncle->color_ == RED : false;
  bool is_left_red =
      uncle ? uncle->left_child_ ? uncle->left_child_->color_ == RED : false
            : false;  // color of the left child of the uncle node
  bool is_right_red =
      uncle ? uncle->right_child_ ? uncle->right_child_->color_ == RED : false
            : false;  // color of the right child of the uncle node

  // case1: parent->color_ == RED
  //        and the color of the uncle node and its children is black
  if (is_parent_red && !is_uncle_red && !is_left_red && !is_right_red) {
    parent->color_ = BLACK;
    if (uncle) uncle->color_ = RED;
    return;
  }

  // case2: parent->color_ == BLACK
  //        and the color of the uncle node and its children is black
  if (!is_parent_red && !is_uncle_red && !is_left_red && !is_right_red) {
    if (uncle) uncle->color_ = RED;
    if (parent != this->root_)
      _DeleteColorCheck(parent, parent->parent_,
                        parent == parent->parent_->left_child_);
    return;
  }

  if (is_left_child) {
    // case3: uncle->color_ == BLACK
    //        and the color of its right child is RED
    if (!is_uncle_red && is_right_red) {
      _RotateLeft(parent);
      SWAP(parent->color_, uncle->color_);
      uncle->right_child_->color_ = BLACK;
      return;
    }

    // case4: uncle->color_ == BLACK
    //        and the color of its left child is RED, right child BLACK
    if (!is_uncle_red && is_left_red && !is_right_red) {
      _RotateRight(uncle);
      if (uncle->left_child_) {
        SWAP(uncle->color_, uncle->left_child_->color_);
      } else {
        uncle->color_ = BLACK;
      }
      _DeleteColorCheck(node, parent, is_left_child);
      return;
    }

    // case5: parent->color_ == BLACK
    //        and the color of the uncle node is RED, both children BLACK
    if (!is_parent_red && is_uncle_red && !is_left_red && !is_left_red) {
      _RotateLeft(parent);
      SWAP(parent->color_, uncle->color_);
      _DeleteColorCheck(node, parent, is_left_child);
      return;
    }
  } else {
    // case3: uncle->color_ == BLACK
    //        and the color of its left child is RED
    if (!is_uncle_red && is_left_red) {
      _RotateRight(parent);
      SWAP(parent->color_, uncle->color_);
      uncle->left_child_->color_ = BLACK;
      return;
    }

    // case4: uncle->color_ == BLACK
    //        and the color of its right child is RED, left child BLACK
    if (!is_uncle_red && is_right_red && !is_left_red) {
      _RotateLeft(uncle);
      if (uncle->right_child_) {
        SWAP(uncle->color_, uncle->right_child_->color_);
      } else {
        uncle->color_ = BLACK;
      }
      _DeleteColorCheck(node, parent, is_left_child);
      return;
    }

    // case5: parent->color_ == BLACK
    //        and the color of the uncle node is RED, both children BLACK
    if (!is_parent_red && is_uncle_red && !is_left_red && !is_left_red) {
      _RotateRight(parent);
      SWAP(parent->color_, uncle->color_);
      _DeleteColorCheck(node, parent, is_left_child);
      return;
    }
  }
}
```









