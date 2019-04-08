---
layout: post
cover: 'assets/images/cover8.jpg'
navigation: True
title: '[데이터베이스]정규화, 1NF, 2NF, .. 등 정리'
date: 2019-04-08
tags: 공부 db
subclass: 'post'
logo: 'assets/images/ghost.png'
author: lanphere
categories: lanphere
disqus: true
---

### 정규화(Normalization)

> 관계형 데이터베이스의 설계에서 **중복을 최소화**하게 데이터를 구조화하는 프로세스를 정규화라고 한다. 데이터베이스 정규화의 목표는 이상이 있는 관계를 재구성하여 **작고 잘 조직된 관계**를 생성하는 것에 있다. 일반적으로 정규화란 크고, 제대로 조직되지 않은 테이블들과 관계들을 작고 잘 조직된 테이블과 관계들로 나누는 것을 포함한다. 정규화의 목적은 하나의 테이블에서의 데이터의 삽입, 삭제, 변경이 정의된 관계들로 인하여 데이터베이스의 나머지 부분들로 전파되게 하는 것이다.

쉽게 정리하면 정규화는 **데이터베이스를 깔끔하고 효율적으로 설계하는 것**이라 할 수 있다.


### 제1 정규화(1NF)

S_ID | S_NAME | S_PHONE | COURSE_ID | GRADE
-----|--------|---------|-----------|------
2017320123| A |010-1234-4567|COSE371, COSE123|A+, B+
2017320456| B |010-4321-7654|COSE371, COSE456|A, B

위와 같은 Relation이 있다고 할 때, 두 Row 모두 COURSE_ID, GRADE에 두 개의 값을 가지고 있다.
이 때문에 모든 Column에 대해서 값들이 Atomic하지 않다고 하며, 1NF를 만족하지 않는다.
1NF의 정의에 대해선 여러가지 기준이 있다고는 하나 **한 Column에 한 값을 가지는 것(Atomic)한 것**이 일반적인 기준이다.

S_ID | S_NAME | S_PHONE | COURSE_ID | GRADE
-----|--------|---------|-----------|------
2017320123| A |010-1234-4567|COSE371|A+
2017320123| A |010-1234-4567|COSE123|B+
2017320456| B |010-4321-7654|COSE371|A
2017320456| B |010-4321-7654|COSE456|B

위 Relation은 처음의 Relation을 1NF를 만족하게 고친 것이다.

여기서 예를 들어 학번이 2017320789이고 이름이 C인 학생을 추가하려고 한다. 하지만 이 **학생 C가 수강한 과목이 없으면 COURSE_ID를 NULL로 하지 않고서는 추가할 수가 없다.** 이를 **삽입 이상(Insertion Anomaly)**이라고 한다.

또한 학생 A에 대해서 **두 수강 기록을 지우게 되면 아예 학생 A에 대한 기록이 사라지게 된다.** 이를 **삭제 이상(Deletion Anomaly)**이라고 한다.

마지막으로, **학생 A의 전화번호를 변경하고자 한다면 두 Row의 모든 S_PHONE 값을 수정해야 한다.** 이를 **수정 이상(Update Anomaly)**이라고 한다. 이런 경우에 빼먹지 않고 모든 데이터를 갱신한다면 문제가 없지만 그렇지 못한 경우가 생길 수 있고, 이는 문제로 이어질 수 있다.

---

### 제2 정규화(2NF)

S_ID | S_NAME | S_PHONE | COURSE_ID | GRADE
-----|--------|---------|-----------|------
2017320123| A |010-1234-4567|COSE371|A+
2017320123| A |010-1234-4567|COSE123|B+
2017320456| B |010-4321-7654|COSE371|A
2017320456| B |010-4321-7654|COSE456|B

위 Relation에서 S_ID와 COURSE_ID가 기본키라고 하자.

S_NAME, S_PHONE의 경우 COUSE_ID는 필요없이 S_ID 하나만 가지고도 유일하게 결정할 수 있다.
이럴 때 S_NAME, S_PHONE은 S_ID와 **부분적 함수 종속관계**에 있다고 한다.

하지만 GRADE는 S_ID, COURSE_ID 즉 기본키의 두 Attribute가 모두 있어야 결정할 수 있다.
따라서 GRADE는 기본키에 대해서 **완전 함수 종속관계**에 있다고 한다.

**Relation의 모든 Column들이 기본키와 완전 함수 종속관계에 있을 때, 그 Relation이 2NF를 만족**한다고 얘기한다.

S_ID | S_NAME | S_PHONE
-----|--------|---------
2017320123| A |010-1234-4567
2017320456| B |010-4321-7654

S_ID | COURSE_ID | GRADE
-----|-----------|--------
2017320123|COSE371|A+
2017320123|COSE123|B+
2017320456|COSE371|A
2017320456|COSE456|B

따라서 2NF를 만족하도록 Relation을 고치면 위와 같이 된다.

---

### 제3 정규화(3NF)

일반적으로 현업에서 제3 정규화까지만 만족시키면 정규화가 됐다고 한다.

1. Relation이 제2 정규화(2NF)를 만족한다.
2. Relation 내의 Primary Key를 제외한 모든 Column들은 오직 Primary Key에만 종속된다.

위 두 가지 조건을 만족하는 Relation에 대해서 제 3정규화(3NF)를 만족한다고 한다.
2번은 다른 말로 Primary Key를 제외한 모든 Column들이 Primary Key에 대해 이행적 종속 관계(Transitive Dependent)에 있지 않다고도 한다.

#### 이행적 종속 관계(Transitive Dependent)

가령 아래와 같은 Relation이 있다고 하자.

S_ID | DEPT_NAME | TUITION
-----|-----------|--------
2017320123|Comp. Sci.|5000
2017320456|Comp. Sci.|5000
2017240123|History|4500
2017450123|Physics|6000

Primary Key는 S_ID라고 할 때, **Primary Key를 이루는 Attribute가 하나만 있기 때문에 자동적으로 위 Relation은 2NF를 만족한다.** 즉, S_ID가 정해지면 DEPT_NAME이 결정되고 TUITION 또한 마찬가지다.

**하지만 DEPT_NAME와 TUITION 사이에도 함수 종속관계에 있다**. 다시 말해 DEPT_NAME은 TUITION을 결정한다. S_ID는 DEPT_NAME을 결정하고, DEPT_NAME은 TUITION을 결정짓는다. 그러므로 S_ID는 TUITION을 결정한다.(A->B, B->C이면 A->C)
이런 관계를 이행적 종속 관계(Transitive Dependent)에 있다고 하고 **제3 정규화에서는 이와 같은 이행적 종속 관계를 없애기 위해 결국엔 Relation을 둘로 나누어야 한다.**

S_ID | DEPT_NAME
-----|----------
2017320123|Comp. Sci.
2017320456|Comp. Sci.
2017240123|History
2017450123|Physics

DEPT_NAME | TUITION
----------|--------
Comp. Sci.|5000
History|4500
Physics|6000

위와 같이 Relation을 둘로 나누면 이 두 Relation은 제3 정규화를 만족하게 된다.

### BCNF 정규화

제4 정규화(4NF), 제5 정규화(5NF)가 존재하지만 이 BCNF는 제3 정규화와 제4 정규화의 중간 정도의 제약이 따르는 정규화다. 강한 제3 정규화, 제3.5 정규화라고도 한다.

1. Relation이 제3 정규화를 만족
2. 함수 종속관계 A -> B에 대해 A는 해당 Relation에 대한 Super Key여야 한다.

S_ID | COURSE_NAME | PROF
-----|-----------|--------
2017320123|Database|Jack
2017320456|Database|Jack
2017320123|Operating System|Smith
2017450123|Operating System|Tom
2017320123|Computer Architecture|Johnson

위와 같은 Relation에서 Primary Key가 S_ID, COURSE_NAME이라 하자.
모든 Column의 모든 Attribute가 1개씩 있으므로 제1 정규화를 만족한다.

또한 S_ID 혼자서 PROF을 결정하지 않고, COURSE_NAME 혼자서 PROF을 결정하지 않는다. 따라서 제2 정규화를 만족한다.

또한 이행적 종속 관계도 없기 때문에 제3 정규화도 만족한다.

이 Relation에서 종속 관계를 찾아보면

1. {S_ID, COURSE_NAME} -> PROF
2. {S_ID, PROF} -> COURSE_NAME
3. PROF -> COURSE_NAME

세 가지가 있다. 여기서 1,2 의 결정자 즉 {S_ID, COURSE_NAME}, {S_ID, PROF}는 이 Relation의 Super Key인 반면 PROF는 Super Key가 아니다. 처음 두 튜플을 보면
둘 다 PROF가 Jack이지만 S_ID는 다르기 때문이다.

S_ID | PROF
-----|------
2017320123|Jack
2017320456|Jack
2017320123|Smith
2017450123|Tom
2017320123|Johnson

COURSE_NAME | PROF
------------|------
Jack|Database
Smith|Operating System
Tom|Operating System
Johnson|Computer Architecture

이렇게 두 Relation으로 나누면 BCNF를 만족하게 할 수 있다.