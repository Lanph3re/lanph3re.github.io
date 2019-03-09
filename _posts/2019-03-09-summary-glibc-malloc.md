---
layout: post
cover: 'assets/images/cover8.jpg'
navigation: true
title: Glibc malloc heap chunk 정리
date: 2019-03-09
tags: glibc heap malloc pwn
subclass: 'post'
logo: 'assets/images/ghost.png'
author: lanphere
categories: lanphere
disqus: true
---

heap문제를 제대로 공부해야하는데 자료를 찾지 못하다가 괜찮은 사이트를 찾았다.
[https://dangokyo.me/2017/12/05/introduction-on-ptmalloc-part1/](https://dangokyo.me/2017/12/05/introduction-on-ptmalloc-part1/)를 참고했다. 이 사이트에선 glibc 2.25를 분석했는데 이 글에선 glibc 2.23를 보면서 같이 쓰다보니 충돌이 있을 수도 있다.

> malloc_consolidate

malloc_consolidate 함수는 fastbin에 있는 free chunks를 merge해서 unsorted bin에 넣는다. fastbin에서 chunks를 가져오고 아래의 과정을 거친다.

1. 인접한 이전 chunk가 Free chunk인지 아닌지 확인한다.
  - 만약 Free chunk라면 merge한다.
2. 인접한 다음 chunk가 top chunk인지 확인한다.
  - 만약 Top chunk라면 현재 chunk와 top chunk를 merge해서 top chunk로 만든다.
  - 아니라면 아래 과정으로 넘어간다.
3. 인접한 다음 chunk가 Free chunk인지 아닌지 확인한다.
  - 만약 Free chunk가 아니면 현재 chunk를 unsorted bin에 넣고 다음 chunk의 P Flag를 unset한다.
  - 만약 Free chunk면 다음 chunk와 merge하고 unsorted bin에 넣고 다음 chunk(merge된 chunk의 다음)의 P Flag를 unset한다.

> __int_malloc

**__int_malloc**함수는 malloc()에서 요청한 메모리를 bin이나 main_arena에서 찾아서 return하는 함수이다.

먼저 현재 available한 arena가 없으면 sysmalloc을 호출해서 arena를 받아온다.

그 다음 malloc의 인자로 들어온 메모리의 크기 값을 malloc alignment에 맞게 변환한 후(x86은 8바이트 x64는 16바이트) 요청받은 크기의 메모리를 Fastbin, Unsorted bin, Small bin, Large bin, 그리고 Top chunk 순서대로 찾아 나간다.

**Fastbin**
```
  /*
     If the size qualifies as a fastbin, first check corresponding bin.
     This code is safe to execute even if av is not yet initialized, so we
     can try it without checking, which saves some time on this fast path.
   */

  if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
    {
      idx = fastbin_index (nb);
      mfastbinptr *fb = &fastbin (av, idx);
      mchunkptr pp = *fb;
      do
        {
          victim = pp;
          if (victim == NULL)
            break;
        }
      while ((pp = catomic_compare_and_exchange_val_acq (fb, victim->fd, victim))
             != victim);
      if (victim != 0)
        {
          if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0))
            {
              errstr = "malloc(): memory corruption (fast)";
            errout:
              malloc_printerr (check_action, errstr, chunk2mem (victim), av);
              return NULL;
            }
          check_remalloced_chunk (av, victim, nb);
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;
        }
    }
```
요청 받은 크기가 global_max_fast(fastbin chunk의 최대크기)보다 작거나 같으면 fastbin에 적당한 chunk가 있는지 찾는다.

**Small bin**
```
/*
   If a small request, check regular bin.  Since these "smallbins"
   hold one size each, no searching within bins is necessary.
   (For a large request, we need to wait until unsorted chunks are
   processed to find best fit. But for small ones, fits are exact
   anyway, so we can check now, which is faster.)
 */
 
if (in_smallbin_range (nb))
  {
    idx = smallbin_index (nb);
    bin = bin_at (av, idx);
 
    if ((victim = last (bin)) != bin)
      {
        if (victim == 0) /* initialization check */
          malloc_consolidate (av);
        else
        {
            bck = victim->bk;
        if (__glibc_unlikely (bck->fd != victim))
            {
                errstr = "malloc(): smallbin double linked list corrupted";
                goto errout;
            }
            set_inuse_bit_at_offset (victim, nb);
            bin->bk = bck;
            bck->fd = bin;
 
            if (av != &main_arena)
      set_non_main_arena (victim);
            check_malloced_chunk (av, victim, nb);
            void *p = chunk2mem (victim);
            alloc_perturb (p, bytes);
            return p;
         }
      }
  }
```
요청받은 크기가 Small bin에 해당하면 Small bin에서 적합한 chunk를 찾고, FIFO에 따라 chunk를 반환한다. 만약 Small bin에서 chunk를 찾지 못하면 malloc_consolidate을 호출한다.

**Large bin**
```
  /*
     If this is a large request, consolidate fastbins before continuing.
     While it might look excessive to kill all fastbins before
     even seeing if there is space available, this avoids
     fragmentation problems normally associated with fastbins.
     Also, in practice, programs tend to have runs of either small or
     large requests, but less often mixtures, so consolidation is not
     invoked all that often in most programs. And the programs that
     it is called frequently in otherwise tend to fragment.
   */

  else
    {
      idx = largebin_index (nb);
      if (have_fastchunks (av))
        malloc_consolidate (av);
    }
```
Small bin에 해당하는 사이즈가 아니라면 먼저 malloc_consolidate를 호출해서 fastbin에 있는 chunk들을 merge시킨다.

**Unsorted bin**
```
while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
{
     bck = victim->bk;
     if (__builtin_expect (chunksize_nomask (victim)  av->system_mem, 0))
        malloc_printerr (check_action, "malloc(): memory corruption",
                             chunk2mem (victim), av);
     size = chunksize (victim);
 
     /*
         If a small request, try to use last remainder if it is the
         only chunk in unsorted bin.  This helps promote locality for
         runs of consecutive small requests. This is the only
         exception to best-fit, and applies only when there is
         no exact fit for a small chunk.
     */
 
     if (in_smallbin_range (nb) &&
         bck == unsorted_chunks (av) &&
         victim == av->last_remainder &&
         (unsigned long) (size) > (unsigned long) (nb + MINSIZE))
     {
         /* split and reattach remainder */
         remainder_size = size - nb;
         remainder = chunk_at_offset (victim, nb);
         unsorted_chunks (av)->bk = unsorted_chunks (av)->fd = remainder;
         av->last_remainder = remainder;
         remainder->bk = remainder->fd = unsorted_chunks (av);
         if (!in_smallbin_range (remainder_size))
         {
            remainder->fd_nextsize = NULL;
            remainder->bk_nextsize = NULL;
         }
 
         set_head (victim, nb | PREV_INUSE |
                  (av != &main_arena ? NON_MAIN_ARENA : 0));
         set_head (remainder, remainder_size | PREV_INUSE);
         set_foot (remainder, remainder_size);
 
         check_malloced_chunk (av, victim, nb);
         void *p = chunk2mem (victim);
         alloc_perturb (p, bytes);
         return p;
      }
 
      /* remove from unsorted list */
      unsorted_chunks (av)->bk = bck;
      bck->fd = unsorted_chunks (av);
 
      /* Take now instead of binning if exact fit */
 
      if (size == nb)
      {
          set_inuse_bit_at_offset (victim, size);
          if (av != &main_arena)
             set_non_main_arena (victim);
          check_malloced_chunk (av, victim, nb);
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;
       }
 
       /* place chunk in bin */
 
       if (in_smallbin_range (size))
       {
           victim_index = smallbin_index (size);
           bck = bin_at (av, victim_index);
           fwd = bck->fd;
       }
       else
       {
           victim_index = largebin_index (size);
           bck = bin_at (av, victim_index);
           fwd = bck->fd;
 
           /* maintain large bins in sorted order */
           if (fwd != bck)
           {
               /* Or with inuse bit to speed comparisons */
               size |= PREV_INUSE;
               /* if smaller than smallest, bypass loop below */
               assert (chunk_main_arena (bck->bk));
               if ((unsigned long) (size)
              bk))
               {
                   fwd = bck;
                   bck = bck->bk;
 
                   victim->fd_nextsize = fwd->fd;
                   victim->bk_nextsize = fwd->fd->bk_nextsize;
                   fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
               }
               else
               {
                   assert (chunk_main_arena (fwd));
                   while ((unsigned long) size fd_nextsize;
               assert (chunk_main_arena (fwd));
                   }
 
                   if ((unsigned long) size
                == (unsigned long) chunksize_nomask (fwd))
                       /* Always insert in the second position.  */
                       fwd = fwd->fd;
                   else
                   {
                       victim->fd_nextsize = fwd;
                       victim->bk_nextsize = fwd->bk_nextsize;
                       fwd->bk_nextsize = victim;
                       victim->bk_nextsize->fd_nextsize = victim;
                   }
                   bck = fwd->bk;
                }
            }
            else
                victim->fd_nextsize = victim->bk_nextsize = victim;
       }
 
       mark_bin (av, victim_index);
       victim->bk = bck;
       victim->fd = fwd;
       fwd->bk = victim;
       bck->fd = victim;
 
#define MAX_ITERS       10000
       if (++iters >= MAX_ITERS)
          break;
}
```
할당자는 Unsorted bin에서 위 코드의 과정을 반복한다. 만약 bin내의 첫 chunk가 아래의 조건들을 만족하면 그 chunk는 요청받은 크기와 나머지로 분리된 후 요청받은 크기의 chunk는 반환되고 나머지 chunk는 다시 Unsorted bin에 들어가게 된다.
1. 요청받은 크기가 Small bin에 해당하는 경우
2. Unsorted Bin에 있는 chunk가 1개일 경우
3. Unsorted Bin에 있는 chunk가 또한 last remainder chunk인 경우
4. 분리된 후의 chunk 크기가 충분히 큰 경우(remain chunk의 크기가 chunk의 최소 크기보다 큰 경우)

위 4가지 조건 중 하나라도 만족하지 않으면 아래의 과정을 따른다.

만약 Unsorted bin에 있는 chunk의 크기가 요청받은 크기와 같은 경우 해당 chunk를 반환하고 끝난다. 그렇지 않으면 위 코드의 과정이 반복되면서 Unsorted chunk의 상태를 확인한다.
1. 만약 Unsorted chunk의 크기 Small bin에 해당하는 경우 해당 chunk는 적절한 Small bin에 들어가게 되고, 위 코드의 과정을 다음 Unsorted chunk에 대해 반복
2. 그렇지 않으면(Small bin 범위가 아니면), 즉 Chunk가 Large bin 범위이고 해당 Large bin이 비어 있으면 해당 Chunk를 Large bin에 넣고 위 코드의 과정을 다음 Unsorted chunk에 대해 반복
3. Chunk가 Large bin 범위이고 해당 Large bin이 비어 있지 않으면 해당 Chunk는 크기에 대해 내림차순으로 해당 Large bin에 들어간다

전체 for문을 MAX_ITERS 만큼 반복 후에는 나머지 과정을 처리하게 된다.