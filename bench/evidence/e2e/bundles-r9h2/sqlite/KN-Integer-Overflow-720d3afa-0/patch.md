## Patch Description

Fix potential integer overflow in btree overflow page cache computation,
reported by Project Fortify.  Test cases in TH3.

FossilOrigin-Name: dfa674d6e6bffdb930dbefa767831db7862c322b6d3c7a6322f0fa0f087aaaf9

## Buggy Code

```c
// Function: accessPayload in src/btree.c
static int accessPayload(
  BtCursor *pCur,      /* Cursor pointing to entry to read from */
  u32 offset,          /* Begin reading this far into payload */
  u32 amt,             /* Read this many bytes */
  unsigned char *pBuf, /* Write the bytes into this buffer */
  int eOp              /* zero to read. non-zero to write. */
){
  unsigned char *aPayload;
  int rc = SQLITE_OK;
  int iIdx = 0;
  MemPage *pPage = pCur->pPage;               /* Btree page of current entry */
  BtShared *pBt = pCur->pBt;                  /* Btree this cursor belongs to */
#ifdef SQLITE_DIRECT_OVERFLOW_READ
  unsigned char * const pBufStart = pBuf;     /* Start of original out buffer */
#endif

  assert( pPage );
  assert( eOp==0 || eOp==1 );
  assert( pCur->eState==CURSOR_VALID );
  if( pCur->ix>=pPage->nCell ){
    return SQLITE_CORRUPT_PAGE(pPage);
  }
  assert( cursorHoldsMutex(pCur) );

  getCellInfo(pCur);
  aPayload = pCur->info.pPayload;
  assert( (u64)offset+(u64)amt <= (u64)pCur->info.nPayload );

  assert( aPayload > pPage->aData );
  if( (uptr)(aPayload - pPage->aData) > (pBt->usableSize - pCur->info.nLocal) ){
    /* Trying to read or write past the end of the data is an error.  The
    ** conditional above is really:
    **    &aPayload[pCur->info.nLocal] > &pPage->aData[pBt->usableSize]
    ** but is recast into its current form to avoid integer overflow problems
    */
    return SQLITE_CORRUPT_PAGE(pPage);
  }

  /* Check if data must be read/written to/from the btree page itself. */
  if( offset<pCur->info.nLocal ){
    int a = amt;
    if( a+offset>pCur->info.nLocal ){
      a = pCur->info.nLocal - offset;
    }
    rc = copyPayload(&aPayload[offset], pBuf, a, eOp, pPage->pDbPage);
    offset = 0;
    pBuf += a;
    amt -= a;
  }else{
    offset -= pCur->info.nLocal;
  }


  if( rc==SQLITE_OK && amt>0 ){
    const u32 ovflSize = pBt->usableSize - 4;  /* Bytes content per ovfl page */
    Pgno nextPage;

    nextPage = get4byte(&aPayload[pCur->info.nLocal]);

    /* If the BtCursor.aOverflow[] has not been allocated, allocate it now.
    **
    ** The aOverflow[] array is sized at one entry for each overflow page
    ** in the overflow chain. The page number of the first overflow page is
    ** stored in aOverflow[0], etc. A value of 0 in the aOverflow[] array
    ** means "not yet known" (the cache is lazily populated).
    */
    if( (pCur->curFlags & BTCF_ValidOvfl)==0 ){
      int nOvfl = (pCur->info.nPayload-pCur->info.nLocal+ovflSize-1)/ovflSize;
      if( pCur->aOverflow==0
       || nOvfl*(int)sizeof(Pgno) > sqlite3MallocSize(pCur->aOverflow)
      ){
        Pgno *aNew;
        if( sqlite3FaultSim(413) ){
          aNew = 0;
        }else{
          aNew = (Pgno*)sqlite3Realloc(pCur->aOverflow, nOvfl*2*sizeof(Pgno));
        }
        if( aNew==0 ){
          return SQLITE_NOMEM_BKPT;
        }else{
          pCur->aOverflow = aNew;
        }
      }
      memset(pCur->aOverflow, 0, nOvfl*sizeof(Pgno));
      pCur->curFlags |= BTCF_ValidOvfl;
    }else{
      /* Sanity check the validity of the overflow page cache */
      assert( pCur->aOverflow[0]==nextPage
           || pCur->aOverflow[0]==0
           || CORRUPT_DB );
      assert( pCur->aOverflow[0]!=0 || pCur->aOverflow[offset/ovflSize]==0 );

      /* If the overflow page-list cache has been allocated and the
      ** entry for the first required overflow page is valid, skip
      ** directly to it.
      */
      if( pCur->aOverflow[offset/ovflSize] ){
        iIdx = (offset/ovflSize);
        nextPage = pCur->aOverflow[iIdx];
        offset = (offset%ovflSize);
      }
    }

    assert( rc==SQLITE_OK && amt>0 );
    while( nextPage ){
      /* If required, populate the overflow page-list cache. */
      if( nextPage > pBt->nPage ) return SQLITE_CORRUPT_BKPT;
      assert( pCur->aOverflow[iIdx]==0
              || pCur->aOverflow[iIdx]==nextPage
              || CORRUPT_DB );
      pCur->aOverflow[iIdx] = nextPage;

      if( offset>=ovflSize ){
        /* The only reason to read this page is to obtain the page
        ** number for the next page in the overflow chain. The page
        ** data is not required. So first try to lookup the overflow
        ** page-list cache, if any, then fall back to the getOverflowPage()
        ** function.
        */
        assert( pCur->curFlags & BTCF_ValidOvfl );
        assert( pCur->pBtree->db==pBt->db );
        if( pCur->aOverflow[iIdx+1] ){
          nextPage = pCur->aOverflow[iIdx+1];
        }else{
          rc = getOverflowPage(pBt, nextPage, 0, &nextPage);
        }
        offset -= ovflSize;
      }else{
        /* Need to read this page properly. It contains some of the
        ** range of data that is being read (eOp==0) or written (eOp!=0).
        */
        int a = amt;
        if( a + offset > ovflSize ){
          a = ovflSize - offset;
        }

#ifdef SQLITE_DIRECT_OVERFLOW_READ
        /* If all the following are true:
        **
        **   1) this is a read operation, and
        **   2) data is required from the start of this overflow page, and
        **   3) there are no dirty pages in the page-cache
        **   4) the database is file-backed, and
        **   5) the page is not in the WAL file
        **   6) at least 4 bytes have already been read into the output buffer
        **
        ** then data can be read directly from the database file into the
        ** output buffer, bypassing the page-cache altogether. This speeds
        ** up loading large records that span many overflow pages.
        */
        if( eOp==0                                             /* (1) */
         && offset==0                                          /* (2) */
         && sqlite3PagerDirectReadOk(pBt->pPager, nextPage)    /* (3,4,5) */
         && &pBuf[-4]>=pBufStart                               /* (6) */
        ){
          sqlite3_file *fd = sqlite3PagerFile(pBt->pPager);
          u8 aSave[4];
          u8 *aWrite = &pBuf[-4];
          assert( aWrite>=pBufStart );                         /* due to (6) */
          memcpy(aSave, aWrite, 4);
          rc = sqlite3OsRead(fd, aWrite, a+4, (i64)pBt->pageSize*(nextPage-1));
          nextPage = get4byte(aWrite);
          memcpy(aWrite, aSave, 4);
        }else
#endif

        {
          DbPage *pDbPage;
          rc = sqlite3PagerGet(pBt->pPager, nextPage, &pDbPage,
              (eOp==0 ? PAGER_GET_READONLY : 0)
          );
          if( rc==SQLITE_OK ){
            if( eOp!=0
             && (sqlite3PagerPageRefcount(pDbPage)!=1
                 || NEVER(((MemPage*)sqlite3PagerGetExtra(pDbPage))->isInit))
             && sqlite3FaultSim(411)==SQLITE_OK
            ){
              sqlite3PagerUnref(pDbPage);
              return SQLITE_CORRUPT_PAGE(pPage);
            }
            aPayload = sqlite3PagerGetData(pDbPage);
            nextPage = get4byte(aPayload);
            rc = copyPayload(&aPayload[offset+4], pBuf, a, eOp, pDbPage);
            sqlite3PagerUnref(pDbPage);
            offset = 0;
          }
        }
        amt -= a;
        if( amt==0 ) return rc;
        pBuf += a;
      }
      if( rc ) break;
      iIdx++;
    }
  }

  if( rc==SQLITE_OK && amt>0 ){
    /* Overflow chain ends prematurely */
    return SQLITE_CORRUPT_PAGE(pPage);
  }
  return rc;
}
```

## Bug Fix Patch

```diff
diff --git a/manifest b/manifest
index 69ce4de208..8f82d17074 100644
--- a/manifest
+++ b/manifest
@@ -1,5 +1,5 @@
-C Patch\stest/indexexpr1.test\sto\swork\swhen\sbuilt\swith\sSQLITE_DQS=0.\sAddresses\s[forum:2026-05-26T18:08:20Z|forum\spost\s2026-05-26T18:08:20Z].
-D 2026-05-26T19:25:36.487
+C Fix\spotential\sinteger\soverflow\sin\sbtree\soverflow\spage\scache\scomputation,\nreported\sby\sProject\sFortify.\s\sTest\scases\sin\sTH3.
+D 2026-05-28T10:14:25.247
 F .fossil-settings/binary-glob 61195414528fb3ea9693577e1980230d78a1f8b0a54c78cf1b9b24d0a409ed6a x
 F .fossil-settings/empty-dirs dbb81e8fc0401ac46a1491ab34a7f2c7c0452f2f06b54ebb845d024ca8283ef1
 F .fossil-settings/ignore-glob 35175cdfcf539b2318cb04a9901442804be81cd677d8b889fcc9149c21f239ea
@@ -678,7 +678,7 @@ F src/auth.c b5ece4e1edccad082c0332fa0087df225473bae0feea9269f824312201377185
 F src/backup.c 6ebe22ccbedfcb92423833992130e8d65824be4e6599c3a03f540ab38fc7d13c
 F src/bitvec.c e242d4496774dfc88fa278177dd23b607dce369ccafb3f61b41638eea2c9b399
 F src/btmutex.c 30dada73a819a1ef5b7583786370dce1842e12e1ad941e4d05ac29695528daea
-F src/btree.c 8aa7c903ef0181ff92c8365545ae75a1d648f57151b60c03c11b0a51da979edb
+F src/btree.c 2f74489af68281d143f5c4e9ef8ba280cee86fce67a64b3eff9344bbabc5dadf
 F src/btree.h e823c46d87f63d904d735a24b76146d19f51f04445ea561f71cc3382fd1307f0
 F src/btreeInt.h 9c0f9ea5c9b5f4dcaea18111d43efe95f2ac276cd86d770dce10fd99ccc93886
 F src/build.c 866e584cdf40fbc83f530af9fd4d0991582a6fdbd8a9911b7cdbbea5f26a4a9e
@@ -2208,8 +2208,8 @@ F tool/warnings-clang.sh bbf6a1e685e534c92ec2bfba5b1745f34fb6f0bc2a362850723a9ee
 F tool/warnings.sh a554d13f6e5cf3760f041b87939e3d616ec6961859c3245e8ef701d1eafc2ca2
 F tool/win/sqlite.vsix deb315d026cc8400325c5863eef847784a219a2f
 F tool/winmain.c 00c8fb88e365c9017db14c73d3c78af62194d9644feaf60e220ab0f411f3604c
-P e78198e6aec57c28e33a5b1c5ae9943115a35d2fbfa04c8428318567f17eefbe
-R a628ab30284205241205a853323276ec
-U stephan
-Z c98417d5ae241afbaee0903a7ef064d4
+P b470a5d69e70d3440467e7792231f8556111d2c1126cf62879bbfd214ac0a9e0
+R f93211bf011e728b05fb024ce9234ada
+U drh
+Z 01ed8bae8d232f4e5f402b3795da7d4b
 # Remove this line to create a well-formed Fossil manifest.
diff --git a/manifest.uuid b/manifest.uuid
index 9f810aa70f..9536c9a6aa 100644
--- a/manifest.uuid
+++ b/manifest.uuid
@@ -1 +1 @@
-b470a5d69e70d3440467e7792231f8556111d2c1126cf62879bbfd214ac0a9e0
+dfa674d6e6bffdb930dbefa767831db7862c322b6d3c7a6322f0fa0f087aaaf9
diff --git a/src/btree.c b/src/btree.c
index fd2c384479..88a8ede43a 100644
--- a/src/btree.c
+++ b/src/btree.c
@@ -5195,7 +5195,9 @@ static int accessPayload(
     ** means "not yet known" (the cache is lazily populated).
     */
     if( (pCur->curFlags & BTCF_ValidOvfl)==0 ){
-      int nOvfl = (pCur->info.nPayload-pCur->info.nLocal+ovflSize-1)/ovflSize;
+      i64 nOvfl = pCur->info.nPayload;
+      testcase( nOvfl - pCur->info.nLocal + ovflSize - 1 > 0xffffffffU );
+      nOvfl = (nOvfl - pCur->info.nLocal + ovflSize-1)/ovflSize;
       if( pCur->aOverflow==0
        || nOvfl*(int)sizeof(Pgno) > sqlite3MallocSize(pCur->aOverflow)
       ){
```
