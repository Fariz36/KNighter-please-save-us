## Patch Description

Fix a memory leak that could follow an OOM on this branch.

FossilOrigin-Name: 3223fee0b93bbbe277b955a98c13bb583ded78109f8e601c9ec0a7bd3749fd55

## Buggy Code

```c
// Function: sqlite3TriggerUpdateStep in src/trigger.c
TriggerStep *sqlite3TriggerUpdateStep(
  Parse *pParse,          /* Parser */
  SrcList *pTabList,   /* Name of the table to be updated */
  SrcList *pFrom,      /* FROM clause for an UPDATE-FROM, or NULL */
  ExprList *pEList,    /* The SET clause: list of column and new values */
  Expr *pWhere,        /* The WHERE clause */
  u8 orconf,           /* The conflict algorithm. (OE_Abort, OE_Ignore, etc) */
  const char *zStart,  /* Start of SQL text */
  const char *zEnd     /* End of SQL text */
){
  sqlite3 *db = pParse->db;
  TriggerStep *pTriggerStep;

  pTriggerStep = triggerStepAllocate(pParse, TK_UPDATE, pTabList, zStart, zEnd);
  if( pTriggerStep ){
    SrcList *pFromDup = 0;
    if( IN_RENAME_OBJECT ){
      pTriggerStep->pExprList = pEList;
      pTriggerStep->pWhere = pWhere;
      pFromDup = pFrom;
      pEList = 0;
      pWhere = 0;
      pFrom = 0;
    }else{
      pTriggerStep->pExprList = sqlite3ExprListDup(db, pEList, EXPRDUP_REDUCE);
      pTriggerStep->pWhere = sqlite3ExprDup(db, pWhere, EXPRDUP_REDUCE);
      pFromDup = sqlite3SrcListDup(db, pFrom, EXPRDUP_REDUCE);
    }
    pTriggerStep->orconf = orconf;

    if( pFromDup && !IN_RENAME_OBJECT){
      Select *pSub;
      Token as = {0, 0};
      pSub = sqlite3SelectNew(pParse, 0, pFromDup, 0,0,0,0, SF_NestedFrom, 0);
      pFromDup = sqlite3SrcListAppendFromTerm(pParse, 0, 0, 0, &as, pSub ,0);
    }
    if( pFromDup && pTriggerStep->pSrc ){
      pTriggerStep->pSrc = sqlite3SrcListAppendList(
          pParse, pTriggerStep->pSrc, pFromDup
      );
    }
  }
  sqlite3ExprListDelete(db, pEList);
  sqlite3ExprDelete(db, pWhere);
  sqlite3SrcListDelete(db, pFrom);
  return pTriggerStep;
}
```

## Bug Fix Patch

```diff
diff --git a/manifest b/manifest
index 4d732a04c3..8e98ef3c2d 100644
--- a/manifest
+++ b/manifest
@@ -1,5 +1,5 @@
-C Fix\sanother\scrash\son\sthis\sbranch\sthat\scould\sfollow\san\sOOM.
-D 2025-12-01T17:39:04.441
+C Fix\sa\smemory\sleak\sthat\scould\sfollow\san\sOOM\son\sthis\sbranch.
+D 2025-12-01T18:11:08.093
 F .fossil-settings/binary-glob 61195414528fb3ea9693577e1980230d78a1f8b0a54c78cf1b9b24d0a409ed6a x
 F .fossil-settings/empty-dirs dbb81e8fc0401ac46a1491ab34a7f2c7c0452f2f06b54ebb845d024ca8283ef1
 F .fossil-settings/ignore-glob 35175cdfcf539b2318cb04a9901442804be81cd677d8b889fcc9149c21f239ea
@@ -796,7 +796,7 @@ F src/test_wsd.c 41cadfd9d97fe8e3e4e44f61a4a8ccd6f7ca8fe9
 F src/threads.c 4ae07fa022a3dc7c5beb373cf744a85d3c5c6c3c
 F src/tokenize.c ca1382f02a3990d1a770acd5c55731dee10cd644465b2855eca33e4d2ea299ed
 F src/treeview.c 3ce7ac9835d2d70cc1c868b01b747ae8a062322e155701e58e3d62ca79aada7a
-F src/trigger.c f5e76027f4859c0121b8abace40b5b78422d14022105cc841a338341d2d8a58b
+F src/trigger.c 96e5ceb7461b0c469a6e155feb00f39b992b6205f3f5118d01905f45f8234372
 F src/update.c 3e5e7ff66fa19ebe4d1b113d480639a24cc1175adbefabbd1a948a07f28e37cf
 F src/upsert.c 215328c3f91623c520ec8672c44323553f12caeb4f01b1090ebdca99fdf7b4f1
 F src/utf.c 7267c3fb9e2467020507601af3354c2446c61f444387e094c779dccd5ca62165
@@ -2181,8 +2181,8 @@ F tool/version-info.c 33d0390ef484b3b1cb685d59362be891ea162123cea181cb8e6d2cf6dd
 F tool/warnings-clang.sh bbf6a1e685e534c92ec2bfba5b1745f34fb6f0bc2a362850723a9ee87c1b31a7
 F tool/warnings.sh d924598cf2f55a4ecbc2aeb055c10bd5f48114793e7ba25f9585435da29e7e98
 F tool/win/sqlite.vsix deb315d026cc8400325c5863eef847784a219a2f
-P 230fd5533e07ec36f1938f34153c9ef97a7acd6604d023b56dfc5269ca6173c2
-R c04ca40ba485e1c531dd57154158be42
+P 75c49267ec6b84c8aad0e264c34506e4b24f69475ae5def0ee7530ba3822c15d
+R 2e866f8f96424c36ead738f7cc32a381
 U dan
-Z bd3bd1668859d1c4e36bd3d372e46aa5
+Z b33421e6e016ff0d1ecfa51911613b2c
 # Remove this line to create a well-formed Fossil manifest.
diff --git a/manifest.uuid b/manifest.uuid
index 965b9cfb3d..7c57f38d88 100644
--- a/manifest.uuid
+++ b/manifest.uuid
@@ -1 +1 @@
-75c49267ec6b84c8aad0e264c34506e4b24f69475ae5def0ee7530ba3822c15d
+3223fee0b93bbbe277b955a98c13bb583ded78109f8e601c9ec0a7bd3749fd55
diff --git a/src/trigger.c b/src/trigger.c
index a9903b5e3f..f0afe4625e 100644
--- a/src/trigger.c
+++ b/src/trigger.c
@@ -589,6 +589,8 @@ TriggerStep *sqlite3TriggerUpdateStep(
       pTriggerStep->pSrc = sqlite3SrcListAppendList(
           pParse, pTriggerStep->pSrc, pFromDup
       );
+    }else{
+      sqlite3SrcListDelete(db, pFromDup);
     }
   }
   sqlite3ExprListDelete(db, pEList);
```
