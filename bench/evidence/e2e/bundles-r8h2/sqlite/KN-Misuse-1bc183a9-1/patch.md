## Patch Description

Fix an assertion fault in sqlite3Dequote() that can occur with
ALTER TABLE DROP CONSTRAINT on a corrupt schema.
dbsqlfuzz 509a778e8a0c21a6448003feb773a1e55ed751e7.  Test case in TH3.

FossilOrigin-Name: 2dc73eb2d215178c448b182ebb227bc4753ad7baf46c8bd58f20a2b22e998726

## Buggy Code

```c
// Function: findConstraintFunc in src/alter.c
static void findConstraintFunc(
  sqlite3_context *ctx,
  int NotUsed,
  sqlite3_value **argv
){
  const u8 *zSql = 0;
  const u8 *zCons = 0;
  int iOff = 0;
  int t = 0;

  (void)NotUsed;
  zSql = sqlite3_value_text(argv[0]);
  zCons = sqlite3_value_text(argv[1]);

  if( zSql==0 || zCons==0 ) return;
  while( t!=TK_LP && t!=TK_ILLEGAL ){
    iOff += sqlite3GetToken(&zSql[iOff], &t);
  }

  while( 1 ){
    iOff += getConstraintToken(&zSql[iOff], &t);
    if( t==TK_CONSTRAINT ){
      int nTok = 0;
      int cmp = 0;
      iOff += getWhitespace(&zSql[iOff]);
      nTok = getConstraintToken(&zSql[iOff], &t);
      if( quotedCompare(ctx, &zSql[iOff], nTok, zCons, &cmp) ) return;
      if( cmp==0 ){
        sqlite3_result_int(ctx, 1);
        return;
      }
    }else if( t==TK_ILLEGAL ){
      break;
    }
  }

  sqlite3_result_int(ctx, 0);
}
```

```c
// Function: quotedCompare in src/alter.c
static int quotedCompare(
  sqlite3_context *ctx,  /* Function context on which to report errors */
  const u8 *zQuote,      /* Possibly quoted text.  Not zero-terminated. */
  int nQuote,            /* Length of zQuote in bytes */
  const u8 *zCmp,        /* Zero-terminated, unquoted name to compare against */
  int *pRes              /* OUT: Set to 0 if equal, non-zero if unequal */
){
  char *zCopy = 0;       /* De-quoted, zero-terminated copy of zQuote[] */

  zCopy = sqlite3MallocZero(nQuote+1);
  if( zCopy==0 ){
    sqlite3_result_error_nomem(ctx);
    return SQLITE_NOMEM_BKPT;
  }
  memcpy(zCopy, zQuote, nQuote);
  sqlite3Dequote(zCopy);
  *pRes = sqlite3_stricmp((const char*)zCopy, (const char*)zCmp);
  sqlite3_free(zCopy);
  return SQLITE_OK;
}
```

```c
// Function: dropConstraintFunc in src/alter.c
static void dropConstraintFunc(
  sqlite3_context *ctx,
  int NotUsed,
  sqlite3_value **argv
){
  const u8 *zSql = sqlite3_value_text(argv[0]);
  const u8 *zCons = 0;
  int iNotNull = -1;
  int ii;
  int iOff = 0;
  int iStart = 0;
  int iEnd = 0;
  char *zNew = 0;
  int t = 0;
  sqlite3 *db;
  UNUSED_PARAMETER(NotUsed);

  if( zSql==0 ) return;

  /* Jump past the "CREATE TABLE" bit. */
  if( skipCreateTable(ctx, zSql, &iOff) ) return;

  if( sqlite3_value_type(argv[1])==SQLITE_INTEGER ){
    iNotNull = sqlite3_value_int(argv[1]);
  }else{
    zCons = sqlite3_value_text(argv[1]);
  }

  /* Search for the named constraint within column definitions. */
  for(ii=0; iEnd==0; ii++){
  
    /* Now parse the column or table constraint definition. Search
    ** for the token CONSTRAINT if this is a DROP CONSTRAINT command, or
    ** NOT in the right column if this is a DROP NOT NULL. */
    while( 1 ){
      iStart = iOff;
      iOff += getConstraintToken(&zSql[iOff], &t);
      if( t==TK_CONSTRAINT && (zCons || iNotNull==ii) ){
        /* Check if this is the constraint we are searching for. */
        int nTok = 0;
        int cmp = 1;

        /* Skip past any whitespace. */
        iOff += getWhitespace(&zSql[iOff]);

        /* Compare the next token - which may be quoted - with the name of
        ** the constraint being dropped.  */
        nTok = getConstraintToken(&zSql[iOff], &t);
        if( zCons ){
          if( quotedCompare(ctx, &zSql[iOff], nTok, zCons, &cmp) ) return;
        }
        iOff += nTok;

        /* The next token is usually the first token of the constraint
        ** definition. This is enough to tell the type of the constraint - 
        ** TK_NOT means it is a NOT NULL, TK_CHECK a CHECK constraint etc.
        **
        ** There is also the chance that the next token is TK_CONSTRAINT
        ** (or TK_DEFAULT or TK_COLLATE), for example if a table has been
        ** created as follows:
        **
        **    CREATE TABLE t1(cols, CONSTRAINT one CONSTRAINT two NOT NULL);
        **
        ** In this case, allow the "CONSTRAINT one" bit to be dropped by
        ** this command if that is what is requested, or to advance to
        ** the next iteration of the loop with &zSql[iOff] still pointing
        ** to the CONSTRAINT keyword.  */
        nTok = getConstraintToken(&zSql[iOff], &t);
        if( t==TK_CONSTRAINT || t==TK_DEFAULT || t==TK_COLLATE 
         || t==TK_COMMA || t==TK_RP || t==TK_GENERATED || t==TK_AS 
        ){
          t = TK_CHECK;
        }else{
          iOff += nTok;
          iOff += getConstraint(&zSql[iOff]);
        }

        if( cmp==0 || (iNotNull>=0 && t==TK_NOT) ){
          if( t!=TK_NOT && t!=TK_CHECK ){
            errorMPrintf(ctx, "constraint may not be dropped: %s", zCons);
            return;
          }
          iEnd = iOff;
          break;
        }

      }else if( t==TK_NOT && iNotNull==ii ){
        iEnd = iOff + getConstraint(&zSql[iOff]);
        break;
      }else if( t==TK_RP || t==TK_ILLEGAL ){
        iEnd = -1;
        break;
      }else if( t==TK_COMMA ){
        break;
      }
    }
  }

  /* If the constraint has not been found it is an error. */
  if( iEnd<=0 ){
    if( zCons ){
      errorMPrintf(ctx, "no such constraint: %s", zCons);
    }else{
      /* SQLite follows postgres in that a DROP NOT NULL on a column that is
      ** not NOT NULL is not an error. So just return the original SQL here. */
      sqlite3_result_text(ctx, (const char*)zSql, -1, SQLITE_TRANSIENT);
    }
  }else{

    /* Figure out if an extra space should be inserted after the constraint
    ** is removed. And if an additional comma preceding the constraint 
    ** should be removed. */
    const char *zSpace = " ";
    iEnd += getWhitespace(&zSql[iEnd]);
    sqlite3GetToken(&zSql[iEnd], &t);
    if( t==TK_RP || t==TK_COMMA ){
      zSpace = "";
      if( zSql[iStart-1]==',' ) iStart--;
    }

    db = sqlite3_context_db_handle(ctx);
    zNew = sqlite3MPrintf(db, "%.*s%s%s", iStart, zSql, zSpace, &zSql[iEnd]);
    sqlite3_result_text(ctx, zNew, -1, SQLITE_DYNAMIC);
  }
}
```

## Bug Fix Patch

```diff
diff --git a/manifest b/manifest
index ff2f3c3e24..4adc8024a5 100644
--- a/manifest
+++ b/manifest
@@ -1,5 +1,5 @@
-C Correct\sa\sdoc\sfalsehood\s-\sjquery.terminal\sdoes\snot\srequire\spre-building.
-D 2025-11-28T17:56:22.595
+C Fix\san\sassertion\sfault\sin\ssqlite3Dequote()\sthat\scan\soccur\swith\nALTER\sTABLE\sDROP\sCONSTRAINT\son\sa\scorrupt\sschema.\ndbsqlfuzz\s509a778e8a0c21a6448003feb773a1e55ed751e7.\s\sTest\scase\sin\sTH3.
+D 2025-11-29T12:06:12.932
 F .fossil-settings/binary-glob 61195414528fb3ea9693577e1980230d78a1f8b0a54c78cf1b9b24d0a409ed6a x
 F .fossil-settings/empty-dirs dbb81e8fc0401ac46a1491ab34a7f2c7c0452f2f06b54ebb845d024ca8283ef1
 F .fossil-settings/ignore-glob 35175cdfcf539b2318cb04a9901442804be81cd677d8b889fcc9149c21f239ea
@@ -668,7 +668,7 @@ F mptest/multiwrite01.test dab5c5f8f9534971efce679152c5146da265222d
 F sqlite.pc.in 42b7bf0d02e08b9e77734a47798d1a55a9e0716b
 F sqlite3.1 1b9c24374a85dfc7eb8fa7c4266ee0db4f9609cceecfc5481cd8307e5af04366
 F sqlite3.pc.in e6dee284fba59ef500092fdc1843df3be8433323a3733c91da96690a50a5b398
-F src/alter.c f31437552c733957f19351cdfae8fad8e8f0c7d11041e5b7966aae57206ad91f
+F src/alter.c fe6fa35700b968f8f9d2515939455e70f6b6ff2586a6e3ce9827bf44756354f2
 F src/analyze.c 03bcfc083fc0cccaa9ded93604e1d4244ea245c17285d463ef6a60425fcb247d
 F src/attach.c 9af61b63b10ee702b1594ecd24fb8cea0839cfdb6addee52fba26fa879f5db9d
 F src/auth.c 54ab9c6c5803b47c0d45b76ce27eff22a03b4b1f767c5945a3a4eb13aa4c78dc
@@ -2180,8 +2180,8 @@ F tool/version-info.c 33d0390ef484b3b1cb685d59362be891ea162123cea181cb8e6d2cf6dd
 F tool/warnings-clang.sh bbf6a1e685e534c92ec2bfba5b1745f34fb6f0bc2a362850723a9ee87c1b31a7
 F tool/warnings.sh d924598cf2f55a4ecbc2aeb055c10bd5f48114793e7ba25f9585435da29e7e98
 F tool/win/sqlite.vsix deb315d026cc8400325c5863eef847784a219a2f
-P 9dd16f8e3b8e181ff138b4061c9dbc116cbc6f85ee867a97cd8af6e9e874c7d1
-R 19f071d72e95cabbab2f39a77dde2c1c
-U stephan
-Z 1378159a2aa74fa957ced5b9c6aaf0e0
+P 4384c9a108b58a0b8c38c51678aad871f088358b9bff3922299cc7ddb3d247ce
+R 7319a92f6ed0f94183ac2bcfe4bf386d
+U drh
+Z 43127c85d2631bbec7cc913abbee76ec
 # Remove this line to create a well-formed Fossil manifest.
diff --git a/manifest.uuid b/manifest.uuid
index 191325cb3f..c211e023f7 100644
--- a/manifest.uuid
+++ b/manifest.uuid
@@ -1 +1 @@
-4384c9a108b58a0b8c38c51678aad871f088358b9bff3922299cc7ddb3d247ce
+2dc73eb2d215178c448b182ebb227bc4753ad7baf46c8bd58f20a2b22e998726
diff --git a/src/alter.c b/src/alter.c
index c5a64211f8..21b90abdb5 100644
--- a/src/alter.c
+++ b/src/alter.c
@@ -2449,6 +2449,7 @@ static int getConstraint(const u8 *z){
 */
 static int quotedCompare(
   sqlite3_context *ctx,  /* Function context on which to report errors */
+  int t,                 /* Token type */
   const u8 *zQuote,      /* Possibly quoted text.  Not zero-terminated. */
   int nQuote,            /* Length of zQuote in bytes */
   const u8 *zCmp,        /* Zero-terminated, unquoted name to compare against */
@@ -2456,6 +2457,10 @@ static int quotedCompare(
 ){
   char *zCopy = 0;       /* De-quoted, zero-terminated copy of zQuote[] */
 
+  if( t==TK_ILLEGAL ){
+    *pRes = 1;
+    return SQLITE_OK;
+  }
   zCopy = sqlite3MallocZero(nQuote+1);
   if( zCopy==0 ){
     sqlite3_result_error_nomem(ctx);
@@ -2554,7 +2559,7 @@ static void dropConstraintFunc(
         ** the constraint being dropped.  */
         nTok = getConstraintToken(&zSql[iOff], &t);
         if( zCons ){
-          if( quotedCompare(ctx, &zSql[iOff], nTok, zCons, &cmp) ) return;
+          if( quotedCompare(ctx, t, &zSql[iOff], nTok, zCons, &cmp) ) return;
         }
         iOff += nTok;
 
@@ -2948,7 +2953,7 @@ static void findConstraintFunc(
       int cmp = 0;
       iOff += getWhitespace(&zSql[iOff]);
       nTok = getConstraintToken(&zSql[iOff], &t);
-      if( quotedCompare(ctx, &zSql[iOff], nTok, zCons, &cmp) ) return;
+      if( quotedCompare(ctx, t, &zSql[iOff], nTok, zCons, &cmp) ) return;
       if( cmp==0 ){
         sqlite3_result_int(ctx, 1);
         return;
```
