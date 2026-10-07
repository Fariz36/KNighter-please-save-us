## Patch Description

urlapi: return NULL from curl_url_dup() when given a NULL handle

Previously, passing a NULL pointer to curl_url_dup() caused a NULL
pointer dereference crash on in->scheme inside the DUP() macro.

Return NULL immediately when !in, matching curl_easy_duphandle() and
preventing unexpected crashes when duplicating uninitialized or failed
handles.

Also verify this behavior in test 1560 and update documentation.

Closes #23051

## Buggy Code

```c
// Function: test_api_errors in tests/libtest/lib1560.c
static int test_api_errors(void)
{
  CURLU *u = curl_url();
  char *p = NULL;
  CURLUcode rc;
  if(!u)
    return 1;

  /* NULL handle */
  rc = curl_url_get(NULL, CURLUPART_URL, &p, 0);
  if(rc != CURLUE_BAD_HANDLE)
    return 1;

  rc = curl_url_set(NULL, CURLUPART_URL, "http://example.com", 0);
  if(rc != CURLUE_BAD_HANDLE)
    return 1;

  /* NULL part pointer */
  rc = curl_url_get(u, CURLUPART_URL, NULL, 0);
  if(rc != CURLUE_BAD_PARTPOINTER)
    return 2;

  /* Unknown part */
  /* NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange) */
  rc = curl_url_get(u, (CURLUPart)12345, &p, 0);
  if(rc != CURLUE_UNKNOWN_PART)
    return 3;

  curl_url_cleanup(u);
  return 0;
}
```

```c
// Function: curl_url_dup in lib/urlapi.c
CURLU *curl_url_dup(const CURLU *in)
{
  struct Curl_URL *u = curlx_calloc(1, sizeof(struct Curl_URL));
  if(u) {
    DUP(u, in, scheme);
    DUP(u, in, user);
    DUP(u, in, password);
    DUP(u, in, options);
    DUP(u, in, host);
    DUP(u, in, path);
    DUP(u, in, query);
    DUP(u, in, fragment);
    DUP(u, in, zoneid);
    u->portnum = in->portnum;
    u->port_present = in->port_present;
    u->fragment_present = in->fragment_present;
    u->query_present = in->query_present;
    u->guessed_scheme = in->guessed_scheme;
  }
  return u;
fail:
  curl_url_cleanup(u);
  return NULL;
}
```

## Bug Fix Patch

```diff
diff --git a/docs/libcurl/curl_url_dup.md b/docs/libcurl/curl_url_dup.md
index cfba5cc1b9..6208494440 100644
--- a/docs/libcurl/curl_url_dup.md
+++ b/docs/libcurl/curl_url_dup.md
@@ -56,4 +56,5 @@ int main(void)
 
 # RETURN VALUE
 
-Returns a pointer to a new `CURLU` handle or NULL if out of memory.
+Returns a pointer to a new `CURLU` handle or NULL if out of memory or if
+*inhandle* is NULL.
diff --git a/lib/urlapi.c b/lib/urlapi.c
index e64adb8027..4f7aacdbf4 100644
--- a/lib/urlapi.c
+++ b/lib/urlapi.c
@@ -1433,7 +1433,12 @@ void curl_url_cleanup(CURLU *u)
 
 CURLU *curl_url_dup(const CURLU *in)
 {
-  struct Curl_URL *u = curlx_calloc(1, sizeof(struct Curl_URL));
+  struct Curl_URL *u;
+
+  if(!in)
+    return NULL;
+
+  u = curlx_calloc(1, sizeof(struct Curl_URL));
   if(u) {
     DUP(u, in, scheme);
     DUP(u, in, user);
diff --git a/tests/libtest/lib1560.c b/tests/libtest/lib1560.c
index f045474be3..65d243eff4 100644
--- a/tests/libtest/lib1560.c
+++ b/tests/libtest/lib1560.c
@@ -2423,6 +2423,9 @@ static int test_api_errors(void)
   if(rc != CURLUE_BAD_HANDLE)
     return 1;
 
+  if(curl_url_dup(NULL))
+    return 4;
+
   /* NULL part pointer */
   rc = curl_url_get(u, CURLUPART_URL, NULL, 0);
   if(rc != CURLUE_BAD_PARTPOINTER)
```
