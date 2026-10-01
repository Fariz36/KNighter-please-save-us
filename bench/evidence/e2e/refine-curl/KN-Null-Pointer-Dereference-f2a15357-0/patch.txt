## Patch Description

curl_easy_send/recv: check pointer arg

Return `CURLE_BAD_FUNCTION_ARGUMENT` when a `NULL` has been passed as
arg `n`.

Reported-by: Joshua Rogers
Closes #23035

## Buggy Code

```c
// Function: curl_easy_send in lib/easy.c
CURLcode curl_easy_send(CURL *curl, const void *buffer, size_t buflen,
                        size_t *n)
{
  struct Curl_eapi_guard guard;
  CURLcode result;

  if(CURL_EAPI_ENTER(&guard, curl, easy_send, &result)) {
    struct Curl_easy *data = curl;
    size_t written = 0;

    result = Curl_senddata(data, buffer, buflen, &written);
    *n = written;
  }
  CURL_EAPI_LEAVE(&guard);
  return result;
}
```

```c
// Function: curl_easy_recv in lib/easy.c
CURLcode curl_easy_recv(CURL *curl, void *buffer, size_t buflen, size_t *n)
{
  struct Curl_eapi_guard guard;
  CURLcode result;

  if(CURL_EAPI_ENTER(&guard, curl, easy_recv, &result)) {
    result = Curl_easy_recv(curl, buffer, buflen, n);
  }
  CURL_EAPI_LEAVE(&guard);
  return result;
}
```

## Bug Fix Patch

```diff
diff --git a/lib/easy.c b/lib/easy.c
index 721f3a0c7a..115a5f2876 100644
--- a/lib/easy.c
+++ b/lib/easy.c
@@ -1304,8 +1304,13 @@ CURLcode curl_easy_recv(CURL *curl, void *buffer, size_t buflen, size_t *n)
   CURLcode result;
 
   if(CURL_EAPI_ENTER(&guard, curl, easy_recv, &result)) {
+    if(!n) {
+      result = CURLE_BAD_FUNCTION_ARGUMENT;
+      goto out;
+    }
     result = Curl_easy_recv(curl, buffer, buflen, n);
   }
+out:
   CURL_EAPI_LEAVE(&guard);
   return result;
 }
@@ -1374,9 +1379,14 @@ CURLcode curl_easy_send(CURL *curl, const void *buffer, size_t buflen,
     struct Curl_easy *data = curl;
     size_t written = 0;
 
+    if(!n) {
+      result = CURLE_BAD_FUNCTION_ARGUMENT;
+      goto out;
+    }
     result = Curl_senddata(data, buffer, buflen, &written);
     *n = written;
   }
+out:
   CURL_EAPI_LEAVE(&guard);
   return result;
 }
```
