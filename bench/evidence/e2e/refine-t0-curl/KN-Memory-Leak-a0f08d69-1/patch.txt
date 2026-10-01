## Patch Description

cf-h2-prox: fix peer leak

The unlinking of the new Curl_peer was happening too later after
the struct had been set to zero. Move the unlink to happen before
that.

Fixes #21602
Reported-by: Joshua Rogers
Closes #21627

## Buggy Code

```c
// Function: cf_h2_proxy_ctx_clear in lib/cf-h2-proxy.c
static void cf_h2_proxy_ctx_clear(struct cf_h2_proxy_ctx *ctx)
{
  struct cf_call_data save = ctx->call_data;

  if(ctx->h2) {
    nghttp2_session_del(ctx->h2);
  }
  Curl_bufq_free(&ctx->inbufq);
  Curl_bufq_free(&ctx->outbufq);
  tunnel_stream_clear(&ctx->tunnel);
  memset(ctx, 0, sizeof(*ctx));
  ctx->call_data = save;
}
```

```c
// Function: cf_h2_proxy_ctx_free in lib/cf-h2-proxy.c
static void cf_h2_proxy_ctx_free(struct cf_h2_proxy_ctx *ctx)
{
  if(ctx) {
    cf_h2_proxy_ctx_clear(ctx);
    Curl_peer_unlink(&ctx->dest);
    curlx_free(ctx);
  }
}
```

## Bug Fix Patch

```diff
diff --git a/lib/cf-h2-proxy.c b/lib/cf-h2-proxy.c
index 1dfd0a0a46..297afb3c8c 100644
--- a/lib/cf-h2-proxy.c
+++ b/lib/cf-h2-proxy.c
@@ -190,6 +190,7 @@ static void cf_h2_proxy_ctx_clear(struct cf_h2_proxy_ctx *ctx)
   }
   Curl_bufq_free(&ctx->inbufq);
   Curl_bufq_free(&ctx->outbufq);
+  Curl_peer_unlink(&ctx->dest);
   tunnel_stream_clear(&ctx->tunnel);
   memset(ctx, 0, sizeof(*ctx));
   ctx->call_data = save;
@@ -199,7 +200,6 @@ static void cf_h2_proxy_ctx_free(struct cf_h2_proxy_ctx *ctx)
 {
   if(ctx) {
     cf_h2_proxy_ctx_clear(ctx);
-    Curl_peer_unlink(&ctx->dest);
     curlx_free(ctx);
   }
 }
```
