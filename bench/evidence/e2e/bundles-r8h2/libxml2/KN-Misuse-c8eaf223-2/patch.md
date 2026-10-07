## Patch Description

parser: fix division-by-zero when maxAmpl is set to 0

Reject maxAmpl == 0 in xmlCtxtSetMaxAmplification and add a safety
check before the division in xmlParserEntityCheck to prevent SIGFPE.

## Buggy Code

```c
// Function: xmlParserEntityCheck in parser.c
static int
xmlParserEntityCheck(xmlParserCtxtPtr ctxt, unsigned long extra)
{
    unsigned long consumed;
    unsigned long *expandedSize;
    xmlParserInputPtr input = ctxt->input;
    xmlEntityPtr entity = input->entity;

    if ((entity) && (entity->flags & XML_ENT_CHECKED))
        return(0);

    /*
     * Compute total consumed bytes so far, including input streams of
     * external entities.
     */
    consumed = input->consumed;
    xmlSaturatedAddSizeT(&consumed, input->cur - input->base);
    xmlSaturatedAdd(&consumed, ctxt->sizeentities);

    if (entity)
        expandedSize = &entity->expandedSize;
    else
        expandedSize = &ctxt->sizeentcopy;

    /*
     * Add extra cost and some fixed cost.
     */
    xmlSaturatedAdd(expandedSize, extra);
    xmlSaturatedAdd(expandedSize, XML_ENT_FIXED_COST);

    /*
     * It's important to always use saturation arithmetic when tracking
     * entity sizes to make the size checks reliable. If "sizeentcopy"
     * overflows, we have to abort.
     */
    if ((*expandedSize > XML_PARSER_ALLOWED_EXPANSION) &&
        ((*expandedSize >= ULONG_MAX) ||
         (*expandedSize / ctxt->maxAmpl > consumed))) {
        xmlFatalErrMsg(ctxt, XML_ERR_RESOURCE_LIMIT,
                       "Maximum entity amplification factor exceeded, see "
                       "xmlCtxtSetMaxAmplification.\n");
        return(1);
    }

    return(0);
}
```

```c
// Function: xmlCtxtSetMaxAmplification in parser.c
void
xmlCtxtSetMaxAmplification(xmlParserCtxt *ctxt, unsigned maxAmpl)
{
    if (ctxt == NULL)
        return;
    ctxt->maxAmpl = maxAmpl;
}
```

## Bug Fix Patch

```diff
diff --git a/parser.c b/parser.c
index 444de044..ad6c26bd 100644
--- a/parser.c
+++ b/parser.c
@@ -465,7 +465,8 @@ xmlParserEntityCheck(xmlParserCtxtPtr ctxt, unsigned long extra)
      * entity sizes to make the size checks reliable. If "sizeentcopy"
      * overflows, we have to abort.
      */
-    if ((*expandedSize > XML_PARSER_ALLOWED_EXPANSION) &&
+    if ((ctxt->maxAmpl > 0) &&
+        (*expandedSize > XML_PARSER_ALLOWED_EXPANSION) &&
         ((*expandedSize >= ULONG_MAX) ||
          (*expandedSize / ctxt->maxAmpl > consumed))) {
         xmlFatalErrMsg(ctxt, XML_ERR_RESOURCE_LIMIT,
@@ -13343,6 +13344,8 @@ xmlCtxtSetMaxAmplification(xmlParserCtxt *ctxt, unsigned maxAmpl)
 {
     if (ctxt == NULL)
         return;
+    if (maxAmpl == 0)
+        return;
     ctxt->maxAmpl = maxAmpl;
 }
 
```
