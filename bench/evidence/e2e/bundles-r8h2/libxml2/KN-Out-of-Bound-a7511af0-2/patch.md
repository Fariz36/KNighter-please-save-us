## Patch Description

xmlregexp: Prevent out-of-bounds read in NXT macro

Fixes: https://gitlab.gnome.org/GNOME/libxml2/-/issues/1099

## Buggy Code

```c
// Function: xmlRegNewParserCtxt in xmlregexp.c
static xmlRegParserCtxtPtr
xmlRegNewParserCtxt(const xmlChar *string) {
    xmlRegParserCtxtPtr ret;

    ret = (xmlRegParserCtxtPtr) xmlMalloc(sizeof(xmlRegParserCtxt));
    if (ret == NULL)
	return(NULL);
    memset(ret, 0, sizeof(xmlRegParserCtxt));
    if (string != NULL) {
	ret->string = xmlStrdup(string);
        if (ret->string == NULL) {
            xmlFree(ret);
            return(NULL);
        }
    }
    ret->cur = ret->string;
    ret->neg = 0;
    ret->negs = 0;
    ret->error = 0;
    ret->determinist = -1;
    return(ret);
}
```

## Bug Fix Patch

```diff
diff --git a/xmlregexp.c b/xmlregexp.c
index 3fe20ac0..ad3b3dd3 100644
--- a/xmlregexp.c
+++ b/xmlregexp.c
@@ -48,7 +48,9 @@
     xmlRegexpErrCompile(ctxt, str);
 #define NEXT ctxt->cur++
 #define CUR (*(ctxt->cur))
-#define NXT(index) (ctxt->cur[index])
+#define NXT(index)									\
+    (((size_t)(ctxt->cur + index - ctxt->string) < ctxt->len)				\
+      ? ctxt->cur[index] : 0)
 
 #define NEXTL(l) ctxt->cur += l;
 #define XML_REG_STRING_SEPARATOR '|'
@@ -288,6 +290,7 @@ typedef xmlRegParserCtxt *xmlRegParserCtxtPtr;
 struct _xmlAutomata {
     xmlChar *string;
     xmlChar *cur;
+    size_t len;
 
     int error;
     int neg;
@@ -734,6 +737,7 @@ xmlRegNewParserCtxt(const xmlChar *string) {
     memset(ret, 0, sizeof(xmlRegParserCtxt));
     if (string != NULL) {
 	ret->string = xmlStrdup(string);
+	ret->len = strlen((const char *) ret->string);
         if (ret->string == NULL) {
             xmlFree(ret);
             return(NULL);
```
