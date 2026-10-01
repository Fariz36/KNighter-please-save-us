## Patch Description

xmlregexp: Calc string length after null checking

Fix https://gitlab.gnome.org/GNOME/libxml2/-/work_items/1107

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
	ret->len = strlen((const char *) ret->string);
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
index ad3b3dd3..fbda3187 100644
--- a/xmlregexp.c
+++ b/xmlregexp.c
@@ -736,12 +736,12 @@ xmlRegNewParserCtxt(const xmlChar *string) {
 	return(NULL);
     memset(ret, 0, sizeof(xmlRegParserCtxt));
     if (string != NULL) {
-	ret->string = xmlStrdup(string);
-	ret->len = strlen((const char *) ret->string);
+        ret->string = xmlStrdup(string);
         if (ret->string == NULL) {
             xmlFree(ret);
             return(NULL);
         }
+        ret->len = strlen((const char *) ret->string);
     }
     ret->cur = ret->string;
     ret->neg = 0;
```
