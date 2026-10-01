## Patch Description

parser: Fix double free in xmlIOParseDTD

The xmlNewIOInputStream frees the `input` buffer if something fails, so
there's no need to free when the return is NULL.

Fix https://gitlab.gnome.org/GNOME/libxml2/-/work_items/1126

## Buggy Code

```c
// Function: xmlIOParseDTD in parser.c
xmlDtd *
xmlIOParseDTD(xmlSAXHandler *sax, xmlParserInputBuffer *input,
	      xmlCharEncoding enc) {
    xmlDtdPtr ret = NULL;
    xmlParserCtxtPtr ctxt;
    xmlParserInputPtr pinput = NULL;

    if (input == NULL)
	return(NULL);

    ctxt = xmlNewSAXParserCtxt(sax, NULL);
    if (ctxt == NULL) {
        xmlFreeParserInputBuffer(input);
	return(NULL);
    }
    xmlCtxtSetOptions(ctxt, XML_PARSE_DTDLOAD);

    /*
     * generate a parser input from the I/O handler
     */

    pinput = xmlNewIOInputStream(ctxt, input, XML_CHAR_ENCODING_NONE);
    if (pinput == NULL) {
        xmlFreeParserInputBuffer(input);
	xmlFreeParserCtxt(ctxt);
	return(NULL);
    }

    if (enc != XML_CHAR_ENCODING_NONE) {
        xmlSwitchEncoding(ctxt, enc);
    }

    ret = xmlCtxtParseDtd(ctxt, pinput, NULL, NULL);

    xmlFreeParserCtxt(ctxt);
    return(ret);
}
```

## Bug Fix Patch

```diff
diff --git a/parser.c b/parser.c
index 85bc39b1..6966cc74 100644
--- a/parser.c
+++ b/parser.c
@@ -11568,7 +11568,6 @@ xmlIOParseDTD(xmlSAXHandler *sax, xmlParserInputBuffer *input,
 
     pinput = xmlNewIOInputStream(ctxt, input, XML_CHAR_ENCODING_NONE);
     if (pinput == NULL) {
-        xmlFreeParserInputBuffer(input);
 	xmlFreeParserCtxt(ctxt);
 	return(NULL);
     }
```
