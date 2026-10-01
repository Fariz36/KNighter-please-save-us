## Patch Description

BUG: shift overflow in utf-8 decode

An initial byte \xFF will ask for 7 continuation bytes, and then the
shift by (count * 5) will try to shift 35 bits.

## Buggy Code

```c
// Function: utf8_decode in lutf8lib.c
static const char *utf8_decode (const char *s, l_uint32 *val, int strict) {
  static const l_uint32 limits[] =
        {~(l_uint32)0, 0x80, 0x800, 0x10000u, 0x200000u, 0x4000000u};
  unsigned int c = (unsigned char)s[0];
  l_uint32 res = 0;  /* final result */
  if (c < 0x80)  /* ASCII? */
    res = c;
  else {
    int count = 0;  /* to count number of continuation bytes */
    for (; c & 0x40; c <<= 1) {  /* while it needs continuation bytes... */
      unsigned int cc = (unsigned char)s[++count];  /* read next byte */
      if (!iscont(cc))  /* not a continuation byte? */
        return NULL;  /* invalid byte sequence */
      res = (res << 6) | (cc & 0x3F);  /* add lower 6 bits from cont. byte */
    }
    res |= ((l_uint32)(c & 0x7F) << (count * 5));  /* add first byte */
    if (count > 5 || res > MAXUTF || res < limits[count])
      return NULL;  /* invalid byte sequence */
    s += count;  /* skip continuation bytes read */
  }
  if (strict) {
    /* check for invalid code points; too large or surrogates */
    if (res > MAXUNICODE || (0xD800u <= res && res <= 0xDFFFu))
      return NULL;
  }
  if (val) *val = res;
  return s + 1;  /* +1 to include first byte */
}
```

## Bug Fix Patch

```diff
diff --git a/lutf8lib.c b/lutf8lib.c
index b7f3fe1e..73f0e49b 100644
--- a/lutf8lib.c
+++ b/lutf8lib.c
@@ -56,6 +56,8 @@ static const char *utf8_decode (const char *s, l_uint32 *val, int strict) {
   l_uint32 res = 0;  /* final result */
   if (c < 0x80)  /* ASCII? */
     res = c;
+  else if (c >= 0xfe)  /* c >= 1111 1110b ? */
+    return NULL;  /* would need six or more continuation bytes */
   else {
     int count = 0;  /* to count number of continuation bytes */
     for (; c & 0x40; c <<= 1) {  /* while it needs continuation bytes... */
@@ -64,8 +66,9 @@ static const char *utf8_decode (const char *s, l_uint32 *val, int strict) {
         return NULL;  /* invalid byte sequence */
       res = (res << 6) | (cc & 0x3F);  /* add lower 6 bits from cont. byte */
     }
+    lua_assert(count <= 5);
     res |= ((l_uint32)(c & 0x7F) << (count * 5));  /* add first byte */
-    if (count > 5 || res > MAXUTF || res < limits[count])
+    if (res > MAXUTF || res < limits[count])
       return NULL;  /* invalid byte sequence */
     s += count;  /* skip continuation bytes read */
   }
diff --git a/makefile b/makefile
index 8674519f..fa165bca 100644
--- a/makefile
+++ b/makefile
@@ -60,7 +60,7 @@ CWARNS= $(CWARNSCPP) $(CWARNSC) $(CWARNGCC)
 # create problems; some are only available in newer gcc versions. To
 # use some of them, we also have to define an environment variable
 # ASAN_OPTIONS="detect_invalid_pointer_pairs=2".
-# -fsanitize=undefined
+# -fsanitize=undefined  (you may need to add "-lubsan" to libs)
 # -fsanitize=pointer-subtract -fsanitize=address -fsanitize=pointer-compare
 # TESTS= -DLUA_USER_H='"ltests.h"' -Og -g
 
diff --git a/testes/utf8.lua b/testes/utf8.lua
index 028995a4..8a0213d6 100644
--- a/testes/utf8.lua
+++ b/testes/utf8.lua
@@ -238,10 +238,18 @@ s = "\0 \x7F\z
 s = string.gsub(s, " ", "")
 check(s, {0,0x7F, 0x80,0x7FF, 0x800,0xFFFF, 0x10000,0x10FFFF})
 
+
+-- again, without strictness
+s = "\xF0\x90\x80\x80 \xF7\xBF\xBF\xBF\z
+     \xF8\x88\x80\x80\x80 \xFB\xBF\xBF\xBF\xBF\z
+     \xFC\x84\x80\x80\x80\x80 \xFD\xBF\xBF\xBF\xBF\xBF"
+s = string.gsub(s, " ", "")
+check(s, {0x10000,0x1FFFFF, 0x200000,0x3FFFFFF, 0x4000000,0x7FFFFFFF}, true)
+
 do
   -- original UTF-8 values
   local s = "\u{4000000}\u{7FFFFFFF}"
-  assert(#s == 12)
+  assert(s == "\xFC\x84\x80\x80\x80\x80\xFD\xBF\xBF\xBF\xBF\xBF")
   check(s, {0x4000000, 0x7FFFFFFF}, true)
 
   s = "\u{200000}\u{3FFFFFF}"
@@ -257,6 +265,10 @@ local x = "日本語a-4\0éó"
 check(x, {26085, 26412, 35486, 97, 45, 52, 0, 233, 243})
 
 
+-- more than 5 continuation bytes
+assert(not utf8.len("\xff\x8f\x8f\x8f\x8f\x8f\x8f\x8f"))
+
+
 -- Supplementary Characters
 check("𣲷𠜎𠱓𡁻𠵼ab𠺢",
       {0x23CB7, 0x2070E, 0x20C53, 0x2107B, 0x20D7C, 0x61, 0x62, 0x20EA2,})
```
