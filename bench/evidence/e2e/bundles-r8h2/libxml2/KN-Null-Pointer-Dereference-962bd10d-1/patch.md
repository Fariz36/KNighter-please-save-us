## Patch Description

xmlGrowArray: guard against NULL capacity pointer

## Buggy Code

```c
// Function: xmlGrowArray in xmlmemory.c
void *
xmlGrowArray(void *array, size_t elemSize, int *capacity, int min, int max) {
    void *tmp;
    int newSize;

    newSize = xmlGrowCapacity(*capacity, elemSize, min, max);
    if (newSize < 0)
        return(NULL);

    tmp = xmlRealloc(array, (size_t) newSize * elemSize);
    if (tmp == NULL)
        return(NULL);

    *capacity = newSize;
    return(tmp);
}
```

## Bug Fix Patch

```diff
diff --git a/xmlmemory.c b/xmlmemory.c
index 90306e38..0875a798 100644
--- a/xmlmemory.c
+++ b/xmlmemory.c
@@ -367,6 +367,9 @@ xmlGrowArray(void *array, size_t elemSize, int *capacity, int min, int max) {
     void *tmp;
     int newSize;
 
+    if (capacity == NULL)
+        return(NULL);
+
     newSize = xmlGrowCapacity(*capacity, elemSize, min, max);
     if (newSize < 0)
         return(NULL);
```
