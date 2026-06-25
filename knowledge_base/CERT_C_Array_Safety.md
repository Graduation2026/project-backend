# CERT C Array Safety Guide (ARR30-C / ARR38-C)

Rule ARR30-C: Do not form or use out-of-bounds pointers or array subscripts. Indexing arrays outside of [0, size-1] is undefined behavior.

Rule ARR38-C: Do not perform pointer arithmetic that results in a pointer outside the bounds of the allocated array. Always verify that pointer bounds remain within their allocation segment before dereferencing.
