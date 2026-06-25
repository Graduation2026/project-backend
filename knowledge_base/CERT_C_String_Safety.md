# CERT C String Safety Guide (STR30-C / STR31-C / STR32-C)

Rule STR30-C: Do not attempt to modify string literals (as they reside in read-only memory and cause instant undefined behavior or crashes).

Rule STR31-C: Guarantee that storage for strings has sufficient space for character data and the null terminator.

Rule STR32-C: Null-terminate all strings returned from legacy string manipulation APIs to prevent out-of-bounds reads during printing or string operations.
