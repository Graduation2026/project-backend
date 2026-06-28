# CERT C Rule: FIO30-C — Exclude user input from format strings

Format string vulnerabilities are among the most dangerous classes of C security bugs. When user-controlled data is passed as the format argument to `printf()`, `fprintf()`, `sprintf()`, `snprintf()`, or `syslog()`, the attacker can read from and write to arbitrary memory locations.

Vulnerable pattern:
```c
// WRONG — user_input is the format string
char *user_input = get_user_input();
printf(user_input);  // If user_input = "%x%x%x%n", this writes to memory!
```

Secure pattern:
```c
// CORRECT — user_input is a data argument, not the format
char *user_input = get_user_input();
printf("%s", user_input);  // user_input is treated as plain text
```

The `%n` specifier is the most dangerous: it writes the number of bytes printed so far to the address pointed to by the corresponding argument. Combined with Direct Parameter Access (`%N$n`), this gives the attacker a precise arbitrary-write primitive.

Detection: Compile with `-Wformat -Wformat-security -Werror=format-security`. These flags warn when a non-literal string is used as a format argument.

Additional mitigation: FORTIFY_SOURCE (`-D_FORTIFY_SOURCE=2`) adds runtime checks that detect `%n` in writable format strings.
