# CWE-134: Use of Externally-Controlled Format String

The software uses input from an external source as the format string argument in formatted output functions like printf, sprintf, fprintf, syslog. Attackers can leverage format specifiers (e.g., %x, %s, %n) to dump stack memory, read arbitrary addresses, or write data to arbitrary memory locations (using %n), leading to full code execution.

CERT C Rule FIO30-C: Exclude user input from format strings.

Mitigation: Always write formatted functions using explicit specifiers, e.g., use printf("%s", user_input) instead of printf(user_input).
