# CWE-78: OS Command Injection

Occurs when an application passes unvalidated user inputs directly to command line executors like system() or popen(). Attackers can insert shell delimiters (like semicolon, ampersand, pipe) to execute arbitrary commands with the privileges of the binary.

CERT C Rule ENV33-C: Do not call system().

Mitigation: Avoid system() entirely. Use safe APIs like execve() or createProcess() which pass parameters as discrete arrays rather than raw shell execution strings.
