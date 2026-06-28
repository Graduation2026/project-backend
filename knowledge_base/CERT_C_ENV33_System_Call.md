# CERT C Rule: ENV33-C — Do not call system()

The `system()` function passes its argument to a command shell interpreter (`/bin/sh` on Unix, `cmd.exe` on Windows). If any part of the command string originates from untrusted input, the attacker can inject arbitrary shell commands using metacharacters like `;`, `|`, `&&`, `$()`, and backticks.

Vulnerable pattern:
```c
char cmd[256];
snprintf(cmd, sizeof(cmd), "ls %s", user_filename);
system(cmd);  // If user_filename = "; rm -rf /", this executes "ls ; rm -rf /"
```

Secure alternatives:
```c
// Option 1: Use exec*() family (no shell interpretation)
execlp("ls", "ls", user_filename, NULL);

// Option 2: Use posix_spawn() for more control
posix_spawn(&pid, "/bin/ls", NULL, NULL, args, environ);

// Option 3: Use library functions instead of shell commands
DIR *dir = opendir(user_filename);  // Direct API, no shell
```

The `exec*()` family functions (execl, execv, execle, execve, execlp, execvp) do NOT invoke a shell — they pass arguments directly to the target program, preventing command injection. However, `execlp()` and `execvp()` search PATH, which can be manipulated.

Additional risk: `popen()` also invokes a shell and has the same injection vulnerability as `system()`. Use `pipe()` + `fork()` + `exec()` instead.
