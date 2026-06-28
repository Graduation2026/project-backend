# CWE-22: Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)

Path traversal vulnerabilities occur when software uses external input to construct a pathname for accessing files or directories that should be restricted. An attacker can use special characters like `../` (dot-dot-slash) sequences to escape the intended directory and access arbitrary files on the filesystem.

Common attack vectors include manipulating file paths in web applications, exploiting archive extraction routines that don't sanitize filenames, and leveraging symbolic links to redirect file operations. In compiled binaries, this manifests when functions like `fopen()`, `open()`, or `realpath()` receive unsanitized user-controlled path components.

CERT C Rule FIO02-C: Canonicalize path names originating from tainted sources.

Mitigation strategies include: (1) Canonicalize all paths using `realpath()` before validation, (2) Implement a whitelist of allowed directories, (3) Reject paths containing `..` sequences, (4) Use chroot jails or filesystem sandboxes to restrict accessible paths, (5) Validate that the resolved path stays within the expected base directory after canonicalization.
