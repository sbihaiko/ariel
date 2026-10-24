# ADR-0007: PS5 *at() calls go through the compat header

## Status

Accepted.

## Context

On firmware 11.200.005 the PS5 link resolves `openat`, `mkdirat`, `unlinkat`, `renameat`, `fstatat`, `fchmodat`, `linkat`, `readlinkat` and `syscall` to `libc.a(syscalls.o)`. Each of those is `syscall; ret`. The carry flag is ignored, so a failure comes back as a positive errno and `errno` stays 0. `open` and `fstat` are the exception: they are the shared `libkernel` symbols, and they return -1 and set `errno`.

A positive errno is a legal file descriptor. `store.c` cannot tell a failed `openat` from an open fd after the call returns. The agent port never started because `nonces_load` treated ENOENT (2) as stderr.

`libc` `syscall()` has the same stub. `dlopen` of `libkernel_sys.sprx`, `libkernel.sprx`, `libkernel_web.sprx` and `libSceLibcInternal.sprx` returned null, and `dlsym(RTLD_DEFAULT, "openat")` returned null, so the kernel symbol is not available to call instead. Absolute `open` works and sets `errno`, and it gives up the directory fd and `O_NOFOLLOW` that the store uses against a swapped symlink.

## Decision

1. Every `openat`, `mkdirat`, `unlinkat`, `renameat` and `fstatat` in PS5 code goes through `ps5_at.h`.
2. The header issues the syscall and, when the carry flag is set, stores the errno and returns -1.
3. The host build defines `ARIEL_HOST_BUILD` and does not use the header. `store.c` keeps the same calls in both builds.
4. `open` and `fstat` stay the kernel symbols. They already return -1 and set `errno`.

## Guard

None yet. This rule is a draft until a named guard test exists.
