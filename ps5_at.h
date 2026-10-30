/* PS5 libc's *at() stubs return the errno in rax and leave errno unchanged.
   The host libc returns -1 and sets errno. store.c and fileops.c keep calling
   openat, mkdirat, unlinkat, renameat, fstatat, linkat and symlinkat; this header is what
   makes those calls POSIX on the PS5 build. */
#ifndef PS5_AT_H
#define PS5_AT_H

#ifndef ARIEL_HOST_BUILD

#include <errno.h>
#include <sys/stat.h>
#include <sys/syscall.h>

static inline long
ariel_syscall(long nr, long a, long b, long c, long d) {
  long ret;
  unsigned char carry;
  register long r10 __asm__("r10") = d;

  __asm__ volatile("syscall"
                   : "=a"(ret), "=@ccc"(carry)
                   : "a"(nr), "D"(a), "S"(b), "d"(c), "r"(r10)
                   : "rcx", "r11", "memory");
  if(carry) {
    errno = (int)ret;
    return -1;
  }
  return ret;
}

static inline int
ariel_openat4(int fd, const char *path, int flags, int mode) {
  return (int)ariel_syscall(SYS_openat, fd, (long)path, flags, mode);
}

static inline int
ariel_openat3(int fd, const char *path, int flags) {
  return ariel_openat4(fd, path, flags, 0);
}

static inline int
ariel_mkdirat(int fd, const char *path, int mode) {
  return (int)ariel_syscall(SYS_mkdirat, fd, (long)path, mode, 0);
}

static inline int
ariel_unlinkat(int fd, const char *path, int flag) {
  return (int)ariel_syscall(SYS_unlinkat, fd, (long)path, flag, 0);
}

static inline int
ariel_renameat(int oldfd, const char *old, int newfd, const char *new) {
  return (int)ariel_syscall(SYS_renameat, oldfd, (long)old, newfd, (long)new);
}

static inline int
ariel_fstatat(int fd, const char *path, struct stat *st, int flag) {
  return (int)ariel_syscall(SYS_fstatat, fd, (long)path, (long)st, flag);
}

static inline int
ariel_linkat(int oldfd, const char *old, int newfd, const char *new, int flag) {
  long ret;
  unsigned char carry;
  register long r10 __asm__("r10") = (long)new;
  register long r8 __asm__("r8") = flag;

  __asm__ volatile("syscall"
                   : "=a"(ret), "=@ccc"(carry)
                   : "a"(SYS_linkat), "D"((long)oldfd), "S"(old),
                     "d"((long)newfd), "r"(r10), "r"(r8)
                   : "rcx", "r11", "memory");
  if(carry) {
    errno = (int)ret;
    return -1;
  }
  return (int)ret;
}

static inline int
ariel_symlinkat(const char *target, int newfd, const char *new) {
  return (int)ariel_syscall(SYS_symlinkat, (long)target, newfd, (long)new, 0);
}

#define ARIEL_OPENAT_DISP(_1, _2, _3, _4, NAME, ...) NAME
#define openat(...) \
  ARIEL_OPENAT_DISP(__VA_ARGS__, ariel_openat4, ariel_openat3)(__VA_ARGS__)
#define mkdirat(fd, path, mode) ariel_mkdirat((fd), (path), (mode))
#define unlinkat(fd, path, flag) ariel_unlinkat((fd), (path), (flag))
#define renameat(oldfd, old, newfd, new) \
  ariel_renameat((oldfd), (old), (newfd), (new))
#define fstatat(fd, path, st, flag) \
  ariel_fstatat((fd), (path), (st), (flag))
#define linkat(oldfd, old, newfd, new, flag) \
  ariel_linkat((oldfd), (old), (newfd), (new), (flag))
#define symlinkat(target, newfd, new) \
  ariel_symlinkat((target), (newfd), (new))

#endif /* !ARIEL_HOST_BUILD */

#endif
