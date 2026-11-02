# ADR-0021: Console Git writes avoid rename and utime probes

## Status

Accepted. 2026-11-02.

## Context

The first commit the console made reported a SHA and pushed nothing: the
object file was missing. Each step had answered success.

Dulwich writes a loose object by first calling `os.utime(path)` and returning
early when it does not raise, then writing `<path>.lock` and renaming it over
`path` with `os.replace`. On this console both calls succeed and produce no
file: `utime` on a missing path neither raises nor creates anything, and the
rename of the lock file leaves neither name behind. The commit SHA is computed
in memory, so the job finishes normally with an object no reader can find.

This is the same stub behaviour [ADR-0007](0007-ps5-at-calls-go-through-the-compat-header.md)
records for the C agent: the `*at` family, including the rename CPython uses,
returns a positive errno with the carry flag set and `errno` untouched.

## Decision

1. On the console, a loose object is written directly: open the final path,
   write, `fsync`, close. No `.lock` file and no rename.
2. Every other dulwich write that goes through `GitFile` keeps the lock file
   and then copies its bytes over the target with a plain write, instead of
   renaming it into place.
3. Neither workaround reads back a success code; each verifies the target
   exists after the write.
4. The host build uses dulwich unmodified. Only the console patches it, at
   the point the Git runner is imported.

## Consequences

- A console commit is visible to the next process: `COMMIT READBACK OK`
  precedes `PUSH OK`, and the pushed branch carries the object.
- Writing loose objects directly forgoes the atomicity git normally has. On
  this platform the atomic path loses the data, so a direct write is the
  stronger option, not the weaker one.
- A future dulwich that stops calling `utime` first, or that write the object
  through another path, would bypass the patch; the readback check in
  `commit_results` is what catches that.

## Guard

None yet. This rule is a draft until a named guard test exists.
