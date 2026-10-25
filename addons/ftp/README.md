# ftp addon

Four addons move files through the console's ftpsrv on port 2121: `ftp-ls`,
`ftp-get`, `ftp-put` and `ftp-rm`. They are one program, `ftp.c`, built once
and installed under four names. Each name is asked for through the one gate
(`addon run <name> ...`), so the owner signs the remote path, the local path
and the server before anything moves.

## Installing

`make addon-ftp` builds `addons/ftp/ftp.elf`. Each addon directory holds that
same ELF under the name Ariel runs, `elf`, the manifest, and a `server` file:

```
/data/ariel/addons/ftp-get/elf
/data/ariel/addons/ftp-get/manifest
/data/ariel/addons/ftp-get/server
```

Each manifest names its own directory and the argument count the command table
below gives, for example:

```
name ftp-get
args 2-2
abi 1
platform ps5
```

`ftp-ls` and `ftp-rm` take one argument, `ftp-put` and `ftp-get` take two. The
`server` file is one line, `HOST:PORT`, such as `192.168.1.20:2121`. The
owner sets it. The agent cannot change it, and the command line never names a
host or a port. Ariel reads the same file to write the server into the
canonical action the owner signs. The addon reads it again itself.

## Commands

| Command | Arguments | Meaning |
| --- | --- | --- |
| `addon run ftp-ls REMOTE` | 1 | Print a LIST of REMOTE |
| `addon run ftp-get REMOTE LOCAL` | 2 | Download REMOTE to a new file LOCAL |
| `addon run ftp-put REMOTE LOCAL` | 2 | Upload LOCAL to REMOTE |
| `addon run ftp-rm REMOTE` | 1 | Delete REMOTE |

REMOTE is absolute on the server. LOCAL must be absolute and resolve under
`/data/`, `/user/` or `/mnt/usbN`. It may not contain `..`.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The operation completed |
| 1 | The operation failed (connection, protocol, I/O, bad server file) |
| 3 | A path is malformed or outside the allowed roots |
| 87 | A path names protected state |

Ariel maps exit 3 to `bad_path` and exit 87 to `protected`. The loader's
timeout (10 seconds), the 64 KiB output cap and the kill apply to every run.

## Safety

- Every remote path is checked against protected.c as root+path and as
  root+`/data`+path, following links. ftpsrv's root was measured as `/` on a
  console on 2026-10-25 ([console findings](../../docs/console-findings.md)),
  so the first check is the one that fires; the second stays as a guard,
  because the root belongs to ftpsrv and the addon must not depend on it.
- Every local path is resolved through every link before it is checked, and the
  resolved path must lie under `/data`, `/user` or `/mnt/usbN`, where N names a
  mount the way fileops.c does: the first segment after `/mnt` starts with `usb`,
  is longer than `usb`, and has something below it. A path that leaves the roots
  through a link, including a mount link, answers `bad_path` and nothing is
  created. A link that stays inside the roots works.
- A link target that begins with `/` is a console path, as every other absolute
  path in this addon: it is resolved under the same root as the local path.
- A local path whose last component is a link is followed like any other link.
  The bytes move to the link's target, which must itself resolve inside the
  roots, and the target is the object `ftp-put` reads or `ftp-get` creates. A
  link whose target is missing is created at that target.
- A link target of `PATH_MAX` bytes or more is refused with `ENAMETOOLONG`
  rather than read as a shorter path.
- `ftp-put` checks the open source file with `protected_object`, so a hard link
  to protected state is refused.
- `ftp-get` creates its local file with `O_EXCL | O_NOFOLLOW`, after the links
  are resolved. A failed download removes the partial file.
- Remote paths may not contain CR, LF or other control bytes.

## Residual risks

- Ariel reads the `server` file for the canonical action, and the addon reads
  it again to connect. A change between the two reads is not detected.
- The local path is resolved once, before the open. A link or directory that is
  swapped between that resolution and the open is not detected: `openat` is not
  usable on the PS5 (ADR-0007), so the open cannot be tied to the directory the
  check saw.
- Passive mode uses the address from the `server` file, not the one in the
  PASV reply.
- The addon sets no socket timeout. The only time bound is the loader's
  10 second timeout, which kills the run.

## Console round trip (run on a console)

Run on 2026-10-25 against a CFI-2014 on firmware 11.20, with Ariel deployed
from `d30134d` and the four addon directories under `/data/ariel/addons`. The
`server` file named the console's own ftpsrv, `192.168.68.74:2121`.

1. `/data/src a.bin` was uploaded over ftpsrv: 48 bytes,
   `7ecc3e745f1c57ff1d1a4f44c3be9a4a450cb275af44eba3235fd557cc6cb2e2`.
2. `addon run ftp-put '/data/ftp-up/my file.bin' '/data/src a.bin'`, signed
   with the anchor key: `result /data/addon-ftp-put-13993681`, `status 0`,
   `exit 0`. The server listed `my file.bin`, 48 bytes.
3. `addon run ftp-get '/data/ftp-up/my file.bin' '/data/back a.bin'`, signed
   the same way: `result /data/addon-ftp-get-13998108`, `status 0`, `exit 0`.
4. `/data/back a.bin` is byte for byte `/data/src a.bin`: the same SHA-256,
   `cmp` equal.
5. `addon run ftp-get '/data/ariel/token' '/data/token-copy'` answered
   `protected` with exit 87, asked nobody, and `/data/token-copy` was never
   created.

The remote operands above are the console's own absolute paths, which is what
measures the root: ftpsrv served `/data/ftp-up/my file.bin` for the path the
addon asked for, so the root is `/` ([console findings](../../docs/console-findings.md)).
The addon keeps its check of both roots, because the root belongs to ftpsrv
and is not this addon's to assume.

The host acceptance suite covers the same behavior against an in-memory
passive FTP server.
