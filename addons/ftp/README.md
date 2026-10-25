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

REMOTE is absolute on the server. LOCAL must be absolute and begin with `/data/`,
`/user/` or `/mnt/usb`. It may not contain `..`.

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
- Every local path is checked the same way. `ftp-put` checks the open source
  file with `protected_object`, so a hard link to protected state is refused.
- `ftp-get` creates its local file with `O_EXCL | O_NOFOLLOW`. A failed download
  removes the partial file.
- Remote paths may not contain CR, LF or other control bytes.

## Residual risks

- Ariel reads the `server` file for the canonical action, and the addon reads
  it again to connect. A change between the two reads is not detected.
- The path checks are string checks on the local path. A symbolic link to a
  directory under `/data` is followed by the check, but a directory that is
  renamed between the check and the open is not.
- Passive mode uses the address from the `server` file, not the one in the
  PASV reply.
- The addon sets no socket timeout. The only time bound is the loader's
  10 second timeout, which kills the run.

## Console round trip (documented, not run)

Not run here. It needs a console, and this change does not touch one. On a
console with the addon installed and the `server` file pointing at its
ftpsrv:

1. Create a file with a space in its name, for example `/data/src a.bin`.
2. `addon run ftp-put '/up/my file.bin' '/data/src a.bin'`, then sign the
   prompt.
3. `addon run ftp-get '/up/my file.bin' '/data/back a.bin'`, then sign the
   prompt.
4. Compare the two files byte for byte.
5. `addon run ftp-get '/data/ariel/token' '/data/token-copy'` answers
   `protected` with exit 87, and no local file is created.

The host acceptance suite covers the same behavior against an in-memory
passive FTP server.
