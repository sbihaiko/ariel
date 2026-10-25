# ftp addon

Four addons move files through the console's ftpsrv on port 2121: `ftp-ls`,
`ftp-get`, `ftp-put` and `ftp-rm`. They are one program, `ftp.c`, built once
and installed under four names. Each name is asked for through the one gate
(`addon run <name> ...`), so the owner signs the remote path, the local path
and the server before anything moves.

## Installing

Each addon directory holds the same ELF, the manifest, and a `server` file:

```
/data/ariel/addons/ftp-get/ftp-get.elf
/data/ariel/addons/ftp-get/manifest
/data/ariel/addons/ftp-get/server
```

The `server` file is one line, `HOST:PORT`, such as `192.168.1.20:2121`. The
owner sets it. The agent cannot change it, and the command line never names a
host or a port. Ariel reads the file to write the server into the canonical
action the owner signs, and passes that text to the addon as its first
argument after the name. The addon reads the file again and refuses to run
(exit 1, no connection) if the file does not name the server it was passed.

## Commands

| Command | Arguments | Meaning |
| --- | --- | --- |
| `addon run ftp-ls REMOTE` | 1 | Print a LIST of REMOTE |
| `addon run ftp-get REMOTE LOCAL` | 2 | Download REMOTE to a new file LOCAL |
| `addon run ftp-put REMOTE LOCAL` | 2 | Upload LOCAL to REMOTE |
| `addon run ftp-rm REMOTE` | 1 | Delete REMOTE |

REMOTE is absolute on the server. LOCAL must be absolute and begin with `/data/`,
`/user/` or `/mnt/usb`. It may not contain `..`. An argument may be up to 255
bytes; one longer than 64 bytes reaches the owner as its SHA-256 (see
`docs/exit-codes.md`, the `addon run` paragraph).

The addon's argv is: the name, the server text, then the arguments.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The operation completed |
| 1 | The operation failed (connection, protocol, I/O, bad server file, a server argument the server file does not name) |
| 3 | A path is malformed, outside the allowed roots, or runs through a link out of them |
| 87 | A path names protected state |

Ariel maps exit 3 to `bad_path` and exit 87 to `protected`. The loader's
timeout (10 seconds), the 64 KiB output cap and the kill apply to every run.

## Safety

- Every remote path is checked against protected.c as root+path and as
  root+`/data`+path, following links. The ftpsrv root mapping (`/` or `/data`)
  is not confirmed on a console, so both are checked.
- Every local path is checked the same way. Each directory of it, below
  `/data`, `/user` or `/mnt/usb*`, is opened with `O_NOFOLLOW | O_DIRECTORY`,
  so a link to a directory out of those roots is refused with exit 3.
- Ariel refuses protected paths before the owner is asked; the addon checks
  them again itself, and exits 87 if one reaches it.
- The addon refuses a server argument that its `server` file does not name,
  before it connects to either.
- `ftp-put` checks the open source file with `protected_object`, so a hard link
  to protected state is refused.
- `ftp-get` creates its local file with `O_EXCL | O_NOFOLLOW`. A failed download
  removes the partial file.
- Remote paths may not contain CR, LF or other control bytes.

## Residual risks

- The directory checks open each directory without following links, but the
  final open is by path. A directory renamed between the check and the open is
  not detected.
- Passive mode uses the address from the `server` file, not the one in the
  PASV reply.
- The addon sets no socket timeout. The only time bound is the loader's
  10 second timeout, which kills the run.

## Console round trip (documented, not run)

AC7 is unmet until this is run on a console. It was not run for this change,
and the ftpsrv root mapping (`/` or `/data`) is still unconfirmed. On a console
with the addon installed and the `server` file pointing at its ftpsrv:

1. Create a file with a space in its name, for example `/data/src a.bin`.
2. `addon run ftp-put '/up/my file.bin' '/data/src a.bin'`, then sign the
   prompt.
3. `addon run ftp-get '/up/my file.bin' '/data/back a.bin'`, then sign the
   prompt.
4. Compare the two files byte for byte.
5. `addon run ftp-get '/data/ariel/token' '/data/token-copy'` answers
   `protected` with exit 87 before the owner is asked, and no local file is
   created.

The host acceptance suite covers the same behavior against an in-memory
passive FTP server. It does not cover the console.
