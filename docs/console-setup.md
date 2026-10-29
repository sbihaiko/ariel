# How this console is jailbroken, and how packages get in

An operating record, measured on 2026-10-28 on the CFI-2014 at 11.20
(`192.168.68.103`). It says how the console is running today, not how it should
run: the numbers are what a payload read back, and anything that changes them
belongs here with its own date.

## What is running

The exploit chain is loaded by `elfldr` on port 9021, which runs each payload as
a process of its own. `ps` on the agent port lists them:

| PID | Payload | What it does |
| --- | --- | --- |
| 91 | `kstuff.elf` | the kernel patches the jailbreak needs; the only one in `RUN` |
| 92 | `shadowmountplus.elf` | mounts the package images under `/mnt/shadowmnt` |
| 93 | `ftpsrv.elf` | the file server on 2121, the only route that moves files |
| 94 | `klogsrv.elf` | the kernel log on 3232 |
| 95 | `shsrv.elf` | the telnet shell on 2323, outside the gate |
| 111 | `payload.elf` | the Ariel agent; answers on 2324 after `auth <token>` |

`eboot.bin` (121) is a title in the foreground. Every payload above dies with a
reboot: the ports shut and a new chain has to be loaded before anything works
again. That happened more than once during the day, which is why the day is
written down with the ports' state rather than as a single run.

## Where things live

One volume of 937 046 507 520 bytes holds both trees, with 354 279 358 464 bytes
free at the end of the day:

- `/user/app/<TITLE>/` — one directory per installed title, holding `app.pkg`,
  `app.pbm`, `app.pbm.backup`, `app.json` and `app.xml`.
- `/user/appmeta/<TITLE>/` — the title's pictures and metadata: `icon0.png`,
  `icon0.dds`, `pic0.png`, `pic0.dds`, `param.json`, and on some titles
  `save_data.png`, `pic1.png`, `pronunciation.xml` and `shareparam.json`.
- `/user/license/` — the fake licences, as a pair per title:
  `fake<CONTENTID>.rif` (2048 bytes) and `fake<CONTENTID>.idx` (80 bytes). The
  first 0x400 bytes are a plaintext header carrying the content ID and the
  entitlement; the signature bytes after 0x660 differ per licence, so a licence
  cannot be produced by copying another one.
- `/user/home/10993c58/savedata/<TITLE>/` — the saves, an image and a small
  index: `sdimg_-JOURNEY-` (10 MiB) and `-JOURNEY-.bin` (96 bytes) for Journey.
- `/data/downloads/` — where a package lands before it is installed:
  `packages/`, `files/`, `archives/`, `extracted/` and `sets/`.

The removable drives are on `/mnt`: `usb0` at 15.8 GB and `usb1` at 127.8 GB,
with `usb2` to `usb7` and `ext0` empty or absent. `shadowmountplus` mounts the
package images it finds under `/mnt/shadowmnt`, one directory per title, which
is how Overdrive is reached (`/mnt/shadowmnt/Overdrive_d68885f3`, holding
`pkg-installer.elf`, `pkg-helper.elf` and `lapy.elf`).

## How a download becomes an install

A package arrives in `/data/downloads/packages/` named
`<TITLE>-game-<version>-r<hash>.pkg`, with a `.complete` marker of 168 bytes
written beside it when the transfer finished. The title ID at the front is not
decoration: Ariel's `pkg_install` takes the title from the package's own name,
before its first `-`, and measures `/user/app/<TITLE>` after the call.

Two installers can take it from there.

**Ariel's `pkg_install`.** Gated: the port answers `approval_required` with a
challenge, the owner's key signs the canonical action, and
`approval grant <id> <signature> <console> <action-sha256>` runs it. The
install is asynchronous — the console's own API returns once the request is
accepted — so the command waits for the app directory and then checks the
title's parts, answering `installed <TITLE> <bytes> <sha256>` or
`install_incomplete <TITLE> <part>`, the part naming the step that did not finish
(`docs/exit-codes.md` lists the parts). The source package is never deleted: cleaning it is a separate,
gated `rm`.

**Overdrive.** Runs from `/mnt/shadowmnt`, installs from the packages it can
see, and is the route that writes the appmeta entry and the fake licence in the
same pass.

What the install leaves behind, as measured at the end of the day: 38 titles in
`/user/app`, 37 entries in `/user/appmeta` and 19 licence pairs. The gaps are
`CUSA00694` (Journey, missing appmeta and licence) and `PINK00001`; the 19
`PPSA*` titles carry no fake licence because they are PS5 packages mounted by
`shadowmountplus`, not PS4 fpkg installs. `verify --all` is the command meant to
report exactly this, and it is not on the console yet: the running build predates
it and answers `approval_required` with `command=unlisted`.

## The file server's habits

`ftpsrv` 0.21.1 on 2121, anonymous, with `/` as its root, is idiosyncratic
enough to be written down, because a client that assumes normal FTP gets a
`502 Command not recognized`:

- It answers `MLSD` and not `LIST` or `NLST`.
- It ignores the path given to `MLSD`: the listing is always of the connection's
  current directory, so a client must `CWD` first and then `MLSD ""`.
- `RETR`, `STOR`, `DELE` and `RMD` all work, including with `REST` for a ranged
  read. A successful `DELE` answers `226 File deleted`, which a client may read
  as an error.
- Names on this console start with a dash (`-JOURNEY-.bin`), so a client that
  hands paths to a shell breaks on them.

## What the day showed

No freeze, with the payloads loaded and unloaded between sessions — recorded in
[console findings](console-findings.md#2026-10-28-a-day-of-play-with-no-freeze),
along with what that does and does not claim. The console also answers ping while
running no payload, so a reply says the network stack is alive and never that a
payload is.
