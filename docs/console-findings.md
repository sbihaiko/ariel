# What the console showed: the pad, the title and the payload

A reference page. Every value here was measured on a real console on 2026-10-23 and is written down so the next change does not rediscover it. The run-by-run evidence, including the transcripts, is in [controller-spike-notes.md](controller-spike-notes.md); the runbook is [controller-spike.md](controller-spike.md); the decision it forced is [ADR-0006](adr/0006-the-controller-is-the-approval-source.md).

## The answer

A payload started through the ELF loader **cannot read the controller**. The foreground title can, and returns the real button bits. Borrowing that read through `ptrace` works for a call or two and then stops the title; the console had to be rebooted out of it.

That is why the approval source is now a signature by a key the owner holds, and not the pad.

## Who can do what

| Process | Open a pad | Read the title's handle | Read the pad |
| --- | --- | --- | --- |
| Ariel's payload | `0x809b0081` | `0x80920003` | no |
| Foreground title (`eboot.bin`) | handle `0x03e50700` | itself | yes, real button bits |
| `SceShellCore` (home screen) | `0x80920008` | n/a | no pad open |

The handle is an index into the owning process's pad client, not a global object. Copying the integer across process boundaries does not carry the capability.

## Error codes seen

| Code | Symbol | Where |
| --- | --- | --- |
| `0x809b0081` | `USER_NOT_LOGIN` | `scePadOpen` in the payload, port types 0 and 2 |
| `0x80920008` | `DEVICE_NO_HANDLE` | `scePadGetHandle` in the payload, in `SceShellCore`, and in the title for user id 1 |
| `0x80920003` | — | `scePadReadState` in the payload of a handle valid inside the title |
| `0x80920001` | `INVALID_ARG` | port type 1, which is not a port type |
| `0x80940004` | `SCE_LNC_UTIL_ERROR_NO_APP_INFO` | `sceUserServiceGetInitialUser`; also printed by elfldr while a payload starts |

Port types 0 and 2 both reach the pad API. Index 0 is the port the title owns.

## The account

| Source | Result |
| --- | --- |
| `sceUserServiceGetForegroundUser` | `362804492` |
| `sceUserServiceGetLoginUserIdList` | `362804492` |
| `sceUserServiceGetUserName(362804492)` | `bihaiko` |
| `/system_data/priv/home/` | one directory, `159ff50c` |
| `sceUserServiceGetInitialUser` | `0x80940004`, no user id |

`0x159ff50c` is `362804492`. `sceUserService` refuses a payload until its credentials are raised, which is why the spike does what ProsperoMgr's `EscalatePrivileges` does. Raising them makes the user service answer; it does not make the pad open.

## Reading the pad from the title

1. `sceSystemServiceGetAppIdOfRunningBigApp` returns the foreground app id. It was `0x18`.
2. Walk the process list for `eboot.bin`. `sceKernelGetAppInfo` on pid 109 wrote app id `0x18` and title id `PPSA99177`. The title id string sits at **offset 16** in that buffer, the layout with `app_type` before the title id.
3. Resolve `libScePad.sprx` **by name** with `kernel_dynlib_handle` and `kernel_dynlib_resolve`. `pt_resolve` does not work: it only looks at library handles `0x1` and `0x2001`, and `libScePad` is in neither.
4. Call `scePadGetHandle(user 362804492, type 0, index 0)` → `0x03e50700`, then `scePadReadState` on it.

| Item | Value |
| --- | --- |
| `scePadGetHandle` NID | `u1GRHp+oWoY` |
| `scePadReadState` NID | `YndgXqQVV7c` |
| Addresses in pid 109 | `0x8009f1560`, `0x8009f2a80` |
| Cross held | `buttons 0x00004000` (`PAD_BUTTON_CROSS`) |
| Nothing held | `buttons 0x00000000` |

A second `eboot.bin` in the list, pid 66, is the system title `NPXS40039`. It is not the foreground title and was not used.

## What borrowing costs

`pt_call` single-steps the target and the spike's deadline is only checked between probes. One run read a sample and the next in-title read never returned: port 9150 stayed open, the transcript stopped, the picture on the console froze and the controller did nothing. elfldr on 9021 still accepted connections, so the system was up and the title was stopped. A reboot is what ends it.

Do not attach to the foreground title to sample the pad. That is the run that froze the console.

## The *at() calls on this SDK

Measured on firmware 11.200.005, console `192.168.68.77`, under `/data/ariel`. The link of a payload built with `prospero-clang -lkernel_sys` (`-Wl,--trace-symbol`) is:

| Symbol | Definition the link uses |
| --- | --- |
| `open` | `libkernel_stub_weak.so` (shared) |
| `fstat` | `libkernel_stub_weak.so` (shared) |
| `openat`, `mkdirat`, `unlinkat`, `renameat`, `fstatat`, `fchmodat`, `linkat`, `readlinkat`, `syscall` | `libc.a(syscalls.o)` |

`libc.a(syscalls.o)` for each of those is `mov $SYS_*, %rax; mov %rcx, %r10; syscall; ret`. Runtime addresses of the libc copies were `0x200009ae0`–`0x20000a6f0`. `open` was `0x80000ecb0` and `fstat` was `0x800001090`.

| Call | Case | rc | errno |
| --- | --- | --- | --- |
| `open` absolute | `/data/ariel/token` | 9 | 0 |
| `open` absolute | missing `nonces` | -1 | 2 `ENOENT` |
| `openat` | `token` | 10 | 0 |
| `openat` | missing `nonces` | 2 | 0 |
| `syscall(SYS_openat)` | missing `nonces` | 2 | 0 |
| carry-checking `SYS_openat` | missing `nonces` | -1 | 2 `ENOENT` |
| carry-checking `SYS_openat` | `token` | 10 | 0 |
| `mkdirat` | `store` exists | 17 | 0 |
| `syscall(SYS_mkdirat)` | `store` exists | 17 | 0 |
| carry-checking `SYS_mkdirat` | `store` exists | -1 | 17 `EEXIST` |
| `unlinkat` | missing name | 2 | 0 |
| `unlinkat` | existing file | 0 | 0 |
| `syscall(SYS_unlinkat)` | missing name | 2 | 0 |
| carry-checking `SYS_unlinkat` | missing name | -1 | 2 `ENOENT` |
| `renameat` | existing file | 0 | 0 |
| `renameat` | missing name | 2 | 0 |
| `syscall(SYS_renameat)` | missing name | 2 | 0 |
| carry-checking `SYS_renameat` | missing name | -1 | 2 `ENOENT` |
| `fstatat` | `token` | 0 | 0 |
| `fstatat` | missing name | 2 | 0 |
| `syscall(SYS_fstatat)` | missing name | 2 | 0 |
| carry-checking `SYS_fstatat` | missing name | -1 | 2 `ENOENT` |
| `fstat` | open token fd | 0 | 0 |
| `fstat` | fd -1 | -1 | 9 `EBADF` |
| `fchmodat` | `token` mode 0600 | 0 | 0 |
| `fchmodat` | missing name | 2 | 0 |
| `linkat` | `token` to a new name | 45 | 0 |
| `linkat` | missing name | 2 | 0 |
| `readlinkat` | `token` | 78 | 0 |
| `readlinkat` | missing name | 78 | 0 |

45 is `EOPNOTSUPP`. 78 is `ENOSYS`. The `linkat` of `token` did not create the destination (`unlinkat` of that name then returned 2). `dlsym(RTLD_DEFAULT, "openat")` returned null. `dlopen` of `libkernel_sys.sprx`, `libkernel.sprx`, `libkernel_web.sprx` and `libSceLibcInternal.sprx` returned null.

The safe call is a `syscall` instruction whose carry flag is checked: carry set means `errno = rax` and the result is -1. Carry clear means `rax` is the result. That is what `ps5_at.h` does for the five calls `store.c` makes. `open` and `fstat` already do it inside libkernel.

## Ruled out

- **Credentials alone.** The user service answers; the pad does not open.
- **Call order.** Initialising the user service before or after raising credentials changes nothing.
- **Authid.** `0x4801000000000013` and GhostControl's `0x3800000000010003` give the same pad result.
- **The registry sign-in flag.** Key `125874185`, plus `65536` per slot; all 16 slots read back empty.
- **`np-fake-signin`.** It wrote `auth.dat` (1200 bytes) into the home directory. The pad still refused.
- **User ids.** Inside the title, user id `1` is still `DEVICE_NO_HANDLE`; only the real account id resolves.
- **The shell.** `SceShellCore` on the home screen has no pad open, because nothing is in the foreground.
- **Untested, therefore not results.** Port type 3, pad indexes other than 0, the PoorDS4 context setters (`scePadSetLoginUserNumber`, `scePadSetUserNumber`, `scePadSetProcessFocus`) and `scePadVirtualDeviceAddDevice` were never run. A virtual device would create input, not read the owner's.
- **`*at()` via `libc` `syscall()`.** `syscall(SYS_openat)` on a missing file returned 2 and left `errno` at 0. Same for `SYS_mkdirat` (17), `SYS_unlinkat` (2), `SYS_renameat` (2) and `SYS_fstatat` (2).
- **The kernel `openat` symbol.** The link keeps `libc.a(syscalls.o)`. `dlsym(RTLD_DEFAULT, "openat")` was null. `dlopen` of `libkernel_sys.sprx`, `libkernel.sprx`, `libkernel_web.sprx` and `libSceLibcInternal.sprx` was null.
- **Absolute `open` in place of `openat`.** A missing absolute path returns -1 with `errno` 2. It does not take a directory fd or `O_NOFOLLOW`, which is what the store uses.

## Issue #18 probe: openat, renameat, unlinkat, fsync

`primitives-probe.elf` is a separate payload. It is not linked into `shsrv-ps5.elf`. It calls `openat`, `renameat`, `unlinkat` and `fsync` the way the store does, and prints each call, its `rc` and `errno`, and a `PASS` or `FAIL` line for whether the POSIX behavior held.

`renameat` is probed as an atomic replace of a file that already exists: the destination must hold the new content, and the temporary name must be gone. `fsync` is probed twice, once on a file descriptor and once on a directory descriptor. `fsync` is the libkernel symbol, which already returns -1 and sets `errno`, so `ps5_at.h` does not wrap it. The other three go through `ps5_at.h`.

Measured on 2026-10-24 on a CFI-2014 on firmware 11.200.005: every primitive held, `failures 0`. The probe was sent with `nc 192.168.68.77 9021 < primitives-probe.elf`, since `prospero-deploy` needs `socat`.

### Run procedure

1. Build with the PS5 SDK set, as in the [quick start](quick-start.md). `make clean all` writes `primitives-probe.elf`. To build only the probe, run `make primitives-probe.elf`. Do not run `make test`; it sends `shsrv-ps5.elf` to the console, and refuses unless `ARIEL_DEPLOY=yes` is given.
2. Send the probe to the ELF loader. The loader copies the payload's standard output back over this connection, so leave it open:

```console
$ export PS5_HOST=192.168.0.10
$ $PS5_PAYLOAD_SDK/bin/prospero-deploy -h $PS5_HOST -p 9021 primitives-probe.elf
```

3. The payload works under `/data/ariel/probe18` and exits on its own. Each primitive prints three lines: `call <what was called>`, `rc <n> errno <n>`, and `PASS` or `FAIL` with the reason. The last line is `primitives probe: done, failures <n>`.
4. Copy those lines into the table below, one row per primitive, with the firmware and the model of the console that ran it. A `FAIL` is reported on issue #2 before the journal ticket starts.

### Results

| firmware | model | primitive | rc | errno | verdict |
| --- | --- | --- | --- | --- | --- |
| 11.200.005 | CFI-2014 | openat | 8 | 0 | PASS |
| 11.200.005 | CFI-2014 | renameat (atomic replace of an existing file) | 0 | 0 | PASS |
| 11.200.005 | CFI-2014 | unlinkat | 0 (a second call: -1) | 0 (a second call: 2, ENOENT) | PASS |
| 11.200.005 | CFI-2014 | fsync of a file | 0 | 0 | PASS |
| 11.200.005 | CFI-2014 | fsync of a directory | 0 | 0 | PASS |

## The journal's primitives

The journal in `store.c` makes every store change in four steps: **prepared**, **committed**, then **done** or **rolled back**. A journal mark is a temporary file, flushed, renamed over `store/journal` and the store directory flushed. The table maps each step to the calls it makes and to what the #18 probe confirmed.

| Step | Calls | Confirmed by the probe |
| --- | --- | --- |
| prepared | `openat` with `O_CREAT\|O_EXCL\|O_NOFOLLOW` for `objects/<hash>.tmp`, `current/<name>.tmp` and `store/journal.tmp`; `fsync` of each; `renameat` of the journal over `store/journal`; `fsync` of the store directory | `openat` and `fsync` of a file. `O_EXCL` and `O_NOFOLLOW` were not run. |
| committed | `renameat` of `objects/<hash>.tmp` and `current/<name>.tmp` over their final names; `fsync` of the objects and current directories; `renameat` of the committed mark | `renameat` over an existing file, `fsync` of a directory |
| state record | `openat` of `state.tmp` with `O_EXCL`, `fsync`, `renameat` over `state`, `fsync` of the state directory | as above; `O_EXCL` not run |
| recovery at start | `openat` of `store/journal` with `O_NOFOLLOW`; `fstatat` of `objects/<hash>` with `AT_SYMLINK_NOFOLLOW` | `fstatat` of a file and of a missing name (the libc table above). The journal's `O_NOFOLLOW` and `AT_SYMLINK_NOFOLLOW` were not part of those runs. |
| done | `unlinkat` of `store/journal` and of the dropped object; `fsync` of the store and objects directories | `unlinkat` of an existing file, and of a missing one (`ENOENT`) |
| rolled back | `unlinkat` of the temporary objects and current records | as above |

Deviations from the probe:

- The probe opened its files with `O_WRONLY|O_CREAT|O_TRUNC` and its directories with `O_RDONLY|O_DIRECTORY`. The journal also depends on `O_EXCL`, `O_NOFOLLOW` and `AT_SYMLINK_NOFOLLOW`. None of them has been run on a console. A console run of the journal scenarios is what confirms them.
- The probe checked return values and the file contents it read back. It did not cut power. The host crash scenarios end the process with `abort`, so they test the order of the steps, not what survives a power loss. Durability after a power cut rests on POSIX `fsync` semantics and is not measured here.
- `openat`, `renameat`, `unlinkat` and `fstatat` go through the carry-checking wrappers in `ps5_at.h`, the form the table above measured. `fsync` is the libkernel symbol, which the probe called directly.

## Issue #48: keys on the console

Run on 2026-10-24 by the coordinator, on firmware 11.20 (CFI-2014), with the `dev` build at 366c677. The build's anchor was the owner's primary and recovery keys, and the keyring started at generation 0. Each approval was asked on the agent port, signed offline with `ariel-sign` and granted. The freeze file was written and removed through the telnet shell. Ariel was restarted by sending the ELF to the loader again; the console itself was not rebooted.

| Step | Command and signer | Console reply |
| --- | --- | --- |
| Rotate the primary | `key rotate <P2>`, signed by the primary P1 | `key_rotated 1` |
| Old primary after rotation | a `mkdir` approval signed by P1 | `signature_invalid`, exit 79 |
| New primary after rotation | the same approval signed by P2 | `approval_granted`, and the `mkdir` ran |
| Freeze | `/data/ariel/freeze` written; `mkdir`, `payload run helloworld`, `key rotate-recovery` | `frozen`, exit 89, for each |
| Revoke while frozen | `key revoke --since 1 <P3>`, signed by the recovery key | `key_revoked 2` |
| Freeze after revoke | a `mkdir` approval; then the freeze file deleted and the same approval asked again | `frozen`, exit 89, both times |
| Unfreeze | `key unfreeze` signed by P3, then by the recovery key | `signature_invalid` for P3; `key_unfrozen 2` for the recovery key |
| Revoked lineage | an approval signed by P2 | `signature_invalid`, exit 79 |
| Active primary | the same approval signed by P3 | `approval_granted`, and the `mkdir` ran |
| Grant from before generation 1 | `payload run helloworld`, installed at generation 0 | `pid <n>`, exit 0: not suspended |
| Start with the keyring removed | keyring copied aside and deleted, Ariel restarted; a `mkdir`, `key rotate` and `key unfreeze` | `key_refused`, exit 1, for each. No keyring was made from the build's anchor. |
| Keyring restored | the copy put back, Ariel restarted; an approval signed by P1 (the anchor's primary), then by P3 | `signature_invalid` for P1; `approval_granted` for P3 |

The audit log recorded `key_revoke` and `key_unfreeze` with their approval IDs, and `<command>.refused` for each refusal. No `grant_suspended` line was written: no install, pin or autoload entry had been approved at generation 1, so the revocation suspended nothing. The host scenarios cover suspension.

The keyring copy and the test folders were removed from `/data` after the run. The console's primary is now P3.

## Issue #61, #64 and #49: Stage 3 on the console

Run on 2026-10-24 by the coordinator, on firmware 11.20 (CFI-2014), with the `dev` build at `03eef1c`, deployed by sending `shsrv-ps5.elf` to the loader on 9021. Each gated command was asked on the agent port, signed with the keyring's current primary (generation 2, `owner3.key`) and granted; nothing was signed by hand.

| What ran | Console reply |
| --- | --- |
| `read /data/prosperoeden/config/prosperoeden.json` | `bytes <size> <sha256>` naming the file's size and the hash of the same bytes `cat` returns, then the bytes, `exit 0` |
| `read … --offset 12 --limit 24` | the range's 24 bytes and the whole file's hash, `exit 0` |
| `read … --offset <size>` and `--offset <size+1>` | `bytes 0 <sha256>` with exit 0, and `bad_range` with exit 1 |
| `mkdir`, `touch`, `cp -r`, `rm -r` of a throwaway tree | 75 with a challenge, then `exit 0` once, for each |
| `sfocreate -i APP_VER=1 -s32 TITLE=Hello …` | 75, then `exit 0`; `sfoinfo` read back `APP_VER(0x00000001)` and `TITLE('Hello')` |
| `rm` of the SFO | 75, then `exit 0`; `stat` then answered `no_such_file` |

Three things the console taught that the host build cannot:

- **A payload built without the anchor pinned refuses everything gated.** `make` with `ARIEL_PUBKEY` and `ARIEL_RECOVERY_PUBKEY` empty produces a binary that answers `key_refused` (exit 1) to `mkdir`, to `cp -r` and even to `key status`, because the keyring's generation chain does not verify against the build's anchor. Fail-closed as #48 designed it, and the reason a console build must be made with both keys: `make ARIEL_PUBKEY=<owner primary> ARIEL_RECOVERY_PUBKEY=<recovery> all`.
- **`ariel-sign` must be built from the branch under test.** The signer on `master` answers `not a challenge line` to a challenge from `dev`, whose line carries a generation field the older parser does not read. Signing with the wrong binary fails before a signature is made, not after, which is the good failure.
- **One notification at a time.** A second gated command inside the 10 s notification window answers `approval_busy` (76) and asks nothing; the client retries. The driver that ran these checks waits 11 s and tries again.

**A console in rest is not a console that is down.** It keeps answering `ping` on the LAN and answers nothing else: 2323, 2324 and 9021 are all closed. A deploy sent in that state is lost with no error from the console, which reads exactly like a crashed payload. The wake that worked here was a magic packet to the broadcast address (the console has Wake-on-LAN on, MAC `50:b0:3b:42:ed:17`); about 25 s later 9021 answered, and the payloads had to be sent again because none of them survives rest.

One more, from the deploy rather than the commands: sending the ELF with a plain `nc` that closed early crashed the console into a reboot, and the payloads that had been running did not come back (only the loader did). The working shape is to send every byte, shut the writing side, and read until the peer closes.

## Issue #55: the capture API on the console

Run on 2026-10-24 by the coordinator, on firmware 11.20 (CFI-2014). The spike is `capture_spike.c` and the `capture-spike.elf` target in the `Makefile`; it is not part of `all`, is never linked into `shsrv-ps5.elf`, and the operator sends it to the loader on 9021 on its own, as the controller spike is sent. It writes every step to `/data/capture-spike.log` before taking it, so a crash still says where it died. A copy of `/system/common/lib/libSceScreenShot.sprx` fetched over FTP was read on the workstation to name the exports.

**What the library is.** `/system/common/lib/libSceScreenShot.sprx` is the VSH build: an IPC client (`SceScreenShotIpcClient`, command `0x34560000`) in front of a system daemon, not a capture implementation of its own. It carries 13 exported functions. The public PS5 3.20 export dump and the PS4 map agree on these names, and the disassembly agrees with the ones the spike called:

| NID | Name | Called here |
| --- | --- | --- |
| `G7KlmIYFIZc` | `sceScreenShotSetParam` | yes, returned 0 |
| `JuMLLmmvRgk` | `sceScreenShotCapture` | yes, never completed |
| `ahHhOf+QNkQ` | `sceScreenShotSetOverlayImage` | yes, returned `0x80BE0003` |
| `2xxUtuC-RzE` | `sceScreenShotEnable` | no |
| `tIYf0W5VTi8` | `sceScreenShotDisable` | no |
| `-SV-oTNGFQk` | `sceScreenShotIsDisabled` | resolved, not trusted as a flag |
| `ICNJ-1POs84` | `sceScreenShotIsVshScreenCaptureDisabled` | resolved, not trusted as a flag |
| `73WQ4Jj0nJI`, `hNmK4SdhPT0`, `VlAQIgXa2R0`, `ysfza71rm9M`, `BDUaqlVdSAY`, `itlWFWV3Tzc` | unnamed in every public list found | no |

**What a capture hands back.** `sceScreenShotCapture(int mode, char *path, int (*cancel)(void*), void *userdata)` — from the disassembly: `mode` below 2, `path` a non-null 1024-byte buffer the function clears before it starts, `cancel` optional. It polls the daemon every 16 ms while the answer is `0x80020023`, calls `cancel` if one is given, and on success writes into the caller's buffer the path the system chose. The caller therefore chooses no location: it passes metadata (`SceScreenShotParam`, 0x28 bytes: `thisSize`, `photoTitle`, `gameTitle`, `gameComment`, `reserved`) and the system names the file in its own gallery. Public sources put that gallery at `/user/av_contents/photo/<NPXS…>/<TITLEID>/<NNN>/`, outside `/data`; not verified on this console, because no capture completed.

**What the console answered.**

| Attempt | Reply |
| --- | --- |
| `dlopen` of the library by path and by name | null, with `dlerror()` null too; `dlopen` also answers null for `libkernel_sys.sprx` and the other system libraries, as `docs/console-findings.md` already recorded |
| `sceKernelLoadStartModule("/system/common/lib/libSceScreenShot.sprx", …)` at once | loaded (handle 33), and every export resolved, but the first call died inside an unresolved import |
| `sceKernelLoadStartModule` after `/system/common/lib/libSceIpmi.sprx` and `/system/common/lib/libSceSysUtil.sprx` | loaded (handle 35), all 13 exports resolved, calls survive |
| `sceKernelDlsym(handle, nid, &fn)` for each export | `0x80020003` for every one, plain and `#E#A`-decorated; `kernel_dynlib_resolve(getpid(), handle, nid)` answers instead |
| `SetParam("Ariel capture spike", …, "issue #55")` | `0`, twice |
| `Capture(mode 0, buf, cancel at 15 s, …)` | `0x80020023` until the cancel fired, then `0x80BE000A`; buffer empty |
| `Capture(mode 0, buf, cancel at 20 s, …)`, a fresh payload | the same: `0x80020023` for 20 s, then `0x80BE000A`; buffer empty |
| `Capture(mode 1, buf, cancel at 20 s, …)`, a fresh payload | the same for both modes |
| `Capture`, after the two flag calls below answered errors | `0x80020003` at once, both modes: the client is wedged by the calls before it, not by the capture |
| `IsDisabled(&flag)` | `0x80BE0001`, flag untouched: the export does not take an `int *` |
| `IsVshScreenCaptureDisabled(&flag)` | `0x80020003`, flag untouched |
| `SetOverlayImage("/data/shot-spike2.jpg", 1280, 720, 0)` | `0x80BE0003` (the export takes a path and two coordinates; no image either way) |

Four things this run settled:

- **The library loads in a payload only after its imports are present.** Loaded alone, it resolves and then dies on the first call that crosses a PLT entry into `libSceIpmi`/`libSceSysUtil`; loaded after those two, it answers. A payload has no `dlopen` at all, so `sceKernelLoadStartModule` with the full path is the only door, and `kernel_dynlib_resolve` with the kernel's own symbol table is the only lookup.
- **A payload is not refused by the capture service, and not served either.** `SetParam` answers success. `Capture` is accepted — `0x80020023` is "still working", not an error — and never leaves that state: 20 s in both modes on a fresh payload, with the system UI on screen and no title running. No image was produced. Whether a running title or the VSH's own identity changes that is not measured. The one run where `Capture` answered `0x80020003` at once had called `IsDisabled`/`IsVshScreenCaptureDisabled` with a wrong signature just before it, and that is the likelier cause of the wedge than the capture itself.
- **Where the image goes is the system's choice.** The caller's buffer says where it went; it is not an argument.
- **Every payload that called `Capture` was followed by the console dropping off the network.** Three payloads called it; each logged its own end (`capture spike end`) and each console stopped answering ping and every port — 2323, 2324, 9021, 2121 — a few minutes later, with no wake from a magic packet. The owner had to reset the console by hand at least twice after a payload called `Capture`, confirmed on 2026-10-24. The payload that called `SetParam` and `SetOverlayImage` but never `Capture` was not followed by one. The cause is not proven — the console also rests on its own, and no payload survives that — but the correlation is three for three, so **no capture attempt runs on the console unless the owner is present and willing to reset it**.

**The attempt of 2026-10-25.** With the owner standing by, `capture-spike.elf` was sent to the loader once more on a console that had just run the anchored build: `dlopen` still answers nothing, the module loader with `libSceIpmi` and `libSceSysUtil` first still loads it (handle 35) and every export resolves through `kernel_dynlib_resolve`, `SetParam` answers `0`, and both `Capture` modes end at `0x80BE000A` with an empty path when the 20 s cancel fires. `IsDisabled` then answered `0x80BE0001` with the flag untouched, and on the next resolve the console stopped answering 2121, 2324 and 9021 while still answering ping. Four attempts, four wedges: the client does not complete a capture on this firmware, and calling it leaves the console to a hand reset.

**Not measured.** The time and memory a capture costs, the size and format of the file (the system's PNG/JPEG setting), what a protected scene answers (no game or video app was run), and whether a capture works while a title is in the foreground. Each needs a console that completes a capture first.

## Issue #100: the share route, and the error it stops at

Run on 2026-10-25 with the owner on hand, on the same console, after the capture attempts above had already been reset away. The spike is `share_spike.c` and the `share-spike.elf` target in the `Makefile`; like the capture spike it is not part of `all`, is never linked into `shsrv-ps5.elf`, and writes each step to `/data/share-spike.log` before taking it. The question it asks is the owner's: the screenshot client in `libSceScreenShot` is the VSH's own IPC client and wedges the console, so is the system's share feature a second door a payload can open?

**What the library is.** `/system/common/lib/libSceShare.native.sprx` is the share implementation, not a client of one: the file the loader wants by that exact name (`libSceShare.sprx` answers `0x80020002`, no such module). Its exports carry the capture the share menu offers — `ShareCaptureScreenshot`, `ShareCaptureScreenshotExtended`, `ShareGetCurrentStatus`, `ShareSetCaptureSource`, and a `ShareFeaturePermit`/`ShareFeatureProhibit` pair — so a capture through it would be the system's own, not a daemon round trip.

**What the console answered.**

| Attempt | Reply |
| --- | --- |
| `dlopen` of the library, by path and by name | null with `dlerror()` null, as with every system library in a payload |
| `sceKernelLoadStartModule` after `libSceIpmi` and `libSceSysUtil` | loaded: handles 33, 34, 35, mapbase `0x8004b4000` |
| `kernel_dynlib_resolve` for the seven exports | all seven resolve (`8004c0fa0` … `8004c1680`) |
| `ShareGetCurrentStatus(1, status)` | `0x8196000C`, status block untouched |
| `ShareCaptureScreenshot(NULL, &req)` | `0x81960002` (invalid argument), request id untouched |
| `ShareCaptureScreenshotExtended(NULL, &req)` | `0x81960002`, request id untouched |
| `ShareCaptureScreenshot(&zeroed 0x40, &req)` | `0x8196000C`, request id untouched |
| `ShareFeaturePermit(1)` | `0x8196000C` |
| `ShareGetCurrentStatus(1, …)` and the capture again, after the permit | `0x8196000C` both |

**The second run, the same day, after the error codes were named.** The psdevwiki error list names `0x8196000C` as `SCE_SHARE_LIBRARY_ERROR_NOT_INITIALIZED` and `0x81960001` as `SCE_SHARE_LIBRARY_ERROR_INTERNAL`, and the public bindings name an init the first run never called: `sceShareInitialize(size_t heap, int priority, uint64_t affinity)`, NID `nBDD66kiFW8`, with the defaults a title passes (a 128 KiB heap, priority 700, affinity 0). They also name the feature flags: `0x1` is video recording and `0x2` is the screenshot, so the first run asked about the wrong feature. The spike was rebuilt with the init and the corrected flag and sent again. The console had gone to rest; a magic packet woke it.

| Attempt | Reply |
| --- | --- |
| `sceShareInitialize(0x20000, 700, 0)` | `0x81960001` (`INTERNAL`), and the call returns |
| `ShareGetCurrentStatus(0x2, status)`, before and after the permit | `0x8196000C`, status untouched |
| `ShareCaptureScreenshot(NULL, &req)` and the extended form | `0x81960002`, as before |
| `ShareCaptureScreenshot(&zeroed 0x40, &req)`, before and after `FeaturePermit(0x2)` | `0x8196000C` |
| `ShareFeaturePermit(0x2)` | `0x8196000C` |

**The heap the init checks first.** Read back through the kernel, the export starts with `cmp $0x20000, %rdi; jb <reject>`: a heap below 128 KiB is answered `0x81960002` by the library itself, before any call leaves the process. The 128 KiB a published binding uses is exactly that floor. Sent again with `0x20000`, the call passes the check and the service behind it still answers `0x81960001`. The export also treats `0x8196000D` (`ALREADY_INITIALIZED`) as success, and this run did not get that either, so no earlier init is held.

**Where the internal error comes from.** Past that check, `sceShareInitialize` makes two calls. The first builds the IPC client: it zeroes the client, allocates three small lists, sets up a synchronisation object and copies three 64-byte blocks out of a table that is zero in memory even after relocation. It does not check the result. The second sends IPC command `0x1236000C` and returns whatever integer comes back, and that integer is the `0x81960001`. Nothing in this library decides it, so nothing a caller passes can change it. The service that answers the command is not in this file.

**Not measured.** Why the share service answers `INTERNAL` to an init whose arguments passed the library's own check. The heap, the priority and the affinity are within what the export accepts, the function returns rather than hanging, and it does not report an init already held. The code of the service is not in this library. Also not measured: whether a foreground title, or the share process's own identity, lets the init succeed; what the extended capture's parameter block wants beyond the zeroed 0x40 bytes its validation accepts; and whether the permit needs a second flag or a token the payload does not have.

**Where the route ends.** Two doors, two answers: `libSceScreenShot` accepts the request and never completes it, then wedges the console; `libSceShare.native` loads and its init fails with an internal error, so every capture answers not-initialized, and the console keeps running. Neither hands a payload an image, so a screenshot addon has no path on firmware 11.20 that this project can build on. The homebrew that does move screenshots reads the file the Create button already wrote under `/user/av_contents/photo/`; it does not take the shot.

## Issue #72 and #81: the console suite after the state directory closed

Run on 2026-10-24 by the coordinator, on firmware 11.20 (CFI-2014), with `dev` at `93f47ee` — the build that carries #74's per-component protection — anchored with the owner's primary and recovery keys and sent to the loader on 9021. The console had gone to rest on its own; a magic packet did not wake it that time, it came back later, and every payload had to be sent again.

**The state directory is closed.** `ls /data/ariel` answers `protected`, `exit 87`; `ls /data` still lists and exits 0. So the three checks the suite had written to read into that directory could no longer pass, and before the run they were rewritten (#81): the read-only check now lists `/data`, and the install check proves the installed digest through `payload list` instead of hashing the store object.

**A gated `write` carries its bytes when it asks.** `write <path> <size> <sha256>` sent without its body answers `upload_mismatch`, `exit 81` — the upload is checked before the approval is asked. The first version of the new `read` check (#72) sent the bare command through the gated helper and failed on the console with exactly that answer; with the frame sent on both the asking and the running send, it passes (#83). The host fake now refuses a write frame without its bytes, so the mistake fails headlessly too.

Each approval was signed offline with the owner's key and granted over the agent port. Six checks ran; the first pass had five, and the `read` check passed once its frame was fixed:

| Check | Result on the console |
| --- | --- |
| `cp -r` copies a throwaway tree, lists the copy's entry, `rm -r` removes it | pass |
| `read` answers a throwaway file whole and in range as `cat` does, header and both paths' removal included | pass, after the frame fix |
| a commit before the decision asks again, then installs and is listed with its digest | pass |
| the read-only commands over `/` and `/data` exit 0 | pass |
| the token, approvals, nonces and keyring answer `protected`, `exit 87`, read directly | pass |
| the inspection commands run with no approval | pass |

**Not measured.** The rest of the console suite was not run in this pass; it is the next console session's job. The `write` check's own body handling was proven only through the `read` check and the host scenarios.

## Issue #89: ftpsrv's root, and the round trip that waits for the owner

Measured on 2026-10-25, read-only, on the console at firmware 11.200.005 (CFI-2014 A01X, S/N E456015EB10480711), with no Ariel deployed.

**ftpsrv's root is `/`.** A listing of `ftp://<console>:2121/` answers the system tree (`adm`, `app_temp0`, `data`, `dev`, `hdd`, `host`, `user`), and a listing of `/data` answers that directory's entries; so ftpsrv serves the console's filesystem from `/`, not from `/data`. The ftp addon checked both mappings because this was unknown; the first check is the one that fires on a console, and the second stays as a guard, since the root belongs to ftpsrv and the addon must not depend on it.

**The console had no Ariel when this was measured.** `/data` held the owner's other payloads and no `ariel` directory, port 2324 was closed, and 2323 answered `Welcome to shsrv.elf running on pid 97, compiled Aug 2 2026 at 16:40:44` — upstream shsrv, not Ariel. The keyring recorded after [#48](#issue-48-keys-on-the-console) went with the state directory, so the generation-2 primary no longer applies to this console until it is provisioned again.

**The round trip ran on 2026-10-25.** With the owner on hand, an anchored build of `d30134d` (`ARIEL_PUBKEY` = `ced29c6d…5858`, the primary in `~/.config/ariel/owner.key`) was loaded through the ELF loader on 9021. Ariel came up on the agent port 2324 without touching the payload already on 2323, and a second run of the payload was harmless: the telnet shell fails to bind and retries, while the agent port serves.

- `ftp-put` moved `/data/src a.bin` (48 bytes) to `/data/ftp-up/my file.bin` through the console's own ftpsrv, signed with the anchor key: `result /data/addon-ftp-put-13993681`, `status 0`.
- `ftp-get` brought it back to `/data/back a.bin`: the same SHA-256, `7ecc3e74…6cb2e2`, and `cmp` equal.
- `ftp-get /data/ariel/token /data/token-copy` answered `protected` with exit 87, asked nobody, and created nothing.

The remote operands were the console's own absolute paths, so the same run measures the root: ftpsrv served `/data/ftp-up/my file.bin` for that path, which makes the root `/` and not `/data`.

The console's state is not what it was: `/data/ariel` is now a fresh generation-0 directory anchored to `owner.key`, and the key-run state recorded after #48 is gone. The token is the one the payload printed at start, and a rebuild with another anchor would strand this directory.

## What other projects say

- **`jmelovich/ps5-gyroaim`**: a payload is not a registered pad client and cannot open the controller whether or not a title is running; the workaround is injecting into the game. This console agrees.
- **`erickdavestech/ps5-dualsense-overlay`**: attaches with `ptrace` to the foreground title and calls the same two pad exports. It works, with the cost described above.
- **`a-ddr/PoorDS4`**: injects into `SceShellUI` and creates a virtual device. Untested here; it produces synthetic input rather than reading the real pad.
