# Controller spike: what the console actually does

Notes from running `controller-spike.elf` on a real console (shsrv 0.20, elfldr on port 9021, read back on port 9150). Each item below was observed on the console, not inferred. The runbook for the spike stays in [controller-spike.md](controller-spike.md).

**Status: the foreground title reads the pad. The payload process does not. No button edge was captured.**

## The question

Can a payload read the controller while another app is in the foreground? (Issue [#3](https://github.com/sbihaiko/ariel/issues/3), the approval source in [ADR-0006](adr/0006-the-controller-is-the-approval-source.md).)

**What is confirmed:** with a title in front, `scePadReadState` inside that title returns 0 and `connected` is 1. The same handle is rejected in the payload process. No button went down during the samples, so a live button edge is still missing.

## Where the work lives

All changes are in a run worktree:

```
worktrees/run/20261023-181518-99180-89b2ed/
  controller_spike.c      the payload
  pad.h                   pad, user service and RegMgr declarations
  pt.h                    added pt_call declaration
  Makefile                links pt.o and -lSceRegMgr
  docs/controller-spike-notes.md   this file
```

### Build

`llvm-config` must be on `PATH` and the SDK must be exported, otherwise the SDK's clang wrapper fails with `/llvm-clang: No such file or directory`:

```sh
export PATH="/opt/homebrew/opt/llvm/bin:$PATH"
export PS5_PAYLOAD_SDK="$HOME/.local/share/ps5-payload-sdk"
make controller-spike.elf
```

### Deploy

`socat` is not installed, so `prospero-deploy` fails. Send the ELF straight through `nc`:

```sh
nc 192.168.68.77 9021 < controller-spike.elf &
nc -G 5 192.168.68.77 9150    # read the transcript
```

The console was at `192.168.68.77` (elfldr on 9021, spike on 9150). The spike runs 30 seconds and leaves the port free afterwards. `nc -z ... 9150` tells you whether a run is still in progress. The 30 second clock is checked between probes. It does not interrupt a `pt_call` that is already single-stepping inside the title.

## What the console confirmed

### The account

| Source | Result |
| --- | --- |
| `sceUserServiceGetInitialUser` | `0x80940004`, no user id |
| `sceUserServiceGetForegroundUser` | `362804492` |
| `sceUserServiceGetLoginUserIdList` | `362804492` |
| `/system_data/priv/home/` | one directory, `159ff50c` |
| `sceUserServiceGetUserName(362804492)` | `bihaiko` |

`0x159ff50c` is `362804492`. One account, named bihaiko. The home directory is only readable after the credentials are raised.

### The error codes

- `0x809b0081` — `USER_NOT_LOGIN`. What `scePadOpen` returns for this account on port types 0 and 2.
- `0x80920008` — `DEVICE_NO_HANDLE`. What `scePadGetHandle` returns, in this process and inside `SceShellCore`, for every user id tried.
- `0x80920001` — `INVALID_ARG`. Port type 1 is not a port type.
- `0x80940004` — `SCE_LNC_UTIL_ERROR_NO_APP_INFO`, from `sceUserServiceGetInitialUser`.

### Credentials are necessary but not sufficient

A payload starts with the credentials of the ELF loader's parent and `sceUserService` refuses it until they are raised. The spike does what ProsperoMgr does in `EscalatePrivileges` (`source/backend/src/jailbreak.cpp`):

- `kernel_get_proc` first, to confirm kernel read/write works.
- uid, ruid, svuid, rgid, svgid to 0.
- root and jail directories to `kernel_get_root_vnode`.
- authid `0x4801000000000013` (GhostControl uses `0x3800000000010003`; both were tried, same result).
- all 16 capability bytes `0xff`, attribute byte 0 `0x80`.

This makes the user service answer. It does not make the pad open.

### Everything else ruled out

- **Port type.** 0 and 2 give `USER_NOT_LOGIN`; 1 is `INVALID_ARG`.
- **Authid and call order.** Initialising the user service before or after raising credentials, and either authid, change nothing.
- **The registry sign-in flag.** Key `125874185`, plus `65536` per slot. All 16 slots read back as nothing.
- **`np-fake-signin`.** It did run: it wrote `auth.dat`, 1200 bytes, into the bihaiko home directory. `scePadOpen` still returns `0x809b0081`, and the sign-in flag still reads back empty. The PSN sign-in state is not what the pad checks.
- **Borrowing a handle inside `SceShellCore`.** Attach works (pid 59). `kernel_dynlib_handle(pid, "libScePad.sprx", &h)` plus `kernel_dynlib_resolve` gives real addresses (`scePadGetHandle` at `0x829bd9560`, `scePadReadState` at `0x829bdaa80`). Calling it there with user ids `1`, `362804492` and `0x10000000` returns `DEVICE_NO_HANDLE` for all three. The shell has no pad open because nothing is in the foreground.

Note: `pt_resolve` cannot find these functions. It only looks at library handles `0x1` and `0x2001`, and `libScePad` is in neither. Use `kernel_dynlib_handle` by name.

## What the projects say

- **`jmelovich/ps5-gyroaim`**, `docs/CONSOLE_NOTES.md` (firmware 13.200.006): a payload is not a registered pad client, so it cannot open the controller whether or not a title is running. Their solution is to inject into the game, where the pad data already arrives.
- **`erickdavestech/ps5-dualsense-overlay`**, `probe/pad_rpc.c`: attaches with `ptrace` to the foreground title (or `SceShellCore`) and calls `scePadGetHandle` (`u1GRHp+oWoY`) / `scePadReadState` (`YndgXqQVV7c`) there.
- **`a-ddr/PoorDS4`** (the GhostControl payload), `payload/shellui_pad.c`: does not borrow a handle. Injects a stub into `SceShellUI` that calls `scePadSetLoginUserNumber(1)`, `scePadSetUserNumber(1)`, `scePadSetProcessFocus`, creates a virtual device with `scePadVirtualDeviceAddDevice`, then probes `scePadGetHandle` with user ids `1`, the real id and `0x10000000`, port type 3, indexes 0–7. It also needs `scePadSetProcessPrivilege(1)`.

## Next steps, in order

1. **See a button edge from the foreground title.** The title read already returns 0 with `connected` 1. What is missing is one sample where a face button is down, so the bits are known to track the pad. Hold Cross for the whole 30 seconds.
2. **If that fails, reproduce the PoorDS4 path**: the context setters (`scePadSetLoginUserNumber`, `scePadSetUserNumber`, `scePadSetProcessFocus`) before the handle probe, and port type 3 with indexes 0–7. The spike still only tries port types 0 and 2, index 0.
3. **Only then consider a virtual device.** That creates a controller rather than reading the real one, so it does not answer #3 — it is a different design.

## What this build does

Not a console result. The home-screen attempts (local `scePadOpen`, the registry sign-in flag, `np-fake-signin`, and `SceShellCore`) are no longer in the loop.

- A big app id at or below 0 means nothing is in front. The spike says so once and retries until the 30 seconds are up, so the title can come to the foreground during the run.
- It lists every `eboot.bin` with the app id `sceKernelGetAppInfo` writes and any title id string in that buffer. The title id offset is logged because the two SDK samples disagree on the struct layout.
- It attaches to the eboot whose app id equals the big app. If none equals it, it attaches to eboots whose title id is not `NPXS`.
- Inside that process it calls `scePadGetHandle` for user ids `1`, the foreground user and `0x10000000`, port types 0 and 2, index 0, then `scePadReadState`.
- It also tries `scePadReadState` in the payload with that handle. When the payload read works, later samples stay in the payload. When it does not, the spike attaches about once a second and reads inside the title. The title's handle is not closed.

## Caveat for whoever continues

Attaching stops the title for the duration of the call. `pt_call` single-steps the target function, and that call is not bounded by the 30 second window. Hold a button while the spike is running. `nc -z ... 9150` tells you whether a run is still in progress.

## Run with a title claimed in front

Sent `controller-spike.elf` (commit `f173589`, 120 second build) to `192.168.68.77:9021` after the operator said a game was in the foreground.

- The elfldr connection printed `[SceLncUtil] getAppStatus: LNC_ISOK::0x80940004` while the payload was starting. `0x80940004` is the same code the notes already have for "no app info".
- Port 9150 accepted a TCP connection. The payload wrote no line. The first probe inside the title had not returned.
- The operator rebooted the console from that state. A reboot ends the payload. Nothing was read from the pad.

## Run with PPSA99177 in front

Sent the 30 second build (commit `6099943`) to `192.168.68.77:9021`. The operator had a game in the foreground. The transcript:

```
running big app 0x00000018
eboot pid 109 app 0x00000018 title PPSA99177 off 16
eboot pid 66 app 0x0000000d title NPXS40039 off 16
user candidates 1 362804492 268435456
title pid 109 getHandle 8009f1560 readState 8009f2a80
title getHandle user 1 type 0 -> 0x80920008
title getHandle user 1 type 2 -> 0x80920008
title getHandle user 362804492 type 0 -> 0x03e50700
title readState -> 0x00000000 buttons 0x00000000 connected 1
payload init 0x00000000 readState 0x80920003 buttons 0x00000000 connected 0
stop after 30 s, presses 0, errors 0, title handle left open
```

- `sceSystemServiceGetAppIdOfRunningBigApp` returned `0x18`. That matched `eboot.bin` pid 109. The title id `PPSA99177` sits at offset 16 in the `sceKernelGetAppInfo` buffer, which is the layout with `app_type` before the title id.
- Another eboot, pid 66, is the system title `NPXS40039`. The probe did not attach to it.
- User id `1` still gets `DEVICE_NO_HANDLE` for port types 0 and 2. User id `362804492`, port type 0, returns handle `0x03e50700`.
- `scePadReadState` of that handle inside pid 109 returns 0. `connected` is 1. Buttons stayed 0 for the whole window, and the later samples reported no errors, so those reads also returned 0.
- In the payload process, `scePadInit` returns 0 and `scePadReadState` of the same handle returns `0x80920003`. The payload does not read the title's pad by borrowing the integer.
- The elfldr connection again printed `[SceLncUtil] getAppStatus: LNC_ISOK::0x80940004` while a big app was running. That line does not mean the foreground title is absent.

The worktree is `worktrees/run/20261023-181518-99180-89b2ed`, branch `squad/run/20261023-181518-99180-89b2ed`.
