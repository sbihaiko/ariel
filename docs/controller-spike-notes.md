# Controller spike: what the console actually does

Notes from running `controller-spike.elf` on a real console (shsrv 0.20, elfldr on port 9021, read back on port 9150). Each item below was observed on the console, not inferred. The runbook for how to operate the spike stays in [controller-spike.md](controller-spike.md).

**Answer: the foreground title can read the pad. The payload process cannot.**

Issue [#3](https://github.com/sbihaiko/ariel/issues/3), the approval source in [ADR-0006](adr/0006-the-controller-is-the-approval-source.md).

With `PPSA99177` in front, `scePadReadState` inside that title's `eboot.bin` returns 0, `connected` is 1, and a held Cross (the X button) shows up as `0x00004000`. The same handle, read with `scePadReadState` in the payload, returns `0x80920003`.

## The working path

1. Raise credentials, or `sceUserService` refuses the payload.
2. `sceSystemServiceGetAppIdOfRunningBigApp` returns the foreground app id. It was `0x18` for this title.
3. Walk the process list for `eboot.bin`. `sceKernelGetAppInfo` on pid 109 wrote app id `0x18` and title id `PPSA99177`. The same walk also saw pid 66, app id `0x0d`, title `NPXS40039`. The probe attached only to the pid whose app id matched.
4. Resolve `libScePad.sprx` in that pid with `kernel_dynlib_handle` by name, then `kernel_dynlib_resolve`. In pid 109 the addresses were `scePadGetHandle` at `0x8009f1560` and `scePadReadState` at `0x8009f2a80`.
5. Attach and call `scePadGetHandle`. User id `1` returns `0x80920008` (`DEVICE_NO_HANDLE`) for port types 0 and 2. User id `362804492`, port type 0, index 0, returns handle `0x03e50700`.
6. Call `scePadReadState` on that handle inside the same attached process. One sample with no button held returned `buttons 0x00000000`, `connected 1`. One sample with Cross held returned `buttons 0x00004000`, `connected 1`, and the spike reported `press CROSS`. Both calls returned 0.

`0x00004000` is `PAD_BUTTON_CROSS`. The button bits track the pad.

The title id string sits at offset 16 in the `sceKernelGetAppInfo` buffer. That is the layout with `app_type` before the title id. Both `PPSA99177` and `NPXS40039` were found there.

`pt_resolve` does not find these pad exports. It only looks at library handles `0x1` and `0x2001`, and `libScePad` is in neither.

## What the payload process cannot do

`scePadInit` in the payload returns 0. `scePadReadState` of handle `0x03e50700` in the payload returns `0x80920003`. The handle is valid only inside the title that owns it. Copying the integer across is not a read.

`scePadOpen` in the payload returns `0x809b0081` (`USER_NOT_LOGIN`) for this account on port types 0 and 2. Port type 1 returns `0x80920001` (`INVALID_ARG`).

On the home screen, with nothing in front, `scePadGetHandle` inside `SceShellCore` (pid 59) returns `DEVICE_NO_HANDLE` for user ids `1`, `362804492` and `0x10000000`. The shell's `libScePad` resolved at `0x829bd9560` and `0x829bdaa80`. Attach to the shell works. The shell has no pad open.

## Ruled out

These were tried on the home screen. None of them opened the pad.

- **Credentials alone.** Raising them makes the user service answer. It does not make `scePadOpen` succeed. The spike follows ProsperoMgr `EscalatePrivileges`: `kernel_get_proc`, uid/ruid/svuid/rgid/svgid 0, root and jail vnodes, authid `0x4801000000000013`, 16 capability bytes `0xff`, attribute byte 0 `0x80`. GhostControl's authid `0x3800000000010003` was tried as well. Same pad result.
- **Call order.** Initialising the user service before or after raising credentials changes nothing.
- **The registry sign-in flag.** Key `125874185`, plus `65536` per slot. All 16 slots read back empty.
- **`np-fake-signin`.** It wrote `auth.dat`, 1200 bytes, into the bihaiko home directory. `scePadOpen` still returns `0x809b0081`. The sign-in flag still reads empty. The PSN sign-in state is not what the pad checks.
- **User id `1` and `0x10000000`.** Inside the title, user id `1` is still `DEVICE_NO_HANDLE`. `0x10000000` was not reached on the successful probe because user id `362804492` already returned a handle.

Port type 3, pad indexes other than 0, the PoorDS4 context setters, and `scePadVirtualDeviceAddDevice` were not run. The title already holds a real handle, so those paths were left alone.

## The account

| Source | Result |
| --- | --- |
| `sceUserServiceGetInitialUser` | `0x80940004`, no user id |
| `sceUserServiceGetForegroundUser` | `362804492` |
| `sceUserServiceGetLoginUserIdList` | `362804492` |
| `/system_data/priv/home/` | one directory, `159ff50c` |
| `sceUserServiceGetUserName(362804492)` | `bihaiko` |

`0x159ff50c` is `362804492`. One account. The home directory is readable only after credentials are raised.

A payload starts with the ELF loader's parent credentials. `sceUserService` refuses it until they are raised.

## Error codes

- `0x809b0081` — `USER_NOT_LOGIN`. `scePadOpen` in the payload, port types 0 and 2.
- `0x80920008` — `DEVICE_NO_HANDLE`. `scePadGetHandle` in the payload, in `SceShellCore`, and in the title for user id `1`.
- `0x80920003` — the payload's `scePadReadState` of a handle that is valid inside the title.
- `0x80920001` — `INVALID_ARG`. Port type 1.
- `0x80940004` — `SCE_LNC_UTIL_ERROR_NO_APP_INFO`, from `sceUserServiceGetInitialUser`.

The elfldr connection also prints `[SceLncUtil] getAppStatus: LNC_ISOK::0x80940004` while a payload is starting. It printed that line on the run where the big app id was `0x18`. The line does not mean the foreground title is absent.

## Attaching again can fail to return

`pt_call` single-steps the target. The 30 second deadline is checked between probes. It does not interrupt a call that is already inside the title.

One run read the title about once a second with no button held, reported no errors, and printed `stop after 30 s, presses 0`. The Cross run got one good sample (`press CROSS`) and the next in-title read never returned. Port 9150 stayed open and the transcript stopped growing. The operator has had to reboot out of a stuck probe. A reboot ends the payload.

The first send of the 120 second build, before any of the successful reads, also produced no transcript. Port 9150 accepted a connection and the payload wrote nothing. That boot was rebooted. The same probe returned on the next boot.

## Build and deploy

Worktree `worktrees/run/20261023-181518-99180-89b2ed`, branch `squad/run/20261023-181518-99180-89b2ed`. The payload is `controller_spike.c`. The Makefile links `pt.o`, `-lScePad`, `-lSceUserService`, `-lSceSystemService` and `-lSceRegMgr`.

```sh
export PATH="/opt/homebrew/opt/llvm/bin:$PATH"
export PS5_PAYLOAD_SDK="$HOME/.local/share/ps5-payload-sdk"
make controller-spike.elf
```

`llvm-config` has to be on `PATH`. Without it the SDK clang wrapper fails with `/llvm-clang: No such file or directory`.

`socat` is not installed, so `prospero-deploy` fails. The console in these runs was `192.168.68.77`.

```sh
nc 192.168.68.77 9021 < controller-spike.elf &
nc -G 5 192.168.68.77 9150
```

The current build runs 30 seconds and then closes port 9150, unless a `pt_call` is still inside the title. `nc -z ... 9150` tells you whether a run is still in progress. If the IP changes, scan the subnet for port 9021.

The current loop does not repeat the ruled-out home-screen attempts. It waits for a big app, attaches to the matching `eboot.bin`, probes `scePadGetHandle` for user ids `1`, the foreground user and `0x10000000` on port types 0 and 2, reads once inside the title, tries the same handle in the payload, and, when that fails, attaches about once a second for another read. It does not close the title's handle.

## What other projects do

Recorded here so the next change does not rediscover them. These are other people's notes, not results from this console, except where this console has since agreed.

- **`jmelovich/ps5-gyroaim`**, `docs/CONSOLE_NOTES.md` (firmware 13.200.006): a payload is not a registered pad client, so it cannot open the controller whether or not a title is running. Their solution is to inject into the game, where the pad data already arrives. This console agrees that the payload cannot open or borrow the pad, and that the title can read it.
- **`erickdavestech/ps5-dualsense-overlay`**, `probe/pad_rpc.c`: attaches to the foreground title and calls `scePadGetHandle` (`u1GRHp+oWoY`) and `scePadReadState` (`YndgXqQVV7c`) there. Those name ids are the ones this spike resolved.
- **`a-ddr/PoorDS4`** (GhostControl), `payload/shellui_pad.c`: injects into `SceShellUI`, calls `scePadSetLoginUserNumber(1)`, `scePadSetUserNumber(1)`, `scePadSetProcessFocus`, creates a virtual device with `scePadVirtualDeviceAddDevice`, then probes `scePadGetHandle` with user ids `1`, the real id and `0x10000000`, port type 3, indexes 0–7. It also needs `scePadSetProcessPrivilege(1)`. Not run here.
