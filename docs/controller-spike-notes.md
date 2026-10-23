# Controller spike: what the console actually does

Notes from running `controller-spike.elf` on a real console (shsrv 0.20, elfldr on port 9021, read back on port 9150). Each item below was observed on the console, not inferred. The runbook for the spike stays in [controller-spike.md](controller-spike.md).

**Status: the pad has never opened. The question the spike exists to answer is still unanswered.**

## The question

Can a payload read the controller while another app is in the foreground? (Issue [#3](https://github.com/sbihaiko/ariel/issues/3), the approval source in [ADR-0006](adr/0006-the-controller-is-the-approval-source.md).)

**Important gap:** every run so far happened on the home screen with nothing in the foreground. The one condition that matters — a title in front — has not been tested.

## Where the work lives

All changes are in a run worktree, uncommitted:

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

The console was at `192.168.68.77` (elfldr on 9021, spike on 9150). The spike runs 120 seconds and leaves the port free afterwards. `nc -z ... 9150` tells you whether a run is still in progress.

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

1. **Run with a title in the foreground.** This is the actual question, and it has not been tried. Open a game or media app, then run the spike, then attach to the title (`eboot.bin`, found through `sceKernelGetAppInfo`) instead of `SceShellCore`, and call `scePadGetHandle` / `scePadReadState` there. The title is a registered pad client, so it should hold a handle.
2. **If that fails, reproduce the PoorDS4 path**: the context setters (`scePadSetLoginUserNumber`, `scePadSetUserNumber`, `scePadSetProcessFocus`) before the handle probe, and port type 3 with indexes 0–7. The spike currently only tries port types 0–2 and index 0.
3. **Only then consider a virtual device.** That creates a controller rather than reading the real one, so it does not answer #3 — it is a different design.

## Caveat for whoever continues

The spike's current `pad_attempt` tries the login list, then the foreground user, then `pad_from_shell`. All of that runs on the home screen in one pass. The attach/detach around `SceShellCore` is slow (the loop prints several attempts per second), so keep `SPIKE_SECONDS` in mind when reading the transcript.

Nothing here was committed. The worktree is `worktrees/run/20261023-181518-99180-89b2ed`, branch `squad/run/20261023-181518-99180-89b2ed`.
