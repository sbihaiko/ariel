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

## Ruled out

- **Credentials alone.** The user service answers; the pad does not open.
- **Call order.** Initialising the user service before or after raising credentials changes nothing.
- **Authid.** `0x4801000000000013` and GhostControl's `0x3800000000010003` give the same pad result.
- **The registry sign-in flag.** Key `125874185`, plus `65536` per slot; all 16 slots read back empty.
- **`np-fake-signin`.** It wrote `auth.dat` (1200 bytes) into the home directory. The pad still refused.
- **User ids.** Inside the title, user id `1` is still `DEVICE_NO_HANDLE`; only the real account id resolves.
- **The shell.** `SceShellCore` on the home screen has no pad open, because nothing is in the foreground.
- **Untested, therefore not results.** Port type 3, pad indexes other than 0, the PoorDS4 context setters (`scePadSetLoginUserNumber`, `scePadSetUserNumber`, `scePadSetProcessFocus`) and `scePadVirtualDeviceAddDevice` were never run. A virtual device would create input, not read the owner's.

## What other projects say

- **`jmelovich/ps5-gyroaim`**: a payload is not a registered pad client and cannot open the controller whether or not a title is running; the workaround is injecting into the game. This console agrees.
- **`erickdavestech/ps5-dualsense-overlay`**: attaches with `ptrace` to the foreground title and calls the same two pad exports. It works, with the cost described above.
- **`a-ddr/PoorDS4`**: injects into `SceShellUI` and creates a virtual device. Untested here; it produces synthetic input rather than reading the real pad.
