# The four wipes: what we know and what we only suspect

A reference page for the owner's console: a CFI-2014 on firmware 11.20, jailbroken
through a tethered exploit, that lost its internal storage four times. Every entry
is marked as **measured**, **read in source**, **documented upstream** or
**community claim**, because the difference decided most of the argument below.

Written 2026-10-27. The console had been reset that evening, so the state described
here is the clean one.

## What happened

Four losses, in three different layers:

1. one during the autoloader — the entry step of the jailbreak;
2. two while opening games;
3. one while the Overdrive app was downloading.

A "loss" means the console fell to Safe Mode with only *Reset PS5 (reinstall system
software)* selectable. Reinstalling is what erases the internal drive; the console
did not necessarily erase it by itself.

Configuration at the time: tethered exploit (Relapse reached through the WebKit
autoloader), kstuff-lite, ShadowMountPlus, no etaHEN. Games were images (`.exfat`,
`.ffpfsc`, `.ffpkg`) under `/data/homebrew`, mounted by ShadowMountPlus. Overdrive
downloaded into `/data/ps5-react/<TITLE>/`.

## What the four events do not tell us

- **There are no logs.** No klog, no panic text, no Overdrive log, no timestamp.
  Four symptoms with zero evidence. Any causal claim made before this page was
  written was speculation dressed as diagnosis.
- Safe Mode with only option 8 proves the user filesystem would not mount. It does
  not prove which write, which patch or which device made it unmountable.
- Three different layers failing in one day is not one bug. It is a shared
  precondition — kernel-level failure followed by a hard power-off, with writes in
  flight on the internal filesystem.

## Measurements (measured on the console, 2026-10-27)

| Path | Sequential write | Sequential read |
| --- | --- | --- |
| Internal `/data` | 163 MB/s | — |
| USB pendrive (exFAT) | 39 MB/s | 87 MB/s |
| Mac → console over the LAN | 3 MB/s | 3 MB/s |

Measured with a purpose-built payload: 200 MiB per destination with `fsync`, and a
cold `O_DIRECT` read of a file nothing had touched. The first read attempt reported
780 MB/s because the page cache had the file; it was thrown away.

The practical reading: the pendrive is 13× faster than the network, so moving
downloads to it costs nothing during transfer. Its write speed only matters during
extraction, where a 30 GB game takes about 13 minutes instead of 3.

## Hypotheses

Ordered by how much of the four events each one explains, not by how plausible it
sounds.

### H1. Image mounting is the main risk (explains events 2 and 3)

ShadowMountPlus's own documentation warns that mounting images can cause shutdown
problems and data corruption on internal drives, more common on older firmware.
Community threads report images failing at launch (`CE-108255-1`, `SIGBUS`) on
consoles where FPKGs installed natively run, and `CE-108262-9` during play blamed on
background rescanning.

**Falsification:** install one game as a native FPKG and run the same game from an
image. Same console, same firmware, same title.

**Status:** not tested. The documented warning is evidence of risk, not proof of
causation for these four events.

### H2. The entry chain panics during teardown (explains event 1)

Read in source: the Y2JB autoloader terminates the host app itself
(`kill_youtube`, a `SIGKILL` after 5 seconds) and waits 1 second before handing
payloads to the elf loader, added in v1.0.0 "to allow elfldr to stabilize". The
WebKit autoloader does neither — it leaves the browser process holding the pages
the kernel exploit modified, and the owner closes it whenever.

**Falsification:** switch entries and compare only entry-stage failures.

**Status:** plausible, mechanism real, rate claimed by one forum user ("2 of 5
versus every time"). Not measured.

### H3. Native writes during a kernel-level fault cause the wipe (explains all four)

Every event happened with writes in flight on the internal filesystem: the entry
payloads being staged, the game data being registered, the download being written.

**Falsification:** reproduce with the same write load and no jailbreak at all. If it
still fails, the fault is hardware or firmware; if it does not, the jailbreak stack
is implicated.

**Status:** untested. This is the cheapest experiment and the one that decides
whether the rest of this page matters.

### H4. Hardware (explains all four, but only if nothing else does)

The console is new, which lowers the prior and does not establish anything. A
defective unit, its SSD controller or its power supply would produce exactly this
signature.

**Falsification:** the baseline in H3.

**Status:** not excluded. Dismissing it because the unit is new was an error made in
this investigation and then retracted.

### H5. Version pairing (explains events 2 and 3)

Community reports on 11.x and 12.x converge on kstuff-lite 1.08/1.09 with
ShadowMountPlus 1.6 beta 16 as the stable pair, and report 1.11 freezing at the
"Please Wait" screen.

**Falsification:** fix the pair, then change one component at a time.

**Status:** community claim without a denominator. Useful for reproducible
comparison, not as certification.

## What the source says

Read in the repositories themselves, not in forum posts.

### ShadowMountPlus

- `mount_read_only` defaults to 1, `force_mount` to 0. `stability_wait_seconds`
  defaults to 10, and the scan loop runs every 15 seconds — it decides by file age,
  not by whether a file is still growing. A download in progress on the same drive
  is therefore mountable.
- `manual.lst` exists: pointing `scanpath` at an empty directory disables automatic
  scanning, and only listed sources are mounted.

### Overdrive

- The download root is configurable (`downloadRoot`, `/data` or `/mnt/usbN`), set
  from the game's "Save to" row and remembered in `/download0/overdrive/settings.json`.
- `pkgMode` has three values: ask, background (the console's own downloader takes
  the URL and installs it), or download inside the app.
- `deletePackages` controls only whether the `.pkg` is removed after installation.
- A `.pkg` or `.fpkg` artifact is installed through the console's own installer
  (`packages.install`), never through the mounter. A folder or image artifact is
  moved to `<root>/homebrew/` for ShadowMountPlus and is never installed.
- **There is no way to download without installing.** `canInstall()` is always true
  on the console, and the queue installs as soon as the transfer ends. The only
  states that wait are the ones the console itself refused.
- In the streaming path the app writes no file, so `downloadRoot` does not apply to
  it: the two settings are alternatives, not additions.

### Overdrive catalog (measured over 34,491 releases)

| Format | Count | Streamable |
| --- | --- | --- |
| `binary` (probed) | 28,941 | yes, if the probe finds a PKG |
| `pkg` | 4,357 | yes |
| `exfat` / `ffpfsc` / `ffpkg` | 1,064 | no — image, needs the mounter |
| `rar` / `zip` / `7z` | 128 | no — archive |

The format filter admits about 96%. What decides the rest at runtime is the link:
`vikingfile` and `mediafire` resolve to a plain URL without headers and can stream;
`browser`, `datanodes` and `buzzheavier` require a captured browser session. The app
gives the console 30 seconds to take the link and falls back to downloading itself.

### Y2JB

Requires, on top of the exploit: a YouTube app `PPSA01650` at exactly v01.000.003
for firmware 4.03–12.40, a **fake-activated account** (`offact` plus
`np-fake-signin`, or an all-in-one activator that patches the registry and
ShellCore memory), `download0.dat` in `/user/download/PPSA01650/`, and DNS
`127.0.0.2` to block PSN. Its own documentation warns that the optional script
blocking YouTube updates edits the database, and that database corruption deletes
installed FPKGs and save data.

## Ruled out, and why

- **etaHEN on top.** It stacks a second set of kernel patches. Every stability
  report read here points the other way: fewer layers.
- **Y2JB for now.** It explains one of four events and asks for a Sony app package
  from scene sources plus a beta payload that patches registry and ShellCore — the
  layer that has been failing. Revisit only if the baseline shows entry-stage
  failures dominate.
- **Rebuilding the database as a routine fix.** On a jailbroken console it deletes
  internally installed FPKGs, and Slim and Pro owners report losing the optical
  drive pairing. It is a last resort with a database backup, not maintenance.
- **"The console is new, so it is not hardware."** Retracted. It is not evidence.

## The protocol

1. Copy anything irreplaceable off the console before touching the stack. Saves,
   configurations, and a database backup when games exist. The recovery PUP for
   11.20 is on the pendrive; a PUP is a reinstall, not a backup.
2. Record versions and hashes of every payload, free space, mounted images and the
   start time of each session. Define success before starting: a run counts only if
   the console survives the load the failed sessions carried — active writes on the
   internal drive, not idle use.
3. Baseline with no jailbreak, same load, fixed duration.
4. Add one variable at a time: entry, then kstuff, then ShadowMountPlus without
   mounting, then one mount.
5. Only then compare entries and pin versions.
6. Never leave rest mode enabled. Capture the error code Safe Mode shows, if any.

## Recovery ladder

| Level | Symptom | Cost | Recovery |
| --- | --- | --- | --- |
| 0 | app closes, console lives | none | relaunch |
| 1 | whole console hangs, power button dead | none | pull the cable, reboot, redo the jailbreak |
| 2 | Safe Mode with options 1–7 alive | installed FPKGs, if the database is rebuilt | clear cache first, then rebuild with a database backup |
| 3 | Safe Mode with only option 8 | the whole internal drive | reinstall 11.20 from the pendrive |
| 4 | option 8 fails | — | check the PUP path and the drive format; without the PUP, nothing |

## Open questions

- Did the two game-launch losses both happen with a mounted image, and was the same
  image mounted in both?
- Were the four events on the same pendrive, the same cable and the same outlet?
- What error code, if any, did Safe Mode display at each event?
- Does the console's own downloader resume an interrupted package, or does it start
  over?

## Fifth event (2026-10-28): the one the system survived

Written after the fact, from the console's own state.

A freeze during the WebKit autoloader sequence, at boot, with four payloads in
`autoload.txt`: kstuff-lite 1.09, ShadowMountPlus 1.6beta16 configured for manual
mounts only, ftpsrv and the agent. No image had been mounted and nothing was
running in the background; the boot had not finished. Power was cut.

**This one did not cost the internal drive.** On the next boot the console
reported a damaged system, repaired itself, kept `/data` (agent state, ShadowMount
config) and the account, and removed the broken package install that had been left
in `/user/app`. It reached the home screen. Previous events offered Safe Mode with
option 8 only; this one did not.

The same boot sequence with the same pendrive and the same kstuff, **without
ShadowMountPlus in `autoload.txt`**, completed with no hang. ShadowMountPlus was
then loaded by hand, on a running system, and started cleanly: it found nothing to
mount, registered no title and stayed idle.

That was read as a suspect for half an hour, and it was wrong. A screenshot of the
frozen screen shows the autoloader stopped at **stage 2 of 3** -- the Relapse kernel
exploit itself, after it printed the kernel base -- before `/mnt/usb0` was read and
before any payload in `autoload.txt` was started. ShadowMountPlus never ran in those
boots.

Three consecutive hangs at that stage with different kernel bases
(`0xffffffe01f0000`, `0xffffffff87080000`) mean the exploit executes and fails inside
itself, not that a payload is incompatible. The community documentation says the same:
Relapse "may hang or panic the console, so reboot before trying again".

Two of those hangs ended in a self-repair on the next boot, with `/data` and the
account intact -- including one where the repair ran without any prompt. This is the
first evidence that a hang is not itself what destroys the drive. The four earlier
events may have shared a different, additional cause.

### What this rules out for the Overdrive conversion

Converting the app to a native package does not work here, and the reason is not
in our build:

- the package installs and appears on the home screen, but the launcher refuses to
  start it (`getAppStatus` 0x80940004, `launchApp` 0x80020060). Two builds were
  tried, one with `sdkVersion` 0.00 and one with 2.00, with identical results;
- upstream ships Overdrive only as `.exfat`, and Orbit Store as `.elf` plus
  `.ffpkg`. Neither has ever been distributed as a `.pkg`. Big homebrew apps on
  this platform run from a mounted image; the package installer is the games path.

So the mounter is not a detail of one app. It is how homebrew is delivered, and
removing it means giving up the apps.

### Manual mounting, as built

`config.ini` gets `scanpath=/data/shadowmount/noauto` (an empty directory) and the
`manual.lst` watcher is used instead. Mounts then happen only for the paths
written in the list.

One trap, read in the binary and confirmed on the console: ShadowMountPlus watches
`manual.lst` with `kqueue`. Writing the file over FTP replaces the inode, so the
watcher keeps waiting on the old one and nothing mounts. A path added over FTP is
only picked up when the payload starts, not while it runs.

## First measurement after the change (2026-10-28)

Overdrive's download root was moved from `/data` to `/mnt/usb0`, and one PKG was
downloaded and installed end to end: Undertale (`CUSA09415`), 151.9 MB.

| Check | Result |
| --- | --- |
| Where the file was written | `/mnt/usb0/downloads/packages/` |
| `/data/ps5-react/PPSA99058` during the transfer | `app.log` grew 116 KB to 128 KB; cache and queue only |
| Install | native, `/user/app/CUSA09415/app.pkg` plus `/user/appmeta/CUSA09415` |
| Package after install | deleted by the app |

Two things this establishes:

1. A 150 MB download no longer touches `/data`. That was the exact shape of the
   fourth loss -- the only one of the four whose scene was a download -- and the
   write now lands on the pendrive, which is 13x faster than the network anyway.
2. **A game fPKG installs natively and registers on this console.** So the failure
   of the Overdrive package was not the install path being broken; it was that
   Overdrive is shipped as an image, not as a package.

Not established: whether the installed title launches. That is deliberately left
for a session of its own -- it is scenario S5, and launching a PS4 title is the
class of action that produced two of the four losses.

## S5, first run: a native package played and saved (2026-10-28)

The one experiment the whole page was waiting for, run by accident of ordering and
then deliberately finished.

Undertale (`CUSA09415`, PS4 title, 151.9 MB) was downloaded by Overdrive to the
pendrive, installed by the console's own installer, then launched:

| Check | Result |
| --- | --- |
| Process | `eboot.bin` under `CUSA09415`, pid 762 |
| Played | a few minutes, save written |
| Save on disk | `/user/home/10993c58/savedata/CUSA09415/Undertale.bin` |
| Exit | clean, no leftover process |
| `/data` during play | unchanged |
| ShadowMountPlus | loaded the whole time, holding the Overdrive image |

This is the configuration the four losses never had: a title that writes during play,
with no game loaded through the mounter. It did not hang.

What it does **not** prove: it is one title, one session, on a console that also had
ShadowMountPlus loaded. It does not falsify H1 on its own -- that needs the same
title run from an image (S4), which is the next comparison.

## The reproduction (2026-10-28, 23:30)

Child of Light was downloaded as a PKG to a second USB drive, installed natively by
the console's installer (2.28 GB in `/user/app/CUSA00339`), and launched under
conditions chosen to remove every other suspect:

- the download finished before the launch; nothing was writing to `/data`;
- `/data` had 931 GB free;
- exactly one image was mounted (Overdrive itself), as it was at the time of the
  original losses;
- no other title was running.

**The console hung on launch, again.**

That settles what the four losses were not. It was not the mounter, not a download in
flight, not free space, not the drive, and not the way the package was obtained. The
same title, installed the way the console wants, with nothing else happening, still
took the machine down.

What remains is the title itself as it runs on this firmware -- a PS4 binary under
kstuff on 11.20 -- or something both this title and the other two freezers share and
Undertale does not.

The immediate comparison already exists: Undertale, also PS4, also a PKG, also
installed, played and saved without a problem an hour earlier on the same console.
So "PS4 title" alone is not the answer either; something narrower separates them.

Next experiment, in order of cost:

1. Read the kernel log during the launch of a *working* PS4 title and of a hanging
   one, with klog already running, and diff them. This is the only measurement that
   has not been tried, and the only one that can name a mechanism.
2. Run the same title with ShadowMountPlus stopped entirely, so the kstuff pause and
   the fakelib overlay it manages are out of the picture.
3. Run the same title with the console offline, so nothing from PSN or the store is
   reachable at launch.

## The controlled sequence (2026-10-28/29, 00:30 to 01:25)

Four experiments in one night, each removing one suspect. Two titles, both known
freezers, both installed from a complete package on a USB drive.

### Catherine, complete package, nothing else running

Downloaded to the second USB drive: 12,516.8 MiB (13,124,829,184 bytes), `.complete`
marker written, 64/64 connections, `failed=0`, ~45 minutes. Installed natively into
`/user/app/CUSA14836`, `app.pkg` 12,516.8 MiB, appmeta populated, fake licence
`/user/license/fakeUP2611-CUSA14836_00.rif` present.

First launch, disk idle, Overdrive open but not downloading: **hung**. The kernel log
stops at

```
[AppDb][AppInfoClient] Initialize()[305]: Initialize() pid:0x15e
```

after `[PSM] PsmFramework::Initailize() 94 msec. elapsed`. No error, no panic, no
watchdog line. The network dies with the console: 100% ping loss, every TCP port gone.

### What the hang leaves behind

Power cut, boot, "Reparando..." completes, system returns. The next launch is refused:

```
[ScePatchChecker] check (CUSA14836): return 0x8041013d
[NPDRM] del UP2611-CUSA14836_00-CATHERINEFBUS009
mountApp0Dir:        LNC_ISOK::0x80a4000c
initializeApp0Dir:   LNC_ISOK::0x80a4000c
launchApp:           LNC_ISOK::0x80a4000c
LaunchFlowError.CUSA14836 -> "cannot start / delete the application"
```

This corrects the earlier reading of the same chain on Child of Light. `0x80a4000c`
is **the aftermath of the hang**, not evidence of a truncated package: the hang
damages the registration, NPDRM deletes the entitlement, and every later launch fails
to mount app0. The package on the drive was complete and its size matched the
installed copy byte for byte.

`0x8041013d` is not a launch fault either. It appears all over this console --
`PFAuthClient`, `ScePs4AppCategory`, `SceRnpsAppMgr`, `ScePatchChecker` -- whenever
something asks the network. It is the offline error, noise in every log that follows a
launch.

### ShadowMountPlus stopped

The mounter was shut down cleanly with `/data/shadowmount/STOP`: process gone,
`/mnt/shadowmnt` empty, the Overdrive image unmounted, kstuff and ftpsrv untouched.
Catherine was reinstalled from the same package (licence recreated), Overdrive closed,
and the disk confirmed idle by two `/user` samples 45 seconds apart (17.8 G used,
845.7 G free, identical).

Launch: **hung again**, at the same `AppInfoClient Initialize()` line.

The mounter is not the cause, and neither is an image being mounted at launch.

### Heavy writes in flight

Last night's hypothesis: the hang needs writes in flight. Overdrive was set to
download to the internal drive (`/data/downloads/packages`), measured at `recv
10,150 KB/s`, `disk 10,196 KB/s`, `conns=16/16`, `write_max 9 ms`. With that running,
Catherine was launched.

It was **refused, not hung**: first `checkExistingApp: 0x80940010`, then
`mountApp0Dir: 0x80a4000c`, clean `LaunchFlowError`, console alive. Catherine cannot
mount app0 even immediately after a fresh install with the licence in place.

Child of Light was then launched under the same load, and it **ran**:

```
<111> EXEC /app0/childoflight.elf [user], vm#1, dmem#1 abi=ps4 category=ps4_game <717789 msec>
[KERNEL] INFO: pid 111
[KERNEL] INFO: SDK vesion: PS4:01600051
[KERNEL] INFO: Total Memory Size: 0x1e0600000 / DMEM 0x120000000 / FMEM 0x1c000000
### GFX(pipe0) Game. proc gen:0 gpu gen:0 ub:0 vmid:1 pid:111
```

The game process was created, given memory and a GPU pipe. Seconds later the console
**powered itself off**. Booted back into "Reparando...", then normal, with the account
and saves intact.

### What this settles, and what it corrects

- ShadowMountPlus is innocent. Two hangs, one of them with the payload not loaded.
- A download in flight is not required for the hang, and does not produce one by
  itself: the hang happens with the disk idle.
- `0x80a4000c` and `0x8041013d` are aftermath and noise, not cause.
- "Child of Light never opened" was wrong. It opens, executes as pid 111, and the
  console dies afterwards.
- Catherine and Child of Light are not the same failure. Child of Light mounts app0
  and executes; Catherine never mounts app0 at all, and is refused even on a clean
  install.
- Undertale (152 MB) remains the only title that plays and saves.

### The next three measurements

1. Bracket the size. A PS4 PKG of 200 MB to 1 GB, installed and launched the same way,
   between Undertale's 152 MB (works) and Child of Light's 2.28 GB (executes, then
   kills the console). If the boundary is size, the rule becomes practical.
2. Verify the Catherine package offline with the UltraPack tooling
   (`ffpfsc-pkg-tool`, `cli.py --fpkg-inner`) against its declared PFS image size, so
   "cannot mount app0" has a cause that is not guesswork.
3. Diff the kernel log of a working launch (Undertale) against this hanging one
   (`AppInfoClient Initialize()` last line). Still the only measurement that can name
   a mechanism.

## Sixth event (2026-10-28): a power-off during a bulk local copy

The first event with a plain file copy as the load, and the first one whose cause is
not a title launch.

**What was running.** A local copy inside the console, `cp` of one Switch `.nsp` at a
time from the pendrive (`/mnt/usb1`) to the internal drive (`/data/prosperoeden/roms`),
started from the telnet shell. In parallel, an Overdrive download of `CUSA04730` that
had already stopped on its own (`attempt 6 failed: Could not connect to server; HTTP 0`,
`retries=6`, 0 KB/s) with an 8.46 GiB `.part` on disk. Earlier in the same session,
`ProsperoMgr.elf` had been loaded through `hbldr` and was running (TitleId
`FAKE00000`, listening on 7070).

**The load.** One 2.87 GiB `.nsp` had copied and verified byte for byte; the next
(2.90 GiB) was at 0.54 GiB when the console powered off. Throughput was about 7.5 MB/s,
so the copy was a long, steady stream of writes — not a burst.

**What followed.** The console came back with the network up and the payloads loaded,
and the screen showed a black frame naming `FAKE00000`. Closing that window returned
the interface. Nothing was lost: `/data` intact, the pendrive intact, the one finished
`.nsp` complete, the partial one incomplete, and no Safe Mode and no "Reparando".

**What it adds.** Three candidates, and the measurement does not separate them:

1. **The bulk copy.** Fifth appearance of writes in flight with a loss, and the first
   one where no title was launching. It strengthens hypothesis A (a crash landing in a
   metadata-write window) without proving it.
2. **ProsperoMgr.** It was the only new process, it holds a fake title id, and it was
   the only thing on the screen when the console died. A homebrew that takes the
   display is now a candidate no earlier event covered.
3. **The stalled download.** Its HTTP layer had been retrying against an unreachable
   server for minutes, which is the one state no earlier loss had either.

**What was not lost.** No wipe, no Safe Mode, no reinstall. The difference from the
first four events is worth stating: the load was heavy, the console died, and the
data survived.

**The next measurement this event asks for.** Repeat the copy with the download
stopped and ProsperoMgr not loaded. If it survives, candidate 1 takes the weight. If
it dies again, the copy alone is enough and the console cannot be used for bulk
transfers without a defined procedure.

## Seventh event (2026-10-28): a power-off while the agent's process was being swapped

The first event whose load this repository wrote itself, and the first one with no
download, no copy and no title in it.

**What was running.** The ariel agent (pid 158) on 2324 with the build that pinned no
anchor, `shsrv` on 2323, `ftpsrv` on 2121, kstuff-lite. The console was idle.

**The load.** An anchored build of the same agent was being put in place. The old
process was killed to free 2324, and the new ELF was sent to `hbldr`. The console
powered off between the kill and the load.

**What followed.** The console came back by the same path the earlier events took: the
network up, `shsrv` and `ftpsrv` loaded from `autoload.txt`, and the agent absent,
because `autoload.txt` still named the old `ariel.elf` and the new build had been sent
under a different name. Nothing was lost.

**What it adds.** A fourth candidate for the same symptom, and the one that proves the
guardrail is behavioural rather than technical:

1. **A process killed while it owns a listening socket.** 2324 was bound, the process
   was signalled, and the console died. No earlier event had a process killed by us.
2. **The gap between the kill and the replacement.** For some seconds the console had
   no agent at all, which is the one state the payload stack had not been in.

Neither is separated from the other by this measurement, and neither is separated from
the three candidates the sixth event left open.

**What changed because of it.** The swap is never done to a running process again. The
new ELF takes the name `autoload.txt` already points at, and the replacement happens on
the next boot, where the old process is not interrupted mid-life. That procedure is the
guard: nothing in the shell knows how to refuse a kill on a listening port.

**The next measurement this event asks for.** Two independent gaps, and this event adds
a third that is ours to close: the swap-by-reboot above is the only one that needs no
measurement, because it removes the load instead of explaining it.
