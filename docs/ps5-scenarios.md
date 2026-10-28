# Execution scenarios: what to run, and what counts as stable

A test matrix for the console described in [ps5-data-loss.md](ps5-data-loss.md). The
goal is to turn four unexplained losses into a record: one configuration at a time,
one defined load, one defined duration, and an outcome written down before the next
scenario starts.

Written 2026-10-28. Nothing here has been run yet.

## Rules that apply to every scenario

1. **One variable per scenario.** The only difference between two consecutive
   scenarios is the line named in *Changes*.
2. **A defined load, not idle use.** Every loss so far happened with writes in flight.
   A scenario that idles for a day proves nothing. The load is: write at least 20 GB
   to the internal drive, or run the scenario's own workload, whichever the row
   specifies.
3. **A defined duration**, in the table. A scenario that passes for less than its
   duration is *incomplete*, not passed.
4. **Record before, during and after.** The recording sheet is at the end. Without
   it the next loss is worth as much as the previous four.
5. **Two failures end a scenario.** A second hard hang in the same configuration is
   not noise; stop, record, and move to the recovery ladder instead of retrying.
6. **Never launch a scenario with rest mode enabled.** Full shutdown, then boot.
7. **Capture what Safe Mode shows**, including any error code, before touching
   anything. That text is the only log the console gives without tools.

## Baseline inventory (2026-10-28)

Recorded so a later run can prove it used the same files.

| Component | Version | sha256 (first 16) |
| --- | --- | --- |
| Exploit entry | WebKit Autoloader installer v0.7.1, app `PINK00001` | `48a1e68959d00b98` |
| kstuff | kstuff-lite 1.09 | `ec5212794dc6e44e` |
| Mounter | ShadowMountPlus 1.6beta16 | `a35246fb3bb6042b` |
| Transfer | ftpsrv v0.21.1 | `7d4b31c83eae4e05` |
| Agent | ariel `ariel-ps5.elf` | built from `dev` at `32159d4` |

`/mnt/usb0/ps5_autoloader/autoload.txt` loads, in order: `kstuff.elf`, wait 2 s,
`shadowmountplus.elf`, wait 1 s, `ftpsrv.elf`, `ariel.elf`.

Open branch at the time of writing: whether ShadowMountPlus stays for Overdrive only
or Overdrive is converted to a folder app in `/data/homebrew`. Scenarios S3 and S6
depend on the answer.

## Scenarios

### S0 — stock, heavy writes

**Changes:** none. No jailbreak, no payloads, network blocked from PSN.
**DNS:** primary `62.210.39.117` (secondary `62.210.38.117`), set in the console's network settings before the boot.
**Load:** copy 20 GB from the pendrive to the internal drive and back.
**Duration:** 48 hours of normal use after the copy.
**Pass:** no hang, no Safe Mode, no lost files.
**Why it matters:** if this fails, the fault is hardware or firmware and every
scenario below is decoration.

### S1 — entry only

**Changes:** jailbreak through the WebKit Autoloader app; nothing else loaded.
**Load:** repeat the S0 copy under the jailbreak.
**Duration:** 24 hours.
**Pass:** as S0.
**Why it matters:** isolates the entry chain from every payload.

### S2 — entry and kstuff

**Changes:** add kstuff-lite 1.09.
**Load:** S0 copy, plus opening and closing three system apps.
**Duration:** 24 hours.
**Pass:** as S0.

### S3 — kstuff and the mounter, nothing mounted

**Changes:** add ShadowMountPlus with `scanpath` pointing at an empty directory, so
nothing is mounted automatically.
**Load:** S0 copy, with SMP scanning in the background.
**Duration:** 24 hours.
**Pass:** as S0, and no new entry in `/mnt/shadowmnt`.
**Why it matters:** separates "the payload running" from "an image mounted".

### S4 — one image mounted and played

**Changes:** point `scanpath` at the pendrive's `homebrew` folder, mount one game
image, launch it, play 30 minutes.
**Load:** the game's own writes plus the S0 copy in parallel.
**Duration:** 24 hours including three launches.
**Pass:** as S0.
**Why it matters:** this is the configuration of two of the four losses.

### S5 — the same game as a native FPKG

**Changes:** install the same title as FPKG instead of mounting the image; SMP may
stay loaded but must not mount it.
**Load:** as S4.
**Duration:** 24 hours including three launches.
**Pass:** as S0.
**Why it matters:** the only comparison that tests the community claim directly.

### S6 — Overdrive streaming

**Changes:** Overdrive with `pkgMode` set to the console's own downloader; app
closed during the transfer.
**Load:** download and install one game of at least 20 GB.
**Duration:** the download plus one launch.
**Pass:** the game installs and launches; no hang.
**Note:** keeps no copy of the package.

### S7 — Overdrive downloading into the app, to the pendrive

**Changes:** `pkgMode` set to download inside the app, `downloadRoot` set to
`/mnt/usb0`, `keepPackages` on.
**Load:** the same game as S6.
**Duration:** the download plus one launch.
**Pass:** as S6, and the `.pkg` is still on the pendrive afterwards.

### S8 — the other entry chain

**Changes:** Y2JB through the YouTube app instead of the WebKit Autoloader.
**Prerequisites not yet met:** YouTube `PPSA01650` v01.000.003, a fake-activated
account, `download0.dat` in `/user/download/PPSA01650/`.
**Duration:** 24 hours.
**Pass:** as S1.
**Why it matters:** it can only explain an entry-stage failure, so it runs after the
baseline says entry-stage failures are the problem.

## Recording sheet

One block per session. Copy it into the table below.

| # | Date | Scenario | Versions changed | Free space before | Mounts at start | Load | Duration | Outcome | Error code | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | | | | | | | | | | |

## Outcomes

- **pass** — the scenario completed its load and duration with no hang.
- **hang** — the console stopped responding; power had to be cut.
- **crash** — the app or title died and the console lived.
- **wipe** — Safe Mode with only the reinstall option.
- **incomplete** — stopped early for any other reason.

## After a failure

Follow the recovery ladder in [ps5-data-loss.md](ps5-data-loss.md). Do not resume
the failed scenario before writing down: the scenario number, the versions, the
free space before it started, what was mounted, the approximate time of the hang,
and the exact text Safe Mode displayed.
