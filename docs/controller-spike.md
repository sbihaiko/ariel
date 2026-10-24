# Controller spike: reading the controller from a payload

## Why this exists

Ariel asks the owner to approve an action. The first version of that asked for the controller, and the open question in [#3](https://github.com/sbihaiko/ariel/issues/3) was whether a payload can read it while another app is in the foreground.

`controller-spike.elf` answers that question on a real console. It is a separate payload. It is not part of Ariel.

## The decision it settles

The first version of [ADR-0006](adr/0006-the-controller-is-the-approval-source.md) made the controller the approval source on a console. This spike was how that choice was validated on a real console.

The run showed that the payload cannot read the pad, and that borrowing the read from the foreground title freezes the game. The source changed behind the platform port, and ADR-0006 now names a signature by a key the owner holds. The result is recorded in [console-findings.md](console-findings.md) and, with the transcripts, in [controller-spike-notes.md](controller-spike-notes.md).

## What the payload does

- It builds as its own ELF, `controller-spike.elf`, next to `shsrv-ps5.elf`. It is never linked into `shsrv-ps5.elf`.
- It runs as a process started through the ELF loader, the same way Ariel runs.
- It opens the controller with `scePadOpen`, for the console's initial user (or the foreground user when there is no initial user).
- For 120 seconds it reads `scePadReadState` every 16 ms.
- It reports each button press and each error code in two places: as a console notification, and on TCP port 9150, which the operator reads with `nc`.
- A failed open is retried every 2 seconds.
- After 120 seconds it stops on its own, closes the pad handle and the sockets, and exits 0.

Every line below comes from the payload as written. Read the port as 9150 and the duration as 120 seconds everywhere.

## 1. Build it

Set the SDK as in the [quick start](quick-start.md#1-install-the-ps5-payload-sdk), then:

```console
$ make clean all
```

The build writes `controller-spike.elf` next to `shsrv-ps5.elf`. To build only the spike, run `make controller-spike.elf`. Do not run `make test`; it sends `shsrv-ps5.elf` to the console.

## 2. Send it to elfldr on port 9021

```console
$ export PS5_HOST=192.168.0.10
$ $PS5_PAYLOAD_SDK/bin/prospero-deploy -h $PS5_HOST -p 9021 controller-spike.elf
```

The console shows `controller spike: listening on port 9150 for 120 s, connect with nc`.

The deploy command keeps the connection open for the payload's lifetime, which is 120 seconds. Leave it running and use a second terminal for `nc`.

## 3. Connect with `nc`

Connect to port 9150 within those 120 seconds:

```console
$ nc $PS5_HOST 9150
```

The first line shows how much time is left. The lines after it are the transcript of everything since the payload started, so you do not miss the open result when you connect late. Keep `nc` open.

## 4. Put another app in the foreground

Connect `nc` first, then switch apps:

1. Press the PS button and open an app, for example a game or a media app. Wait until it is in the foreground.
2. Press a few buttons on the controller.
3. Return to the home screen and press a few more buttons.

Compare the lines you get in the home screen with the lines you get while the app is in the foreground. That comparison is the answer to #3.

## 5. Expected output

### When reading works

```console
$ nc $PS5_HOST 9150
controller spike: connected, 44 s elapsed, 76 s left
controller spike: listening on port 9150 for 120 s, connect with nc
controller spike: user 1 (initial)
controller spike: open ok user 1 handle 3
controller spike: press CROSS
controller spike: press OPTIONS CROSS
controller spike: stop after 120 s, presses 2, errors 0, controller released
```

When the payload stops, the last line arrives and `nc` exits on its own.

### When reading fails

```console
controller spike: connected, 30 s elapsed, 90 s left
controller spike: listening on port 9150 for 120 s, connect with nc
controller spike: user 1 (initial)
controller spike: open ok user 1 handle 3
controller spike: read error 0x80920007
controller spike: read ok
controller spike: press CROSS
controller spike: input intercepted by the system
controller spike: stop after 120 s, presses 1, errors 1, controller released
```

What each line tells you:

- `open error 0x...`: `scePadOpen` failed, so there is no pad handle. Turn the controller on and make sure a user is logged in. The payload retries every 2 seconds until its time is up.
- `user initial error 0x...` and `user foreground error 0x...`: no user ID was available, so the pad was never opened. Paste both codes into #3.
- `read error 0x...`: the pad is open, but `scePadReadState` failed. The payload prints a code once and prints `read ok` when reading recovers. Note whether this happens in the home screen, only after another app comes to the foreground, or only once the app takes focus.
- `input intercepted by the system`: the read succeeded, but the system set the interception bit (`0x80000000`) in the button state. The system has the controller, so presses do not reach the payload.
- If the pad never opens, the last line ends with `controller never opened` instead of `controller released`, and `presses` stays 0.
- Buttons with no name are printed as a hex code, for example `0x00200000` in `press OPTIONS CROSS 0x00200000`. After a read error the payload forgets the previous button state, so its first successful read reports every button that is held at that moment.

## 6. What to paste into #3

Paste the answers to all of these:

- The console's firmware version.
- How the controller is connected: USB or Bluetooth.
- The `user` line, for example `controller spike: user 1 (initial)`.
- Which app you put in the foreground, and whether the home screen or the app had focus when you pressed the buttons.
- The full `nc` transcript, from the greeting line to the `stop` line.
- The console notifications. They repeat the same lines.
- Whether presses were reported in the home screen and while the app was in the foreground.
- Whether `input intercepted by the system` appeared.
- Whether the payload stopped by itself: the `stop` line, and `nc` exiting.

## Notes

- The payload listens on every interface on port 9150 and has no authentication. Run it on a trusted network, and only while the spike runs.
- If port 9150 is already in use, the console shows `controller spike: cannot listen on port 9150` and the payload exits with status 1.
- A reboot of the console stops every payload.
