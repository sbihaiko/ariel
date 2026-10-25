# Network spike: the interface list, the socket tables and one echo

## Why this exists

The network stage ([#111](https://github.com/sbihaiko/ariel/issues/111)) can add `ifconfig`, `netstat` and `ping` only if a payload can read each of those facts on firmware 11.20. Nobody has measured them on this firmware.

`network-spike.elf` answers that, one fact at a time, on the owner's console. It is a separate payload. It is never linked into `ariel-ps5.elf`, and it is run with the owner present.

The outcome of each probe is recorded in [console-findings.md](console-findings.md#network-spike-the-three-probes-on-firmware-1120).

## What the payload does

It runs three probes in order, from the least to the most risky:

1. **interfaces**: sysctl `NET_RT_IFLIST` on the routing family `PF_ROUTE`. It counts the interfaces and the addresses in the answer.
2. **sockets**: sysctlbyname `net.inet.tcp.pcblist`, then `net.inet.udp.pcblist`, family `AF_INET`. It reads each table and reports its size.
3. **echo**: a raw ICMP socket, `socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)`, sends one echo request to `127.0.0.1` and reads up to 8 packets, each with a 2-second deadline. The packet never leaves the console.

Every step writes what it is about to do to `/data/network-spike.log` before the step, and what it read back after it. Each write is flushed to disk, so the log keeps the result of a finished probe even if the connection drops. The log is appended to, never truncated.

Each probe's first line reports the effective user the payload runs as (`euid`, `uid`, `gid`, `egid`), read from the process. The console also shows a notification before each probe.

The exit status is `0` when every probe that ran read its fact, `1` when one was refused, and `2` when the selector file is refused.

## 1. Build it

Set the SDK as in the [quick start](quick-start.md#1-install-the-ps5-payload-sdk), then:

```console
$ make clean all
```

The build writes `network-spike.elf` next to `ariel-ps5.elf`. To build only the spike, run `make network-spike.elf`. Do not run `make test`; it sends `ariel-ps5.elf` to the console, and it refuses unless `ARIEL_DEPLOY=yes` is given.

## 2. Choose the probe

The ELF loader takes no arguments from `prospero-deploy`, so the selector is a file on the console: `/data/network-spike.select`.

| Contents of the file | Runs |
| --- | --- |
| `interfaces` | probe 1 alone |
| `sockets` | probe 2 alone |
| `echo` | probe 3 alone |
| `all` | all three, in order |
| no file | all three, in order |

Write the file before you send the payload, using the console's file route (ftpsrv on port 2121). Any other contents make the payload log `selector refused` and stop without running a probe.

The payload logs the selector it used at the top of every run, so a leftover file cannot run a different probe without showing it. Remove the file when the run is finished, so the next run goes back to all three.

## 3. Send it to elfldr on port 9021

```console
$ export PS5_HOST=192.168.0.10
$ $PS5_PAYLOAD_SDK/bin/prospero-deploy -h $PS5_HOST -p 9021 network-spike.elf
```

Leave the deploy command running while the payload works. The payload's standard output comes back over the same connection, but the log file on the console is the record that counts.

## 4. Read the log

The log is `/data/network-spike.log` on the console. Copy it off the console over ftpsrv (port 2121). Each line starts with the time and names the probe and step it belongs to:

- `<probe>: intent ...`: what the step is about to do. It is written before the step.
- `<probe>: result read ...`: the step read back.
- `<probe>: result refused, <call> errno N (text)`: the step was refused, with the errno it set.
- `network spike end, failures N`: the run finished.

A run's lines start at `network spike start` and end at `network spike end`.

## 5. After a freeze

Read the last line of the log. If it is an `intent` line with no `result` line after it, the step named on that line froze the console:

| Last line in the log | The probe that froze |
| --- | --- |
| `interfaces: intent sysctl ...` | probe 1, the interface list |
| `sockets: intent sysctlbyname(...)` | probe 2, a socket table |
| `echo: intent socket(...)` | probe 3, opening the raw socket |
| `echo: intent sendto ...` | probe 3, sending the echo request |
| `echo: intent recvfrom ...` | probe 3, waiting for the reply |

The results of probes that finished before it are above that line, and they stay in the log. Then:

1. Reboot the console. A reboot stops every payload.
2. Copy the log off the console and keep it.
3. Write `echo` (or whichever probe is left) to `/data/network-spike.select`, and run that probe alone, as in steps 2 and 3.
4. Remove the selector file.

The log is appended to, so the next run's lines follow the earlier run's lines. Read them by the `network spike start` line that opens each run.

## 6. What to paste into the findings

Paste the answers to all of these:

- The console's firmware version and model.
- The `start` line and the `effective user` line from each probe that ran.
- The selector line from the run.
- Each probe's result line, or its last intent line if it has none.
- The errno and its text for each refused step.
- Whether the console froze, and the last line in the log.

## Notes

- The payload opens no listening socket. Probe 3 is the only one that opens a socket, and it sends one 16-byte ICMP echo request to `127.0.0.1`.
- The log holds names, counts and errnos, not table contents. The socket tables are read and discarded: the probe shows that the read works, not what the table holds.
- A reply to the echo says the network stack answered. It does not say that a payload is serving; that is what the socket table is for.
