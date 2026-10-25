# Quick start: a working Ariel in ten minutes

By the end of this you have Ariel running on a jailbroken console, its agent port answering, a payload installed and run end to end, one approval signed offline by the key you hold, and the newest image the console's Create button saved copied out of its gallery. This is the state of the **Stage 4** release: the gate, the store, the readers and `shots` all work. Sessions and the MCP server are later stages and are not part of this build.

The screenshots in this repository are not from this tutorial; the gallery step copies what the console itself saved.

## What you need

- A PS5 running a jailbreak with [elfldr](https://github.com/ps5-payload-dev/elfldr) listening on port 9021.
- A computer on the same network, with `git`, `make`, `curl`, `nc` and `openssl` (macOS ships `nc` and `openssl`).
- The console's IP address. The examples use `export PS5_HOST=192.168.0.10`; replace it with yours.

## 1. Install the PS5 payload SDK

Download the prebuilt SDK and point `PS5_PAYLOAD_SDK` at it:

```console
$ mkdir -p ~/.local/share && cd ~/.local/share
$ curl -LO https://github.com/ps5-payload-dev/sdk/releases/latest/download/ps5-payload-sdk.zip
$ unzip ps5-payload-sdk.zip && rm ps5-payload-sdk.zip
$ export PS5_PAYLOAD_SDK=~/.local/share/ps5-payload-sdk
```

The SDK uses the host's LLVM toolchain:

- **Debian or Ubuntu:** `sudo apt install xxd clang-18 lld-18`
- **macOS:** `brew install llvm lld`, then `export LLVM_PATH=/opt/homebrew/opt/llvm/bin` and put it on `PATH`. The SDK finds `lld` through Homebrew on its own.

## 2. Make the two keys that will approve everything

Ariel asks the owner — you — to sign every action that changes the console. That key never leaves this computer: the console only needs its public half, pinned into the build.

```console
$ git clone https://github.com/sbihaiko/ariel.git && cd ariel
$ git checkout stage-4
$ make -C hostbuild
$ mkdir -p ~/.config/ariel
$ ./hostbuild/ariel-sign keygen ~/.config/ariel/owner.key
<the owner public key>
$ ./hostbuild/ariel-sign keygen ~/.config/ariel/recovery.key
<the recovery public key>
```

`keygen` writes the key as 64 hex digits into a new file it refuses to overwrite, and prints its public key: those two printed lines are what step 3 pins into the build. Keep both key files offline from here on, and note the public keys down; `./hostbuild/ariel-sign pubkey <keyfile>` prints the public key of a key file again later. The recovery key is the one that survives a lost primary. The two must differ: a build with one key set twice, or with only `ARIEL_PUBKEY` set, stops before it compiles.

## 3. Build Ariel with your keys

```console
$ make ARIEL_PUBKEY=<the owner public key> \
       ARIEL_RECOVERY_PUBKEY=<the recovery public key>
```

The release ships the source, not a ready-made ELF, and this is why: a build without pinned keys cannot approve anything, and a build pinned to somebody else's keys cannot be approved by you. The ELF has to carry the public half of **your** pair, so it has to be built once, by you.

## 4. Send it to the console

```console
$ cat shsrv-ps5.elf | nc -q0 $PS5_HOST 9021
```

The console shows two notifications: the telnet shell is serving on `2323`, and Ariel's agent port is listening on `2324` with the access token. The same token is in `/data/ariel/token` on the console, which the agent port refuses to read back through any command.

```console
$ export ARIEL_TOKEN=<the token shown on the console>
```

## 5. Your first command on the agent port

The agent port is plain text: one `auth` line, then exactly one command, then the reply, which always ends with an `exit <status>` line. A read-only command asks nobody.

```console
$ printf 'auth %s\nsysinfo\n' "$ARIEL_TOKEN" | nc $PS5_HOST 2324
uname FreeBSD 11.00 ...
uptime 12345
memory 12345678 4567890
exit 0
```

`ps`, `ls`, `stat`, `cat`, `read`, `head`, `tail`, `grep`, `find`, `du`, `date`, `dmesg` and the rest answer the same way. Every reply is capped at 64 KiB and a reader that cuts its answer says so with a `truncated <shown> of <total>` line.

## 6. Install and run a payload end to end

Build a payload with the SDK's compiler wrapper:

```c
/* hello.c */
#include <stdio.h>

int
main(int argc, char* argv[]) {
  printf("Hello, world from Ariel!\n");
  for(int i = 1; i < argc; i++) {
    printf("argv[%d] = %s\n", i, argv[i]);
  }
  return 0;
}
```

```console
$ $PS5_PAYLOAD_SDK/bin/prospero-clang -Wall -Werror -o helloworld.elf hello.c
```

Push it. The command declares the size and the SHA-256, and the bytes follow on the same connection. macOS `nc` closes its sending side at the end of input by default; on Linux use `nc -N`.

```console
$ { printf 'auth %s\npayload push helloworld %s %s\n' "$ARIEL_TOKEN" \
      "$(wc -c < helloworld.elf | tr -d ' ')" \
      "$(openssl dgst -sha256 -r helloworld.elf | cut -d' ' -f1)"; cat helloworld.elf; } | nc $PS5_HOST 2324
staged s-4f2a9c
approval_required a-81d0e3
challenge a-81d0e3 ps5-living-room 0c5e9d1a7b3f4e62a8d0c1b9e7f35a24 120000 240000 6172... 0
exit 75
```

Exit 75 means the console is waiting for your signature. The `challenge` line is what the owner signs: copy it to the signer, which is offline and holds the key file. It prints the action it is about to sign, asks for confirmation, and writes one line on standard output:

```console
$ printf '%s\n' '<the whole challenge line>' | ./hostbuild/ariel-sign sign ~/.config/ariel/owner.key
<signature> <console> <action-sha256>
```

Grant it on the agent port, then commit the staged upload:

```console
$ printf 'auth %s\napproval grant a-81d0e3 <signature> <console> <action-sha256>\n' "$ARIEL_TOKEN" | nc $PS5_HOST 2324
approval_granted a-81d0e3
exit 0

$ printf 'auth %s\npayload commit s-4f2a9c\n' "$ARIEL_TOKEN" | nc $PS5_HOST 2324
installed helloworld 3b1f0c...
exit 0
```

Run it. Approving the commit approved running this exact build, so no second approval is needed:

```console
$ printf 'auth %s\npayload run --wait helloworld one two\n' "$ARIEL_TOKEN" | nc $PS5_HOST 2324
Hello, world from Ariel!
argv[1] = one
argv[2] = two
status 0
exit 0
```

`status` is the payload's own exit status and `exit` is Ariel's, so a payload that exits 75 is never mistaken for an approval request. A rebuilt payload is a new hash, so pushing it asks again.

If the challenge expires before the grant arrives, the grant answers `approval_expired` (exit 88) and nothing runs: push again. A grant within ten seconds of the notification answers `approval_busy` (76); a signature for another action or another console is refused with its own word and runs nothing.

## 7. See what the console shows

The console's Create button writes its screenshots and recordings into `/user/av_contents/photo`. Ariel cannot capture the screen on this firmware — both capture routes were measured and neither returns an image ([console findings](console-findings.md)) — but it can copy what the console itself saved:

```console
$ printf 'auth %s\nshots --last\n' "$ARIEL_TOKEN" | nc $PS5_HOST 2324
approval_required a-92b41f
challenge a-92b41f ...
exit 75
```

The selector is part of the signed action, so a grant for `--last` does not fetch a different set. After the grant, each copy answers `shot <path> <bytes> <sha256>` and lands under `/data/shots`, where `read <path>` pulls it back with the same hash. `shots --count <n>` and `shots --minutes <n>` take the newest `n` or the ones written in the last `n` minutes, with `n` from 1 to 64.

## 8. Addons

An addon is an ELF and a manifest in a directory of its own. Only the owner installs one, out of band, under `/data/ariel/addons`; the agent cannot write there, and `addon list` and `addon check <name>` answer without asking. `addon run <name> [args...]` goes through the same gate as everything else: one approval, one signed action, one bounded process with an empty environment. The repository ships two: [`addons/ftp/`](../addons/ftp/README.md) moves files through the console's ftpsrv, and [`addons/sight/`](../addons/sight/) is the reference addon, which refuses because there is no capture to call.

## Troubleshooting

- **`PS5_PAYLOAD_SDK is undefined`:** export the variable in the shell where you run `make` (step 1).
- **The build stops with "ARIEL_PUBKEY without ARIEL_RECOVERY_PUBKEY":** pass both keys (step 3).
- **No answer on 2324:** Ariel is not running. Send the ELF again (step 4). A reboot of the console stops every payload.
- **`exit 70` on every connection:** the token is wrong. Read it again on the console; the file is `/data/ariel/token`.
- **`exit 75` and no notification appears:** the console shows it on screen for ten seconds per request; ask again rather than signing blind.
- **`approval_expired` (88):** the window closed before the grant arrived. Push the action again and sign the fresh challenge.
- **`protected` (87):** the command names Ariel's own state, or writes outside `/data`, `/user` and `/mnt/usb*`. That refusal never asks the owner and never can be approved.
- **A red test after a change:** `make -C hostbuild test` is the headless suite and needs no console. Never run the top-level `make test`: it deploys to the console at `PS5_HOST` and refuses unless you name it with `ARIEL_DEPLOY=yes`.
