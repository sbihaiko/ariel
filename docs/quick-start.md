# Quick start: run a hello world payload from the Ariel shell

This tutorial builds a small `helloworld.elf`, copies it to a jailbroken PS5, and runs it from the Ariel shell. Today Ariel behaves like upstream shsrv, so these steps use only what shsrv already provides.

## What you need

- A PS5 running a jailbreak with [elfldr](https://github.com/ps5-payload-dev/elfldr) listening on port 9021.
- A computer on the same network, with `git`, `make`, `curl` and `nc` (or `telnet`).
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
- **macOS:** `brew install llvm lld`, then `export LLVM_CONFIG=/opt/homebrew/opt/llvm/bin/llvm-config`. The SDK finds `lld` through Homebrew on its own.

## 2. Build and start Ariel

```console
$ git clone https://github.com/sbihaiko/ariel.git && cd ariel
$ make
$ $PS5_PAYLOAD_SDK/bin/prospero-deploy -h $PS5_HOST -p 9021 shsrv-ps5.elf
```

The console shows a "Serving shell on <ip>:2323" notification when the shell server is up.

## 3. Build helloworld.elf

Create `hello.c`:

```c
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

Compile it with the SDK's compiler wrapper:

```console
$ $PS5_PAYLOAD_SDK/bin/prospero-clang -Wall -Werror -o helloworld.elf hello.c
```

The SDK also ships ready-made samples in `$PS5_PAYLOAD_SDK/samples`. Its `hello_world` sample shows a notification on the console instead of printing to the terminal.

## 4. Copy it to the console

Ariel cannot receive files yet (see the [Goals](../README.md#goals)), so use the FTP server from the same project. Start it, then upload the payload into `/data/ariel`:

```console
$ $PS5_PAYLOAD_SDK/bin/prospero-deploy -h $PS5_HOST -p 9021 \
    https://github.com/ps5-payload-dev/ftpsrv/releases/latest/download/ftpsrv-ps5.elf
$ curl --ftp-create-dirs -T helloworld.elf ftp://$PS5_HOST:2121/data/ariel/
```

## 5. Run it from the Ariel shell

Connect to the shell (`telnet $PS5_HOST 2323` works too):

```console
$ nc $PS5_HOST 2323
```

The shell only runs files that are executable, so set the mode first, then run the payload by its absolute path:

```console
/$ chmod 755 /data/ariel/helloworld.elf
/$ /data/ariel/helloworld.elf one two
Hello, world from Ariel!
argv[1] = one
argv[2] = two
```

The payload runs as its own process through the ELF loader, and its output comes back to your terminal.

To run it by name, put it in a folder on the shell's `PATH`, `/user/homebrew/bin` or `/mnt/usb0/homebrew/bin`:

```console
/$ mkdir /user/homebrew
/$ mkdir /user/homebrew/bin
/$ mv /data/ariel/helloworld.elf /user/homebrew/bin/
/$ helloworld.elf
Hello, world from Ariel!
```

## After Stage 1

Steps 4 and 5 will shrink to Ariel alone once [Stage 1](../README.md#stage-1-hello-world-end-to-end) lands: no FTP server and no `chmod`. Stage 1 adds an agent port (2324) next to the telnet shell: raw TCP, one command per connection after `auth`, and every reply ends with an `exit <status>` line. Every connection starts with `auth <token>`, using the access token Ariel shows on the console at first start. Status `75` means the owner must approve the action with the key they hold.

The headless acceptance test runs this section: it substitutes the token, the host and the staging ID, signs with a test key where the owner would, and treats IDs and hashes as placeholders. It builds `helloworld.elf` for the machine under test: with the host compiler for the headless suite, with `prospero-clang` (step 3) for a console.

With `PS5_HOST` set, the same harness runs against a real console instead of starting the host build: it reads the access token from you, builds `helloworld.elf` with `prospero-clang`, prints the notification the console shows at every approval step and waits for you to decide on the controller. It runs only the scenarios that need no test clock, and names the ones it skips. That run is manual: it is not part of CI and not part of the Stage 1 gate.

```console
$ export ARIEL_TOKEN=<token shown on the console>
```

Upload the payload. The command declares its size and SHA-256, and the bytes follow on the same connection. Ariel answers once the upload ends, so `nc` must close its sending side at the end of input: macOS `nc` does this by default; on Linux use `nc -N`.

```console
$ { printf 'auth %s\npayload push helloworld %s %s\n' "$ARIEL_TOKEN" \
      "$(wc -c < helloworld.elf | tr -d ' ')" \
      "$(openssl dgst -sha256 -r helloworld.elf | cut -d' ' -f1)"; cat helloworld.elf; } | nc $PS5_HOST 2324
staged s-4f2a9c
approval_required a-81d0e3
exit 75
```

Approve it. The signer names the payload, its hash, and that it will be executed. Then commit the staged upload:

```console
$ printf 'auth %s\npayload commit s-4f2a9c\n' "$ARIEL_TOKEN" | nc $PS5_HOST 2324
installed helloworld 3b1f0c...
exit 0
```

Run it in the foreground. Approving the commit approved running this exact build, so no new approval is needed:

```console
$ printf 'auth %s\npayload run --wait helloworld one two\n' "$ARIEL_TOKEN" | nc $PS5_HOST 2324
Hello, world from Ariel!
argv[1] = one
argv[2] = two
status 0
exit 0
```

`status` is the payload's own exit status; `exit` is Ariel's, so a payload that exits with 75 is never mistaken for an approval request. A new build of `helloworld` is a new hash, so pushing it asks for approval again.

## Troubleshooting

- **`mkdir` fails because the folder exists:** that is fine; `mkdir` creates one level at a time and has no `-p` yet.
- **`command not found`:** the file is missing, not executable, or not on the `PATH`. Check it with `stat <path>`.
- **No connection on port 2323:** the shell server is not running. Send `shsrv-ps5.elf` again (step 2). A reboot of the console stops every payload.
- **`PS5_PAYLOAD_SDK is undefined`:** export the variable in the shell where you run `make` (step 1).
