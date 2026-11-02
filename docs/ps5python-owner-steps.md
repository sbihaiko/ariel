# Two steps only the owner can take

The spike stops at two places that need the owner's hands. Everything else is
automatic.

## 1. Update kstuff-lite before the next console run

On 2026-11-02 the console went down eight times during the spike, and the
last few took the user filesystem with them, so the decision was to pause
console work until the jailbreak layer is current.

The reasons are recorded in [ADR-0020](adr/0020-console-jobs-are-launched-by-the-host.md)
and on [#149](https://github.com/sbihaiko/ariel/issues/149). The short version:
an idle thread inside an app job, a fork inside an app job, and homebrew
launching more homebrew each took the console down, and the platform notes say
only CPUs 9, 11, 13, 14 and 15 are usable and starving them shuts it down.

What to do:

1. Check the kstuff-lite version on the console. 1.09 fixed ASLR-disable
   handling on 11.xx (the console runs 11.200.005) and 1.10 is the stability
   release; anything older is the first thing to replace.
2. Update kstuff-lite and the exploit chain together, as the release notes
   require, and keep the rest of the chain unchanged.
3. Reboot, re-apply the jailbreak, and confirm `ps5-python` still starts.

Then the spike resumes at the end-to-end run.

## 2. Power-cycle the console when it hangs

A crashed console answers no ping, and Ariel runs on it, so no remote path
remains. Hold the power button until it turns off, then start it and re-apply
the jailbreak. When the console answers ping but opens no port it is in rest
mode, and only the power button brings it back. A machine on the same LAN can
send a Wake-on-LAN packet to the console's MAC as a first try.

After that, from the host:

```sh
python3 tools/ps5python/bootstrap.py \
    --build <ps5-python>/build/ps5 \
    --state <state-dir>
```

Then retry the CPU test with a quarter of the load before the default:

```sh
# in the launcher: ps5git --cpu /data/ps5-git/tests/cpu_report.py --workers 1 --rounds 2048
```

## 3. Create the console's token

The spike's spec requires a fine-grained personal access token limited to
`sbihaiko/ps5-git-spike`, and GitHub asks for sudo mode (passkey, security key,
authenticator or password) to create one. No agent can complete that step.

1. Open <https://github.com/settings/personal-access-tokens/new> while signed
   in as `sbihaiko`.
2. Name it `ps5-git-spike console`.
3. Expiration: 7 days.
4. Repository access: **Only select repositories** → `sbihaiko/ps5-git-spike`.
5. Permissions → Repository permissions → **Contents: Read and write**.
   Nothing else is needed; Metadata is read-only and implied.
6. Generate the token and copy it once.

## 4. Put the token on the console

The file must be mode 0600 and must never be typed into a shell history, a
commit, a log or the repository config. From the host:

```sh
read -rs TOKEN                       # paste at the prompt, nothing is echoed
printf '%s' "$TOKEN" > /tmp/ps5-token
chmod 600 /tmp/ps5-token
python3 tools/ps5python/deploy.py file /tmp/ps5-token /data/ps5-git/secrets/token
shred -u /tmp/ps5-token 2>/dev/null || rm -f /tmp/ps5-token
```

Then, on the console side, the runner refuses to work unless that file is
mode 0600; the launcher app reports `TOKEN REFUSED ...` by name if it is
missing or too permissive. Fix the mode through the telnet shell with
`chmod 600 /data/ps5-git/secrets/token`.

After the spike, revoke the token in the same GitHub page.
