# Two steps only the owner can take

The spike stops at two places that need the owner's hands. Everything else is
automatic.

## 1. Power-cycle the console

On 2026-11-02 the console hung while the CPU test was running: ping, ftpsrv
(2121), the telnet shell (2323), klogsrv (3232) and the launcher (8090) all
stopped answering, and Ariel runs on the console itself, so no remote path
remains. Hold the power button until it turns off, then start it and re-apply
the jailbreak as usual.

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

## 2. Create the console's token

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

## 3. Put the token on the console

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
