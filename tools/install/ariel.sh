#!/bin/sh
# Ariel's installer for macOS and Linux: make the keys, build the payload with
# them, send it to the console, and leave the token where the next command can
# read it.
#
#   ./tools/install/ariel.sh <console-address> [--check]
#
# The payload pins the owner's own two keys, which is why a published build is
# useless: this script builds one that approves on this owner's console and
# nowhere else. Nothing here deploys through `make test`, and nothing changes
# the gate.
#
# Environment: ARIEL_KEY_DIR (default ~/.config/ariel), DOCKER (default
# docker), ARIEL_SDK_IMAGE (default ariel-ps5-sdk). With a PS5_PAYLOAD_SDK on
# the machine the build runs there; otherwise it runs in a container built from
# tools/install/Dockerfile.sdk.

set -eu

root=$(cd "$(dirname "$0")/../.." && pwd)
keydir=${ARIEL_KEY_DIR:-$HOME/.config/ariel}
docker=${DOCKER:-docker}
image=${ARIEL_SDK_IMAGE:-ariel-ps5-sdk}
loader_port=9021
agent_port=2324
ftp_port=2121
payload=$root/ariel-ps5.elf

say() { printf '%s\n' "$*"; }
fail() { printf 'ariel: %s\n' "$*" >&2; exit 1; }

open_port() {
  nc -z -w 2 "$host" "$1" >/dev/null 2>&1
}

usage() {
  sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'
}

host=""
check=0
for arg in "$@"; do
  case $arg in
    --check) check=1 ;;
    -h|--help) usage; exit 0 ;;
    -*) fail "unknown option: $arg" ;;
    *) [ -z "$host" ] || fail "one console address, not two"; host=$arg ;;
  esac
done
if [ -z "$host" ] && [ -t 0 ]; then
  printf "the console's address: "
  read -r host || true
fi
[ -n "$host" ] || { usage; exit 2; }

say "console: $host"
open_port "$loader_port" ||
  fail "nothing answers on $host:$loader_port -- start elfldr on the console first"
say "  the loader answers on $loader_port"

# The signer is the only local build the keys need, and it has no SDK
# dependency: a C compiler is enough.
signer=$root/hostbuild/ariel-sign
if [ ! -x "$signer" ]; then
  say "building the signer"
  make -s -C "$root/hostbuild" ariel-sign >/dev/null 2>&1 ||
    fail "cannot build the signer: a C compiler is needed"
fi

if [ ! -d "$keydir" ]; then
  mkdir -p "$keydir"
  chmod 700 "$keydir"
fi
for name in owner recovery; do
  if [ ! -f "$keydir/$name.key" ]; then
    say "making $keydir/$name.key"
    "$signer" keygen "$keydir/$name.key" >/dev/null
  fi
done
owner=$("$signer" pubkey "$keydir/owner.key")
recovery=$("$signer" pubkey "$keydir/recovery.key")
[ "$owner" != "$recovery" ] ||
  fail "the owner and the recovery key are the same; make one of them again"
say "  owner key:    $owner"
say "  recovery key: $recovery"

if [ "$check" = 1 ]; then
  say "check: the console answers, the keys are in $keydir, and the build would pin them"
  exit 0
fi

if [ -n "${PS5_PAYLOAD_SDK:-}" ] && [ -x "${PS5_PAYLOAD_SDK}/bin/prospero-clang" ]
then
  say "building with the SDK at $PS5_PAYLOAD_SDK"
  ( cd "$root" && ARIEL_PUBKEY=$owner ARIEL_RECOVERY_PUBKEY=$recovery make ) ||
    fail "the build failed"
else
  command -v "$docker" >/dev/null 2>&1 ||
    fail "no PS5 SDK here and no docker: set PS5_PAYLOAD_SDK, or install Docker"
  say "building in a container (the first run builds the image, some minutes)"
  "$docker" build -q -t "$image" -f "$root/tools/install/Dockerfile.sdk" "$root" >/dev/null ||
    fail "cannot build the SDK image"
  "$docker" run --rm -u "$(id -u):$(id -g)" -v "$root":/src -w /src \
      -e ARIEL_PUBKEY="$owner" -e ARIEL_RECOVERY_PUBKEY="$recovery" "$image" \
      make >/dev/null || fail "the build failed"
fi
[ -f "$payload" ] || fail "the build wrote no $payload"

say "sending $payload to $host:$loader_port"
cat "$payload" | nc -w 5 "$host" "$loader_port" || fail "the send failed"

i=0
while [ "$i" -lt 30 ]; do
  open_port "$agent_port" && break
  i=$((i + 1))
  sleep 2
done
open_port "$agent_port" ||
  fail "the payload never opened $agent_port -- read the console's log"
say "  the agent port answers on $agent_port"

# The token is printed on the console's screen and kept in its state directory,
# which ftpsrv serves when it runs. Ask, rather than make the owner retype it.
token=""
if open_port "$ftp_port"; then
  token=$(curl -s --max-time 5 "ftp://$host:$ftp_port/data/ariel/token" || true)
fi
case $token in
  ""|*[!0-9a-f]*) token="" ;;
esac
if [ -z "$token" ] && [ -t 0 ]; then
  say "The token is on the console's screen and in /data/ariel/token."
  printf 'token: '
  read -r token || true
fi
if [ -n "$token" ] && [ ${#token} -ne 32 ]; then
  say "warning: that token is not 32 hex characters"
fi

umask 077
{
  printf 'PS5_HOST=%s\n' "$host"
  printf 'ARIEL_TOKEN=%s\n' "$token"
} > "$root/ariel.env"
say "wrote $root/ariel.env"

say ""
say "Ariel is running. From here:"
say "  . ./ariel.env"
say "  printf 'auth %s\\nls /data\\n' \"\$ARIEL_TOKEN\" | nc \$PS5_HOST $agent_port"
say "The rest is docs/quick-start.md."
