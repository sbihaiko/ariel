#!/bin/sh
# Ariel's installer for macOS and Linux: make the keys, build the payload with
# them, send it to the console, and leave the token where the next command can
# read it.
#
#   ./tools/install/ariel.sh <console-address> [--check] [--build]
#
# --check names the keys and the route and sends nothing; --build stops after
# the payload is built, so the owner can send it by hand.
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

# Downloaded on its own, this script is not inside the repository: fetch the
# source it builds, once, and run from there.
if [ ! -f "$root/Makefile" ] || [ ! -d "$root/hostbuild" ]; then
  src=${ARIEL_SRC:-$HOME/.cache/ariel/src}
  ref=${ARIEL_REF:-master}
  command -v git >/dev/null 2>&1 || {
    printf 'ariel: git is needed to fetch the source of Ariel\n' >&2
    exit 1
  }
  if [ -d "$src/.git" ]; then
    git -C "$src" fetch --quiet --tags origin || {
      printf 'ariel: cannot fetch %s\n' "$ref" >&2
      exit 1
    }
  else
    mkdir -p "$(dirname "$src")"
    git clone --quiet https://github.com/sbihaiko/ariel "$src" || {
      printf 'ariel: cannot clone the source of Ariel\n' >&2
      exit 1
    }
  fi
  git -C "$src" checkout --quiet "$ref" || {
    printf 'ariel: cannot check out %s\n' "$ref" >&2
    exit 1
  }
  exec sh "$src/tools/install/ariel.sh" "$@"
fi
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

# The SDK ships the target toolchain but not the host compiler: it drives the
# machine's own LLVM, so this asks for an llvm-config the SDK can find.
have_llvm() {
  command -v llvm-config >/dev/null 2>&1 && return 0
  for n in 23 22 21 20 19 18 17 16 15; do
    command -v "llvm-config-$n" >/dev/null 2>&1 && return 0
  done
  # Homebrew keeps LLVM out of the PATH on purpose; the SDK looks here too.
  for dir in /opt/homebrew/opt/llvm/bin /usr/local/opt/llvm/bin; do
    if [ -x "$dir/llvm-config" ]; then
      PATH=$dir:$PATH
      export PATH
      return 0
    fi
  done
  return 1
}

# Fetch the payload SDK once, into ~/.local/share unless PS5_PAYLOAD_SDK says
# otherwise, and point the build at it. It is the small part of a local build.
fetch_sdk() {
  sdk=${PS5_PAYLOAD_SDK:-$HOME/.local/share/ps5-payload-sdk}
  if [ ! -x "$sdk/bin/prospero-clang" ]; then
    command -v curl >/dev/null 2>&1 || return 1
    command -v unzip >/dev/null 2>&1 || return 1
    say "downloading the PS5 payload SDK into $sdk (about 60 MB)"
    tmp=$(mktemp -d) || return 1
    if ! curl -fL --max-time 600 -o "$tmp/sdk.zip" \
        "https://github.com/ps5-payload-dev/sdk/releases/latest/download/ps5-payload-sdk.zip"
    then
      rm -rf "$tmp"
      return 1
    fi
    mkdir -p "$(dirname "$sdk")"
    if ! unzip -q -o "$tmp/sdk.zip" -d "$(dirname "$sdk")"; then
      rm -rf "$tmp"
      return 1
    fi
    rm -rf "$tmp"
  fi
  [ -x "$sdk/bin/prospero-clang" ] || return 1
  PS5_PAYLOAD_SDK=$sdk
  export PS5_PAYLOAD_SDK
  return 0
}

usage() {
  sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'
}

host=""
check=0
build_only=0
for arg in "$@"; do
  case $arg in
    --check) check=1 ;;
    --build) build_only=1 ;;
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
  if [ -n "${PS5_PAYLOAD_SDK:-}" ] && [ -x "${PS5_PAYLOAD_SDK}/bin/prospero-clang" ]
  then
    route="the SDK at $PS5_PAYLOAD_SDK"
  elif have_llvm; then
    route="a local build, with the SDK downloaded on the way"
  elif command -v "$docker" >/dev/null 2>&1; then
    route="a container built from tools/install/Dockerfile.sdk"
  else
    route="nothing yet: install Docker, or install LLVM and run this again"
  fi
  say "check: the console answers, the keys are in $keydir, and the build would use $route"
  exit 0
fi

# ARIEL_BUILD forces the route (local, sdk or docker); by default the cheapest
# that works is taken: a local build needs no daemon, and a container needs no
# toolchain.
build=${ARIEL_BUILD:-}
if [ -z "$build" ]; then
  if have_llvm; then
    build=local
  elif command -v "$docker" >/dev/null 2>&1; then
    build=docker
  elif command -v curl >/dev/null 2>&1; then
    build=sdk
  fi
fi

case $build in
  local)
    fetch_sdk || fail "cannot fetch the PS5 payload SDK"
    say "building with the SDK at $PS5_PAYLOAD_SDK"
    ( cd "$root" && ARIEL_PUBKEY=$owner ARIEL_RECOVERY_PUBKEY=$recovery make ) ||
      fail "the build failed"
    ;;
  sdk)
    fetch_sdk || fail "cannot fetch the PS5 payload SDK"
    have_llvm || fail "the PS5 payload SDK drives the machine's own LLVM:
         macOS:         brew install llvm lld
         Debian/Ubuntu: sudo apt install xxd clang-18 lld-18"
    say "building with the SDK at $PS5_PAYLOAD_SDK"
    ( cd "$root" && ARIEL_PUBKEY=$owner ARIEL_RECOVERY_PUBKEY=$recovery make ) ||
      fail "the build failed"
    ;;
  docker)
    command -v "$docker" >/dev/null 2>&1 ||
      fail "ARIEL_BUILD=docker but there is no $docker on this machine"
    say "building in a container (the first run builds the image, some minutes)"
    "$docker" build -q -t "$image" -f "$root/tools/install/Dockerfile.sdk" "$root" >/dev/null ||
      fail "cannot build the SDK image"
    "$docker" run --rm -u "$(id -u):$(id -g)" -v "$root":/src -w /src \
        -e ARIEL_PUBKEY="$owner" -e ARIEL_RECOVERY_PUBKEY="$recovery" "$image" \
        make >/dev/null || fail "the build failed"
    ;;
  *)
    fail "nothing here can build the payload: install Docker, or install the
       LLVM this machine is missing and run this again:
         macOS:         brew install llvm lld
         Debian/Ubuntu: sudo apt install xxd clang-18 lld-18"
    ;;
esac
[ -f "$payload" ] || fail "the build wrote no $payload"

if [ "$build_only" = 1 ]; then
  say "built $payload; nothing was sent"
  exit 0
fi

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
