#!/bin/sh
# The gate: one command that checks the change, whatever this machine carries.
#
#   sh tools/gate.sh [--payload-only|--host-only]
#
# It runs two halves and names each one on its own line:
#
#   payload    the PS5 build, on the cheapest route this machine has: an
#              exported PS5_PAYLOAD_SDK plus LLVM, the SDK in ~/.local/share,
#              or a container built from tools/install/Dockerfile.sdk.
#   hostbuild  the host build and its headless acceptance suite, on any
#              machine that has a C compiler.
#
# A half that cannot run is reported `unavailable` and fails the gate with
# status 3: a gate that could not measure the change is not a green gate, and
# saying so is the point (ADR-0001). Nothing here deploys or reads a console.
#
# Exit status: 0 the gate passed, 1 the host suite is red, 2 the payload build
# is red, 3 the payload could not be built on this machine.

set -u

root=$(cd "$(dirname "$0")/.." && pwd)
payload_only=0
host_only=0
for arg in "$@"; do
  case $arg in
    --payload-only) payload_only=1 ;;
    --host-only) host_only=1 ;;
    -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) printf 'gate: unknown option: %s\n' "$arg" >&2; exit 2 ;;
  esac
done

say() { printf 'gate: %s\n' "$*"; }

# The SDK drives the machine's own LLVM, which Homebrew keeps off the PATH.
have_llvm() {
  command -v llvm-config >/dev/null 2>&1 && return 0
  for dir in /opt/homebrew/opt/llvm/bin /usr/local/opt/llvm/bin; do
    if [ -x "$dir/llvm-config" ]; then
      PATH=$dir:$PATH
      export PATH
      return 0
    fi
  done
  return 1
}

sdk_path=""
if [ -n "${PS5_PAYLOAD_SDK:-}" ] && [ -x "$PS5_PAYLOAD_SDK/bin/prospero-clang" ]
then
  sdk_path=$PS5_PAYLOAD_SDK
elif [ -x "$HOME/.local/share/ps5-payload-sdk/bin/prospero-clang" ]; then
  sdk_path=$HOME/.local/share/ps5-payload-sdk
fi

have_docker() {
  command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1
}

route=""
if [ -n "$sdk_path" ] && have_llvm; then
  PS5_PAYLOAD_SDK=$sdk_path
  export PS5_PAYLOAD_SDK
  route=sdk
elif have_docker; then
  route=docker
fi

run_payload() {
  if [ "$host_only" = 1 ]; then
    say "payload: skipped (--host-only)"
    return 0
  fi
  case $route in
    sdk)
      say "payload: building with the SDK at $PS5_PAYLOAD_SDK"
      if ! out=$( cd "$root" && make clean all 2>&1 ); then
        say "payload: RED"
        printf '%s\n' "$out" | tail -20 | sed 's/^/gate:   /'
        return 2
      fi
      ;;
    docker)
      say "payload: building in a container from tools/install/Dockerfile.sdk"
      image=${ARIEL_SDK_IMAGE:-ariel-ps5-sdk}
      docker build -q -t "$image" -f "$root/tools/install/Dockerfile.sdk" "$root" \
        >/dev/null 2>&1 || return 2
      docker run --rm -u "$(id -u):$(id -g)" -v "$root":/src -w /src "$image" \
        make >/dev/null 2>&1 || return 2
      ;;
    *)
      say "payload: unavailable (no PS5_PAYLOAD_SDK with LLVM, no Docker)"
      say "payload: tools/install/ariel.sh --check names the route this machine would use"
      return 3
      ;;
  esac
  say "payload: built"
  return 0
}

run_host() {
  if [ "$payload_only" = 1 ]; then
    say "hostbuild: skipped (--payload-only)"
    return 0
  fi
  if [ ! -d "$root/hostbuild" ]; then
    say "hostbuild: skipped (no hostbuild/)"
    return 0
  fi
  out=$(make -C "$root/hostbuild" clean all test 2>&1)
  rc=$?
  tail=$(printf '%s\n' "$out" | grep -E 'scenarios|FAIL|error:' | tail -1)
  if [ "$rc" -ne 0 ]; then
    say "hostbuild: RED"
    [ -n "$tail" ] && say "  $tail"
    return 1
  fi
  if [ -n "$tail" ]; then
    say "hostbuild: $(printf '%s\n' "$tail" | sed 's/^ *//')"
  else
    say "hostbuild: passed"
  fi
  return 0
}

run_payload
prc=$?
run_host
hrc=$?

if [ "$prc" -eq 0 ] && [ "$hrc" -eq 0 ]; then
  say "PASS"
  exit 0
fi
say "FAIL (payload=$prc hostbuild=$hrc)"
[ "$hrc" -ne 0 ] && exit 1
[ "$prc" -eq 3 ] && exit 3
exit 2
