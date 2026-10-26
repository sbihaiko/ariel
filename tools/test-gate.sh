#!/bin/sh
# The gate's own test: a throwaway repository, a stub make, a stub docker and
# a stub llvm-config, so every route and every verdict is proven without a
# toolchain, a container or a console.
#
#   sh tools/test-gate.sh
#
# What it proves: the host suite runs even when the payload half is red or
# cannot run at all (#118), each half is named on its own line, the SDK, the
# container and the unavailable routes are chosen in that order, and the exit
# status separates a red suite, a red payload build and an unavailable build.

set -eu

here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

repo=$work/repo
mkdir -p "$repo/tools" "$repo/hostbuild" "$work/bin" "$work/home" "$work/log"
cp "$here/gate.sh" "$repo/tools/gate.sh"
chmod +x "$repo/tools/gate.sh"

fail() { printf 'FAIL %s\n' "$*" >&2; exit 1; }

# make: records which half ran, in $STUB_LOG, and answers with the rc each
# half is told to give.
cat > "$work/bin/make" <<'EOF'
#!/bin/sh
half=payload
for arg in "$@"; do
  case $arg in
    -C) next=dir ;;
    *hostbuild*) half=hostbuild ;;
  esac
  if [ "${next:-}" = dir ]; then next=""; half=hostbuild; fi
done
printf '%s\n' "$half" >> "$STUB_LOG"
if [ "$half" = hostbuild ]; then
  [ "${STUB_HOST_RC:-0}" = 0 ] && printf 'all 425 scenarios passed\n'
  exit "${STUB_HOST_RC:-0}"
fi
exit "${STUB_PAYLOAD_RC:-0}"
EOF

# docker: info answers, and build/run are recorded as the container route.
cat > "$work/bin/docker" <<'EOF'
#!/bin/sh
printf 'docker %s\n' "$1" >> "$STUB_LOG"
case $1 in
  info) exit 0 ;;
  *) exit 0 ;;
esac
EOF

# llvm-config: the SDK route needs one on the PATH.
cat > "$work/bin/llvm-config" <<'EOF'
#!/bin/sh
echo 20.1.0
EOF
chmod +x "$work/bin/make" "$work/bin/docker" "$work/bin/llvm-config"

# The SDK a machine would have exported.
sdk=$work/sdk
mkdir -p "$sdk/bin"
: > "$sdk/bin/prospero-clang"
chmod +x "$sdk/bin/prospero-clang"

# Runs the gate with a clean environment; the caller sets what it wants.
run_gate() {
  : > "$work/log/calls"
  env -i PATH="$work/bin:/usr/bin:/bin" HOME="$work/home" \
      STUB_LOG="$work/log/calls" ${SDK:+PS5_PAYLOAD_SDK=$SDK} \
      ${HOST_RC:+STUB_HOST_RC=$HOST_RC} \
      ${PAYLOAD_RC:+STUB_PAYLOAD_RC=$PAYLOAD_RC} \
      sh "$repo/tools/gate.sh" "$@" 2>&1
}

expect() {
  text=$1
  case $2 in
    *"$text"*) ;;
    *) fail "expected '$text' in the gate's output, got: $2" ;;
  esac
}

expect_call() {
  grep -qx "$1" "$work/log/calls" || fail "expected the gate to run $1: $(cat "$work/log/calls")"
}

expect_no_call() {
  ! grep -qx "$1" "$work/log/calls" || fail "the gate ran $1 and should not have"
}

# 1. The SDK route, both halves green.
set +e
out=$(SDK=$sdk run_gate); rc=$?
set -e
[ "$rc" = 0 ] || fail "the SDK route with both halves green exited $rc: $out"
expect "payload: building with the SDK at $sdk" "$out"
expect "payload: built" "$out"
expect "hostbuild: all 425 scenarios passed" "$out"
expect "gate: PASS" "$out"
expect_call payload
expect_call hostbuild

# 2. No route at all: both halves are named, the host suite still runs, and
#    the gate refuses to call itself green.
set +e
out=$(env -i PATH="$work/bin:/usr/bin:/bin" HOME="$work/home" STUB_LOG="$work/log/calls" \
      sh -c "rm -f $work/bin/llvm-config $work/bin/docker; sh $repo/tools/gate.sh" 2>&1); rc=$?
set -e
expect "payload: unavailable" "$out"
expect "hostbuild: all 425 scenarios passed" "$out"
[ "$rc" = 3 ] || fail "an unavailable payload half exited $rc, not 3: $out"
expect_call hostbuild
# Put the stubs back for the cases below.
cat > "$work/bin/llvm-config" <<'EOF'
#!/bin/sh
echo 20.1.0
EOF
cat > "$work/bin/docker" <<'EOF'
#!/bin/sh
printf 'docker %s\n' "$1" >> "$STUB_LOG"
exit 0
EOF
chmod +x "$work/bin/llvm-config" "$work/bin/docker"

# 3. The payload build is red: the host suite runs anyway, and the status is
#    the payload's. This is the `&&` of the old command, undone.
set +e
out=$(SDK=$sdk PAYLOAD_RC=2 run_gate); rc=$?
set -e
expect "gate: FAIL (payload=2 hostbuild=0)" "$out"
[ "$rc" = 2 ] || fail "a red payload build exited $rc, not 2: $out"
expect_call payload
expect_call hostbuild
expect "hostbuild: all 425 scenarios passed" "$out"

# 4. The host suite is red: the status is the suite's.
set +e
out=$(SDK=$sdk HOST_RC=1 run_gate); rc=$?
set -e
expect "hostbuild: RED" "$out"
[ "$rc" = 1 ] || fail "a red host suite exited $rc, not 1: $out"
expect_call payload

# 5. No SDK but a container: the container route builds the payload.
set +e
out=$(run_gate); rc=$?
set -e
[ "$rc" = 0 ] || fail "the container route exited $rc: $out"
expect "payload: building in a container" "$out"
expect_call "docker build"
expect_call "docker run"
expect_call hostbuild

# 6. One half on request.
set +e
out=$(SDK=$sdk run_gate --host-only); rc=$?
set -e
[ "$rc" = 0 ] || fail "--host-only exited $rc: $out"
expect "payload: skipped (--host-only)" "$out"
expect_no_call payload

set +e
out=$(SDK=$sdk run_gate --payload-only); rc=$?
set -e
[ "$rc" = 0 ] || fail "--payload-only exited $rc: $out"
expect "hostbuild: skipped (--payload-only)" "$out"
expect_no_call hostbuild

printf 'all gate cases passed\n'
