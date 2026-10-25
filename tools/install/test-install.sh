#!/bin/sh
# The installer's own test: a throwaway repository, a stub signer, a stub
# docker, a stub nc and a stub curl, so the whole flow is proven without a
# console, a toolchain or an image.
#
#   sh tools/install/test-install.sh
#
# What it proves: the installer refuses when the loader is closed, asks nobody
# before it has the keys, pins the owner's two keys into the build it asks for,
# sends the built payload once, and leaves PS5_HOST and ARIEL_TOKEN behind.

set -eu

here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

repo=$work/repo
mkdir -p "$repo/tools/install" "$repo/hostbuild" "$work/bin"
# A Makefile and hostbuild/ are how the script knows it is inside the
# repository and needs no fetch.
: > "$repo/Makefile"

# A local build runs the repository's make, so the fake one writes the payload
# and records the keys it was handed.
cat > "$repo/Makefile" <<'EOF'
all:
	@printf 'elf\n' > ariel-ps5.elf
	@printf 'ARIEL_PUBKEY=%s ARIEL_RECOVERY_PUBKEY=%s\n' \
	        "$(ARIEL_PUBKEY)" "$(ARIEL_RECOVERY_PUBKEY)" > build.log
EOF
cp "$here/ariel.sh" "$repo/tools/install/ariel.sh"
chmod +x "$repo/tools/install/ariel.sh"

fail() { printf 'FAIL %s\n' "$*" >&2; exit 1; }

# The signer: two different keys, and the same answer for pubkey every time.
cat > "$repo/hostbuild/ariel-sign" <<'EOF'
#!/bin/sh
case $1 in
  keygen) printf 'key\n' > "$2" ;;
  pubkey) case $2 in
            *recovery*) printf '%s\n' 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' ;;
            *) printf '%s\n' 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' ;;
          esac ;;
esac
EOF
chmod +x "$repo/hostbuild/ariel-sign"

# nc: -z answers from $STUB_PORTS, and a send copies its input to $STUB_SENT.
cat > "$work/bin/nc" <<'EOF'
#!/bin/sh
zero=0
port=""
for arg in "$@"; do
  case $arg in
    -z) zero=1 ;;
    -w) ;;
    -*) ;;
    *) case $arg in
         [0-9]*) port=$arg ;;
         *) host=$arg ;;
       esac ;;
  esac
done
[ -n "$port" ] || exit 1
if [ "$zero" = 1 ]; then
  case " $STUB_PORTS " in *" $port "*) exit 0 ;; *) exit 1 ;; esac
fi
cat > "$STUB_SENT"
EOF

# curl: the token the console would serve over ftpsrv.
cat > "$work/bin/curl" <<'EOF'
#!/bin/sh
[ -n "${STUB_TOKEN:-}" ] || exit 22
printf '%s\n' "$STUB_TOKEN"
EOF

# docker: remember the call, and write the payload a build would have written.
cat > "$work/bin/docker" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$STUB_DOCKER_LOG"
case " $* " in
  *" make "*|*" make"*) printf 'elf\n' > "$STUB_PAYLOAD" ;;
esac
exit 0
EOF
chmod +x "$work/bin/nc" "$work/bin/curl" "$work/bin/docker"

export PATH=$work/bin:$PATH
export ARIEL_KEY_DIR=$work/keys
export STUB_SENT=$work/sent
export STUB_DOCKER_LOG=$work/docker.log
export STUB_PAYLOAD=$repo/ariel-ps5.elf
export STUB_TOKEN=836e8d059bb54808125ec64fddb1fd5e
: > "$STUB_DOCKER_LOG"

# 1. A closed loader is refused before anything is built or asked for.
set +e
STUB_PORTS="2324" sh "$repo/tools/install/ariel.sh" 192.0.2.10 --check >"$work/out" 2>&1
status=$?
set -e
[ "$status" -ne 0 ] || fail "a closed loader must be refused"
grep -q "start elfldr" "$work/out" || fail "the refusal must name elfldr: $(cat "$work/out")"
[ ! -s "$STUB_DOCKER_LOG" ] || fail "nothing may be built when the loader is closed"
[ ! -f "$repo/ariel-ps5.elf" ] || fail "nothing may be built when the loader is closed"

# 2. --check names the keys and stops before the build.
STUB_PORTS="9021 2324 2121" sh "$repo/tools/install/ariel.sh" 192.0.2.10 --check >"$work/out" 2>&1 ||
  fail "--check must exit 0 with the loader open: $(cat "$work/out")"
grep -q "owner key:    aaa" "$work/out" || fail "--check must name the owner key: $(cat "$work/out")"
grep -q "recovery key: bbb" "$work/out" || fail "--check must name the recovery key: $(cat "$work/out")"
[ ! -s "$STUB_DOCKER_LOG" ] || fail "--check must not build"
[ -f "$ARIEL_KEY_DIR/owner.key" ] || fail "--check must leave the keys it made"

# 3. The whole run: the build pins both keys, the payload is sent once, and
#    ariel.env carries the host and the token.
STUB_PORTS="9021 2324 2121" ARIEL_BUILD=docker sh "$repo/tools/install/ariel.sh" 192.0.2.10 >"$work/out" 2>&1 ||
  fail "the install must succeed: $(cat "$work/out")"
grep -q "ARIEL_PUBKEY=aaa" "$STUB_DOCKER_LOG" ||
  fail "the build must pin the owner key: $(cat "$STUB_DOCKER_LOG")"
grep -q "ARIEL_RECOVERY_PUBKEY=bbb" "$STUB_DOCKER_LOG" ||
  fail "the build must pin the recovery key: $(cat "$STUB_DOCKER_LOG")"
[ -s "$STUB_SENT" ] || fail "the payload must be sent"
printf 'elf\n' | cmp -s - "$STUB_SENT" || fail "what was sent must be the payload"
grep -q "^PS5_HOST=192.0.2.10$" "$repo/ariel.env" || fail "ariel.env must carry the host"
grep -q "^ARIEL_TOKEN=$STUB_TOKEN$" "$repo/ariel.env" || fail "ariel.env must carry the token"

# 4. A local build pins the same two keys, with no container at all. The SDK is
#    a stand-in, so nothing is downloaded.
mkdir -p "$work/sdk/bin"
printf '#!/bin/sh\nexit 0\n' > "$work/sdk/bin/prospero-clang"
chmod +x "$work/sdk/bin/prospero-clang"
rm -f "$STUB_SENT" "$repo/ariel.env" "$repo/build.log"
STUB_PORTS="9021 2324 2121" ARIEL_BUILD=local PS5_PAYLOAD_SDK=$work/sdk \
  sh "$repo/tools/install/ariel.sh" 192.0.2.10 >"$work/out" 2>&1 ||
  fail "the local build must succeed: $(cat "$work/out")"
grep -q "ARIEL_PUBKEY=aaa" "$repo/build.log" ||
  fail "a local build must pin the owner key: $(cat "$repo/build.log" 2>/dev/null)"
grep -q "ARIEL_RECOVERY_PUBKEY=bbb" "$repo/build.log" ||
  fail "a local build must pin the recovery key: $(cat "$repo/build.log" 2>/dev/null)"

echo "PASS the installer refuses a closed loader, pins the keys either way, and writes the environment"
