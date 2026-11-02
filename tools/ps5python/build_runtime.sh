#!/bin/sh
# Build the PS5 Python runtime reproducibly, from a pinned ps5-python checkout.
#
#   sh tools/ps5python/build_runtime.sh <checkout> [--jobs N]
#
# The checkout must be at the commit PINS records (702247f). The build takes
# the local patch in tools/ps5python/patches/ — the 11.20 build fixes and the
# linker flag that removes the build-id — then builds the web launcher,
# supervisor and the runtime library.
#
# Two runs of this script on the same checkout produce byte-identical ELFs.
# SOURCE_DATE_EPOCH is what makes the `__DATE__`/`__TIME__` in CPython's build
# information stable, and `-Wl,--build-id=none` drops the one note that lld
# does not derive from the content. Both are part of the patch or the
# environment below, so the recipe lives in this repository, not in a shell
# history.

set -eu

root=$(cd "$(dirname "$0")/../.." && pwd)
checkout=${1:-}
if [ -z "$checkout" ]; then
    echo "usage: $0 <ps5-python checkout> [--jobs N]" >&2
    exit 2
fi
shift || true

jobs=8
while [ $# -gt 0 ]; do
    case $1 in
        --jobs) jobs=$2; shift 2 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

patch="$root/tools/ps5python/patches/ps5-python-build.patch"
if [ ! -f "$patch" ]; then
    echo "missing patch: $patch" >&2
    exit 2
fi

if ! git -C "$checkout" apply --reverse --check "$patch" 2>/dev/null; then
    if ! git -C "$checkout" apply --check "$patch" 2>/dev/null; then
        echo "patch does not apply to $checkout; is it the pinned commit?" >&2
        exit 2
    fi
    git -C "$checkout" apply "$patch"
    echo "applied $(basename "$patch")"
fi

# The fixed epoch is not a convenience: it is what makes two builds agree.
# 2021-01-01T00:00:00Z.
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-1609459200}
export SOURCE_DATE_EPOCH
export PS5_JOBS=$jobs
export PS5_CACHE=${PS5_CACHE:-none}
if [ -z "${PS5_PAYLOAD_SDK:-}" ] && [ -x "$HOME/.local/share/ps5-payload-sdk/bin/prospero-clang" ]; then
    PS5_PAYLOAD_SDK=$HOME/.local/share/ps5-payload-sdk
    export PS5_PAYLOAD_SDK
fi

# The ps5-python build calls GNU tools macOS does not ship, and macOS ships a
# /sbin/sha256sum that rejects --check. The shims below are always created and
# take precedence on PATH, so the recipe does not depend on what the machine
# happens to carry.
shim=$(mktemp -d)
trap 'rm -rf "$shim"' EXIT
{
    echo '#!/bin/sh'
    echo 'exec sysctl -n hw.ncpu'
} > "$shim/nproc"
chmod +x "$shim/nproc"
{
    echo '#!/bin/sh'
    echo 'if [ "$1" = "-i" ]; then'
    echo '  shift'
    echo "  exec /usr/bin/sed -i '' \"\$@\""
    echo 'fi'
    echo 'exec /usr/bin/sed "$@"'
} > "$shim/sed"
chmod +x "$shim/sed"
{
    echo '#!/bin/sh'
    echo 'if [ "$1" = "--check" ] || [ "$1" = "-c" ]; then'
    echo '  shift'
    echo '  exec shasum -a 256 -c "$@"'
    echo 'fi'
    echo 'exec shasum -a 256 "$@"'
} > "$shim/sha256sum"
chmod +x "$shim/sha256sum"
PATH=$shim:$PATH
export PATH

# The SDK drives the machine's own LLVM, which Homebrew keeps off the PATH.
if ! command -v llvm-config >/dev/null 2>&1; then
    for dir in /opt/homebrew/opt/llvm/bin /usr/local/opt/llvm/bin; do
        if [ -x "$dir/llvm-config" ]; then
            PATH=$dir:$PATH
            export PATH
            break
        fi
    done
fi

cd "$checkout"
bash tools/build_ps5.sh web

build="$checkout/build/ps5"
for rel in python-web.elf python-app-supervisor.elf cpython-lib; do
    if [ ! -e "$build/$rel" ]; then
        echo "missing build artifact: $build/$rel" >&2
        exit 1
    fi
done
echo "runtime built in $build"
