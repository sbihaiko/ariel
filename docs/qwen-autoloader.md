# Two homescreen icons, one chain each

The console boots one of two payload chains, chosen on the home screen. Each
icon carries its own `autoload.txt`: picking an icon never edits the other
chain's file.

| Icon (title ID) | Serves | Autoloader entry id | Config it reads |
| --- | --- | --- | --- |
| `WebKit Autoloader` (`PINK00001`) | `http://127.0.0.1:18181/app/ariel.html` | `webkit` (released upstream) | `/mnt/usb0/ps5_autoloader/autoload.txt` |
| `WebKit Autoloader Qwen` (`PINK00002`) | `http://127.0.0.1:18182/app/qwen.html` | `qwen` (patched) | `/mnt/usb0/ps5_autoloader_qwen/autoload.txt` |

Both icons are the same design: a fake homescreen app whose `param.json`
deeplinks into the console's own WebKit browser, and a WebKit autoloader
installer ELF that serves one page, caches it in the browser's AppCache, and
installs the app. After that the page runs offline, so the installer does not
have to be running when the icon is tapped.

The two installers listen on different ports because the AppCache is per
origin: `127.0.0.1:18181` and `127.0.0.1:18182` hold separate caches, so
upgrading one icon can never invalidate the other's cached page.

## What each chain loads

`ps5_autoloader/autoload.txt` (ariel, unchanged, sha256 `a52bdb01…`):
kstuff-lite 1.09, ShadowMountPlus 1.6 beta 16, ftpsrv, klogsrv, ariel.

`ps5_autoloader_qwen/autoload.txt` (Qwen, sha256 `e0a2851d…`):
kstuff-lite 1.09, ShadowMountPlus 1.7 beta 11, ftpsrv, klogsrv, ariel. The
1.7 mount is what PS5LM Plus 0.8.4 needs to reach `/data/PS5LM`.

## Building the Qwen installer

The upstream source is `itsPLK/ps5-webkit-autoloader` at `v0.1.7-abc3b82` with
its unified autoloader submodule. Two edits make it the Qwen variant:

1. `third_party/ps5-unified-autoloader/src/app_killer.c` — the WebKit entry
   point id becomes `qwen`, so the autoloader looks for
   `ps5_autoloader_qwen` before falling back to the generic directory.
2. `include/wkali.h` — `WKAL_TITLE_ID` is `PINK00002` and `WKALI_PORT` is
   `18182`; `assets/param.json.template` names the app and points the deeplink
   at `/app/qwen.html`.

The page set also gains a `qwen.html` chain page (the relapse chain with the
patched autoloader embedded) and a `/app/qwen.html` pointer that skips the
exploit-choice lookup, so the icon works with no installer page involved.

The installer links statically against libmicrohttpd, which the payload SDK
does not ship. Build it once for the console:

```sh
export PS5_PAYLOAD_SDK=$HOME/.local/share/ps5-payload-sdk
export PATH=/opt/homebrew/opt/llvm/bin:$PS5_PAYLOAD_SDK/bin:$PATH
export CC=prospero-clang AR=prospero-ar NM=prospero-nm RANLIB=prospero-ranlib
curl -sSLO https://ftp.gnu.org/gnu/libmicrohttpd/libmicrohttpd-1.0.1.tar.gz
tar xf libmicrohttpd-1.0.1.tar.gz && cd libmicrohttpd-1.0.1
./configure --host=x86_64-pc-freebsd12 --disable-shared --enable-static \
            --disable-curl --disable-examples --prefix=$PS5_PAYLOAD_SDK/target
make -j8 && cp src/microhttpd/.libs/libmicrohttpd.a $PS5_PAYLOAD_SDK/target/lib/
cp src/include/microhttpd.h $PS5_PAYLOAD_SDK/target/include/
```

Then, in the autoloader checkout:

```sh
make SDK=$PS5_PAYLOAD_SDK CC=$PS5_PAYLOAD_SDK/bin/prospero-clang \
     STRIP=$PS5_PAYLOAD_SDK/bin/prospero-strip \
     PAYLOAD_TAG=v0.1.7-abc3b82 all
```

`PAYLOAD_TAG` is required: `tools/download_deps.sh` otherwise derives a tag
from the submodule commit, which has no matching release.

## Installing

The installer installs its own app only when its `/install` route is called,
after the browser has cached the page. Run the ELF, wait for
`GET /` on its port to answer, then:

```sh
curl http://<console>:18182/install   # installs PINK00002 and stops the server
```

The app appears on the home screen as `WebKit Autoloader Qwen`. Its
`param.json` and `icon0.png` live at `/user/app/PINK00002/sce_sys/`.

## Verifying routing without loading payloads

Point `ps5_autoloader_qwen/autoload.txt` at a bare `!1500`, run the patched
autoloader through the shell, and the log names the file it read:

```
[autoloader] Found config on USB0: /mnt/usb0/ps5_autoloader_qwen/autoload.txt
[autoloader] Processing: !1500
[autoloader] Autoload sequence complete. Launched 0 payload(s).
```

Restore the real config afterwards — the file's hash above is what proves the
ariel chain was never touched.

## Failure modes

- The icon shows "Cache incomplete. Run the installer again." — the page was
  never fully cached for that origin. Re-run that port's installer ELF and wait
  for the cache to finish before the server stops.
- The autoloader falls back to `ps5_autoloader/` — `ps5_autoloader_qwen/` is
  missing or on a different USB mount (`/mnt/usb0` is checked first).
- The Qwen chain boots but PS5LM sees no models — check
  `/data/PS5LM/models/`; the mounted `/data` must be the one SMP 1.7 provides.
