# EglantinePS5 on the console

EglantinePS5 is the Switch / Switch 2 emulator ([viejunerd/Eglantine-PS5-](https://github.com/viejunerd/Eglantine-PS5-),
a fork of [Eglantine-Community/Eglantine](https://github.com/Eglantine-Community/Eglantine)). It is not
Eden: Eden (ProsperoEden) runs `.nsp` libraries, Eglantine has the NX2 core and opens `.nup` packages.
Both live on the external drive; only Eglantine's settings are edited by hand (see below).

## Where it keeps things

From `headless/storage_paths.h` in the source:

| Path | What |
| --- | --- |
| `/data/homebrew/PPSA98515` | the app folder (`eboot.bin`, `ui/`); the mount is `/user/app/PPSA98515/mount.lnk` |
| `/data/eglantineps5/config/eglantineps5.json` | the settings file the UI writes |
| `/data/eglantineps5/config/env.txt` | the `EDEN_NX2_*` testing switches |
| `/data/eglantineps5/logs/heap.log` | `EDEN_VULKAN_FRAME` / `EDEN_LOADING_DONE` metrics |
| `/data/eglantineps5/user/lossless/Lossless.dll` | the user-supplied frame-generation DLL |

`eden_links.elf` only rewrites `prosperoeden.json`. Eglantine's `game_files` is edited by hand, with
the app closed — it rewrites the file on exit — and on this console the app was pointed at
`/mnt/usb1/eden`.

## Settings that matter

The `performance` keys map to the UI as:

| Key | UI name |
| --- | --- |
| `block_list` | Compile ahead |
| `async_shaders` | Async shaders |
| `fast_gpu` | Faster GPU emulation |
| `unsafe_cpu` | Faster CPU emulation |
| `unsafe_dma` | Faster DMA |
| `reactive_flushing` | (off by default for Switch 2 titles) |
| `skip_invalidation` | Invalidation skip |

Measured on The Legend of Zelda: Ocarina of Time (`.nup`, 25.6 GB, 1080p, 1x, Vulkan), reading
`worst_ms` out of `logs/heap.log`:

| Configuration | Result |
| --- | --- |
| `async_shaders` + `fast_gpu` + `skip_invalidation` | 59.9 fps median, spikes of 77–112 ms every ~1.5 min |
| `frame_gen: true`, no DLL | locked at 30.0 fps (150 frames / 5 s) — worse |
| `frame_gen: true` with `Lossless.dll` in place | still locked at 30.0 fps: the DLL is not picked up, the loss is the same |
| **plus `unsafe_cpu` + `unsafe_dma`** | **59.9 fps on 20/20 windows, worst frame 17–24 ms, no spike above 40 ms** |

So `frame_gen` stays `false`: it does not make the game faster and, on this build, halves the frame
rate. `unsafe_cpu` and `unsafe_dma` are the two switches that removed the stutter — the residual
hitches were CPU/DMA stalls, not shader compilation.

## Testing switches (`env.txt`)

`headless/test_switches.h` gives the location: `TestSwitches::Path()` is `ConfigFile("env.txt")`,
i.e. **`/data/eglantineps5/config/env.txt`** — one `NAME=VALUE` per line, `#` starts a comment.
`headless/main.cpp` sets each one with `setenv` and logs `EDEN_ENV <name>=<value> (testing switches)`.

A second file is read right after, `AppFile("env.txt")`, i.e. `<app dir>/env.txt`, and **wins over
the config one**; it is read-only in practice because the app dir is the mounted image (`/app0`).

The switches are read once at startup, before the core starts — a change needs the app restarted.
A file put at `/data/eglantineps5/env.txt` (the data root rather than `config/`) is read by nothing.

Most of the `EDEN_NX2_*` names in the community notes (`EDEN_NX2_PIPELINE_WORKERS`,
`EDEN_JIT_CACHE_MIB`, `EDEN_NX2_OOT_DYNAMIC_FPS`) do not exist in this build; `strings` on the
`eboot.bin` is the quickest way to see which ones do (`EDEN_NX2_TC_EXPECTED_MIB`,
`EDEN_NX2_SHADER_REUSE`, `EDEN_NX2_UNIFORM_PREFETCH`, `EDEN_NX2_TRANSCODE_THREADS` are present).

## Reading the metrics

```
EDEN_VULKAN_FRAME frames=300 seconds=5.005 fps=59.940 worst_ms=17.3 total=4463 not_shown=0 clock_hz=60.0
```

One line every 5 s. `worst_ms` is the longest single frame in the window; anything much above
`1000/60 = 16.7 ms` is a dropped frame, and anything above ~50 ms is a visible hitch.

## Sources

- [viejunerd/Eglantine-PS5- issue #21: Ocarina of Time on PS5](https://github.com/viejunerd/Eglantine-PS5-/issues/21)
- [GrowingBlackBeans gist: freeze fixes for ocarina-test-1](https://gist.github.com/GrowingBlackBeans/e3676cf28960bc360f5a5e3cd23c2646)
- [release v1.219.028](https://newreleases.io/project/github/viejunerd/Eglantine-PS5-/release/v1.219.028)
