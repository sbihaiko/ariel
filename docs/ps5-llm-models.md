# Running an LLM on the console: what fits, and how fast

PS5LM Plus 0.8.4 serves llama.cpp on port 8081 with an OpenAI-compatible API.
The pool it can use is about 11.0 GiB of Vulkan-visible memory, and that single
number decides which models are usable: the weights and the KV cache have to
share it, and the app picks the largest context that leaves room for the cache.

Measurements below come from one CFI-2014 at 11.200.005, one slot,
`ctx_cap` 32768, batch prompts of generated Python, `max_tokens` 32 to 256.
Requests carry no float fields — the console build aborts in `json.hpp:8314`
when a number with a decimal point reaches the JSON parser, so `temperature`
and friends are never sent.

## Results

| Model | Quant | Weights | Context | Prefill (3k) | Prefill (22–30k) | Gen | `tool_calls` |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Qwen2.5-Coder-14B | Q4_K_M | 9.0 GB | 32k | 140 tok/s | 87 tok/s | 35,7 tok/s | não |
| Qwen2.5-Coder-7B | Q4_K_M | 4.7 GB | 32k | 363 tok/s | 256 tok/s | 57,4 tok/s | não |
| **Qwen3.5-9B** | Q4_K_M | 5,7 GB | 32k | **170–342 tok/s** | **145–295 tok/s** | 52–54 tok/s | **sim** |
| Qwen3-Coder-30B-A3B | UD-IQ2_M | 10,8 GB | **4k** | 164 tok/s | — | 89,8 tok/s | sim |

Prefill is reported as a range because it varies from session to session by
roughly a factor of two, for a reason not yet identified. See "Prefill varies
between sessions" below. Generation is stable — 52 to 54 tok/s in every
condition measured.

The 30B never reached a 23k prompt: the app could only give it 4096 tokens of
context, because its weights already take 10,9 of the 11,0 GiB pool and the KV
cache at q4_0 needs the rest. Requests at 6k, 13k and 26k were rejected with
`exceeds the available context size (4096 tokens)`. No smaller quant fixes
this — Q4 would be roughly 18 GB.

Prefill degrades with context length on every model, so a long first turn costs
more per token than a short one. Prefix caching does not: a second request that
shares a prefix prefills only the new tokens (4 tokens in 0.7 s on the 9B), so
a turn that appends to the same conversation pays for the delta, not the whole
prompt.

## Prefill varies between sessions, for an unknown reason

One 9B process ran a 2967-token prompt at 336 tok/s on its first request, and
then at 169 tok/s for the rest of its life — after a 30k-token request, at 57/63
°C, and again after four idle minutes at 49/54 °C. A 5927-token prompt in that
same process measured 145 tok/s while hot and 251 tok/s after the cooldown.
Generation stayed at 52–54 tok/s throughout.

The next process did not reproduce it. Three controlled tests there:

| Test | Result |
| --- | --- |
| 2967-token prompt, fresh process, 46/51 °C | 339 tok/s |
| Same prompt again after a 29,907-token request filled the slot, 67/75 °C | 337 tok/s |
| Same prompt after a rejected 44,907-token request | 342 tok/s |

So context length, temperature and a rejected oversized request are all ruled
out, and the 169 tok/s figure is not a property of sustained use. What separates
the two processes is unknown; the slot cannot be cleared to probe it further
(`POST /slots/0?action=erase` answers 501 in this build), so a model reload is
the only reset.

The practical reading: expect 170 to 340 tok/s of prefill at agent-sized
prompts, depending on the session, and do not plan around the high number. If a
session feels slow, reopening the PS5LM title is cheap.

A long context does cost prefill on its own, independent of any of this: the
same process went from 339 tok/s at 2967 tokens to 284 tok/s at 29,907 tokens,
and the older 9B runs measured 295 tok/s at 23k.

## The choice

Qwen3.5-9B Q4_K_M. It matches the 7B on prefill within about 8%, has eight
times the context of the 30B, and is the only small model here whose template
emits structured `tool_calls`. The 30B's faster generation does not pay for a
4k context: an agent turn does not fit.

That last point decided it. With `tool_choice: "required"`, the Qwen2.5-Coder
models still returned the call as assistant *text* with `finish_reason: "stop"`,
so a client has to parse JSON out of prose. Qwen3.5 returns:

```json
[{"type":"function","function":{"name":"read_file",
  "arguments":"{\"path\":\"/etc/hostname\"}"},
  "id":"Yxue481ompXPArRFKXhseA8ZGBUHeMv6"}]
```

with `finish_reason: "tool_calls"`. The 30B does this too, but 4k of context
disqualifies it for agent work.

The 14B, 7B and 30B were deleted from the console; none of them beat the 9B on
anything that matters here.

## Why no GPU figure

The console reports no GPU utilisation, and that is normal — there is no
exposed counter. Throughput is the evidence that the GPU is doing the work:
333 tokens/s of prefill on a 9B model is roughly 4,8 TFLOP/s, which the CPU
alone cannot produce.

## Settings

`/data/PS5LM/settings.json` is read when the app starts, so changing
`default_model` or `ctx_cap` takes effect only after the PS5LM title is closed
and reopened. The shell on 2323 exposes no way to kill or inspect app
processes (there is no procfs), so reopening the title is an owner action.
