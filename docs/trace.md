# The trace verb

`trace NAME [--replace]` writes the console's state as a named record under Ariel's state directory, in `<state>/trace/`, and answers the same record on the agent port, then `exit 0`. A record is kept across a reboot of the console and a restart of Ariel. The verb asks nobody and changes nothing the owner owns.

## Names and refusals

A name is 1 to 32 bytes of printable ASCII with no space and no `/`. Any other name answers `bad_path` (exit 1), and `trace` with no name answers `missing_operand` (exit 1). An argument after the name other than `--replace`, or more than one, answers `bad_option` (exit 1).

A name that is already kept answers `trace_exists` (exit 96) and writes nothing, unless `--replace` is given. `--replace` writes the new record first and then removes every file kept under the name, so an interrupted replace can leave the older files beside the new one. The record of a name is the file with the highest sequence number, and the next replace removes all of them. A write that fails answers `operation_failed` (exit 1).

Eight records are kept. A ninth record drops the oldest.

## The record

The fields come once each, in this order:

- `clock <unix seconds>`
- `uptime <seconds since boot>`
- `boot <unix seconds of the last boot>`
- `space <available bytes> <total bytes>`, for the volume of the state directory
- `mounts <count>`, then up to 8 `mount <target> <source>`
- `titles <count>`, then up to 32 `title <name> <bytes>`, one for each directory under `user/app`
- `metadata <count>`, then up to 32 `meta <name>`, from `user/appmeta`
- `licences <count>`, then up to 32 `licence <name>`, from `user/license`
- `payloads <count>`, then up to 8 `payload <name>`, one for each background run still going, in name order

A section that holds more entries than it shows ends with `truncated <shown> of <total>`, where `<shown>` is its bound: 8 for mounts and payloads, 32 for titles, metadata and licences.

A title's size is the sum of the regular files under it. Symbolic links are not followed. A title whose tree is deeper than 8 directories, or has a directory that cannot be read, answers `title <name> -`, and the rest of the record is still written.

A name in the record is written with the escape of [exit-codes.md](exit-codes.md): each byte outside letters, digits, `.`, `_` and `-` is `%XX`. An escaped name longer than 64 bytes is cut before a whole escape and ends in `~`. The escape never writes `~`, so a trailing `~` always marks a cut.

The bounds fix the worst case at under 10 KiB: each name is at most 64 bytes and each section shows at most its bound. A record that would still not fit under the output cap answers `operation_failed`.

The record holds counts, sizes and names. It never holds file contents, the token, key material or approval state.
