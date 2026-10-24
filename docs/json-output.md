# JSON output of the table commands

`ps`, `ls`, `stat`, `df`, `find` and `sysinfo` take `--json`, which answers one JSON object per line in place of the aligned text. The answer ends with the `exit <n>` line, as every answer does (ADR-0012, decision 8). `--json` may stand anywhere after the command name. `ls` and `find` also take `--limit N` before their operands, in either order with `--json`, and answer the same objects bounded by N. Any other option (a word that starts with `-`), an operand `ps` does not take, or `--json` with a command that has no JSON form answers `bad_option` (exit 1) and nothing else. A command without `--json` prints what it always printed.

`sysinfo` answers exactly one object, not one per fact: its three plain lines are one machine, so they are one row. An operand it does not take answers `bad_argument` (exit 1), and an option other than `--json` answers `bad_option` (exit 1).

An object is kept whole or left out: its encoded length counts against the answer's content cap of 64 KiB less the 64 bytes the marker may need, and an object that does not fit ends the answer. A cut answer then ends with `truncated <shown> of <total>` as plain output does, before `exit 0`.

An error keeps its word line, as without the flag: `relative_path`, `no_such_file` and the rest answer on the error channel, then `exit 1`. Objects printed before a failure, as with `find`, stay printed.

Each object is written with its keys in the order below. A string is written in double quotes. A quote is written `\"`, a backslash `\\`, and a control byte below `0x20` as `\u00XX` in lowercase hex. Every other byte is written as it is.

## Stable keys

The keys are part of the protocol. Renaming a key is a protocol change: it changes the answer a client reads, so it needs a decision of its own and a note in the commit that makes it. Removing a key or changing a value's type is also a protocol change.

## `ps`

One object per process, in the order `ps` lists them. There is no header line.

| Key | Type | Meaning |
|---|---|---|
| `pid` | number | The process id. |
| `ppid` | number | The parent's process id. |
| `pgid` | number | The process group id. |
| `sid` | number | The session id. |
| `uid` | number | The user id. |
| `state` | string | The state letters of the process. |
| `command` | string | The command name. |

## `ls`

One object per entry of the directory, sorted by name.

| Key | Type | Meaning |
|---|---|---|
| `name` | string | The entry's name, without its directory. |

## `stat`

One object for the path.

| Key | Type | Meaning |
|---|---|---|
| `path` | string | The path as it was given. |
| `bytes` | number | The size in bytes. |
| `mode` | string | The permission bits in octal, such as `640`. |
| `inode` | number | The inode number. |

## `df`

One object for the path.

| Key | Type | Meaning |
|---|---|---|
| `path` | string | The path as it was given. |
| `total_bytes` | number | The size of the file system in bytes. |
| `free_bytes` | number | The free bytes, including those reserved for the superuser. |
| `available_bytes` | number | The bytes an unprivileged process may use. |

## `find`

One object per path, the root first, then the tree in the order `find` walks it.

| Key | Type | Meaning |
|---|---|---|
| `path` | string | The path, starting from the root as it was given. |

## `sysinfo`

One object for the machine. The plain answer's three lines, `uname`, `uptime` and `memory`, describe one machine, so they make one row.

| Key | Type | Meaning |
|---|---|---|
| `sysname` | string | The operating system name, as `uname` gives it. |
| `release` | string | The kernel release. |
| `machine` | string | The machine architecture. |
| `uptime_seconds` | number | Whole seconds since the machine booted. |
| `memory_total_bytes` | number | The machine's total memory in bytes. |
| `memory_free_bytes` | number | The memory free at the moment of the answer, in bytes. |

## Host build

On the host build, `ps` reads the host's own `ps` with the fields of the PS5 build and converts each row to the keys above. A row whose fields it cannot read is not printed, and the answer ends with `operation_failed` and exit 1. The `sid` of the host is the session id that the host `ps` reports, which can differ from the PS5's.

`sysinfo` reads the host's own `uname`, uptime and memory, so its `sysname`, `release`, `machine`, `uptime_seconds` and memory figures are the host's, not a console's. A host whose uptime or memory cannot be read answers `not available on this platform` with exit 1 instead of zeros.
