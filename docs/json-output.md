# JSON output of the table commands

`ps`, `ls`, `stat`, `df` and `find` take `--json`, which answers one JSON object per line in place of the aligned text. The answer ends with the `exit <n>` line, as every answer does (ADR-0012, decision 8). `--json` may stand anywhere after the command name, and it is the only option these commands take. Any other option (a word that starts with `-`), an operand `ps` does not take, or `--json` with a command that has no JSON form answers `bad_option` (exit 1) and nothing else. A command without `--json` prints what it always printed.

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

## Host build

On the host build, `ps` reads the host's own `ps` with the fields of the PS5 build and converts each row to the keys above. A row whose fields it cannot read is not printed, and the answer ends with `operation_failed` and exit 1. The `sid` of the host is the session id that the host `ps` reports, which can differ from the PS5's.
