# ADR-0013: The connection stack is a budget every recursive walk fits inside

## Status

Accepted.

## Context

Every agent connection runs on a thread of its own, sized `CONNECTION_STACK`
in `agent_server.c`: 64 KiB at first, the PS5's default, so the host build was
no more forgiving than a console. Three commands walk a tree by recursion and
stop at `TREE_DEPTH_MAX` levels: `cp -r` and `rm -r` in `fileops.c`, `grep -r`
in `runner.c`.

The limit was a promise the stack could not keep. `tree_copy` carried a whole
`approval_facts_t` on each frame; #86 grew that record to 2 KiB so an addon
argument could be 255 bytes long, and the walk fit about twelve levels. A tree
one level short of the limit killed the connection thread, and under GCC's
larger frames in CI a two-level tree did too, taking the agent down with it
(#96).

## Decision

1. A frame on the connection thread is part of a fixed budget, not free. The
   constant that sizes the stack states what it must hold: the handler frames,
   `TREE_DEPTH_MAX` frames of the deepest walk, the buffer at the bottom of
   that walk, and headroom.
2. A recursive frame carries the smallest thing it re-opens, not a record that
   other features grow. `tree_copy` carries the device and inode its scan saw.
3. The stack is 128 KiB, on the PS5 and on the host alike, so the documented
   depth limit fits even where a compiler makes frames larger.
4. The acceptance suite holds the budget: a scenario copies and removes a tree
   one level short of the limit through the gate, and checks that one level
   past it answers without killing the thread. A frame that grows fails the
   gate, not a console and not CI.

## Consequences

- The depth limit is reachable rather than nominal, and the next feature that
  widens a shared record is caught by the suite.
- Four connection threads cost at most 512 KiB of stack instead of 256 KiB.
- A new recursive walk must either keep its frame small or say why the budget
  still holds.

## Guard

`cp -r and rm -r hold a tree as deep as the walk promises, on the connection
thread's stack` in `hostbuild/tests/acceptance.py`.
