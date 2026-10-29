# ADR-0016: A change is complete when its own signal says so, never when its files stop growing

## Status

Accepted.

## Context

A verb that changes the console has to say when it is done. An earlier design
took a proxy for that signal. The agent watched the size of a package file and
treated the install as complete once the file stopped growing. The title it
called complete never mounted its application directory, and the error code the
launch then answered was the aftermath of a hang, not its cause. Wrong
diagnoses were built on that heuristic, and no verb could confirm or deny them,
because the port offered no signal of its own to read.

A file that stopped growing records that a write paused. It does not record
that the write finished. Size was never the discriminator: in the failed case
the size, the application's `app.pbm`, its `appmeta` entry and its license were
all present and correct, and the title still did not open.

## Decision

1. **A change is complete when its own signal says so.** The signal is a fact
   the change itself reports: a size and a hash of what it wrote, a named part
   that is missing, or a comparison against a fact that does not depend on
   timing. Stillness, silence and the absence of further change are never the
   signal.
2. **A change that cannot give its own signal does not claim completion.** It
   answers a word that names what could not be established, and the caller
   decides what to do next.
3. **`pkg_install` is the first application.** Its granted run is to end with
   `installed <TITLE> <bytes> <sha256>` when the package it installed is whole,
   or `install_incomplete <TITLE> <part>` naming the part that is missing. It
   does not point at a file that stopped growing.
4. **The rule is general.** Every verb that changes state defines its signal in
   the exit-code registry before its code emits the word. A read-only verb
   applies the same discipline: each check reports what it checked, and a check
   that could not run answers its own word instead of passing.

## Consequences

- A proxy such as "the file stopped growing" is not an accepted completion
  signal, in any verb, and a change that has no signal is reported as
  unverified rather than complete.
- Diagnosis stays read-only and needs no approval. Only the change itself is
  gated.

## Guard

None yet. This rule is a draft until a named guard test exists.
