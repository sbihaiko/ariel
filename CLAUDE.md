# CLAUDE.md

Guidance for agents in this repository. Rules and pointers only.

## Purpose

ariel: a PS5 payload shell, forked from shsrv, that lets an AI agent inspect the console, install and run payloads, and recover from crashes safely (see README.md). Everything written is in one language; see the ADRs.

## Layout

```
CLAUDE.md   this file: rules and pointers (AGENTS.md links here)
GLOSSARY.md  domain terms
docs/adr/   decisions; index in docs/adr/README.md
docs/agents/ issue tracker, triage labels, domain-doc rules
```

## Rules

- **ADRs are guides, not locks** ([ADR-0000](docs/adr/0000-adrs-are-guides.md)). Guard: None yet. This rule is a draft until a named guard test exists.
- **A failing gate is a defect; a gate is a stop condition** ([ADR-0001](docs/adr/0001-a-failing-gate-is-a-defect.md)). Guard: None yet. This rule is a draft until a named guard test exists.
- **A red test is fixed, whoever broke it** ([ADR-0002](docs/adr/0002-a-red-test-is-fixed.md)). Guard: None yet. This rule is a draft until a named guard test exists.
- **Commits and pushes are automatic** ([ADR-0003](docs/adr/0003-commits-and-pushes-are-automatic.md)). Guard: None yet. This rule is a draft until a named guard test exists.
- **Everything written is English** ([ADR-0004](docs/adr/0004-language-of-the-record.md)). Guard: None yet. This rule is a draft until a named guard test exists.
- **Where decisions go** ([ADR-0005](docs/adr/0005-where-decisions-go.md)). Guard: None yet. This rule is a draft until a named guard test exists.
- **The gate is one command: `sh tools/gate.sh`** ([ADR-0015](docs/adr/0015-the-gate-is-one-command.md)). It names `payload:` and `hostbuild:` on their own lines; never write `make clean all && …` as an acceptance command. Guard: `tools/test-gate.sh`.

## Where decisions go

- A durable engineering decision: an ADR in `docs/adr/`.
- A decision for one ticket: a comment on that ticket.
- A one-off fact or grant: a memory file. `MEMORY.md` is the index.
- Anything else: the commit message.

## Agent skills

### Issue tracker

Issues live in GitHub Issues for sbihaiko/ariel, via the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

The five default labels: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `GLOSSARY.md` and `docs/adr/` at the repo root. See `docs/agents/domain.md`.
