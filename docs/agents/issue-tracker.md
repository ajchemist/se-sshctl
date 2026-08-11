# Issue Tracker

This repository uses Beads (`bd`) for durable work tracking. Issues live in
the local Dolt database under `.beads/`; GitHub Issues and local Markdown
files are not the source of truth.

Run `bd prime` before operating on issues.

## Common commands

- `bd ready` — find available work
- `bd show <id>` — inspect an issue
- `bd create ...` — create durable work
- `bd update <id> --claim` — claim work
- `bd close <id>` — complete work
- `bd list --type=decision --all` — list architectural decisions

Use `decision` records for architectural decisions. Close accepted decisions
so they do not appear as actionable work.

Do not commit, push, or synchronize the Dolt remote unless the user or active
repository profile explicitly authorizes it.
