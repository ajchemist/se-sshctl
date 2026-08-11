# Domain Docs

## Before exploring

- Read `CONTEXT-MAP.md` when present; otherwise read `CONTEXT.md` at the repository root.
- Run `bd list --type=decision --all`.
- Use `bd show <id>` to read decisions relevant to the area being changed.

If domain docs or relevant decisions do not exist, proceed silently.

## Storage

- Domain vocabulary currently lives in the root `CONTEXT.md`; a future
  `CONTEXT-MAP.md` may point to per-context domain files when useful.
- Architectural decisions live as Beads `decision` records.
- Do not create `docs/adr/`; architectural decisions belong in Beads.

When a durable architectural decision is accepted, create it with
`bd create --type=decision`, preserve its rationale and consequences, and
close it so it does not appear as actionable work.

## Vocabulary

Use terms defined in `CONTEXT.md`. Do not substitute synonyms that the glossary
explicitly avoids.

## Decision conflicts

If proposed work contradicts an existing decision, identify the decision and
surface the conflict instead of silently overriding it.
