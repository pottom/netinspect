# Documentation and design

## Purpose

Hold the two documents that govern work elsewhere in the repository: what the
output must look like, and how far along the build is.

## Ownership

`docs/**`.

## Local Contracts

- **`DESIGN.md` is normative for `src/render/`.** It replaces the colour table
  in §7.3 of the implementation spec; where the two disagree, `DESIGN.md` wins.
  Changing it is changing the product, not the documentation.
- `design/` holds the imported Claude Design project — the visual reference
  `DESIGN.md` points at. **Treat it as read-only here.** It is a snapshot of
  `claude.ai/design/p/9df2afac-67e1-4eae-af1a-df3df5607f7c`; edit it there and
  re-import, or the two diverge silently. `support.js` is that project's
  generated viewer runtime and is not part of the CLI.
- The `Design Rules` artboard is the presentation twin of `DESIGN.md` and lives
  only in the design project; nothing here depends on it.
- Where the visual reference and `DESIGN.md` disagree on a detail, the prose
  wins — a hand-drawn frame is a sketch of the rule, not the rule. Every such
  divergence is recorded as an implementation note in `DESIGN.md` rather than
  resolved silently.
- `MILESTONES.md` is updated as part of the work it describes, not afterwards.

## Verification

The design rules are enforced by tests, not by reading: see
`src/render/AGENTS.md`.
