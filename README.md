# Govern AI Coding

Keep complex AI coding changes aligned with project facts, decisions, and
evidence.

`govern-ai-coding` is an Agent Skill for AI-assisted development in governed
projects. It first decides whether governance applies, then governs related
changes as one reviewable batch instead of reacting to every edit.

It reserves one fixed file: every governed workspace has a root `README.md` as
the navigation starting point for humans and AI. All semantic authority paths
and other directory layouts remain adapter-defined. Navigation alone does not
make README authoritative for product, architecture, work state, release, or
history.

## What is included

- Canonical Agent Skill: `skills/govern-ai-coding/`
- Codex plugin wrapper: `plugins/govern-ai-coding/`
- Adapter and result contract: `skills/govern-ai-coding/references/adapter-schema.md`
- Governed batch workflow: `skills/govern-ai-coding/references/batch-workflow.md`
- Conditional semantic review: `skills/govern-ai-coding/references/semantic-review.md`
- Internal deterministic executor:
  `skills/govern-ai-coding/scripts/govern_ai_coding.py`
- Controlled archive protocol:
  `skills/govern-ai-coding/references/controlled-archive.md`
- Claude Code copy instructions: `docs/claude/README.md`

## Repository roles

This checkout's development history and the public package history have
different roles. [`GOVERNANCE.md`](GOVERNANCE.md) defines the binding boundary;
[`STATUS.md`](STATUS.md) records the current local and publication state. The
GitHub package-only `main` contains the published Skill surface and is not a
development upstream. Do not merge, rebase, pull from, or push development
branches to that history as ordinary synchronization.

## What it does

- Resolves document authority by governed question and scope, not by filename.
- Runs one Impact before the first governed edit of a batch.
- Allows related code, tests, and authority updates to accumulate without
  rerunning GAC for each edit.
- Finalizes the completed batch once before its post-Closeout commit.
- Separates mechanical checks, AI semantic review, and human approval boundaries.
- Supports Git, filesystem receipts, supplied inventories, and explicit path fallback.
- Optionally validates a project-owned Markdown Work Map and emits read-only
  start/finish recovery packets plus same-source table and Mermaid views.
- Audits a closed Event Manifest v2 through its explicit current attempt,
  immutable receipt bindings, and current frozen workspace content without
  scanning for evidence or writing state.
- Separates archive candidate analysis and global read-only preflight from
  exact-grant execution, with classified references, independent receipts,
  resumable non-atomic tasks, and legacy result normalization.
- Keeps adapters as pointers and rules, not copied project facts.

## What it does not do

- It does not decide product meaning, architecture meaning, formal release/version claims, or irreversible archival choices.
- It does not make generated findings into project authority.
- It does not require projects to use fixed status, task-list, changelog, or document-map filenames.
- It does not modify protected, excluded, or non-document project files as part of documentation governance.

## Install in Codex

Copy the canonical skill into your Codex skills directory:

```bash
mkdir -p ~/.codex/skills/govern-ai-coding
cp -R skills/govern-ai-coding/. ~/.codex/skills/govern-ai-coding/
```

Or install the local Codex plugin wrapper if your Codex setup supports local plugin manifests.

## Use

In a governed project task, tell the agent:

```text
Use $govern-ai-coding to decide whether GAC applies and govern this batch.
```

The default lifecycle is:

```text
Impact → batch work → finalize → commit
```

Finalization internally runs conditional Semantic Review, Freeze, affected
project validation, and Closeout in that order. Semantic Review is omitted
when governed meaning is unchanged. Event manifests, Work Maps, structured
validation receipts, attestations, integration verification, event preflight,
and controlled archive are loaded only when a current consumer or boundary
requires them. The bundled CLI is an internal deterministic executor; users
normally invoke the Skill rather than assembling each CLI call themselves.

## Adapter

A project adapter is JSON. Schema 2 declares authority rules, a required
`navigation_entrypoint` fixed to root `README.md`, boundaries, and human
approval categories. It should store only pointers and rules, not project
facts. README must be an ordinary governed document, so a batch affecting it
still requires Impact and finalization. It does not require a separate GAC
cycle for each README edit inside that batch.

Before adding another authority for a governed question and scope, resolve the
current authority first. Add one only for a different normative question or a
named authority gap. README, `AGENTS.md`, and other navigation or auto-loaded
files remain projections unless an explicit authority decision says otherwise;
each new projection must point back to its source and serve a named discovery
or execution consumer. GAC does not require every project to create
`AGENTS.md`, and this semantic sufficiency test is not a static gate.

Read the full contract in:

```text
skills/govern-ai-coding/references/adapter-schema.md
```

## Validation

Validate the skill:

```bash
python3 ~/.codex/skills/.system/skill-creator/scripts/quick_validate.py skills/govern-ai-coding
```

Run a simple adapter check:

```bash
python3 skills/govern-ai-coding/scripts/govern_ai_coding.py validate-adapter \
  path/to/adapter.json --workspace /path/to/project
```

Start a governed Git batch and write a receipt:

```bash
python3 skills/govern-ai-coding/scripts/govern_ai_coding.py impact \
  path/to/adapter.json \
  --workspace /path/to/project \
  --changed-path docs/state.md \
  --write-receipt /safe/generated/impact.json
```

Pass that file directly to Closeout with `--receipt`. A complete Impact JSON
envelope is also accepted. In a non-Git project, select
`--change-source filesystem` explicitly when filesystem snapshot isolation is
intended; `auto` does not silently claim Git verification. A filesystem
baseline proves only that explicit snapshot. It does not gain Git HEAD, index,
ignore, history, or dirty-state semantics.

If batch work discovers another required path after editing has started,
collect eligible additions and extend the preserved original Impact once before
finalization. Do not replace the pre-edit baseline with a fresh Impact:

```bash
python3 skills/govern-ai-coding/scripts/govern_ai_coding.py impact \
  path/to/adapter.json \
  --workspace /path/to/project \
  --extend-receipt /safe/generated/original-impact.json \
  --changed-path docs/additional-policy.md \
  --write-receipt /safe/generated/extended-impact.json
```

The parent is never overwritten. An unobserved path, an originally dirty Git
path, an unbound older receipt, or a mismatched event manifest remains
`unproven`; preserve current edits and recover through a separate event at an
isolated clean boundary or a known clean filesystem copy. Rerunning unrelated
tests cannot restore missing baseline attribution.

For a multi-batch, cross-session, retried Closeout, integration, Work Map,
preflight, or external-handoff workflow with a real manifest consumer, start from
[`examples/minimal/event-manifest.json`](examples/minimal/event-manifest.json)
and pass `--event-manifest` to Impact, Freeze, and Closeout. The manifest
uses v2 append-only Closeout attempts and one explicit current pointer while
remaining generated evidence. Closeout requires a stable `--attempt-id` and a
unique `--write-receipt` destination. Existing v1 manifests remain readable
and are never silently upgraded. A normal single-session, single-batch change
without a manifest consumer does not need a manifest. Prefer
`--authorized-path`; the old `--authorized-doc` option remains compatible with
a deprecation warning.

Projects that opt into `work_map` keep their configured Markdown table as the
only work-state authority. Generated patches, graphs, and receipts are derived
evidence and never assign or close tasks.

Controlled archive analysis and preflight are read-only and never imply
execution approval or create an execution grant. Actual movement requires
non-inferred user intent bound to an exact execution grant and remains one
independently verified single-file transaction per operation. Source content
and actual archive-root identity are bound before movement. See the controlled
archive protocol for task-wide preflight, immutable summary chaining, resume,
amendment, lifecycle, and compatibility details.

Create an immutable attestation only when release, audit, integration, Work Map,
or external handoff needs one. In that case, write the report's validation facts
and future attestation path before Freeze; a passing Closeout can create the
separate attestation without modifying the frozen report.

After integrating a closed event, `verify-integration` can compare only the
attested paths, target adapter, available Git ancestry, and explicitly declared
validation input classes. It is read-only and never claims branch, release, or
product readiness.

For a local read-only audit of one closed Event Manifest v2, use:

```bash
python3 skills/govern-ai-coding/scripts/govern_ai_coding.py audit-event \
  path/to/adapter.json \
  --workspace /path/to/project \
  --event-manifest /safe/generated/event.json
```

The command follows only `closeout.current`, revalidates its receipt, embedded
Impact and Freeze snapshots, optional attestation and current frozen content,
and reports supported and unsupported claims. It does not modify the manifest,
search neighboring files, install a package, or turn a passing audit into a
release or readiness claim. Event Manifest v1 is reported as unsupported
`unproven` rather than inferred.

Repository development can compare an explicitly discovered installed CLI and
the source candidate with `scripts/gac_dual_run.py`. The harness gives both
CLIs one materialized frozen corpus and compares complete findings plus result,
receipt digests and claim boundaries. Any difference is initially `unproven`;
an optional `govern-ai-coding.dual-run-classification-review.v1` file must bind
the exact comparison digest, classification and rationale before the report can
pass. This development evidence is not release or readiness approval.

## Author

Odinary-AI

## License

MIT
