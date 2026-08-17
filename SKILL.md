---
name: govern-ai-coding
description: Use when a workspace has an explicit GAC governance contract and the requested change touches a mapped authority, protected path, governed decision, historical interpretation, or release authorization; also use when the user explicitly requests GAC setup, adapter repair, diagnosis, execution, or closeout, or when an active governed event must resume. Do not use merely because work involves plans, documentation, tests, evidence, multiple files, releases, another Skill, or a complex codebase. Do not bootstrap governance artifacts for an ordinary coding task.
---

# Govern AI Coding

Keep AI-assisted changes aligned with project facts, decisions, and evidence
without governing every edit. Resolve authority before a governed batch begins,
then finalize the completed batch once.

## Core Rule

Govern by `(question, scope)`, not by filename. Skill output is evidence, never
project authority. Write durable conclusions into the mapped project sources.

## Applicability Gate

Run this lightweight gate before creating an adapter, governance document,
receipt, or extra validation:

1. GAC applies when the user explicitly requests GAC setup, adapter creation or
   repair, diagnosis, execution, or closeout, or when a verifiably active
   governed event must resume Freeze, validation, or Closeout.
2. Otherwise, locate an existing valid adapter. Do not create an adapter as a
   discovery fallback.
3. Compare the exact intended change paths and governed question with the
   adapter. At least one actual boundary must be present: a mapped authority,
   protected path, required human approval, governed decision, historical
   interpretation, or governed release authorization. Adapter existence alone
   is insufficient.
4. If neither branch applies, **Stop using this Skill**. Do not run Impact, do
   not create a receipt, adapter, governance document, or extra gate, and do
   not add validation beyond the repository's ordinary requirements.
5. Keywords, file count, codebase complexity, Git operations, and using another
   Skill are not GAC triggers.
6. ASE, Skill Creator, and GAC each require independent applicability.

For adapter setup or repair, finish only that requested work. Rerun this gate
against the valid adapter before treating later development as governed.

## Inputs

Use a project adapter containing pointers, rules, and boundaries, never copied
current facts. Every governed workspace has a root `README.md` navigation
entrypoint for humans and AI; navigation does not grant semantic authority.

Before adding an authority, resolve the exact `(question, scope)`. Update an
existing answer instead of creating a peer. A new authority must answer a
different normative question or close a named gap. README, `AGENTS.md`, and
generated or auto-loaded projections gain no authority through visibility.

Read [Adapter and Result Contract](references/adapter-schema.md) only when
creating, repairing, or validating an adapter or a protocol payload. Use
`scripts/govern_ai_coding.py` for deterministic checks; use command `--help`
instead of loading flag documentation into the normal workflow.

The CLI preserves producer-owned JSON envelopes and returns process status 0
for `pass`, 1 for `fail`, 2 for `unproven`, and 3 for usage or unexpected
internal failure. `--legacy-zero-exit` is a temporary caller-migration option
that never changes JSON meaning. Use `--version` to identify the installed
base version and Git-independent Skill package digest before diagnosing a
suspected runtime mismatch.

Use `validate-semantic-review REVIEW.json` to catch schema, answer, finding,
status, boolean, and resolution-field shape defects before Closeout. This is a
shape-only preflight: only Closeout can bind the review and its resolution
evidence to the governed event.

Use `build-validation-receipt ADAPTER --workspace WORKSPACE --freeze FREEZE
--facts FACTS --write-receipt OUTPUT` to construct a create-only receipt from
explicit validation facts, then use `validate-validation-receipt RECEIPT
--freeze FREEZE` to check its structure and exact Freeze binding. These
commands do not select or run validation, parse framework output, or infer
approval, release, or readiness claims. The packaged facts example is
`references/validation-facts-example.json`.

Validation Receipt consumers select one explicit versioned profile:
`standalone-freeze-bound-v1` for the standalone validator,
`closeout-compatible-v1` for ordinary Closeout and attestation rebinding, or
`work-map-closeout-v1` for a Closeout Event Manifest carrying a Work Map
binding. The profile registry evaluates structure, binding, content, and
freshness as independent axes. Profile acceptance means only that its required
mechanical checks passed; it does not turn recorded validation facts into
approval, release, product, or readiness evidence. Read
[Adapter and Result Contract](references/adapter-schema.md) for compatibility
omissions and supported conclusions.

Use `audit-event ADAPTER --workspace WORKSPACE --event-manifest MANIFEST`
only for a read-only audit of Event Manifest v2. It selects evidence solely
through the explicit `closeout.current` pointer and
`current_closeout_attempt()`, revalidates the bound Closeout receipt, Impact,
Freeze, optional attestation, adapter, workspace, and current frozen content,
and reports bounded supported and unsupported claims. It never scans for a
newer-looking file, mutates the manifest, writes evidence, or installs a
package. Event Manifest v1 returns `unproven` as unsupported rather than being
guessed or upgraded.

Use `verify-integration ADAPTER --workspace RECORDED_WORKSPACE
--event-manifest MANIFEST --attestation ATTESTATION --target-workspace TARGET
--target-adapter TARGET_ADAPTER` only as read-only, derived evidence after a
closed batch is integrated. Supplying neither `--source-repository` nor
`--source-ref` preserves the complete legacy path; supplying exactly one is a
structured failure. With both supplied, `ADAPTER` and `--target-adapter` are
strict repository-relative paths, source and target refs must be complete OIDs
or full `refs/...` names, and the verifier observes one source commit directly
from Git objects. That commit must have one sole parent equal to the manifest
baseline, its no-rename baseline diff must exactly equal attested
`actual_paths`, and its regular blobs must match the attested final content
and adapter. A merge source is unsupported. If an existing attestation names
`final_git_commit`, it must be that derived commit exactly. The recorded event
workspace remains historical identity and may be absent: one Git-tree content
observer rebinds final content and modern Validation Receipt freshness from
the source objects. Explicit mode requires safely observable external v1/v2
evidence when that workspace has been removed. Target history passes only when
the target ref is the source commit or a descendant; directly observed
contradictions fail, while unavailable Git objects, shallow/graft limits, and
other insufficient evidence are `unproven`. `git-history` claims inherit only
when every directly observable relation passes. The command rejects Git
replacement/graft overlays and inherited Git redirection environments; it
never approves integration, release, readiness, or status. Read
[Integration Verification](references/integration-verification.md) for the
consumer contract.

## Governed Batch

A governed batch is a related set of changes with one clear goal that can be
independently accepted and represented by one post-Closeout commit. It may
contain multiple files and editing rounds. Batch size is a reviewability
judgment, not a file-count or line-count limit.

Use this default lifecycle:

`Impact → batch work → finalize → commit`

- Run one Impact before the first governed edit.
- Complete related code, tests, and authority updates during batch work.
- Do not rerun Impact for each edit, save, test addition, or related document
  update. Accumulate eligible scope additions and extend the original receipt
  once before finalization.
- Do not Freeze intermediate states or create intermediate commits.
- Finalize once after all governed edits are complete.

Split the batch when its goal or acceptance criteria changes, a new approval or
irreversible boundary appears, the original baseline cannot prove a required
path, or the result can no longer be independently reviewed and validated.
Read [Governed Batch Workflow](references/batch-workflow.md) when opening,
extending, recovering, freezing, validating, or closing a batch.

## Essential Workflow

Finalization preserves this internal proof order:

`conditional Semantic Review → Freeze → affected validation → Closeout`

Semantic Review is required when governed facts, decisions, authority meaning,
formal release or version claims, historical interpretation, or material public
or runtime-contract meaning changes. It may be omitted for implementation,
tests, or mechanical refactoring that preserves governed meaning, unless the
adapter or project contract explicitly requires it. Read
[Semantic Review and Human Approval](references/semantic-review.md) when that
condition or a human boundary is present.

Freeze fingerprints the completed batch. Run only project validation affected
by those final bytes. Closeout binds the baseline, actual paths, any required
review and approvals, the Freeze, and supplied validation evidence. Any
governed edit after Freeze invalidates finalization: refreeze, rerun affected
validation, and rerun Closeout.

Keep Git HEAD at the Impact baseline until Closeout passes. Working-tree and
staged edits remain part of the batch. If another workflow requests an
intermediate commit, either defer it or close the current batch and begin a new
one.

## Impact

Run Impact before the first governed edit of a batch. Preserve its receipt
outside project authority. In Git mode, retain the verified baseline inventory;
outside Git, select `filesystem` explicitly when that weaker snapshot boundary
is intended.

If batch work discovers additional existing paths, collect them before using
`impact --extend-receipt`. Extension is valid only when the preserved original
receipt observed each path cleanly. It cannot manufacture a baseline for a new,
unobserved, or originally dirty path. If extension is unproven, preserve current
edits and split the added work at an isolated clean boundary. Do not replace the
original baseline or rerun unrelated tests as compensation.

Impact returns affected authorities, evidence entrypoints, protected or
excluded paths, candidate authority updates, and human approval boundaries.
An empty scope is `unproven`, not a successful no-op.

## Finalize And Closeout

Create Freeze only after all governed edits and required semantic dispositions.
Run the deduplicated union of affected project checks against those exact
bytes. Reuse validation only while its inputs, command, configuration,
environment, and supported claim remain unchanged; do not default to the full
test suite.

Run Closeout before declaring the governed batch complete. Reconcile actual
paths against the Impact plan: unplanned actual paths fail and unused planned
paths warn. Path authorization permits bytes to change; it never approves
product, architecture, release, or historical meaning. Protected, excluded,
historical, and human-decision boundaries remain fail-closed.

For a generated authorization list, use repeatable
`--authorized-paths-from`; it has the strict path-file contract used by
`--paths-from` but contributes only authorization, never changed or actual
scope. Use `--compact` on Closeout or archive commands only when the consumer
needs the bounded presentation schema. Full producer JSON remains the default
and is required when an omitted command-specific field is needed.

Return `pass` only when deterministic checks and required evidence agree;
return `fail` for proven defects and `unproven` for insufficient evidence or a
pending human decision. Follow the smallest reported recovery action. Do not
restart a valid Impact merely because a later receipt or pointer is missing.

Receipts are generated evidence. Keep them outside governed authority or in an
adapter-excluded location, and do not commit them unless the project explicitly
chooses to. Do not write promises such as “Closeout will run later” into
persistent project facts.

## Optional Capabilities

Do not create optional evidence without a current consumer. Load exactly one
of these references only when its condition is present:

- **Event manifest:** cross-task recovery, complex scope reuse, or another
  command that requires one. Read [Event Manifest](references/event-manifest.md).
- **Work Map:** the adapter declares `work_map` and this batch uses it. Read
  [Work Map](references/work-map.md).
- **Attestation:** release, audit, integration, Work Map, or external handoff
  needs immutable proof. Read
  [Closeout Attestation](references/closeout-attestation.md).
- **Integration verification:** a closed batch has been integrated and its
  bounded evidence must be checked. Read
  [Integration Verification](references/integration-verification.md).
- **Declared event preflight:** parallel governed batches have supplied scope
  declarations. Read [Declared Event Preflight](references/event-preflight.md).
- **Controlled archive:** an explicit archive request requires analysis or an
  exactly authorized move. Read the full
  [Controlled Archive Protocol](references/controlled-archive.md) before any
  archive operation. Archive review, stale-material checks, dependency
  analysis, candidate identification, and archive preflight are read-only; no
  ordinary GAC command grants archive execution. New multi-operation summaries
  use Task Summary v2 receipt references for verified successes; failures and
  unknown outcomes retain complete diagnostic and recovery envelopes.

## Live Diagnostic And Mechanical Boundaries

Use `diagnose` for read-only checks of a real workspace. It checks adapter
structure, root README navigation, mapped targets and entrypoints, plan-status
conflicts, and local Markdown links. Its output remains evidence.

Mechanical checks may block only provable defects such as invalid adapters,
missing mapped sources, broken configured links, invalid inventories or
receipts, actual-path mismatch, stale Freeze content, and unauthorized
protected or excluded changes. They cannot prove who made a change or decide
product, architecture, release, historical, or irreversible meaning.

Ask for human approval before authority reassignment, product or architecture
meaning changes, formal release or version claims, or deletion, significant
supersession, and irreversible archive handling.

## Codex Runtime Target

This Skill only needs to run reliably in Codex for V1. Do not add CI or other
platform machinery unless a later task explicitly expands the scope.
