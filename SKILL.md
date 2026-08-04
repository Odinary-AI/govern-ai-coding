---
name: govern-ai-coding
description: Use when a workspace has an explicit GAC governance contract and the requested change touches a mapped authority, protected path, governed decision, historical interpretation, or release authorization; also use when the user explicitly requests GAC setup, adapter repair, diagnosis, execution, or closeout, or when an active governed event must resume. Do not use merely because work involves plans, documentation, tests, evidence, multiple files, releases, another Skill, or a complex codebase. Do not bootstrap governance artifacts for an ordinary coding task.
---

# Govern AI Coding

Keep complex AI coding changes aligned with project facts, decisions, and
evidence. Resolve authority before edits, then bind semantic review, final
content, project validation, and human decisions before calling work complete.

## Core Rule

Govern by `(question, scope)`, not by filename. A project may use any document
structure if each governed question resolves through one rule or an explicitly
ordered set of sources.

Do not treat Skill output as project authority. Findings are evidence until the
durable conclusion is written back into mapped project documents.

## Applicability Gate

Run this lightweight gate immediately after loading the Skill and before
creating an adapter, governance document, receipt, or extra validation:

1. Applicability is established when the user explicitly requests GAC setup,
   adapter creation or repair, diagnosis, execution, or closeout, or when a
   verifiably active governed event must resume Freeze, validation, or
   Closeout.
2. Otherwise, locate an existing valid adapter. Do not create an adapter as a
   discovery fallback.
3. When relying on the adapter, compare the exact intended change paths and
   governed question with its declared rules. At least one actual boundary
   must be present: a mapped authority rule, protected path, required human
   approval, governed decision, historical interpretation, or governed
   release authorization. Adapter existence by itself is insufficient.
4. If neither branch applies, **Stop using this Skill**. Do not run Impact, do
   not create a receipt, adapter, governance decision file, or extra gate, and
   do not add validation beyond the repository's ordinary requirements.
5. The words release, plan, evidence, decision, history, or authority, the
   number of files, and codebase complexity are not applicability evidence.
   Using another Skill is not a GAC trigger.
6. ASE, Skill Creator, and GAC each require independent applicability. When ASE
   and GAC are both used, keep their findings and lifecycle obligations
   separate.

For explicit adapter setup or repair, perform only that requested adapter work
until the adapter is valid. Before treating later development as a governed
event, rerun this gate against the valid adapter and the event's exact paths.

## Inputs

Use a project adapter with only pointers, rules, and boundaries. Do not copy
current project facts into the adapter.

Every governed workspace must declare and contain a root `README.md` navigation
entrypoint for humans and AI. Navigation alone grants no product, architecture,
work-state, release, or historical authority. README edits remain ordinary
governed-document changes unless an authority rule explicitly assigns another
role.

Before creating another current authority, resolve the existing authority for
the exact `(question, scope)`. If it already answers that pair, update it rather
than creating a peer. A new authority must answer a different normative
question or close a named authority gap. README, `AGENTS.md`, generated views,
and other navigation or auto-loaded files do not gain authority from visibility:
a projection points back to its source and names a real discovery or execution
consumer. Convenience, completeness, or possible future use is insufficient,
and no project is required to create `AGENTS.md`. Treat this as a semantic
review and human-authority boundary; mechanically block only defects that the
checker can reliably prove.

Read `references/adapter-schema.md` when creating or validating an adapter.
Use `scripts/govern_ai_coding.py` for deterministic adapter, fixture, and
live diagnostic checks.

## Essential Workflow

Use one order for a governed development event:

`Impact → authorized edits → semantic review → freeze → project validation → Closeout → no governed edits`

Impact records the pre-change baseline. Freeze fingerprints the final event
paths. Project-selected validation runs against those exact bytes. Closeout
binds the baseline, final paths, semantic review, approvals, and freeze receipt.
Any governed edit after freeze invalidates the proof: refreeze, rerun
project-selected affected validation, and rerun Closeout.

When Git supplies event isolation, keep Git HEAD at the Impact baseline until
Closeout passes; working-tree and staged edits remain part of that event. In
the usual case, one governed event maps to one post-Closeout commit. If another
workflow requests intermediate commits, either defer them or close the current
event and start a new Impact for the next commit-sized event.

Do not write promises such as “Closeout will run later” into persistent project
facts. Run the gate in the task that is closing. Impact, freeze, and Closeout
receipts are generated, non-authoritative evidence; keep them outside governed
authority or in an adapter-excluded location, and do not commit them unless the
project explicitly chooses to.

## Validation Reuse And Invalidation

After any governed edit made after Freeze, create a new Freeze, run the
project-selected validation affected by that edit, and rerun Closeout. This does
not default to rerunning all tests.

Reuse validation evidence while its relevant inputs, command, configuration,
environment, and supported claim are unchanged. A status update, gate rename,
or Closeout retry does not by itself invalidate unrelated evidence.

- Ordinary governance-document edits normally invalidate only the structural,
  link, documentation, or architecture checks that consume them. If the
  project validation contract treats a document as a tested current-fact or
  executable input, rerun every obligation that consumes it.
- Runtime, public API, persistence, routing, architecture-contract, evaluation,
  or other full-regression input changes invalidate the corresponding complete
  validation required by the project contract.
- For `unproven`, follow `recovery_actions`; do not repeat unrelated tests to
  compensate for missing event isolation, approval mapping, or a human decision.
- When several validation layers require the same obligation, execute the
  deduplicated union only when command, inputs, configuration, environment, and
  claim scope are materially identical.

## Impact

Run Impact before work starts or when the task meaning changes.

For a live event, use `--workspace` and preserve the emitted receipt outside
project authority. Prefer `--write-receipt PATH`; the written receipt is
accepted by Closeout without hand editing. Closeout also accepts the complete
Impact JSON envelope. An empty Impact scope is `unproven`, not a successful
no-op.

In a Git worktree, default Impact inventory uses tracked, staged, unstaged, and
eligible non-ignored untracked files. It reports ignored and excluded paths
separately but does not treat them as event paths. Outside Git, `auto` is
`unproven`; select `--change-source filesystem` explicitly when a filesystem
baseline is intended.

If editing or semantic review reveals an additional required path, do not run a
fresh Impact on the edited tree and call it the pre-change baseline. Use
`impact --extend-receipt ORIGINAL --changed-path PATH --write-receipt NEW` only
when the preserved original receipt observed the path. Extension requires a
newly adapter-bound, verified Git or explicit filesystem receipt. Git paths
marked dirty at the original baseline and paths absent from that inventory
remain `unproven`. The extended receipt preserves the original inventory,
binds its parent digest and exact added observations, and never overwrites its
parent. A manifest may adopt it only when it embeds that exact parent.

If extension is unproven, preserve current edits. Either split the added path
into a separate event from an isolated clean worktree, or reproduce a known
clean pre-change boundary in an explicit filesystem copy and begin that event
there. Do not discard edits or use destructive recovery. Unrelated test reruns
cannot replace missing attribution evidence.

For a medium or large event, use the optional versioned event manifest. It is
generated evidence, never project authority. It keeps the event goal, baseline,
planned and actual paths, authority documents, authorized development paths,
evidence-only paths, approval bindings, Semantic Review pointer, validation
pointers, receipts, and Closeout result together. Later commands reuse the
validated receipts:

```bash
python3 scripts/govern_ai_coding.py impact adapter.json \
  --workspace /path/to/project \
  --event-manifest /safe/generated/event.json \
  --paths-from /safe/generated/planned-paths.json \
  --baseline-ref HEAD
```

Direct paths, path-list files, and manifest paths form a normalized union.
`--paths-from` accepts newline text, a JSON string list, or a JSON object with a
path-list field. A manifest identity, workspace, or baseline mismatch fails
before edits.

Return:

- affected governed questions and authority rules;
- evidence entrypoints to inspect;
- protected or excluded paths touched;
- candidate document authorities likely to need update;
- human approval boundaries.

Every `human: true` rule must resolve to one approval type before work starts.
Use one declared `human_approval_types` value. A legacy rule may infer the only
top-level type with a warning; no type or multiple candidates fail validation
and Impact before edits.

Impact result:

- `pass` when the work has mapped authority and no known human or protected
  boundary;
- `unproven` when the adapter is missing, authority, evidence, or approval is
  missing or uncertain, or excluded paths are touched;
- `fail` only for directly provable structural defects.

## Optional Work Map

When an adapter declares `work_map`, treat its configured Markdown table as
the sole project work-state authority. The `work-map` commands are read-only:

```bash
python3 scripts/govern_ai_coding.py work-map check adapter.json --workspace /project
python3 scripts/govern_ai_coding.py work-map status adapter.json --workspace /project \
  --event-manifest /safe/generated/event.json
python3 scripts/govern_ai_coding.py work-map start adapter.json --workspace /project \
  --item ITEM-01 --task-id 019fb5c7-3361-76b2-8908-40bc995f084b
python3 scripts/govern_ai_coding.py work-map finish adapter.json --workspace /project \
  --item ITEM-01 --task-id 019fb5c7-3361-76b2-8908-40bc995f084b \
  --disposition completed
python3 scripts/govern_ai_coding.py work-map render adapter.json --workspace /project \
  --format mermaid
```

`start` and `finish` emit a transition packet and unified patch. They never
edit the source, allocate a task ID, assign work, or close an external task.
The same active task is an idempotent pass/no-op; a different task is a
conflict. Table and Mermaid renderers consume the same normalized source-table
model, and generated views never become input. Table status vocabulary belongs
to the adapter; the core maps a transition disposition only to its configured
progress classification.
The first configured value remains the canonical transition output; final
verification accepts every value configured for that protocol disposition.

An event manifest may bind `work_map_binding`. In that opt-in mode Closeout
also reconciles Impact-planned and actual paths and requires a structured
validation receipt bound to the exact Freeze. `work_map_binding.source_digest` is the full Work Map source-table digest captured at the event baseline,
distinct from `final_table_digest` in the final observation. `work-map status` reads that
binding, observes the current item, and compares it with the declared external
attestation without changing either source. A pass is limited to that bounded
current observation and a complete immutable attestation whose schema markers,
adapter and event identities, final scope and content, receipt bindings, and
manifest-recorded path and digest all match. Active bound work with no
attestation is `unproven`, not failed. An attestation without `work_map_observation`
remains readable but is `unproven` for current governance closure. Historical
`govern-project-docs` attestations are evidence only and likewise cannot prove
current closure.

## Controlled Archive Intake

Read the full
[Controlled Archive Protocol](references/controlled-archive.md) before using
this capability.

Document review, stale-material checks, dependency analysis, candidate
identification, and archive preflight are read-only. A Skill trigger, candidate
approval, or passing preflight is not approval to move a file.

Those read-only events and ordinary governance events must not create, reissue,
or reuse an execution grant. A grant must preserve a current explicit user
execution instruction and bind it to the exact operation scope.

Run an archive write only after the user has expressed verifiable execution
intent, the exact source/target/receipt scope is fixed, the irreversible and
non-atomic boundaries are acknowledged, exact approval evidence exists, the
adapter permits the operation, and a separately bound execution grant
validates. Otherwise return candidates, risks, and the confirmation still
needed.

Never infer archive execution from Impact, Freeze, Closeout, diagnose, link or
consistency checks, task completion, session end, or proactive discovery.
Those operations must not call the archive executor or modify excluded archive
paths.

Every actual move remains an independent single-file transaction: never
overwrite; verify identical content; retain the source or complete
identity-checked recovery on failure; publish an exclusive immutable receipt;
bind the source content and actual archive-root identity before execution;
never promise multi-file atomicity, roll back completed task items, rewrite
historical evidence, modify archive content, or change protected
configuration automatically. Uncertainty remains fail-closed.

## Closeout

Run Closeout before declaring a task, batch, decision, validation change, or
release-stage transition complete.

For live Codex work, pass the declared changed paths, the documents authorized
for the event, the Impact receipt, and a final-content freeze receipt. Closeout
consumes a common Change Inventory, not raw Git semantics. Both verified Git
and explicitly selected filesystem inventories can support bounded before/after
comparison, but they are not equivalent evidence: only Git supplies repository
identity, HEAD/index/ignore context, and dirty-at-baseline attribution.
Supplied or explicit path-only modes remain `unproven`. Fixture-only Closeout
is for regression cases, not live task approval.

Every receipt-backed Closeout reconciles actual event paths with the Impact
plan. An unplanned actual path fails; unused planned paths warn. After Freeze,
any changed frozen path still requires a new Freeze and rerun of the validation
whose declared frozen inputs changed. Modern validation receipts whose own
frozen inputs remain byte-identical can still be reused; Work Map validation
continues to require an exact binding to the complete current Freeze.

Create the freeze after all governed edits and semantic dispositions, then run
the project's own validation:

```bash
python3 scripts/govern_ai_coding.py freeze adapter.json \
  --workspace /path/to/project \
  --changed-path STATUS.md \
  --write-receipt /tmp/project-freeze.json
```

Protected paths fail by default. When a human has explicitly approved a
protected configuration change, bind each approved path to a durable ordinary
document changed and authorized in the same event with
`--protected-approval PATH=EVIDENCE`. The evidence document must record the
approval scope. Never use this mechanism for excluded, generated, historical,
or otherwise unauthorized paths.

When a human has explicitly approved a governed semantic boundary such as
historical material change, bind the approval type to an in-event ordinary
evidence document with `--human-approval "TYPE=EVIDENCE"`. `TYPE` must be
declared in the project adapter and mapped by the affected authority rule's
`human_approval_types`. The evidence must contain `Approval type:`, `Object:`,
`Scope:`, and `Does not approve:`. One exact type never satisfies another; a
protected-path approval never satisfies a semantic approval. The checker
verifies the binding, not the truth or identity of the human decision.

One evidence document may contain several approval blocks. Each exact
`Approval type:` starts an independent record; one matching record must carry
all four non-empty fields and its own `Object` must cover every required
target as a complete path token. Closeout never combines fields or target
coverage across blocks. If no record succeeds, diagnostics distinguish an
unrecorded type, an incomplete block, uncovered targets, and a structurally
ambiguous block.

Use `--authorized-path` for paths this event may modify. Path authorization
permits bytes to change; it never approves product, architecture, release, or
historical meaning. `--authorized-doc` remains a compatibility alias and emits
a deprecation warning.

Return one result:

- `pass`: mapped authorities, evidence, and allowed document changes agree;
- `fail`: deterministic defects remain;
- `unproven`: evidence or authority is insufficient, or a human decision is
  required.

When semantic review is required, bind it with `--semantic-review REVIEW.json`.
Missing, unresolved, or unhandled semantic findings keep Closeout `unproven`;
malformed review input fails mechanically.

Closeout must include recovery information for the next AI task.
Use `result_reasons`, `recovery_actions`, and `approval_summary` for automation;
the legacy `recovery` sentence remains for compatibility.

Avoid a Freeze/report cycle with two-stage reporting. Before Freeze, the
ordinary acceptance report records validation facts, says governance signing
is pending, and names the future attestation path. After a `pass` Closeout,
write the separate immutable attestation with `--write-attestation PATH`.
Closeout never creates it for `fail` or `unproven` and never overwrites an
existing path. The frozen report stays byte-for-byte unchanged and may cite the
attestation as the final governance result.

Use the additive `diagnostics` list to recover precisely. It distinguishes
blocking, unproven, and warning severity and separates adapter configuration,
receipt format, scope mismatch, approval evidence, freeze invalidation,
validation missing, and semantic review. Each item carries `fields` or `paths`
when applicable and a non-empty `recovery_actions` list. Follow the smallest recovery action;
do not restart a valid Impact merely because Freeze or one evidence pointer is
missing.

The module that detects a finding owns its severity, category, context, and
minimum recovery action. Output aggregation preserves those diagnostics and
the existing command-specific result fields. A validation receipt command
uses the exact result value `pass`; explanatory text belongs outside that enum.
If the value is invalid, follow the indexed receipt-only recovery action and do
not repeat still-valid Impact, Freeze, review, or validation steps.

Ordinary command JSON inputs that require an object fail as structured JSON
when unreadable, malformed, or rooted at an array or scalar. Semantic Review
also requires correctly typed finding fields; `human_boundary` is a boolean
marker and does not itself select or prove an approval type.

## Integration Verification

After integration, run the read-only verifier against the original immutable
attestation and its source event context:

```bash
python3 scripts/govern_ai_coding.py verify-integration adapter.json \
  --workspace /source/workspace \
  --event-manifest /safe/generated/event.json \
  --attestation /safe/generated/attestation.json \
  --target-workspace /integrated/workspace \
  --target-adapter adapter.json \
  --target-ref refs/heads/target
```

Without `--target-ref`, content and the target adapter are read from the target
workspace. With a ref, blobs are read from Git without checkout. Matching bytes
and adapter identity do not prove rewritten history; unavailable ancestry stays
`unproven`. A validation receipt may add `input_classes`; claims inherit only
when every declared class is directly observed and matches. Unknown or
unobservable classes stay `unproven`. The verifier never establishes branch,
release, deployment, or product readiness and never merges or modifies files.

## Declared Event Preflight

Before parallel edits, compare only manifests that have already declared their
scope:

```bash
python3 scripts/govern_ai_coding.py preflight-event adapter.json \
  --workspace /current/workspace \
  --event-manifest /safe/generated/current-event.json \
  --peer-manifest /safe/generated/peer-event.json
```

Different tasks bound to one Work Map item, exact mutation-path overlap, an
unfinished configured dependency, or trusted peer evidence that changed a
declared baseline input fails. Authority-rule overlap warns and remains
`unproven`; missing or invalid peer evidence cannot manufacture a conflict.
The command inspects no sessions, tasks, processes, branches, or worktrees and
does not schedule, lock, merge, or modify anything. Its result says nothing
about concurrent work that was not supplied.

## Live Diagnostic

Run `diagnose` for a read-only Codex diagnostic of a real workspace. It checks
adapter structure, the required root README navigation entrypoint and its local
links, mapped authority targets, current and evidence entrypoints, configured
plan-status conflicts, and local Markdown links in current authority documents.
README navigation-link coverage is reported separately from current-authority
link coverage.

Do not treat diagnostic output as project authority. Write durable conclusions
back into mapped documents only when the event authorizes documentation edits.

## Mechanical Checks

Mechanical findings may block only directly provable defects:

- invalid adapter JSON;
- missing project adapter;
- missing required adapter sections or wrong basic types;
- duplicate authority rule id;
- missing mapped target or evidence entrypoint;
- broken active link when checked by the project;
- current/evidence entrypoints missing from the workspace;
- plan files marked active while current state says no active batch;
- historical material configured as current;
- generated result presented as authority;
- actual changed path not declared, or declared path not actually changed when
  actual-path verification is available;
- protected or excluded path changed in a closeout.

The only exception to a protected-path failure is a valid path-scoped approval
binding backed by an in-event evidence document. Missing, mismatched, external,
or out-of-event evidence fails mechanically; excluded paths remain blocked.

Valid human approval bindings are reported separately as
`verified_human_approvals`. They may satisfy a required human boundary, but
they are not mechanical proof of the product or architecture decision itself.

Live `pass` requires event isolation and an unchanged final-content freeze.
No supported collector proves which human or AI actor changed a file; Closeout
reports that limitation without downgrading an otherwise complete result.

## AI Semantic Review

Ask four questions:

1. What important claims changed?
2. Which governed questions are affected?
3. Do current documents agree with available evidence?
4. What remains uncertain?

Each semantic finding must include evidence, confidence, suggested handling, and
whether a human decision is required. Semantic findings are not deterministic
failures unless the project has promoted the condition to a repeatable check.

Required semantic finding fields:

- `code`
- `affected_question`
- `evidence`
- `confidence`
- `decision_boundary`
- `suggested_handling`
- `human_boundary`

## Human Approval

Ask before changing:

- authority assignment;
- product or architecture meaning;
- formal release or version claims;
- deletion, significant supersession, or irreversible archive handling.

## Codex Runtime Target

This Skill only needs to run reliably in Codex for V1. Do not add CI or other
platform machinery unless a later task explicitly expands the scope.
