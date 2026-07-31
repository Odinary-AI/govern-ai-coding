# Adapter And Result Contract

The adapter is JSON in V1. It stores pointers and rules, not current project
facts.

## Adapter Fields

- `schema_version`: string, currently `"1"`.
- `project`: project or fixture identifier.
- `authority_rules`: list of rules.
- `entrypoints.current`: current authority entrypoints.
- `entrypoints.historical`: historical evidence entrypoints.
- `entrypoints.evidence`: validation and evidence entrypoints.
- `boundaries.protected`: paths that may be read as evidence but not modified
  by documentation governance.
- `boundaries.excluded`: paths ignored by default.
- `boundaries.ordinary_docs`: documentation candidates that still need event
  authorization before edits.
- `human_approval`: human decision categories.
- `plan_status_checks`: optional consistency checks between a current status
  document and mapped plan files.
- `controlled_archive`: optional single-file active-to-archive intake
  configuration.
- `work_map`: optional Markdown Work Map configuration. It declares `path`,
  exact `heading`, nine semantic `columns`, explicit `shared_columns`,
  `null_markers`, `multi_value_separator`, commitment and progress
  classifications, task identity policy, decision-item pattern, current and
  historical attestation schemas, and generated-view markers.

`entrypoints`, `boundaries`, and `human_approval` are required. `current` and
`evidence` entrypoints must be non-empty lists. All path lists contain strings.

## Authority Rule

Each authority rule contains:

- `id`: project-local stable handle.
- `question`: governed question.
- `scope`: scope string.
- `paths`: ordered source pointers.
- `protected`: optional boolean.
- `human`: optional boolean.
- `triggers`: optional list of implementation, test, config, or evidence path
  prefixes that may affect this governed question.
- `human_approval_types`: optional list of precise approval categories declared
  in top-level `human_approval`.

Rule ids must be unique. Ordered `paths` express precedence without copying
facts. `triggers` route Impact only; they never authorize protected source,
test, config, or generated writes.

## Result

Every run returns:

- `result`: `pass`, `fail`, or `unproven`;
- `mechanical_findings`;
- `semantic_findings`;
- `human_approval_required`;
- `coverage`;
- `recovery`.

Closeout also returns additive schema-1 fields:

- `result_reasons`: ordered mechanical, unverified-capability, and missing-
  approval reasons;
- `recovery_actions`: ordered actions a fresh task can execute;
- `approval_summary.required`, `.verified`, and `.missing`.

`fail` is reserved for deterministic defects. Semantic uncertainty or missing
human approval is `unproven`.

## Controlled Archive Contract

The complete request, grant, preflight, task, amendment, receipt, lifecycle,
result-normalization, and migration contracts are in
[Controlled Archive Protocol](controlled-archive.md). Adapter schema remains
`"1"` and all additions below are optional.

```json
{
  "controlled_archive": {
    "source_roots": ["<active-root>"],
    "archive_roots": ["<archive-root>"],
    "approval_type": "<approval-type>",
    "reference_rules": [
      {
        "id": "<rule-id>",
        "selectors": ["entrypoints.current"],
        "patterns": ["<optional-pattern>"],
        "category": "current-dependency",
        "handling": "disposition-required"
      }
    ],
    "mapping_amendment_policies": [
      {
        "id": "<policy-id>",
        "allowed_changed_fields": ["target"],
        "supplemental_approval_type": "<supplemental-approval-type>"
      }
    ],
    "authorization_scopes": [
      {
        "id": "<authorization-id>",
        "source_roots": ["<active-root>"]
      }
    ]
  }
}
```

Declare `approval_type` in `human_approval`. Every `archive_roots` entry must
be covered by `boundaries.excluded`; this keeps ordinary inventory and
Closeout behavior fail-closed after intake. Source roots must not overlap
excluded, protected, historical, or archive roots. Archive roots must not
overlap each other because every move and amendment binds one unambiguous
archive-root identity.

Reference rule categories are open identifiers. Handling is
`disposition-required`, `trace-only`, or `human-review`. Unknown or conflicting
classification fails closed. `mapping_amendment_policies` can permit a
separately evidenced mechanical target correction; source, authority,
visibility, actual archive-root identity, archive-root class, approval, or
recovery-boundary changes always require new explicit approval.
`authorization_scopes` support read-only lifecycle reporting, must remain
inside configured active source roots without crossing inactive boundaries,
and never authorize automatic configuration edits.

## Optional Work Map Contract

Required `work_map.columns` keys are `id`, `parent`, `result`, `commitment`,
`progress`, `owner_task`, `dependencies`, `next_reentry`, and
`authority_evidence`. Two semantic fields may share a physical header only
when that header is declared in `shared_columns`. All vocabulary is
adapter-owned; the core does not hard-code project languages or status words.

`work-map check|start|finish|render` returns `result`, source path/heading/table
digest, target, ordered checks, proposed fields, unified patch, recovery
actions, and claim boundary. Commands never mutate the workspace.

An event manifest may add:

```json
{
  "work_map_binding": {
    "item_id": "ITEM-01",
    "task_id": "019fb5c7-3361-76b2-8908-40bc995f084b",
    "source_digest": "64 lowercase hexadecimal characters",
    "expected_disposition": "completed",
    "attestation_path": "/safe/external/attestation.json"
  }
}
```

With this binding, unplanned actual paths fail, unused planned paths warn, and
Closeout requires `govern-ai-coding.validation-receipt.v1`. That receipt must
have result `pass`, bind the canonical Freeze digest and every frozen path
digest, list passing commands and environment, and state supported and
unsupported claims. The immutable attestation binds its canonical content
digest. Events without `work_map_binding` retain the schema-1 legacy validation
pointer behavior.

Missing adapter files return `unproven` with `adapter-missing` rather than a
traceback. Create a candidate adapter from project pointers and ask for human
approval before treating it as project governance authority.

## Impact

`impact <adapter> --changed-path <path>` first validates the adapter. Invalid
adapters return `fail` and do not produce a passable Impact. Valid Impact output
includes affected authority rules, candidate authority paths, protected paths,
excluded paths, and evidence entrypoints. `paths` and optional `triggers` both
route changes to governed questions.

With `--workspace`, Impact emits a receipt:

- `schema`: receipt schema id;
- adapter/project identity;
- workspace identity;
- inventory source kind and metadata;
- baseline inventory or stable summary;
- planned paths;
- affected governed questions;
- candidate authority paths;
- protected/excluded/human boundaries;
- verification capability;
- recovery instructions.

The receipt is derived evidence, not project authority. Pass it to Closeout with
`--receipt` when you need filesystem or Git baseline isolation.

Impact rejects an empty scope as `unproven`. Inventory inputs fail mechanically
when schemas, source kinds, entry types, existence/digest fields, rename fields,
or receipt identity do not match the contract. Impact receipts carry
`derived_evidence: true`, `generated: true`, and `project_authority: false`.

## Final-Content Freeze

After the final governed edit and any semantic disposition, fingerprint every
event path:

```bash
scripts/govern_ai_coding.py freeze adapter.json \
  --workspace /path/to/project \
  --changed-path STATUS.md \
  --write-receipt /tmp/project-freeze.json
```

The freeze receipt contains:

- schema and `final-content-freeze` kind;
- exact adapter and resolved-workspace identity;
- a non-empty list of normalized event paths;
- existence plus SHA-256 digest for each present file;
- explicit non-existence for deleted files; and
- generated, derived, non-authority markers.

`--write-receipt` may write outside the workspace or under an adapter-excluded
path. It fails before writing to a governed workspace path. Run project-selected
validation after freeze. Any subsequent event-path edit makes Closeout fail with
the stale paths; refreeze, rerun project-selected affected validation, and
rerun Closeout.

## Validation Evidence Reuse

Evidence freshness depends on its relevant inputs, command, configuration,
environment or toolchain, and supported claim. After a governed post-Freeze
edit, create a new Freeze, rerun the project-selected affected validation, and
rerun Closeout; the checker does not select project tests, and no adapter field
is added.

| Change or result | Validation action |
| --- | --- |
| Ordinary governance document not consumed by runtime regression | Rerun affected document, link, or architecture checks only. |
| Tested current-fact or executable document | Rerun every consuming obligation. |
| Runtime, API, persistence, routing, architecture, or evaluation input | Rerun the corresponding complete validation from the project contract. |
| Status label, gate name, or Closeout retry only | Reuse unaffected evidence. |
| `unproven` caused by isolation, approval, or human boundary | Follow the recovery action; do not rerun unrelated tests. |

Deduplicate only when command, inputs, configuration, environment or toolchain,
and claim scope are materially identical. Route recovery as follows: missing
evidence → produce relevant evidence; broad claim → narrow the claim; missing
isolation → restore baseline-capable evidence; missing approval mapping or human
decision → request that decision.

## Live Diagnostic

`diagnose <adapter> --workspace <path>` checks:

- adapter structure;
- mapped authority targets;
- current entrypoints;
- evidence entrypoints;
- configured plan-status conflicts;
- local Markdown links in current authority documents.

It does not crawl the whole repository.

## Live Closeout

Use live mode for real Codex tasks:

```bash
scripts/govern_ai_coding.py closeout adapter.json \
  --workspace /path/to/project \
  --receipt /tmp/project-impact.json \
  --freeze-receipt /tmp/project-freeze.json \
  --changed-path STATUS.md \
  --authorized-doc STATUS.md
```

The command fails protected, excluded, unauthorized ordinary-document, and
unauthorized non-document writes. Authorized historical writes remain
`unproven` when the adapter requires human approval for archive handling.

Closeout consumes a common Change Inventory:

- `path`;
- `kind`: `added`, `modified`, `deleted`, or `renamed`;
- optional `old_path` and `new_path`;
- `existence`;
- digest or other stable fingerprint when available;
- inventory source;
- `verified`;
- source-specific metadata.

Supported sources:

- `--change-source git`: compare declarations against the Git working tree;
- `--change-source filesystem` plus `--receipt`: compare a filesystem baseline
  with a final filesystem snapshot;
- `--change-source supplied --baseline-inventory A --final-inventory B`:
  compare externally supplied inventories;
- `--change-source supplied --actual-path PATH`: compare declarations against a
  verified final actual path list only;
- `--change-source explicit`: trust only declared paths and return `unproven`
  if no deterministic defect exists.

The default `auto` mode uses supplied `--actual-path` values when present,
then Git when available, then filesystem snapshot when a receipt is supplied,
then explicit fallback. When actual verification is available, undeclared actual
paths and declared-but-unchanged paths fail mechanically.

Filesystem snapshot mode does not require Git. It scans inside the workspace,
skips adapter-declared excluded paths, preserves hidden directories such as
`.venv/` and `.github/`, rejects absolute or `..` escaping paths, and rejects
symlink targets outside the workspace. Rename detection is not attempted without
source support; unrecognized renames are treated as deleted plus added.

Git is an optional inventory collector. It uses NUL-delimited porcelain status
and reports staged, unstaged, untracked, deleted, and renamed paths. Git metadata
such as HEAD is source-specific metadata only; core governance checks must not
require it.

Supplied actual paths prove final path scope only. Supplied baseline plus final
inventory, filesystem receipt, or another baseline-capable source is needed to
verify event isolation. Live `pass` requires event isolation and an unchanged
freeze receipt. Git and filesystem snapshots provide equivalent core evidence;
Git is not required. No mode proves which actor changed a file.

### Approved Protected Changes

Protected paths remain fail-by-default. For an explicitly human-approved
protected configuration change, bind each protected path to one durable evidence
document:

```bash
scripts/govern_ai_coding.py closeout adapter.json \
  --workspace /path/to/project \
  --changed-path AGENTS.md \
  --changed-path reports/approval.md \
  --authorized-doc AGENTS.md \
  --authorized-doc reports/approval.md \
  --protected-approval AGENTS.md=reports/approval.md
```

The binding is valid only when:

- the protected path is an exact actual changed path and is event-authorized;
- the evidence is an ordinary document changed and authorized in the same
  event;
- the evidence file exists inside the workspace; and
- neither target nor evidence is excluded or historical.

The evidence document must state the human approval, protected paths, event
scope, and claim boundary. AI semantic review confirms that content; the
deterministic checker confirms path, event, and boundary integrity.

`closeout.protected_approvals` records accepted path-to-evidence bindings.
Malformed, duplicate, missing, mismatched, external, or out-of-event evidence
fails mechanically. An excluded path cannot be approved.

### Approved Human Boundaries

For a human-approved semantic boundary, bind the adapter-declared approval type
to one durable evidence document:

```bash
scripts/govern_ai_coding.py closeout adapter.json \
  --workspace /path/to/project \
  --changed-path archive/resolved-question.md \
  --changed-path docs/decision.md \
  --authorized-doc archive/resolved-question.md \
  --authorized-doc docs/decision.md \
  --human-approval "historical material change=docs/decision.md"
```

The binding is valid only when:

- the approval type exists in `human_approval`;
- the evidence is inside the workspace;
- the evidence is an ordinary, non-protected, non-excluded, non-historical
  document;
- the evidence is actually changed and event-authorized;
- every target path for that exact authority/approval type is actually changed
  and event-authorized;
- the affected authority rule maps the exact type through
  `human_approval_types`; and
- the evidence contains non-empty `Approval type:`, `Object:`, `Scope:`, and
  `Does not approve:` fields, with the exact type and affected object.

Valid bindings appear in `closeout.verified_human_approvals`. They can satisfy
only the exact mapped type. Architecture approval cannot satisfy release
approval, technical acceptance cannot become release approval, and a protected
approval never becomes semantic approval. A generated Impact, freeze, or
Closeout receipt cannot be approval evidence. The checker verifies structure
and event binding; it does not turn the human decision into a mechanical fact.

Legacy `human: true` remains valid when the adapter declares exactly one
top-level approval type and emits a deprecation warning. A `human: true` rule
with no candidate or several candidates fails adapter validation and Impact
before edits. Use exactly one declared `human_approval_types` value. A
historical path with no precise authority-rule mapping remains unresolved until
the existing optional mapping is made precise. Adapter schema remains `"1"`.

## Git-Aware Impact Inventory

Git Impact builds its baseline from:

```text
git ls-files -z --cached --others --exclude-standard
git status --porcelain=v2 -z --untracked-files=all --ignored=matching
```

The effective inventory includes tracked and eligible untracked files.
`inventory_source.metadata.classifications` separately reports
`tracked_changes`, `staged`, `unstaged`, `eligible_untracked`, `ignored`, and
`excluded`. Ignored and excluded observations are not event entries.

Default exclusions cover `.git`, dependency directories, common caches, build
output, and runtime data in addition to adapter exclusions. Escaping symlinks
fail. `auto` outside Git returns `unproven`; explicitly select filesystem,
supplied, or explicit mode.

Impact supports:

```bash
scripts/govern_ai_coding.py impact adapter.json \
  --workspace /path/to/project \
  --changed-path docs/state.md \
  --write-receipt /safe/generated/impact.json
```

The receipt remains schema `govern-ai-coding.receipt.v1` and adds
`schema_version: "1"`. Closeout accepts this standalone receipt or the complete
Impact output envelope. JSON writes validate first, serialize with sorted keys,
and replace atomically. Unsafe or symlink-escaping destinations fail without a
partial receipt.

Impact retains `human_approval_required` and adds structured
`impact.approval_requirements` containing the authority rule, object, type,
scope, target paths, and explicit non-approved approval/path boundaries.

## Optional Event Manifest

The event manifest schema is `govern-ai-coding.event-manifest.v1`, version
`"1"`. It is generated event evidence and must not become project authority.
The minimum object is:

```json
{
  "schema": "govern-ai-coding.event-manifest.v1",
  "schema_version": "1",
  "event": {
    "id": "event-001",
    "goal": "Update current state",
    "workspace": ".",
    "baseline_ref": null
  },
  "scope": {
    "planned_paths": ["docs/state.md"],
    "actual_event_paths": ["docs/state.md"],
    "governed_authority_documents": ["docs/state.md"],
    "authorized_development_paths": [],
    "evidence_only_paths": ["docs/evidence.md"]
  },
  "approvals": [],
  "semantic_review": {},
  "receipts": {
    "impact": null,
    "freeze": null,
    "validation": [],
    "closeout_attestation": null
  },
  "closeout": {
    "result": null,
    "result_reasons": [],
    "recovery_actions": []
  }
}
```

Relative `event.workspace` is resolved from the manifest directory. The five
scope lists stay distinct. Authority and authorized development paths may be
written; evidence-only paths are not implicitly write-authorized. Approval
evidence uses either:

```json
{"kind": "human", "type": "release decision", "evidence": "docs/decision.md"}
```

or:

```json
{"kind": "protected", "path": "AGENTS.md", "evidence": "docs/decision.md"}
```

Impact embeds its validated receipt. Freeze embeds its receipt and the actual
event paths. Closeout reuses both, plus approval bindings and an optional
`semantic_review.path`, and records its result and recovery actions. Validation
receipt entries are project-provided file pointers; an explicitly declared
missing pointer fails mechanically.

`--paths-from` accepts newline text, a JSON string list, or a JSON object using
`paths`, `changed_paths`, `planned_paths`, or `actual_event_paths`.
`--baseline-ref` must resolve to the current Git `HEAD`; contradictory
workspace, identity, or baseline inputs fail. Manifest writes are deterministic
and atomic and are allowed only outside the workspace or under an adapter
excluded boundary.

## Path Authorization And Diagnostics

Use `--authorized-path` for the event's writable paths. The former
`--authorized-doc` spelling remains a compatibility alias and emits
`authorized-doc-deprecated`. Both feed the compatibility
`closeout.authorized_docs` field; `closeout.authorized_paths` is the precise
additive name.

Path authorization does not approve document claims. Human and protected
approval bindings remain separate and are checked exactly as before.

Every command adds deterministic `diagnostics`. Each diagnostic has `severity`,
`category`, `code`, `message`, `fields` or `paths` when applicable, and a
non-empty `recovery_actions` list. Severity is
`blocking`, `unproven`, or `warning`. Categories include
`adapter_configuration`, `receipt_format`, `scope_mismatch`,
`approval_evidence`, `freeze_invalidation`, `validation_missing`, and
`semantic_review`. Diagnostics are explanatory and do not change
`pass`/`fail`/`unproven`.

## Immutable Closeout Attestation

Use:

```bash
scripts/govern_ai_coding.py closeout adapter.json \
  --workspace /path/to/project \
  --event-manifest /safe/generated/event.json \
  --write-attestation /safe/generated/closeout-attestation.json
```

The path must satisfy the same outside-workspace or excluded-generated
boundary as receipts. An attestation is created only when all Closeout gates
already produce `pass`. Creation is atomic and exclusive; an existing
destination is never overwritten. `fail` and `unproven` leave an unused path
available for a later recovered Closeout.

Schema `govern-ai-coding.closeout-attestation.v1` binds the adapter and event
identity, baseline, actual paths, final-content digests, verified approvals,
Impact, Semantic Review, and Freeze digests, validation pointers, result reasons,
recovery, and known limitations. It includes:

```json
{
  "immutable": true,
  "derived_evidence": true,
  "generated": true,
  "project_authority": false,
  "result": "pass"
}
```

The Semantic Review binding is computed during review validation and carried
into the attestation. The attestation writer does not reread the review path
after validation.

When an event manifest is used, `receipts.closeout_attestation` is recorded
only after successful creation. The acceptance report should already name that future
path before Freeze; it does not need a post-Closeout content edit.

### Semantic Review Binding

When a task requires AI semantic review, pass a review document:

```bash
scripts/govern_ai_coding.py closeout adapter.json \
  --workspace /path/to/project \
  --receipt receipt.json \
  --changed-path STATUS.md \
  --authorized-doc STATUS.md \
  --require-semantic-review \
  --semantic-review review.json
```

The review is JSON in V1. It must include:

- four answers: `important_claims_changed`, `affected_questions`,
  `documents_agree_with_evidence`, and `remaining_uncertainty`;
- `findings`;
- each finding must include the seven semantic finding fields plus `status`;
- resolved findings require `resolution` and `resolution_evidence`.

Closeout behavior:

- missing required review: `unproven`;
- malformed review: `fail`;
- unresolved finding: `unproven`;
- resolved finding without event-authorized resolution evidence: `unproven`;
- all resolved findings with valid evidence may pass when mechanical and human
  boundaries also pass.

Mechanical checks validate structure, paths, and disposition completeness only.
They do not judge the truth of the semantic content.

## Recovery Contract

Use `result_reasons` to understand why the result is not `pass`, then execute
`recovery_actions` in order. `approval_summary` distinguishes exact required,
verified, and missing semantic types. The existing `recovery` string is retained
for callers that have not adopted the structured fields. These additions do not
change adapter schema 1 or existing command syntax.

## Semantic Finding Contract

Every semantic finding contains:

- `code`;
- `affected_question`;
- `evidence`;
- `confidence`;
- `decision_boundary`;
- `suggested_handling`;
- `human_boundary`.
