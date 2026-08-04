# Adapter And Result Contract

The adapter is JSON with schema version 2. It stores pointers and rules, not current project
facts.

## Adapter Fields

- `schema_version`: string, currently `"2"`.
- `project`: project or fixture identifier.
- `navigation_entrypoint.path`: required and exactly `README.md`; this is the
  common navigation starting point for humans and AI, not an implicit semantic
  authority assignment.
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

`navigation_entrypoint`, `entrypoints`, `boundaries`, and `human_approval` are
required. `current` and `evidence` entrypoints must be non-empty lists. All path
lists contain strings. `README.md` must be covered by `ordinary_docs` and must
not be covered by protected, excluded, or historical patterns. Do not add it to
`entrypoints.current` unless a separate authority decision explicitly gives its
content that role.

Schema-1 adapters fail with `adapter-schema-migration-required`; they are never
silently defaulted. Migrate by manually establishing the root README, adding
the navigation object and ordinary-document coverage, removing boundary
conflicts, setting schema 2, then running `validate-adapter --workspace` and
`diagnose`. Existing schema-1 receipts remain readable but their adapter binding
does not match a migrated schema-2 event.

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

Authority admission remains semantic: resolve the current rule for the exact
`(question, scope)` before adding another. A peer is justified only by a
different normative question or a named authority gap. Navigation and
auto-loaded projections such as README or `AGENTS.md` do not become authorities
through visibility; a new projection points to its source and names its actual
discovery or execution consumer. There is no universal `AGENTS.md` requirement
and no static sufficiency gate for this judgment.

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
[Controlled Archive Protocol](controlled-archive.md). Adapter schema is `"2"`;
the controlled-archive additions below remain optional.

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
actions, and claim boundary. `work-map status` additionally requires an event
manifest with `work_map_binding`; it returns the current observation and its
attestation relation. Commands never mutate the workspace. The table's status
vocabulary is adapter-owned: the core maps a transition disposition to the
configured progress classification rather than treating a label as universal.
The first configured value is the canonical `start` or `finish` output, while
final observation accepts any configured value for the expected disposition.

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

`source_digest` is the full Work Map source-table digest captured at the event baseline.
It is distinct from `final_table_digest`, which records the final
table observed for the attestation.

With this binding, unplanned actual paths fail, unused planned paths warn, and
Closeout requires `govern-ai-coding.validation-receipt.v1`. That receipt must
have result `pass`, bind the canonical Freeze digest and every frozen path
digest, list passing commands and environment, and state supported and
unsupported claims. A pass Closeout attestation includes `work_map_observation`
with the binding identity plus final table and typed-item digests. Read-only
status requires that observation to match the current item and immutable
attestation. Matching also verifies the complete current attestation envelope
against the validated manifest: schema and authority markers, adapter and event
identity, final scope and content digests, receipt bindings, and the recorded
attestation path and digest. Bound work that remains in any configured active
state is `unproven`; only a proven identity or binding contradiction fails.
An older attestation without the observation remains readable, but is
`unproven` for current governance closure. Events without
`work_map_binding` retain the schema-1 legacy validation pointer behavior.

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

New receipts also bind the canonical adapter content and path. An additive
`scope_extensions` entry records the canonical parent receipt digest, exact
added paths, their preserved baseline observations, and either
`git-baseline-with-dirty-state` or `explicit-filesystem-snapshot` semantics.
The baseline inventory itself is unchanged.

The receipt is derived evidence, not project authority. Pass it to Closeout with
`--receipt` when you need filesystem or Git baseline isolation.

Impact rejects an empty scope as `unproven`. Inventory inputs fail mechanically
when schemas, source kinds, entry types, existence/digest fields, rename fields,
or receipt identity do not match the contract. Impact receipts carry
`derived_evidence: true`, `generated: true`, and `project_authority: false`.

`impact --extend-receipt ORIGINAL` is the only supported post-edit scope
extension. It requires a verified, adapter-bound Git or explicit filesystem
parent and permits only paths already observed in that parent. A Git entry
marked dirty at baseline is rejected. The command never overwrites its parent;
a manifest may adopt the derived receipt only when its embedded Impact has the
same canonical digest. Missing observation or attribution remains `unproven`
and cannot be compensated by unrelated validation.

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

A current structured receipt has this project-independent shape:

```json
{
  "schema": "govern-ai-coding.validation-receipt.v1",
  "result": "pass",
  "freeze": {"digest": "<canonical-freeze-sha256>"},
  "input_classes": ["paths"],
  "frozen_paths": [
    {"path": "relative/path", "digest": "<file-sha256>"}
  ],
  "commands": [
    {"command": "<project-selected validation>", "result": "pass"}
  ],
  "environment": {"runtime": "<identity>"},
  "supported_claims": ["<bounded claim>"],
  "unsupported_claims": ["<explicitly unsupported claim>"]
}
```

The Freeze digest is SHA-256 over its UTF-8 canonical JSON: sorted object keys,
no insignificant whitespace, and `,` / `:` separators. `frozen_paths` repeats
every Freeze path and digest; use JSON `null` for a frozen missing file. The
optional `input_classes` field enables bounded post-integration inheritance;
omitting it leaves the validation receipt usable for Closeout but supplies no
inheritable validation-input claim. Present input classes must be a non-empty
list. Commands, environment, and claim wording remain project-selected. Every
`commands[*].result` is the exact enum value `pass`; values such as `pass + 12
tests` or `pass (reviewed)` are invalid. Explanatory text belongs in another
project-owned field or evidence document, not in the result enum. A rejection
identifies each invalid command index, the expected value, and the received
value so only the receipt needs correction when its underlying evidence
remains valid.

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
- exact root `README.md`, regular readable non-empty UTF-8 content, and
  supported local links that remain within the workspace;
- mapped authority targets;
- current entrypoints;
- evidence entrypoints;
- configured plan-status conflicts;
- local Markdown links in current authority documents.

README navigation coverage is separate from current-authority link coverage.
It does not crawl the whole repository, fetch external URLs, validate heading
anchors, judge README correctness, or assign README semantic authority.

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

An evidence document may contain multiple approval blocks. Each exact
`Approval type:` field starts a separate record. A binding succeeds when any
one record of the exact bound type independently contains all four fields and
its own `Object` covers every target as a complete path token. A target embedded
inside a longer path-like value does not count. Records are evaluated in
document order and are never combined to supply fields or target coverage.
Once a record is complete, later ordinary `Object:` or `Scope:` text cannot
overwrite it.

Fail-closed evidence diagnostics are specific:

- `human-approval-type-not-recorded`: no block records the exact bound type;
- `human-approval-block-incomplete`: matching blocks exist but none contains
  all four non-empty fields;
- `human-approval-target-not-covered`: complete matching blocks exist but no
  single `Object` covers every target;
- `human-approval-block-ambiguous`: no valid block exists and a matching
  unsealed block repeats a protocol field.

These codes replace the earlier catch-all
`human-approval-scope-mismatch` for approval evidence evaluation. Adapter
schema version and `--human-approval TYPE=EVIDENCE` syntax are unchanged.

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
the existing optional mapping is made precise. Adapter schema remains `"2"`.

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

The producer that detects a finding owns its diagnostic semantics and minimum
recovery. The output boundary validates, preserves, deduplicates, and sorts
producer diagnostics; it does not replace their context or recovery action.
Existing `result`, `mechanical_findings`, `conflicts`, `checks`, component
results, and recovery fields remain present for compatibility. Ordinary CLI
JSON inputs that require objects return structured failures for unreadable
bytes, invalid JSON, arrays, and scalar roots rather than raising an uncaught
exception.

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

New attestations add the canonical adapter digest. When every frozen path
matches the current Git `HEAD`, Freeze records that commit and Closeout binds
the same value as `event.final_git_commit`. A
structured validation receipt may declare `input_classes` such as `paths`,
`adapter`, or `git-history`; its commands, environment, frozen paths, claims,
and receipt identity are copied into `validation_inputs` and rebound when the
attestation is consumed. Older attestations remain readable, but missing
additive identity or input evidence limits dependent conclusions to
`unproven`.

## Post-Integration Verification

`verify-integration` requires the source adapter, source workspace, source
event manifest, immutable attestation, target workspace, and target adapter
path. An optional Git ref reads target blobs without checkout. The result
separates attestation binding, target adapter identity, per-path content,
ancestry or unresolved-index evidence, and per-claim validation inheritance.
Only explicitly declared input classes with direct target evidence can pass;
unknown or unavailable classes remain `unproven`. Changes outside attested
paths do not invalidate content evidence. The command is read-only and does
not prove branch, release, deployment, or product readiness.

## Declared Event Preflight

`preflight-event` accepts one current event manifest and one or more explicitly
supplied peer manifests. Mutation scope is the union of `planned_paths`,
`actual_event_paths`, `governed_authority_documents`, and
`authorized_development_paths`; `evidence_only_paths` does not assert a
mutation. Exact path overlap and different tasks bound to one Work Map item are
deterministic conflicts. Dependency completion uses only the adapter's Work Map
mapping and configured completed values. Authority-rule overlap is a warning,
not proof of a conflict.

A baseline-change conflict additionally requires a valid current embedded
Impact receipt and peer Closeout evidence rebound through the peer's own
manifest and workspace. Missing, historical, malformed, wrong-event,
wrong-workspace, or wrong-scope peer evidence remains `unproven` and cannot
create that conflict. The command has no visibility beyond supplied
declarations and evidence; it does not enumerate or control sessions, tasks,
processes, branches, or worktrees and is not a scheduler or lock manager.

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

The four answers contain non-empty strings or non-empty string lists. Each
finding field except `human_boundary` is a non-empty string;
`human_boundary` is a JSON boolean. It is not automatically mapped to an
adapter approval type.

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
further change adapter schema 2 or existing command syntax.

## Semantic Finding Contract

Every semantic finding contains:

- `code`;
- `affected_question`;
- `evidence`;
- `confidence`;
- `decision_boundary`;
- `suggested_handling`;
- `human_boundary`.
