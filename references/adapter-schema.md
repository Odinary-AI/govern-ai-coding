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

Closeout and archive commands may project their completed producer payloads as
`govern-ai-coding.compact-result.v1` when `--compact` is explicit. The
projection retains result/verdict, phase, recovery, approvals, receipt
bindings, and every structured diagnostic occurrence. It groups occurrences
by existing severity, category, code, and recovery actions and lists omitted
top-level producer fields. The projection does not change producer payload
construction, receipt or summary files, filesystem state, or process status.
Full output remains the default and there is no global finding registry.

## Canonical Evidence Digest Profiles

Canonical JSON digests are protocol fields, not the formatting of JSON files or
CLI output. Existing v1 contracts use two profiles and must not be normalized
into one:

- **Evidence v1 / ASCII-escaped:** `json.dumps(value, sort_keys=True,
  separators=(",", ":"))`, UTF-8 encoding of that text, then SHA-256. Python's
  default `ensure_ascii=True` is part of this profile.
- **Controlled Archive v1 / literal UTF-8:** the same operation with
  `ensure_ascii=False` before UTF-8 encoding and SHA-256.

Both profiles sort keys recursively, omit insignificant whitespace, and encode
JSON `null`, `true`, and `false` in the normal JSON form. They produce identical
digests for ASCII-only values and different digests when a string or key
contains non-ASCII characters. Neither profile performs Unicode normalization.
Consumers must call the profile owned by their protocol; equal output for an
ASCII fixture does not prove that two protocols are interchangeable.

### Schema Producer And Consumer Inventory

| Schema or object | Producer | Digest consumer or binding | Profile |
| --- | --- | --- | --- |
| adapter schema 2 | project owner; validated by the core CLI | Impact `adapter_binding`, Closeout Attestation `adapter.digest`, integration verification | Evidence v1 |
| `govern-ai-coding.inventory.v1` | core Git/filesystem inventory | Impact and Closeout; no standalone inventory identity, but bytes become part of a digested Impact receipt | Evidence v1 when the containing receipt is bound |
| `govern-ai-coding.receipt.v1` | core Impact | scope extension, Event Manifest, Closeout, declared-event preflight, Closeout Attestation | Evidence v1 |
| `govern-ai-coding.freeze-receipt.v1` | core Freeze | Validation Receipt, Closeout, Closeout Attestation | Evidence v1 |
| `govern-ai-coding.event-manifest.v1` | core Impact/Freeze/Closeout updates | core phase reuse, declared-event preflight, Work Map status, integration verification | No standalone canonical digest field in v1; deterministic file serialization is not an identity profile |
| `govern-ai-coding.event-manifest.v2` | core Impact/Freeze/Closeout updates | core phase reuse; explicit current-attempt reading by declared-event preflight, Work Map status, and integration verification | No standalone manifest digest; attempts bind their receipts and optional attestations with Evidence v1 |
| `govern-ai-coding.semantic-review.v1` | reviewing task | core validation, Closeout, Closeout Attestation | Evidence v1 |
| `govern-ai-coding.validation-facts.v1` | project validation workflow | Validation Receipt builder | No standalone canonical digest; selected fields are copied into the receipt |
| `govern-ai-coding.validation-receipt.v1` | Closeout evidence owner | Closeout, attestation binding, integration verification | Evidence v1 |
| `govern-ai-coding.closeout-receipt.v1` | core Closeout | caller, v1 result projection, and v2 attempt binding | Evidence v1 when bound by a v2 attempt; no standalone digest field in v1 |
| `govern-ai-coding.closeout-attestation.v1` | Closeout evidence owner | declared-event preflight and integration verification | Evidence v1 |
| `govern-ai-coding.compact-result.v1` | core presentation boundary | opt-in CLI caller | No standalone canonical digest field |
| `govern-ai-coding.archive-request.v1` | archive request author | archive preflight, execution grant, task preflight and reconciliation | Controlled Archive v1, except the retained Archive Receipt v1 field below |
| `govern-ai-coding.archive-preflight.v1` | Controlled Archive owner | execution-grant validation | Controlled Archive v1 for `preflight_sha256` |
| `govern-ai-coding.archive-execution-grant.v1` | explicitly authorized archive workflow | core archive execution and receipt authorization | Controlled Archive v1 |
| `govern-ai-coding.archive-receipt.v1` | core archive executor | task resume/status/reconciliation and Task Summary | Mixed retained v1 contract: whole-receipt and grant bindings use Controlled Archive v1; `request_sha256` produced by the core executor uses the legacy ASCII-escaped profile |
| `govern-ai-coding.archive-task.v1` | archive task author | global/task preflight, task grant, reconciliation | Controlled Archive v1 |
| `govern-ai-coding.archive-task-preflight.v1` | Controlled Archive/core task preflight | task execution grant and task execution | Controlled Archive v1 |
| `govern-ai-coding.archive-task-execution-grant.v1` | explicitly authorized archive workflow | core task execution and per-operation grant refresh | Controlled Archive v1 |
| `govern-ai-coding.archive-task-summary.v1` | historical Controlled Archive task reconciliation | current normalizer and resume/status readers | Controlled Archive v1 for embedded manifest/receipt bindings; any previous-summary file link is raw file SHA-256 |
| `govern-ai-coding.archive-task-summary.v2` | current Controlled Archive task reconciliation | current normalizer and resume/status readers | Controlled Archive v1 for manifest, receipt-object, and execution-result bindings; any previous-summary file link is raw file SHA-256 |
| `govern-ai-coding.archive-mapping-amendment.v1` | explicitly authorized archive workflow | archive preflight, grant refresh, receipt authorization | Controlled Archive v1 |
| `govern-ai-coding.normalized-result.v1` | Controlled Archive result normalizer | core/archive presentation and recovery callers | No standalone canonical digest field |
| Work Map typed item | Work Map parser | Closeout observation and Work Map status | Evidence-v1 byte profile, owned separately as the Work Map item-v1 digest |
| Work Map source table | Work Map parser | Impact baseline, Closeout observation, status | Raw selected table bytes, not canonical JSON |
| Skill package identity | core `--version` | runtime mismatch diagnosis | Ordered relative paths and raw file bytes, not canonical JSON |
| governed file content | inventory, Freeze, archive and integration observers | isolation, final-content and archive-content checks | Raw file bytes, not canonical JSON |
| `govern-project-docs.closeout-attestation.v1` | historical predecessor | integration verifier's compatibility reader | Read-only historical envelope; missing modern evidence-v1 identity limits conclusions to `unproven` |
| `govern-ai-coding.publication-verification.v1` | external release workflow | human/release audit only | No runtime producer, consumer, or canonical JSON identity in this Skill |

The Archive Receipt v1 exception is intentionally explicit. For a non-ASCII
archive request, its retained ASCII-escaped `request_sha256` does not equal the
literal-UTF-8 request digest expected by current archive reconciliation. Batch A
does not rewrite that v1 field. A compatible repair requires a new schema or an
explicit migration contract rather than silently changing an existing digest.

`canonical_evidence_v1_digest` in `closeout_evidence.py` owns the shared
evidence contract used by the core CLI and integration verifier.
`canonical_archive_v1_digest` in `controlled_archive.py` owns the archive
contract. `legacy_archive_receipt_v1_request_digest` exists only for the
retained Archive Receipt v1 producer behavior. The main CLI also retains
`archive_protocol_digest` as a module-level compatibility alias for existing
callers; new archive code uses the versioned owner name.

These profiles describe the current Python implementation and constrained
payloads. They do not claim cross-language portability for unconstrained
numbers, Unicode normalization equivalence, or compatibility for a producer
that changes JSON type semantics.

## Controlled Archive Contract

The complete request, grant, preflight, task, amendment, receipt, lifecycle,
result-normalization, and migration contracts are in
[Controlled Archive Protocol](controlled-archive.md). Adapter schema is `"2"`;
the controlled-archive additions below remain optional.

New archive task summaries use
`govern-ai-coding.archive-task-summary.v2`. Verified successful operations
retain receipt path/digest and execution-result digest references rather than
duplicating the complete success envelope. Failed, unknown, or unbound results
remain complete, individual receipts remain self-contained, and v1 summaries
remain readable.

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

The standalone builder accepts
`govern-ai-coding.validation-facts.v1`: exact `pass` result, non-empty unique
`input_classes`, non-empty commands whose results are exactly `pass`, a
non-empty environment object, and non-empty supported and unsupported claim
lists. It copies those fields and binds the canonical Freeze digest plus every
frozen path digest into the existing V1 receipt. It does not execute commands,
parse their output, or infer claims. Builder output is create-only and must be
adapter-excluded or outside project authority. See
`validation-facts-example.json` for the packaged input shape.

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

### Validation Receipt Consumer Profiles

`VALIDATION_CONSUMER_PROFILES` in `closeout_evidence.py` is the centralized
versioned registry for current consumers. Every new internal validation or
collection call must name a profile; the old boolean Python entrypoints remain
deprecated compatibility wrappers and are not used by production callers.
Each registered profile mechanically declares its consumers and purpose,
requirements on four independent axes, compatible omissions, supported and
unsupported conclusions, and reopen and sunset conditions. Machine-readable
`mode` and `required_when` values are checked against the implemented policy
set on every profile evaluation; unknown profiles or drift between registry
and implementation fail before receipt evaluation.

The axes are orthogonal and each reports `pass`, `fail`, or `unproven`:

- **structure** checks the receipt schema and required field shapes plus any
  supplied Freeze schema/kind required by the selected profile;
- **binding** checks the receipt's exact Evidence-v1 Freeze digest relation;
- **content** checks valid path/digest entries and the receipt projection
  against the supplied Freeze;
- **freshness** checks the relevant frozen bytes against the current workspace.

They are not a linear evidence state machine. An optional or compatibility
axis may remain `unproven` while the profile accepts the receipt. Acceptance
means the receipt is mechanically usable by that consumer; only the profile's
explicit supported conclusions may be carried forward. Acceptance never means
that commands were executed or that a batch, product, release, or deployment
is ready.

| Profile | Current consumers | Required checks | Compatible omissions | Supported boundary |
| --- | --- | --- | --- | --- |
| `standalone-freeze-bound-v1` | `validate-validation-receipt` | current structure; exact complete-Freeze digest and path projection | `input_classes` may be absent | structure and exact supplied-Freeze binding only; freshness is `unproven` |
| `closeout-compatible-v1` | ordinary Closeout; Closeout Attestation source rebinding; Integration Verification trust preflight | current-V1 structure; freshness only when a complete modern input projection exists | legacy string-schema receipts remain identity-only; current receipts may omit `input_classes`; receipt-to-Freeze binding is not required | receipt identity, plus current listed bytes for a complete modern projection; identity-only acceptance supports no validation claim |
| `work-map-closeout-v1` | Closeout only when the Event Manifest has `work_map_binding` | current structure; exact supplied-Freeze digest and projection; every supplied frozen path is current | supplied Freeze kind may be omitted on the retained partial-Freeze path; `input_classes` may be absent | exact supplied-Freeze relation and current supplied paths; enclosing Closeout must separately prove that Freeze is the event's complete valid Freeze |

The ordinary profile is selected even when an Event Manifest is present; the
Work Map binding, not manifest presence, selects `work-map-closeout-v1`.
`work-map-closeout-v1` pass implies the same modern receipt is accepted by
`closeout-compatible-v1`. No general implication exists from standalone pass
to compatible pass because the standalone consumer deliberately does not read
workspace bytes.

Removing required receipt evidence, changing its Freeze binding or projection,
or making checked workspace content stale cannot strengthen a profile result.
An `unproven` axis is never promoted to `pass` merely because the profile
permits that omission. Reopen a profile conclusion whenever the inputs named
by its registry entry change. Retire a V1 profile only through the entry's
sunset condition and an explicit receipt migration contract; do not silently
reinterpret historical V1 receipts.

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

## Read-only Event Audit

`audit-event <adapter> --workspace <path> --event-manifest <manifest>` accepts
Event Manifest v2 only. It validates the adapter and manifest, then selects
the current Closeout evidence exclusively through the manifest's explicit
`closeout.current` pointer and `current_closeout_attempt()`. It never scans an
evidence directory, infers a conventional filename, compares timestamps, or
falls back from a stale pointer to a nearby file.

The command revalidates the current attempt's receipt path, schema, canonical
Evidence-v1 digest, result and Freeze binding; the receipt's complete Impact
and Freeze snapshots; adapter, workspace and baseline identity; current frozen
workspace bytes; and, when present, the attestation path, schema, digest and
complete source-context binding. Relative evidence paths retain the v2
manifest-directory rules. Missing, unsafe, symlinked, hardlinked,
wrong-schema, wrong-digest, stale-content or identity-mismatched evidence fails
closed. An empty valid ledger is `unproven`; a malformed or contradictory
ledger is `fail`.

Output schema `govern-ai-coding.audit-event-result.v1` separates checks,
mechanical findings, supported claims, unsupported claims and recovery. A
valid current receipt can pass without an optional attestation while portable
attestation claims remain explicitly unsupported. Event Manifest v1 returns
`unproven` with `audit-event-v1-unsupported`; it is never guessed, rewritten or
silently upgraded. The command is strictly read-only, does not require
`fcntl`, writes no receipt or manifest, and never installs a package. Its pass
does not prove actor identity, semantic truth, human approval, release,
deployment, product acceptance or readiness.

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

Event Manifest v1 (`govern-ai-coding.event-manifest.v1`, version `"1"`) and v2
(`govern-ai-coding.event-manifest.v2`, version `"2"`) are generated event
evidence and must not become project authority. Existing v1 objects are read
and updated with their existing semantics; they are never automatically
rewritten or upgraded. The v1 minimum object remains:

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

### Event Manifest v2 Closeout ledger

V2 retains the v1 `event`, `scope`, `approvals`, `semantic_review`, optional
`work_map_binding`, and `receipts.impact`, `.freeze`, and `.validation` fields.
It removes `receipts.closeout_attestation` and replaces the overwriteable v1
Closeout result slot with one append-only ledger:

```json
{
  "schema": "govern-ai-coding.event-manifest.v2",
  "schema_version": "2",
  "closeout": {
    "attempts": [
      {
        "id": "batch-c-closeout-01",
        "result": "pass",
        "result_reasons": ["all-closeout-gates-satisfied"],
        "recovery_actions": ["preserve immutable evidence"],
        "receipt": {
          "path": "attempts/batch-c-closeout-01.json",
          "schema": "govern-ai-coding.closeout-receipt.v1",
          "digest": "64 lowercase hexadecimal characters"
        },
        "freeze_digest": "64 lowercase hexadecimal characters",
        "attestation": null
      }
    ],
    "current": "batch-c-closeout-01"
  }
}
```

`attempts` is the only v2 Closeout ledger. V2 rejects parallel
`closeout.result`, `result_reasons`, or `recovery_actions` projections and the
v1 attestation slot. Each attempt ID matches
`[A-Za-z0-9][A-Za-z0-9._-]{0,127}` and is supplied explicitly with
`closeout --attempt-id`; it is an audit identity, not a timestamp or inferred
ordering key. V2 also requires `--write-receipt`. Recorded duplicate IDs,
receipt paths, or attestation paths fail. An unrecorded existing destination is
reusable only when rereading proves the complete JSON object and canonical
Evidence-v1 digest are identical; no evidence file is overwritten. A
post-link interruption alias is cleaned only after its controlled temp name,
same-directory inode identity, canonical payload, and complete link count all
match; any unrecognized alias fails closed.

Every attempt binds a real `govern-ai-coding.closeout-receipt.v1` file, its
schema and canonical Evidence-v1 digest, the exact final `pass`, `fail`, or
`unproven` result, and the receipt's additive canonical Impact and Freeze
snapshots. The complete Freeze snapshot's digest, kind, adapter, workspace,
paths, derived markers, and Closeout final-content projection are checked. Optional
attestations must be pass attestations with matching schema and digest and may
appear only on pass attempts. Relative evidence paths resolve from the event
manifest directory. Absolute paths must be canonical. Parent escapes, symlink
or hardlink alias traversal, repeated or dot path aliases, missing or
non-regular files, and in-workspace evidence
outside adapter-excluded boundaries fail.

`current` is either JSON `null` when no valid pass exists or the ID of the last
mechanically valid pass appended to `attempts`. A pass receipt must already be
persisted and reread before its attempt can be appended. A requested
attestation must likewise be persisted and reread first. The candidate attempt
and `current` advance in one locked compare-and-swap against the exact loaded
manifest; Impact and Freeze use the same stale-writer guard. A fail or unproven
attempt appends without clearing or downgrading an earlier valid current.
Receipt, attestation, or manifest publication failure creates no attempt; any
already persisted, unreferenced, canonically equivalent evidence can be strictly
rebound by the retry.

The CLI does not require `fcntl` merely to import or run v1 and read-only v2
paths. V1 manifest updates keep their existing atomic-file semantics when that
module is absent. A v2 manifest write, including Impact, Freeze, or Closeout,
requires the inter-process lock that protects its compare-and-swap. Without
that capability it returns structured `fail` with
`event-manifest-lock-unavailable`, leaves the manifest unchanged, and never
uses an unlocked fallback. A v2 write also requires the exact raw canonical
digest of the loaded snapshot; omitting it returns
`event-manifest-cas-required` instead of performing a non-CAS replacement. If
an existing destination is unreadable, a legacy candidate also fails closed
because the writer cannot prove that the destination is non-v2.

Validators check attempt uniqueness, current referential integrity, result,
schema, canonical digest, Freeze binding, optional attestation binding, and
path safety for every attempt. `current_closeout_attempt()` is the mechanical
read-only API for later consumers: it returns only the explicitly pointed
attempt and its rebound Closeout receipt/attestation bindings. It never scans a
directory, chooses the greatest timestamp, or guesses a filename. Work Map
status, declared-event preflight, and Integration Verification retain their v1
pointer behavior and use this helper for v2. V2 attestation rebinding uses the
current receipt's immutable Impact/Freeze snapshots and the attestation's own
Semantic Review and validation bindings, not mutable top-level review or
receipt slots. Integration Verification resolves this context through
`current_closeout_attempt()`; top-level v2 actual scope cannot override the
current receipt's final-content paths. V1 keeps its existing top-level pointer
contract.

| Consumer or update | Event Manifest v1 | Event Manifest v2 |
| --- | --- | --- |
| Impact | Updates normalized planned scope and embedded Impact receipt | Same fields; schema remains v2 |
| Freeze | Updates actual scope, Freeze, and validation pointers | Same fields; preserves attempts/current |
| Closeout | Replaces `closeout.result` details and may set `receipts.closeout_attestation` | Appends one unique attempt; valid pass atomically advances `current` |
| Attestation binding | Reads `receipts.closeout_attestation` | Reads only current attempt's attestation binding |
| Work Map status | Existing v1 pointer behavior | Reads only validated `current` |
| Declared-event preflight | Existing declarations and v1 peer pointer | Same declarations; peer proof only through validated `current` |
| Integration Verification | Rebinds supplied attestation to v1 pointer | Supplied attestation must equal validated current binding |

## Path Authorization And Diagnostics

Use `--authorized-path` for the event's writable paths. The former
`--authorized-doc` spelling remains a compatibility alias and emits
`authorized-doc-deprecated`. Both feed the compatibility
`closeout.authorized_docs` field; `closeout.authorized_paths` is the precise
additive name.

Repeatable `--authorized-paths-from` reuses the strict `--paths-from` file
formats and path normalization, but its values are unioned only into
authorization. They never add changed or actual event scope. Missing,
malformed, or unsafe inputs fail before a Closeout receipt or attestation is
written.

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

`verify-integration` requires a source adapter, recorded event workspace,
event manifest, immutable attestation, target workspace, and target adapter
path. `--source-repository` and `--source-ref` are paired: neither retains the
exact legacy filesystem behavior, while one alone is a structured failure. In
explicit mode the positional source adapter and target adapter are strict
repository-relative paths, and refs are only full OIDs or valid full
`refs/...` names. Revision expressions and discovery scans are not inputs.

The derived source commit must have one sole parent equal to the manifest
baseline; source merge commits are unsupported. Its no-rename diff paths must
equal `actual_paths` exactly, and its regular blobs must match final-content
existence and bytes plus adapter identity. An existing `final_git_commit` is
accepted only when it equals the derived commit. The recorded
`event.workspace` remains identity and may be absent. One Git-tree content
observer rebinds final content and modern Validation Receipt freshness from
source objects. Explicit v1/v2 mode safely preflights external bound evidence,
which is required after workspace deletion when workspace-relative evidence is
not observable; legacy callers retain their filesystem behavior.

The result separates source identity, attestation binding, target adapter
identity, per-path content, ancestry, and per-claim validation inheritance. A
target ref passes history only when it is the derived source commit or a
descendant. A direct non-descendant is `fail`; unavailable objects and
shallow/graft boundaries are `unproven`. `git-history` and other claims inherit
only after all directly observable required relations pass. Git replacement,
graft, and inherited Git repository/worktree/object/index/namespace/shallow
environment redirection cannot alter observation. The command is read-only
derived evidence, not approval, status, branch, release, deployment, or
product-readiness authority.

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

With Event Manifest v1, `receipts.closeout_attestation` is recorded only after
successful creation. With v2, the binding is recorded only in the new pass
attempt and is selected only through `closeout.current`. The acceptance report
should already name that future path before Freeze; it does not need a
post-Closeout content edit.

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

The review is JSON in V1. Run standalone shape preflight when useful:

```bash
scripts/govern_ai_coding.py validate-semantic-review review.json
```

The standalone command checks shape only. The packaged
`semantic-review-example.json` is the canonical complete example consumed by
documentation and tests. A valid review must include:

- exact schema `govern-ai-coding.semantic-review.v1`;
- four answers: `important_claims_changed`, `affected_questions`,
  `documents_agree_with_evidence`, and `remaining_uncertainty`;
- `findings`;
- each finding must include the seven semantic finding fields plus `status`;
- resolved findings require `resolution` and `resolution_evidence`.

The four answers contain non-empty strings or non-empty string lists. Each
finding core field except `human_boundary` is a non-empty string;
`human_boundary` is a JSON boolean. `status` is exactly `resolved` or
`unresolved`. Resolved findings require non-empty string `resolution` and
`resolution_evidence`; unresolved findings may omit them, but supplied values
must still be non-empty strings. `human_boundary` is not automatically mapped
to an adapter approval type.

Standalone preflight does not check event paths or authorization and does not
turn unresolved findings into a Closeout pass. Closeout reuses the same shape
validator and then applies contextual resolution-evidence binding.

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
