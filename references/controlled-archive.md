# Controlled Archive Protocol

This protocol separates read-only analysis and preflight from an explicitly
authorized move. It is generic: adapters supply paths, categories, policies,
and approval types.

## Safety Model

- One source-to-target move is one independent transaction.
- A task is a sequence of independent transactions, never an atomic batch.
- Existing targets, receipts, amendments, grants, and summaries are not
  overwritten.
- Source and target SHA-256 digests must agree before the source is removed.
- Failure retains the source or performs identity-checked recovery.
- Concurrent replacements are never deleted during recovery.
- Archive bytes, historical receipts, and approval evidence are not
  automatically modified or deleted.
- Impact, Freeze, Closeout, diagnose, link checks, consistency checks, task
  completion, and session end do not authorize or invoke archive writes.
- Protected configuration changes require a separate governed event.
- Unclassified, conflicting, unreadable, unsupported, or ambiguous state is
  fail-closed.

## Trigger Boundary

Requests to inspect stale, duplicate, superseded, unconsumed, or historical
material authorize only read-only analysis. They may produce candidates,
dependency findings, risks, and confirmation requirements.

A request to assess whether something could be archived is also read-only.
Approving a candidate analysis is not approval to move it.

Execution requires all of:

1. verifiable user intent to perform the archive move;
2. an exact source, target, receipt, and authority disposition;
3. an acknowledged irreversible boundary;
4. approval evidence bound to the exact object;
5. an adapter that permits controlled archive;
6. a passing current preflight;
7. an execution grant bound to that preflight.

No fixed keyword is required in natural language. The Skill applies the
semantic boundary; the executor requires the structured grant and does not
infer intent from prose.

Candidate analysis, candidate approval, preflight, ordinary governance events,
task completion, and session end must never create, reissue, or reuse an
execution grant. A grant is created only from a current explicit user
instruction to execute the exact bound move. Its intent evidence preserves the
instruction text, binds the operation scope digest, and states that intent was
not inferred.

## Runtime Capability Gate

Read-only preflight reports:

- Python implementation and version;
- descriptor-relative open, stat, rename, and unlink support;
- no-follow, directory-open, exclusive-create, and create flags;
- existing source, target, and receipt parent availability;
- parent read/write/search access, read-only mount state, and available-space
  signals;
- operations not performed;
- state-change facts and recovery actions.

The support policy is Python 3.9 or later with all required capabilities. The
gate compares the actual runtime version; it does not rely on the policy
label. Filesystem signals are read-only checks, not a promise that capacity,
permissions, mounts, or identities cannot change later.
Preflight creates no probe files. Execution repeats the capability and identity
checks immediately before movement.

An unsupported runtime returns a structured `fail` before movement. Unexpected
command-boundary exceptions return their phase, exception type, state and
recovery facts without presenting a traceback as the normal result.

## Single-Operation Request

Schema: `govern-ai-coding.archive-request.v1`.

Required fields:

- `schema`, `schema_version`;
- `mapping.source`, `mapping.target`;
- non-empty `reason`;
- `authority_disposition.kind`, `.statement`, and `.replacement` where
  applicable;
- `approval.type`, `.evidence`;
- `references.status`, and exact legacy dispositions where required.

`authority_disposition.kind` is `replacement`, `authority-transfer`, or
`no-replacement`. The first two require an existing active replacement.

Approval evidence is an active, ordinary, non-generated document containing
non-empty `Approval type:`, `Object:`, `Scope:`, and `Does not approve:`
fields. `Object:` names the exact source and target. The executor binds the
evidence digest; it does not claim to prove human identity.

## Read-Only Preflight

Run:

```text
python3 <executor> controlled-archive <adapter> \
  --workspace <workspace> \
  --request <request> \
  --write-receipt <receipt-path> \
  --preflight
```

The receipt argument declares the proposed receipt destination; preflight does
not create it.

Schema: `govern-ai-coding.archive-preflight.v1`.

A result always includes:

- `analysis_only: true`;
- `execution_approved: false`;
- `files_moved: []`;
- `atomicity: "none-read-only"`;
- request and preflight digests;
- normalized operation bindings, including source content digest and size,
  matched archive-root identity, exact target, and receipt;
- approval digest;
- runtime report;
- complete reference summary;
- findings, unknowns, and recovery.

A passing preflight is not execution approval and can become stale.

## Execution Grant

Schema: `govern-ai-coding.archive-execution-grant.v1`.

```json
{
  "schema": "govern-ai-coding.archive-execution-grant.v1",
  "schema_version": "1",
  "mode": "execute",
  "request_sha256": "<request-digest>",
  "preflight_sha256": "<preflight-digest>",
  "approval_sha256": "<approval-evidence-digest>",
  "amendment_sha256": null,
  "operation": {
    "source": "<source-path>",
    "target": "<archive-target>",
    "receipt": "<receipt-path>",
    "source_sha256": "<source-content-digest>",
    "source_size": 0,
    "archive_root_sha256": "<matched-archive-root-identity>",
    "authority_disposition_sha256": "<disposition-digest>"
  },
  "intent_evidence": {
    "kind": "explicit-user-execution-instruction",
    "statement": "<current-user-instruction-to-execute-this-exact-move>",
    "scope_sha256": "<canonical-operation-digest>",
    "not_inferred": true
  },
  "boundaries": {
    "irreversible_move_acknowledged": true,
    "single_file_independent_transaction": true,
    "no_multi_file_atomicity": true,
    "no_overwrite": true
  }
}
```

Every value is copied from the current preflight. The intent scope digest is
the canonical digest of `operation`. Any mismatch, source-content change, or
missing non-inferred intent evidence blocks before movement.

Execute:

```text
python3 <executor> controlled-archive <adapter> \
  --workspace <workspace> \
  --request <request> \
  --write-receipt <receipt-path> \
  --execution-grant <execution-grant>
```

`--amendment <mapping-amendment>` is optional and valid only under the
amendment rules below. It must be accompanied by
`--original-execution-grant <original-grant>` so the immutable linkage can be
verified.

## Reference Classification

Every discovered reference contains:

- path, line, and column;
- text or local-link match form;
- scanned selector and scope;
- category and handling;
- disposition and required action.

Minimum categories:

- `current-dependency`: current content that depends on the source;
- `governance-authorization`: authorization or scope declaration;
- `audit-trace`: approval, receipt, audit, or historical trace.

Categories are extensible adapter values. Handling is:

- `disposition-required`;
- `trace-only`;
- `human-review`.

An adapter rule contains `id`, `selectors`, optional `patterns`, `category`,
and `handling`. Rules are ordered data, not hard-coded project directories.
Unknown or multiple matching classifications require human review and block.
A governance authorization with `trace-only` handling is not treated as a
current dependency.

Failure and unproven results retain `discovered`, `scanned_scopes`,
`blocking`, and `required_actions`, so callers do not need an internal scanner.

## Task Manifest and Global Preflight

Schema: `govern-ai-coding.archive-task.v1`.

`operations` is a variable-length non-empty list. Each operation has a unique
`id`, one complete archive request, an unused receipt path, and an optional
mapping amendment.

```json
{
  "schema": "govern-ai-coding.archive-task.v1",
  "schema_version": "1",
  "operations": [
    {
      "id": "<operation-id>",
      "request": {
        "schema": "govern-ai-coding.archive-request.v1",
        "schema_version": "1",
        "mapping": {
          "source": "<source-path>",
          "target": "<archive-target>"
        },
        "reason": "<exit-reason>",
        "authority_disposition": {
          "kind": "no-replacement",
          "statement": "<authority-disposition>"
        },
        "approval": {
          "type": "<approval-type>",
          "evidence": "<approval-evidence>"
        },
        "references": {
          "status": "updated",
          "legacy": []
        }
      },
      "receipt": "<receipt-path>"
    }
  ]
}
```

Repeat the operation object for the required scope; the protocol defines no
fixed task size.

Run:

```text
python3 <executor> archive-task preflight <adapter> \
  --workspace <workspace> \
  --manifest <task-manifest> \
  --write-summary <optional-unused-summary-path> \
  --previous-summary <optional-predecessor-summary>
```

Global preflight checks every single operation plus duplicate sources,
targets, receipts, cross-role aliases, conservative Unicode/case-fold name
collisions, occupied destinations, exact per-operation preflight bindings,
approval coverage, reference dispositions, runtime capability, optional task
summary output, predecessor digest, and predictable stop conditions before any
move. A summary output must not alias a source, target, or individual receipt.

It is read-only, moves no file, grants no execution authority, and reports
`task_atomicity: "non-atomic-independent-operations"`.

## Task Execution, Status, and Resume

Task grant schema:
`govern-ai-coding.archive-task-execution-grant.v1`.

It binds the manifest digest, global preflight digest, the exact operation ID
set, every single-operation grant, task-summary binding, and an
`intent_evidence` object whose scope digest covers the manifest digest and
sorted operation IDs. It also binds these boundaries:

- independent single-file transactions;
- no multi-file atomicity;
- no rollback of completed operations;
- no scope extension.

```json
{
  "schema": "govern-ai-coding.archive-task-execution-grant.v1",
  "schema_version": "1",
  "mode": "execute",
  "manifest_sha256": "<manifest-digest>",
  "preflight_sha256": "<global-preflight-digest>",
  "operation_grants": {
    "<operation-id>": {
      "schema": "govern-ai-coding.archive-execution-grant.v1",
      "schema_version": "1",
      "mode": "execute",
      "request_sha256": "<request-digest>",
      "preflight_sha256": "<operation-preflight-digest>",
      "approval_sha256": "<approval-digest>",
      "amendment_sha256": null,
      "operation": "<exact-operation-object>",
      "intent_evidence": "<exact-operation-intent-evidence>",
      "boundaries": "<single-operation-boundaries>"
    }
  },
  "intent_evidence": {
    "kind": "explicit-user-execution-instruction",
    "statement": "<current-user-instruction-for-this-exact-task>",
    "scope_sha256": "<digest-of-manifest-digest-and-sorted-operation-ids>",
    "not_inferred": true
  },
  "boundaries": {
    "independent_single_file_transactions": true,
    "no_multi_file_atomicity": true,
    "no_completed_operation_rollback": true,
    "no_scope_extension": true
  }
}
```

Run:

```text
python3 <executor> archive-task execute <adapter> \
  --workspace <workspace> \
  --manifest <task-manifest> \
  --execution-grant <task-grant> \
  --write-summary <same-preflighted-unused-summary-path> \
  --previous-summary <same-preflighted-predecessor-summary>
```

Each pending operation reruns preflight immediately before its independent
transaction. A preflight snapshot may be mechanically refreshed only when the
request, approval, mapping, disposition, and task scope remain exact; the
refreshed digest is recorded in the individual receipt.

On failure:

- completed operations are not rolled back;
- verified receipts identify completed operations only after schema,
  immutability, authorization, request, mapping, source absence, target
  content, and receipt-file checks all agree;
- completed sources are not processed again;
- resume considers only failed and not-started operations;
- an uncaught execution exception with unknown filesystem outcome is reported
  as `execution-outcome-unknown`, with `resumable: false`, rather than as an
  ordinary execution failure;
- before retrying an unknown outcome, run read-only `archive-task status`; only
  a passing operation preflight that proves the expected source remains and no
  target or receipt exists may transition it to `preflight-passed` and
  `resumable: true`;
- if status finds a target, receipt, changed source, unreadable state, or any
  other blocker, the operation remains non-resumable until the state is safely
  reconciled; do not re-execute it speculatively;
- an ordinary `execution-failed` result that already proves the operation did
  not complete remains resumable;
- new objects or targets require a new grant;
- the summary continues to state non-atomicity.

Read current state without movement:

```text
python3 <executor> archive-task status <adapter> \
  --workspace <workspace> \
  --manifest <task-manifest>
```

Task summary schema:
`govern-ai-coding.archive-task-summary.v1`.

States include not started, preflight passed, awaiting authorization,
completed with verified receipt, execution failed, execution outcome unknown,
revision required, and resumable. The unknown state is independently visible
through normalized results and never implies permission to retry. Summary
publication is exclusive; a later generation uses another path and passes its
predecessor during preflight rather than overwriting it. Each summary binds the
manifest, global preflight, task grant, operation request digests, and verified
individual receipt digests.

## Immutable Mapping Amendment

Schema: `govern-ai-coding.archive-mapping-amendment.v1`.

An amendment records:

- original grant digest;
- original and corrected mappings;
- original and corrected matched archive-root identity digests;
- adapter policy ID;
- reason;
- unchanged authority, visibility, archive-root class, approval type, and
  recovery boundary;
- independent supplemental evidence path and digest.

Its root binding is explicit:

```json
{
  "archive_root_binding": {
    "original_sha256": "<original-matched-root-identity>",
    "corrected_sha256": "<corrected-matched-root-identity>"
  }
}
```

The supplemental evidence also carries the adapter-declared supplemental
approval type and records `Approval type:`, `Original object:`,
`Corrected object:`, `Reason:`, and `Does not approve:` fields.

Only adapter-declared changed fields are eligible. A source, authority,
visibility, actual archive-root identity, archive-root class, approval,
recovery-boundary, or operation-set change returns
`new-explicit-approval-required`. A generic class label cannot make different
roots equivalent. The executor never invents an amendment or rewrites the
original approval.

## Authorization Lifecycle

Run:

```text
python3 <executor> archive-authorization-status <adapter> \
  --workspace <workspace> \
  --authorization-id <optional-authorization-id>
```

The read-only report distinguishes active use from no active covered objects,
recommends retain or review-expiry/closure, and explains retention impact.
`configuration_changed` is always false. Closing or changing authorization is
a separate protected configuration event with new approval.

Each authorization scope must be contained by a configured active source root
and must not overlap excluded, protected, historical, or archive roots.

Task completion, Closeout, and session end never imply authorization closure.

## Normalized Result Reading

Run:

```text
python3 <executor> normalize-archive-result --input <result-or-receipt>
```

Schema: `govern-ai-coding.normalized-result.v1`.

The parser accepts legacy command results, legacy archive receipts, wrapped
receipts, and new task results. It returns a stable verdict, phase, operation
state, changed flag, atomicity, authorization state, receipt bindings,
diagnostics, and recovery without modifying the input. Conflicting legacy
status fields normalize to `unproven`. Historical task results whose nested
state changes require inspection normalize to `unproven` with operation state
`execution-outcome-unknown`, even if an older embedded normalized view called
them an execution failure; the historical input is not rewritten.

Existing root `result` and receipt `execution.result` fields remain available
for old consumers.

## Project-Independent Read-Only Example

The user asks to inspect whether active material is stale or potentially
archivable. The Skill performs dependency and candidate analysis and may run
preflight only after a complete proposed mapping is available. A conforming
placeholder request is:

```json
{
  "schema": "govern-ai-coding.archive-request.v1",
  "schema_version": "1",
  "mapping": {
    "source": "<source-path>",
    "target": "<proposed-archive-target>"
  },
  "reason": "<candidate-exit-reason>",
  "authority_disposition": {
    "kind": "no-replacement",
    "statement": "<proposed-authority-disposition>"
  },
  "approval": {
    "type": "<approval-type>",
    "evidence": "<approval-evidence>"
  },
  "references": {
    "status": "updated",
    "legacy": []
  }
}
```

The outcome states:

```json
{
  "analysis_only": true,
  "execution_approved": false,
  "files_moved": [],
  "atomicity": "none-read-only"
}
```

It returns candidates, reference locations, risks, and missing confirmation.
It does not create an execution grant or call a write command.

## Project-Independent Authorized Execution Example

The user explicitly directs movement of `<source-path>` to
`<archive-target>`, confirms `<receipt-path>`, acknowledges that the operation
is irreversible and that a task is non-atomic, and supplies
`<approval-evidence>` covering that exact mapping.

The caller:

1. runs read-only preflight;
2. copies the exact returned digests and operation into an immutable execution
   grant, records the current explicit user instruction in `intent_evidence`,
   and binds its scope digest to that exact operation;
3. submits the request, unused receipt path, and grant to the execute command;
4. accepts success only when the individual receipt reports matching before
   and after digests and `execution.result: "pass"`.

The executor moves only that bound source. It does not extend authorization,
overwrite a target, edit the archive, close authorization, or modify protected
configuration.
