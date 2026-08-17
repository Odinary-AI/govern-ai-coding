# Integration Verification

Use this read-only capability after a governed batch has closed and been
integrated, when a consumer must check whether its bounded evidence still
applies.

```bash
python3 scripts/govern_ai_coding.py verify-integration adapter.json \
  --workspace /source/workspace \
  --event-manifest /safe/event.json \
  --attestation /safe/attestation.json \
  --source-repository /source/repository \
  --source-ref refs/heads/post-closeout \
  --target-workspace /integrated/workspace \
  --target-adapter adapter.json \
  --target-ref refs/heads/target
```

`--source-repository` and `--source-ref` are one paired explicit mode: supply
both or neither. Supplying one is a structured failure. With neither, the
positional adapter remains the legacy filesystem source adapter and all legacy
v1/v2 and `final_git_commit` behavior is retained exactly. With the pair, the
positional adapter is instead a strict source-commit-relative path, and
`--target-adapter` always identifies a repository-relative target path. In
explicit source mode, both adapter spellings are strict: absolute paths,
backslashes, dot or parent segments, and aliases are rejected. With a target
ref, the target adapter is read from that commit; without one, it is read from
the target worktree and explicit history remains `unproven`. Source and target
refs must be complete 40/64-hex object IDs or valid full `refs/...` names;
short names, revision expressions, and scans for a likely ref are not accepted.

Explicit mode resolves only the supplied source ref and the manifest baseline
in the supplied source repository. The source must be one ordinary commit
whose sole parent is exactly that baseline; source merges are unsupported. Its
literal no-rename baseline diff must equal attested `actual_paths` exactly.
The source adapter and every existing attested path must be regular source
blobs and match the attested bytes, existence, and adapter identity. Every
attested deletion must remain absent. An existing attestation
`final_git_commit` must equal this derived source commit exactly.

The recorded `event.workspace` is historical identity, not a required live
source path, and may no longer exist. Explicit mode uses one Git-tree content
observer to rebind both final content and modern Validation Receipt freshness
from source objects. It performs a safe external v1/v2 evidence preflight for
the manifest, attestation, and bound Closeout, Validation Receipt, and Semantic
Review evidence; when workspace-relative evidence cannot be observed after
workspace deletion, external evidence is required. The no-source-pair path
keeps its legacy filesystem binding.

Without `--target-ref`, target content and the target adapter are read from the
target worktree, and explicit history is `unproven`. With a ref, the verifier
reads Git blobs without checkout. In explicit mode, history passes only if the
target ref is the derived source commit or its descendant. A directly
observable non-descendant fails; missing objects, shallow history, or a target
graft boundary are `unproven`. Validation claims, including `git-history`,
inherit only when every declared input class and every directly observable
required relation passes.

For Event Manifest v2, the supplied attestation must be the attestation bound
by the mechanically valid `closeout.current` attempt. V1 retains its existing
`receipts.closeout_attestation` binding. No reader scans for a newer file.
V2 context rebinding uses that attempt's immutable receipt snapshots and
attestation bindings rather than mutable top-level retry slots. Explicit
preflight calls `current_closeout_attempt()`; top-level v2 `semantic_review`,
receipt, and actual-scope fields cannot override current. Unsafe or mismatched
evidence named by the current attestation still fails closed. V1 retains its
existing top-level attestation and Semantic Review pointer contract.

Matching bytes do not prove rewritten history. The verifier disables Git
replacement objects, rejects source graft overlays, treats target graft and
shallow non-ancestry boundaries as insufficient evidence, and clears inherited
Git repository, worktree, object, index, namespace, shallow-file, and
alternates overrides. Unknown or unobservable inputs remain `unproven`.

Before target comparison, source-context attestation rebinding uses the
`closeout-compatible-v1` Validation Receipt profile. That profile may preserve
a legacy receipt as identity-only evidence or accept a current receipt without
an inheritable input projection. Such acceptance proves neither validation
claim sufficiency nor readiness: only a bound `validation_inputs` projection
whose declared inputs are directly observable can support the verifier's
bounded per-claim result.

The verifier never merges, edits files, establishes approval, or creates event
status. Its result is derived evidence only; it does not establish integration,
branch, release, deployment, or product readiness. Read
[Closeout Attestation](closeout-attestation.md) for producer requirements and
[Adapter and Result Contract](adapter-schema.md) for exact result fields.
