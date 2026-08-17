# Closeout Attestation

Use an immutable Closeout attestation only when a release, audit, integration,
Work Map, or external handoff consumer requires portable proof. A normal local
governed batch can finish with a passing Closeout receipt alone.

Before Freeze, write any human-facing acceptance report with its validation
facts, governance status pending, and future attestation path. Do not edit that
report after Freeze merely to add the result.

After Closeout passes, create the separate attestation with
`--write-attestation`. Closeout never creates one for `fail` or `unproven` and
never overwrites an existing destination.

Event Manifest v1 records the created attestation in
`receipts.closeout_attestation`. Event Manifest v2 records it only inside the
new pass attempt and exposes it through `closeout.current`; consumers must not
fall back to directory scanning or the removed v1 slot.
For v2, rebinding uses the current Closeout receipt's immutable Impact and
Freeze snapshots plus the attestation's own validation bindings. Later retry
updates to top-level receipt slots cannot redefine the historical current.

The attestation binds:

- adapter and batch identity;
- Impact, required Semantic Review, Freeze, and validation receipts;
- actual paths and final content digests;
- optional validation input classes;
- optional final Work Map observation;
- the final Git commit identity when available under the protocol.

Closeout selects `closeout-compatible-v1` for ordinary validation receipts and
`work-map-closeout-v1` only when the Event Manifest carries a Work Map binding.
The later source-context rebinding step uses `closeout-compatible-v1` to
preserve historical identity behavior. A receipt accepted only as legacy or
capability-limited evidence remains a binding with no validation-input
projection; it therefore cannot support an inherited validation claim.
Attestation binding and profile acceptance are not readiness conclusions.

Attestations are immutable derived evidence, not project authority. Do not
generate one without a named downstream consumer. Read
[Adapter and Result Contract](adapter-schema.md) for the exact schema and
[Integration Verification](integration-verification.md) when checking an
integrated result.
