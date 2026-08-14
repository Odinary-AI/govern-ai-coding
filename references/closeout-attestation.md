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

The attestation binds:

- adapter and batch identity;
- Impact, required Semantic Review, Freeze, and validation receipts;
- actual paths and final content digests;
- optional validation input classes;
- optional final Work Map observation;
- the final Git commit identity when available under the protocol.

Attestations are immutable derived evidence, not project authority. Do not
generate one without a named downstream consumer. Read
[Adapter and Result Contract](adapter-schema.md) for the exact schema and
[Integration Verification](integration-verification.md) when checking an
integrated result.
