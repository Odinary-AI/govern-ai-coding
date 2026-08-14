# Integration Verification

Use this read-only capability after a governed batch has closed and been
integrated, when a consumer must check whether its bounded evidence still
applies.

```bash
python3 scripts/govern_ai_coding.py verify-integration adapter.json \
  --workspace /source/workspace \
  --event-manifest /safe/event.json \
  --attestation /safe/attestation.json \
  --target-workspace /integrated/workspace \
  --target-adapter adapter.json \
  --target-ref refs/heads/target
```

Without `--target-ref`, the verifier reads the target workspace. With a ref, it
reads Git blobs without checkout. It compares only attested paths, adapter
identity, available ancestry, and explicitly declared validation input classes.

Matching bytes do not prove rewritten history. Claims inherit only when every
declared input class is directly observable and matches. Unknown or
unobservable inputs remain `unproven`.

The verifier never merges, edits files, or establishes branch, release,
deployment, or product readiness. Read
[Closeout Attestation](closeout-attestation.md) for producer requirements and
[Adapter and Result Contract](adapter-schema.md) for exact result fields.
