# Event Manifest

Use the optional versioned event manifest only when a governed batch needs
cross-task recovery, stable scope reuse, Work Map binding, integration
verification, declared-event preflight, or another consumer that explicitly
requires it. A normal single-task batch does not need a manifest.

The manifest is generated evidence, never project authority. It can bind:

- batch identity, goal, workspace, and baseline;
- planned and actual paths;
- governed authorities and authorized development paths;
- evidence-only paths and approval bindings;
- Impact, Semantic Review, Freeze, validation, attestation, and Closeout
  pointers;
- optional `work_map_binding`.

Start it at Impact and pass it to later commands:

```bash
python3 scripts/govern_ai_coding.py impact adapter.json \
  --workspace /project \
  --event-manifest /safe/event.json \
  --paths-from /safe/planned-paths.json \
  --baseline-ref HEAD
```

Direct paths, path-list files, and manifest paths form a normalized union.
`--paths-from` accepts newline text, a JSON string list, or an object containing
a path-list field. Identity, workspace, baseline, receipt, or parent-extension
mismatch fails before the manifest can carry the batch forward.

Do not create a manifest only to group receipts that have no downstream
consumer. Receipts can be supplied directly to Freeze and Closeout.

The exact fields and validation rules remain in
[Adapter and Result Contract](adapter-schema.md).
