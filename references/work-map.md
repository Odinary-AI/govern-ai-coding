# Work Map

Use this reference only when the adapter declares `work_map` and the current
governed batch reads or updates that project-owned work-state authority.

The configured Markdown table is the sole work-state authority. Normalized
models, packets, patches, graphs, receipts, and attestations are derived
evidence. Commands are read-only:

```bash
python3 scripts/govern_ai_coding.py work-map check adapter.json --workspace /project
python3 scripts/govern_ai_coding.py work-map status adapter.json --workspace /project \
  --event-manifest /safe/event.json
python3 scripts/govern_ai_coding.py work-map start adapter.json --workspace /project \
  --item ITEM-01 --task-id TASK-ID
python3 scripts/govern_ai_coding.py work-map finish adapter.json --workspace /project \
  --item ITEM-01 --task-id TASK-ID --disposition completed
python3 scripts/govern_ai_coding.py work-map render adapter.json --workspace /project \
  --format mermaid
```

`start` and `finish` emit a transition packet and unified patch. They never
edit the table, allocate a task ID, assign work, or close an external task. A
same-task start is idempotent; a different active task conflicts. Vocabulary
and disposition mappings belong to the adapter.

An event manifest may bind `work_map_binding`. Its `source_digest` is the full Work Map source-table digest captured at the event baseline and is distinct
from the final `final_table_digest`. Bound Closeout requires a structured
validation receipt tied to the exact Freeze and records a final
`work_map_observation` in the attestation.

`work-map status` compares the current item with the declared immutable
attestation. Active bound work without an attestation is `unproven`. An
attestation without `work_map_observation` remains readable but cannot prove
current Work Map closure. Historical `govern-project-docs` attestations remain
evidence only.

With Event Manifest v2, status obtains the attestation only through the valid
`closeout.current` attempt. Event Manifest v1 keeps the existing
`receipts.closeout_attestation` behavior.

Read [Adapter and Result Contract](adapter-schema.md) for the complete adapter,
manifest, validation-receipt, and observation schemas. Read
[Closeout Attestation](closeout-attestation.md) only when immutable proof is a
current consumer requirement.
