# Governed Batch Workflow

Use this reference after GAC applies and a governed batch must be opened,
extended, finalized, or recovered.

## Batch Boundary

A governed batch has one clear goal, one acceptance boundary, and one
post-Closeout commit. It can include multiple related files and editing rounds.
Do not split it because a file was saved, a related test was added, or a mapped
authority was updated to reflect the same result.

Split the batch when:

- the goal or acceptance criteria changes;
- a new protected, historical, release, human-approval, or irreversible
  boundary appears;
- the original Impact cannot prove a required path;
- the changes no longer form one independently reviewable and reversible unit;
- a separate commit is required before the current batch can close.

## Open Once

Run Impact before the first governed edit. Declare the paths reasonably known
at that point and preserve the receipt outside project authority. Keep Git HEAD
at the Impact baseline until Closeout passes.

Do not run a new Impact during ordinary batch work. A post-edit Impact is not a
pre-change baseline.

## Work Freely Inside The Boundary

Complete all related implementation, tests, and authority updates before
Freeze. Ordinary project checks may run during development, but GAC does not
need to run after each edit.

If additional existing paths are discovered, collect them and extend the
original receipt once before finalization:

```bash
python3 scripts/govern_ai_coding.py impact adapter.json \
  --workspace /project \
  --extend-receipt /safe/original-impact.json \
  --changed-path docs/additional.md \
  --write-receipt /safe/extended-impact.json
```

Extension requires the original inventory to have observed the path cleanly.
An unobserved, newly created after Impact, or originally dirty path remains
`unproven`. Preserve edits and split that work at a clean boundary; do not
discard work or substitute unrelated validation.

## Finalize Once

Use this order after all governed edits are complete:

1. Run Semantic Review only when its trigger is present.
2. Freeze every actual batch path.
3. Run the deduplicated affected project validation against the frozen bytes.
4. Run Closeout with the Impact and Freeze receipts, actual paths, authorized
   paths, and any required review or approval evidence.
5. Commit only after Closeout passes.

Any governed edit after Freeze invalidates finalization. Create a new Freeze,
rerun only validation affected by the changed frozen inputs, and rerun
Closeout. Do not restart Impact if its baseline and scope remain valid.

## Validation Reuse

Reuse evidence only when its relevant inputs, command, configuration,
environment, and supported claim are unchanged. Documentation-only changes
normally invalidate documentation or architecture checks that consume them;
runtime, API, persistence, routing, evaluation, or executable-contract changes
invalidate the corresponding complete project obligations.

## Recovery

Follow the smallest `recovery_actions` entry returned by the producing command.
Missing Freeze, validation, review, or approval evidence does not invalidate a
still-valid Impact. `fail` means a deterministic defect; `unproven` means the
available evidence or authority cannot establish completion.
