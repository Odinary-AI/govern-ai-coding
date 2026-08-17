# Declared Event Preflight

Use this read-only check only for parallel governed batches that have already
declared their scope in event manifests.

```bash
python3 scripts/govern_ai_coding.py preflight-event adapter.json \
  --workspace /current/workspace \
  --event-manifest /safe/current-event.json \
  --peer-manifest /safe/peer-event.json
```

The check can prove exact mutation-path overlap, conflicting tasks bound to one
Work Map item, an unfinished configured dependency, or trusted peer evidence
that changed a declared baseline input. Authority-rule overlap warns and stays
`unproven`; incomplete peer evidence cannot manufacture a conflict.

V1 peer evidence uses `receipts.closeout_attestation`. V2 peer evidence is
eligible only through the mechanically valid `closeout.current` attempt. The
preflight never selects another attempt or a neighboring evidence file.
Relative `event.workspace` values resolve from each supplied manifest's own
directory, for both the current event and peers.

The command inspects only supplied declarations. It does not discover sessions,
tasks, processes, branches, or worktrees and does not schedule, lock, merge, or
modify anything. Its result says nothing about concurrent work that was not
supplied.

Do not create manifests or run this check for a single governed batch. Read
[Event Manifest](event-manifest.md) for manifest boundaries and
[Adapter and Result Contract](adapter-schema.md) for exact result fields.
