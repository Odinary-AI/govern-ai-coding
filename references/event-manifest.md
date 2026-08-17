# Event Manifest

Use the optional versioned event manifest only when a governed batch needs
cross-task recovery, stable scope reuse, Work Map binding, integration
verification, declared-event preflight, or another consumer that explicitly
requires it. A normal single-task batch does not need a manifest.

Use v2 for multi-batch or cross-session recovery, Closeout retries, integration
verification, declared-event preflight, Work Map closure, or external handoff.
For a single-session, single-batch change with no manifest consumer, a manifest
remains optional. Existing v1 manifests stay readable and are never rewritten
or silently upgraded; create a new v2 manifest when durable attempt history is
needed.

The manifest is generated evidence, never project authority. It can bind:

- batch identity, goal, workspace, and baseline;
- planned and actual paths;
- governed authorities and authorized development paths;
- evidence-only paths and approval bindings;
- Impact, Semantic Review, Freeze, validation, attestation, and Closeout
  pointers;
- optional `work_map_binding`.

V2 stores Closeout state in one ledger only:

- `closeout.attempts` is append-only and records explicit stable attempt IDs,
  final results, result/recovery details, immutable Closeout receipt bindings,
  canonical Freeze digests, and optional attestation bindings;
- `closeout.current` is an explicit attempt-ID pointer and is the only way a
  reader selects current Closeout evidence;
- v2 has no parallel `closeout.result`, result-reasons, recovery projection, or
  `receipts.closeout_attestation` slot.

Choose `--attempt-id` from a stable workflow identifier such as
`batch-c-closeout-01`. IDs are 1-128 ASCII letters, digits, `.`, `_`, or `-`,
starting with a letter or digit. They are user-supplied audit identities, not
timestamps or ordering claims. V2 Closeout also requires a unique
`--write-receipt` destination. A recorded duplicate ID always fails. After an
interrupted finalization, an unrecorded complete JSON receipt or attestation
with the same canonical Evidence-v1 digest may be reused after reread
verification; it is never overwritten. A post-link interruption alias is
removed only when its exact controlled temp name, directory, inode, payload,
digest, and complete link count are proven; any unknown alias fails closed.

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

For v2 Closeout, the receipt is atomically created or strictly rebound and
reread first. A requested attestation is then created or strictly rebound and
reread. Only after those files exist with the expected schema and canonical
Evidence-v1 digest is one attempt appended and the manifest atomically
replaced by a locked compare-and-swap against the exact manifest read by the
command. Impact and Freeze use the same publication guard, so a stale phase
writer cannot erase an appended attempt. A pass advances `current`; fail or
unproven preserves an earlier valid current. Manifest publication failure
leaves only unreferenced immutable evidence, which the same retry can reuse.

Lock capability is optional at CLI import, not at v2 publication. On a runtime
without `fcntl`, v1 readers and updates retain their existing behavior, while
every v2 manifest write returns structured `fail` with
`event-manifest-lock-unavailable` before changing the manifest. The writer
never degrades v2 to an unlocked compare-and-swap. Read-only v2 validation and
current-attempt consumption remain available. Even when the lock exists, a v2
write without the exact raw canonical digest of the loaded snapshot fails with
`event-manifest-cas-required`; there is no non-CAS v2 publication path. A
legacy candidate cannot replace an unreadable existing destination because
the writer cannot prove that destination is not v2.

Each v2 Closeout receipt carries canonical snapshots of the attempt's Impact
and Freeze receipts. The Freeze snapshot is fully revalidated and must match
the Closeout final-content paths, adapter, and workspace. This lets consumers
rebind an older valid `current` without consulting mutable top-level
Impact/Freeze/validation slots changed by a later retry.

Relative attempt evidence paths resolve from the manifest directory. Absolute
paths must already be canonical. Symlink and hardlink aliases, parent escapes,
repeated or dot path aliases, non-files,
digest/schema/result/Freeze mismatches, and in-workspace paths outside an
adapter-excluded boundary fail. Readers validate the pointer and its bound file;
they never scan a directory, choose a timestamp, or infer a conventional name.

`audit-event` is a read-only v2 consumer of that exact current-attempt API. It
revalidates the current receipt's immutable Impact and Freeze snapshots,
current workspace content, and any explicitly bound attestation. It returns
Event Manifest v1 as unsupported `unproven`; it never interprets the v1 result
slot as a v2 attempt or searches for replacement evidence.

Do not create a manifest only to group receipts that have no downstream
consumer. Receipts can be supplied directly to Freeze and Closeout.

The exact fields and validation rules remain in
[Adapter and Result Contract](adapter-schema.md).
