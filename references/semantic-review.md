# Semantic Review And Human Approval

Use this reference when a governed batch changes meaning or encounters a human
decision boundary.

## Trigger

Run Semantic Review when the batch changes one or more of:

- current governed facts or decisions;
- authority assignment or precedence;
- product, architecture, public interface, or material runtime-contract
  meaning;
- formal release or version claims;
- historical interpretation;
- the disposition of an earlier semantic finding;
- a claim class that the project adapter explicitly requires to be reviewed.

Semantic Review may be omitted for implementation, tests, formatting, or
mechanical refactoring that preserves governed meaning. A changed file alone is
not the trigger.

## Review Questions

Ask:

1. What important claims changed?
2. Which governed questions are affected?
3. Do current authorities agree with the available evidence?
4. What remains uncertain?

The review is a JSON object with schema
`govern-ai-coding.semantic-review.v1`, the four answers, and a `findings`
array. Use the packaged
[`semantic-review-example.json`](semantic-review-example.json) as the complete
copyable shape.

Each finding contains these required core fields:

- `code`
- `affected_question`
- `evidence`
- `confidence`
- `decision_boundary`
- `suggested_handling`
- `human_boundary`
- `status`

Every core field except `human_boundary` is a non-empty string;
`human_boundary` is a JSON boolean. `status` is exactly `resolved` or
`unresolved`. A resolved finding also requires non-empty string `resolution`
and `resolution_evidence`. An unresolved finding may omit both; if either is
present it must be a non-empty string.

Each answer is a non-empty string or a non-empty list of non-empty strings.

Run shape-only preflight before binding the review to a governed event:

```bash
python3 scripts/govern_ai_coding.py validate-semantic-review REVIEW.json
```

A preflight pass proves only that the JSON shape is valid. It does not prove
that resolution evidence is part of or authorized for the event, that an
unresolved finding is resolved, or that a human decision exists. Closeout owns
those contextual checks through `--semantic-review`.

Bind required review with `--semantic-review REVIEW.json`. Missing, malformed,
unresolved, or unhandled required review keeps Closeout from passing.

## Human Approval

Ask before authority reassignment, product or architecture meaning changes,
formal release or version claims, or deletion, significant supersession, and
irreversible archive handling.

Bind each exact type with `--human-approval TYPE=EVIDENCE`. Evidence must be an
authorized ordinary document changed in the same batch and contain an
independent block with:

- `Approval type:`
- `Object:`
- `Scope:`
- `Does not approve:`

One approval type cannot satisfy another. One block must independently contain
all fields and cover every target; Closeout never combines fields or target
coverage across blocks. The checker validates the binding structure, not the
identity or truth of the human decision.

For an explicitly approved protected path, additionally bind
`--protected-approval PATH=EVIDENCE`. This permits the exact bytes to change; it
does not approve their semantic meaning. Excluded paths remain blocked.
