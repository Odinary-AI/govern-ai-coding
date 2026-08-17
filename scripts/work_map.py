"""Optional Markdown Work Map parsing and derived operations."""

from __future__ import annotations

from collections import Counter
import difflib
import hashlib
import importlib.util
import json
from pathlib import Path
import re

try:
    from closeout_evidence import (
        bind_closeout_attestation,
        parse_closeout_attestation,
    )
except ModuleNotFoundError:
    _evidence_path = Path(__file__).with_name("closeout_evidence.py")
    _evidence_spec = importlib.util.spec_from_file_location(
        "govern_ai_coding_closeout_evidence", _evidence_path,
    )
    if _evidence_spec is None or _evidence_spec.loader is None:
        raise
    _evidence_module = importlib.util.module_from_spec(_evidence_spec)
    _evidence_spec.loader.exec_module(_evidence_module)
    bind_closeout_attestation = _evidence_module.bind_closeout_attestation
    parse_closeout_attestation = _evidence_module.parse_closeout_attestation


REQUIRED_COLUMNS = {
    "id",
    "parent",
    "result",
    "commitment",
    "progress",
    "owner_task",
    "dependencies",
    "next_reentry",
    "authority_evidence",
}


_DISPOSITION_PROGRESS_KEYS = {
    "completed": "completed",
    "transferred": "not_started",
    "blocked": "blocked",
    "deferred": "deferred",
    "cancelled": "cancelled",
    "superseded": "superseded",
}


def canonical_item_digest(item: dict) -> str:
    """Return a stable digest of the Work Map item's typed semantic fields."""
    semantic = {key: item.get(key) for key in (
        "id", "parent", "result", "commitment", "progress", "owner_task",
        "dependencies", "next_reentry", "authority_evidence",
    )}
    encoded = json.dumps(semantic, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _evidence_finding(relation: str, message: str, **fields) -> dict:
    return {
        "code": f"work-map-evidence-{relation}",
        "relation": relation,
        "message": message,
        "recovery_actions": [message],
        **fields,
    }


def _expected_progress_values(config: dict, disposition: object) -> tuple[str, ...]:
    if not isinstance(disposition, str):
        return ()
    state_key = _DISPOSITION_PROGRESS_KEYS.get(disposition)
    states = config.get("progress_states", {})
    values = states.get(state_key) if isinstance(states, dict) and state_key else None
    if not isinstance(values, list):
        return ()
    return tuple(value for value in values if isinstance(value, str) and value)


def _expected_progress(config: dict, disposition: object) -> str | None:
    values = _expected_progress_values(config, disposition)
    return values[0] if values else None


def _binding_identity(binding: dict, path: str) -> dict:
    return {
        "item_id": binding.get("item_id"),
        "task_id": binding.get("task_id"),
        "source_digest": binding.get("source_digest"),
        "expected_disposition": binding.get("expected_disposition"),
        "path": path,
    }


def _load_validated_work_map(adapter: dict, workspace: Path) -> tuple[dict, list[dict]]:
    model = load_work_map(adapter, workspace)
    findings = validate_work_map_model(model, adapter["work_map"])
    if findings:
        return model, [
            _evidence_finding(
                "evidence-incomplete",
                "Correct Work Map validation findings before deriving closure evidence.",
                validation_findings=findings,
            )
        ]
    return model, []


def _bound_item(model: dict, config: dict, binding: dict) -> tuple[dict | None, list[dict]]:
    item_id = binding.get("item_id")
    task_id = binding.get("task_id")
    if not isinstance(item_id, str) or not item_id or not isinstance(task_id, str) or not task_id:
        return None, [_evidence_finding(
            "identity-mismatch",
            "Bind a non-empty Work Map item ID and exact task ID.",
        )]
    item = model["items"].get(item_id)
    if item is None:
        return None, [_evidence_finding(
            "identity-mismatch",
            "Bind an existing Work Map item.",
            item_id=item_id,
        )]
    task_ids = re.compile(config["task_identity"]["pattern"]).findall(item["owner_task"] or "")
    if task_ids != [task_id]:
        return None, [_evidence_finding(
            "identity-mismatch",
            "Bind the exact task recorded on the Work Map item.",
            item_id=item_id,
            recorded_task_ids=task_ids,
            task_id=task_id,
        )]
    return item, []


def verify_work_map_binding(adapter: dict, workspace: Path, binding: dict) -> tuple[dict | None, list[dict]]:
    """Verify a binding against the unchanged baseline Work Map table."""
    config = adapter["work_map"]
    model, findings = _load_validated_work_map(adapter, workspace)
    if findings:
        return None, findings
    item, findings = _bound_item(model, config, binding)
    if findings:
        return None, findings
    if binding.get("source_digest") != model["source_digest"]:
        return None, [_evidence_finding(
            "binding-mismatch",
            "Recreate the binding from the baseline Work Map table digest.",
            expected_source_digest=model["source_digest"],
            bound_source_digest=binding.get("source_digest"),
        )]
    if _expected_progress(config, binding.get("expected_disposition")) is None:
        return None, [_evidence_finding(
            "binding-mismatch",
            "Choose an expected disposition supported by the adapter.",
            expected_disposition=binding.get("expected_disposition"),
        )]
    return _binding_identity(binding, model["source"]["path"]), []


def observe_work_map_final(adapter: dict, workspace: Path, binding: dict) -> tuple[dict | None, list[dict]]:
    """Observe the current bound item without mutating the Work Map or binding."""
    config = adapter["work_map"]
    model, findings = _load_validated_work_map(adapter, workspace)
    if findings:
        return None, findings
    item, findings = _bound_item(model, config, binding)
    if findings:
        return None, findings
    expected_progress_values = _expected_progress_values(
        config, binding.get("expected_disposition"),
    )
    if not expected_progress_values:
        return None, [_evidence_finding(
            "binding-mismatch",
            "Choose an expected disposition supported by the adapter.",
            expected_disposition=binding.get("expected_disposition"),
        )]
    if item["progress"] not in expected_progress_values:
        return None, [_evidence_finding(
            "evidence-incomplete",
            "Record the adapter-mapped expected disposition on the bound Work Map item.",
            item_id=item["id"],
            expected_progress_values=list(expected_progress_values),
            observed_progress=item["progress"],
        )]
    return {
        **_binding_identity(binding, model["source"]["path"]),
        "final_table_digest": model["source_digest"],
        "final_item_digest": canonical_item_digest(item),
    }, []


def _finding(code: str, field: str, message: str) -> dict:
    return {
        "code": code,
        "field": field,
        "message": message,
        "recovery_actions": [f"Correct adapter field {field} and validate again."],
    }


def validate_work_map_config(adapter: dict) -> list[dict]:
    config = adapter.get("work_map")
    if config is None:
        return []
    if not isinstance(config, dict):
        return [_finding("work-map-invalid-config", "work_map", "work_map must be an object")]

    findings: list[dict] = []
    for field in ("path", "heading"):
        if not isinstance(config.get(field), str) or not config[field].strip():
            findings.append(_finding("work-map-invalid-field", f"work_map.{field}", "expected non-empty string"))

    columns = config.get("columns")
    if not isinstance(columns, dict):
        return findings + [_finding("work-map-invalid-columns", "work_map.columns", "expected object")]
    for key in sorted(REQUIRED_COLUMNS - set(columns)):
        findings.append(_finding("work-map-missing-column", f"work_map.columns.{key}", "required semantic column is missing"))
    for key, value in columns.items():
        if not isinstance(value, str) or not value.strip():
            findings.append(_finding("work-map-invalid-column", f"work_map.columns.{key}", "expected non-empty header string"))

    shared = config.get("shared_columns", {})
    if not isinstance(shared, dict):
        findings.append(_finding("work-map-invalid-shared-columns", "work_map.shared_columns", "expected object"))
        shared = {}
    counts = Counter(value for value in columns.values() if isinstance(value, str))
    for header, count in sorted(counts.items()):
        if count > 1 and header not in shared:
            findings.append(_finding("work-map-undeclared-shared-column", "work_map.shared_columns", f"{header!r} is mapped more than once"))
    for header, roles in shared.items():
        if not isinstance(header, str) or not isinstance(roles, list) or not roles or not all(isinstance(role, str) for role in roles):
            findings.append(_finding("work-map-invalid-shared-column", f"work_map.shared_columns.{header}", "expected non-empty list of semantic roles"))

    view = config.get("generated_views", {}).get("mermaid", {}) if isinstance(config.get("generated_views", {}), dict) else {}
    begin = view.get("begin_marker") if isinstance(view, dict) else None
    end = view.get("end_marker") if isinstance(view, dict) else None
    if not isinstance(begin, str) or not isinstance(end, str) or not begin or not end or begin == end:
        findings.append(_finding("work-map-unsafe-view-markers", "work_map.generated_views.mermaid", "begin and end markers must be distinct non-empty strings"))
    return findings


def _split_table_row(line: str) -> list[str]:
    stripped = line.strip()
    if stripped.startswith("|"):
        stripped = stripped[1:]
    if stripped.endswith("|"):
        stripped = stripped[:-1]
    cells: list[str] = []
    current: list[str] = []
    escaped = False
    for character in stripped:
        if escaped:
            current.append(character)
            escaped = False
        elif character == "\\":
            current.append(character)
            escaped = True
        elif character == "|":
            cells.append("".join(current).strip())
            current = []
        else:
            current.append(character)
    cells.append("".join(current).strip())
    return cells


def _is_delimiter(cells: list[str]) -> bool:
    return bool(cells) and all(cell.replace(":", "").replace("-", "") == "" and "-" in cell for cell in cells)


def load_work_map(adapter: dict, workspace: Path) -> dict:
    config = adapter["work_map"]
    source_path = workspace / config["path"]
    text = source_path.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    heading_indexes = [
        index for index, line in enumerate(lines)
        if line.rstrip("\r\n") == config["heading"]
    ]
    findings: list[dict] = []
    if len(heading_indexes) != 1:
        findings.append(_finding(
            "work-map-heading-not-unique",
            "work_map.heading",
            f"expected one exact heading, found {len(heading_indexes)}",
        ))
    if not heading_indexes:
        return {
            "source": {"path": config["path"], "heading": config["heading"]},
            "columns": {},
            "items": {},
            "order": [],
            "source_digest": None,
            "findings": findings,
            "text": text,
        }

    heading_index = heading_indexes[0]
    table_start = next(
        (
            index for index in range(heading_index + 1, len(lines))
            if lines[index].lstrip().startswith("|")
        ),
        None,
    )
    if table_start is None:
        findings.append(_finding("work-map-table-missing", "work_map.heading", "no Markdown table follows the configured heading"))
        return {
            "source": {"path": config["path"], "heading": config["heading"]},
            "columns": {},
            "items": {},
            "order": [],
            "source_digest": None,
            "findings": findings,
            "text": text,
        }
    table_end = table_start
    while table_end < len(lines) and lines[table_end].lstrip().startswith("|"):
        table_end += 1
    table_lines = lines[table_start:table_end]
    headers = _split_table_row(table_lines[0])
    if len(table_lines) < 2 or not _is_delimiter(_split_table_row(table_lines[1])):
        findings.append(_finding("work-map-table-delimiter-invalid", config["path"], "table delimiter row is missing or malformed"))

    columns = config["columns"]
    for semantic, header in columns.items():
        if header not in headers:
            findings.append(_finding("work-map-header-missing", f"work_map.columns.{semantic}", f"header {header!r} is absent"))

    nulls = set(config.get("null_markers", []))
    separator = config.get("multi_value_separator", ",")
    items: dict[str, dict] = {}
    order: list[str] = []
    for offset, line in enumerate(table_lines[2:], start=2):
        cells = _split_table_row(line)
        source_line = table_start + offset + 1
        if len(cells) != len(headers):
            findings.append(_finding("work-map-row-shape-invalid", f"{config['path']}:{source_line}", "row cell count differs from header"))
            continue
        raw = dict(zip(headers, cells))
        item_id = raw.get(columns["id"], "").strip()
        if not item_id:
            findings.append(_finding("work-map-item-id-missing", f"{config['path']}:{source_line}", "item ID is empty"))
            continue
        if item_id in items:
            findings.append(_finding("work-map-item-id-duplicate", f"{config['path']}:{source_line}", f"duplicate item ID {item_id}"))
            continue
        def value(name: str):
            cell = raw.get(columns[name], "").strip()
            return None if cell in nulls or not cell else cell

        dependencies_value = value("dependencies")
        dependencies = (
            [part.strip() for part in dependencies_value.split(separator) if part.strip()]
            if dependencies_value else []
        )
        item = {
            "id": item_id,
            "parent": value("parent"),
            "result": value("result"),
            "commitment": value("commitment"),
            "progress": value("progress"),
            "owner_task": value("owner_task"),
            "dependencies": dependencies,
            "next_reentry": value("next_reentry"),
            "authority_evidence": value("authority_evidence"),
            "raw": raw,
            "source_line": source_line,
        }
        items[item_id] = item
        order.append(item_id)

    table_bytes = "".join(table_lines).encode("utf-8")
    return {
        "source": {
            "path": config["path"],
            "heading": config["heading"],
            "table_start_line": table_start + 1,
            "table_end_line": table_end,
        },
        "columns": columns,
        "items": items,
        "order": order,
        "source_digest": hashlib.sha256(table_bytes).hexdigest(),
        "findings": findings,
        "text": text,
        "table_range": (table_start, table_end),
    }


def _check(code: str, item: dict | None, message: str, *, severity: str = "fail", **fields) -> dict:
    result = {
        "code": code,
        "severity": severity,
        "message": message,
        "recovery_actions": [message],
    }
    if item:
        result.update({"item_id": item["id"], "source_line": item["source_line"]})
    result.update(fields)
    return result


def _cycle(graph: dict[str, list[str]]) -> list[str] | None:
    colors: dict[str, int] = {}
    stack: list[str] = []

    def visit(node: str) -> list[str] | None:
        colors[node] = 1
        stack.append(node)
        for target in graph.get(node, []):
            if target not in graph:
                continue
            if colors.get(target, 0) == 1:
                start = stack.index(target)
                return stack[start:] + [target]
            if colors.get(target, 0) == 0:
                found = visit(target)
                if found:
                    return found
        stack.pop()
        colors[node] = 2
        return None

    for node in graph:
        if colors.get(node, 0) == 0:
            found = visit(node)
            if found:
                return found
    return None


def validate_work_map_model(model: dict, config: dict) -> list[dict]:
    checks = [
        {**finding, "severity": "fail"}
        for finding in model.get("findings", [])
    ]
    items = model["items"]
    parent_graph: dict[str, list[str]] = {}
    dependency_graph: dict[str, list[str]] = {}
    task_owners: dict[str, str] = {}
    task_config = config["task_identity"]
    task_pattern = re.compile(task_config["pattern"])
    active_values = set(config["progress_states"]["active"])
    candidate_values = set(config["commitment_states"]["candidate"])
    completed_values = set(config["progress_states"]["completed"])
    deferred_values = set(config["progress_states"]["deferred"])
    blocked_values = set(config["progress_states"]["blocked"])
    superseded_values = set(config["progress_states"]["superseded"])
    required_task_values = set(task_config.get("required_progress", []))
    exemptions = set(task_config.get("exempt_items", []))

    for item_id in model["order"]:
        item = items[item_id]
        parent = item["parent"]
        parent_graph[item_id] = [parent] if parent else []
        dependency_graph[item_id] = list(item["dependencies"])
        if parent and parent not in items:
            checks.append(_check("work-map-parent-missing", item, f"Add parent {parent} or correct {item_id}.", parent=parent))
        for dependency in item["dependencies"]:
            if dependency not in items:
                checks.append(_check("work-map-dependency-missing", item, f"Add dependency {dependency} or correct {item_id}.", dependency=dependency))

        if item["commitment"] in candidate_values and item["progress"] in active_values:
            checks.append(_check("work-map-candidate-active", item, "Approve the candidate before making it active."))
        task_ids = task_pattern.findall(item["owner_task"] or "")
        if item["progress"] in required_task_values and item_id not in exemptions:
            if not task_ids:
                checks.append(_check("work-map-active-task-missing", item, "Bind exactly one current task ID."))
            elif len(set(task_ids)) != 1:
                checks.append(_check("work-map-active-task-ambiguous", item, "Keep exactly one current task ID."))
        for task_id in set(task_ids):
            if item["progress"] in active_values:
                if task_id in task_owners and task_owners[task_id] != item_id:
                    checks.append(_check(
                        "work-map-active-task-duplicate",
                        item,
                        f"Task {task_id} is already active on {task_owners[task_id]}.",
                        task_id=task_id,
                    ))
                task_owners[task_id] = item_id
        if item["progress"] in completed_values and not item["authority_evidence"]:
            checks.append(_check("work-map-completion-evidence-missing", item, "Bind completion evidence before completing the item."))
        if item["progress"] in deferred_values and not item["next_reentry"]:
            checks.append(_check("work-map-reentry-missing", item, "Record a re-entry condition for the deferred item."))
        if item["progress"] in blocked_values and not item["next_reentry"]:
            checks.append(_check("work-map-block-recovery-missing", item, "Record the block reason and recovery action."))
        if item["progress"] in superseded_values:
            successor = next((candidate for candidate in items if candidate != item_id and candidate in (item["next_reentry"] or "")), None)
            if not successor:
                checks.append(_check("work-map-successor-missing", item, "Name an existing successor item."))

    parent_cycle = _cycle(parent_graph)
    if parent_cycle:
        checks.append(_check("work-map-parent-cycle", None, "Break the parent cycle.", cycle=parent_cycle))
    dependency_cycle = _cycle(dependency_graph)
    if dependency_cycle:
        checks.append(_check("work-map-dependency-cycle", None, "Break the dependency cycle.", cycle=dependency_cycle))
    return checks


def _check_diagnostic(item: dict) -> dict:
    severity = {
        "fail": "blocking",
        "unproven": "unproven",
        "warning": "warning",
    }.get(item.get("severity"), "blocking")
    recovery_actions = [
        action
        for action in item.get("recovery_actions", [])
        if isinstance(action, str) and action
    ]
    if not recovery_actions:
        recovery_actions = ["Correct this Work Map finding and rerun only work-map check."]
    fields = {
        key: value
        for key, value in item.items()
        if key not in {"code", "message", "recovery_actions", "severity"}
    }
    return {
        "severity": severity,
        "category": "blocking",
        "code": str(item.get("code", "work-map-finding")),
        "message": str(item.get("message") or recovery_actions[0]),
        "fields": fields,
        "recovery_actions": recovery_actions,
    }


def check_work_map(adapter: dict, workspace: Path) -> dict:
    model = load_work_map(adapter, workspace)
    checks = validate_work_map_model(model, adapter["work_map"])
    result = "fail" if any(item.get("severity") == "fail" for item in checks) else (
        "unproven" if any(item.get("severity") == "unproven" for item in checks) else "pass"
    )
    return {
        "result": result,
        "source": {
            "path": model["source"]["path"],
            "heading": model["source"]["heading"],
            "digest": model["source_digest"],
        },
        "target": None,
        "checks": checks,
        "diagnostics": sorted(
            (_check_diagnostic(item) for item in checks),
            key=lambda item: (
                item["severity"], item["category"], item["code"],
                json.dumps(item["fields"], sort_keys=True),
            ),
        ),
        "proposed_fields": {},
        "patch": None,
        "recovery_actions": [
            action
            for item in checks
            for action in item.get("recovery_actions", [])
        ],
        "claim_boundary": {
            "proves": ["configured Work Map mechanical invariants"],
            "does_not_prove": [
                "semantic truth of evidence",
                "external task closure",
                "product or research outcomes",
            ],
        },
    }


def classify_attestation(
    path: Path,
    config: dict,
    binding: dict,
    current_observation: dict | None = None,
    *,
    adapter: dict | None = None,
    workspace: Path | None = None,
    manifest: dict | None = None,
    manifest_path: Path | None = None,
) -> dict:
    """Classify attestation evidence without treating historical evidence as closure."""
    schemas = config.get("attestations", {})
    parsed = parse_closeout_attestation(
        path,
        current_schemas=schemas.get("current_schemas", []),
        historical_schemas=schemas.get("historical_schemas", []),
    )
    parsed_payload = parsed.get("payload")
    if (
        isinstance(parsed_payload, dict)
        and parsed_payload.get("work_map_binding") != binding
    ):
        return {
            "status": "binding-mismatch",
            "path": str(path),
            "schema": parsed.get("schema"),
        }
    if parsed.get("status") != "parsed":
        return {
            key: value for key, value in parsed.items()
            if key not in {"payload", "capabilities"}
        }
    payload = parsed["payload"]
    schema = parsed["schema"]

    observation = payload.get("work_map_observation")
    if not isinstance(observation, dict) or current_observation is None:
        return {"status": "evidence-incomplete", "path": str(path), "schema": schema}
    for key in ("item_id", "task_id"):
        if observation.get(key) != current_observation.get(key):
            return {"status": "identity-mismatch", "path": str(path), "schema": schema}
    if observation.get("path") != current_observation.get("path"):
        return {"status": "scope-mismatch", "path": str(path), "schema": schema}
    for key in ("source_digest", "expected_disposition"):
        if observation.get(key) != current_observation.get(key):
            return {"status": "binding-mismatch", "path": str(path), "schema": schema}
    for key in ("final_table_digest", "final_item_digest"):
        if observation.get(key) != current_observation.get(key):
            return {"status": "content-mismatch", "path": str(path), "schema": schema}

    if not (
        isinstance(adapter, dict)
        and isinstance(workspace, Path)
        and isinstance(manifest, dict)
    ):
        return {"status": "evidence-incomplete", "path": str(path), "schema": schema}
    bound = bind_closeout_attestation(
        parsed,
        path=path,
        adapter=adapter,
        workspace=workspace,
        manifest=manifest,
        manifest_path=manifest_path,
    )
    if bound.get("status") != "matching":
        return {
            key: value for key, value in bound.items()
            if key not in {"payload", "capabilities"}
        }

    work_map_freeze = next((
        entry for entry in payload["final_content"]
        if entry.get("path") == current_observation.get("path")
    ), None)
    if (
        not isinstance(work_map_freeze, dict)
        or observation.get("frozen_file_digest") != work_map_freeze.get("digest")
    ):
        return {"status": "content-mismatch", "path": str(path), "schema": schema}
    return {"status": "matching", "path": str(path), "schema": schema}


def work_map_status(
    adapter: dict,
    workspace: Path,
    binding: dict,
    manifest: dict | None = None,
    manifest_path: Path | None = None,
) -> dict:
    """Derive bounded Work Map closure status using only current read-only evidence."""
    observation, findings = observe_work_map_final(adapter, workspace, binding)
    finding_relations = {finding.get("relation") for finding in findings}
    observed_progress = next((
        finding.get("observed_progress")
        for finding in findings
        if isinstance(finding, dict) and "observed_progress" in finding
    ), None)
    if observation is not None:
        engineering_relation = "expected-disposition-observed"
        engineering_result = "unproven"
    elif finding_relations & {"identity-mismatch", "binding-mismatch"}:
        engineering_relation = "binding-no-longer-matches"
        engineering_result = "fail"
    elif observed_progress in set(adapter["work_map"]["progress_states"]["active"]):
        engineering_relation = "work-remains-active"
        engineering_result = "unproven"
    elif observed_progress in {
        value
        for disposition in _DISPOSITION_PROGRESS_KEYS
        for value in _expected_progress_values(adapter["work_map"], disposition)
    }:
        engineering_relation = "binding-no-longer-matches"
        engineering_result = "fail"
    else:
        engineering_relation = "evidence-incomplete"
        engineering_result = "unproven"
    attestation_path = binding.get("attestation_path")
    if isinstance(attestation_path, str) and attestation_path:
        attestation = classify_attestation(
            Path(attestation_path), adapter["work_map"], binding, observation,
            adapter=adapter,
            workspace=workspace,
            manifest=manifest,
            manifest_path=manifest_path,
        )
    else:
        attestation = {"status": "evidence-incomplete", "path": None}
    attestation_relation = attestation["status"]
    if engineering_result == "fail":
        result = "fail"
    elif observation is not None and attestation_relation == "matching":
        result = "pass"
    elif attestation_relation in {"missing", "evidence-incomplete"}:
        result = "unproven"
    else:
        result = "fail"
    return {
        "result": result,
        "engineering_relation": engineering_relation,
        "attestation_relation": attestation_relation,
        "observation": observation,
        "attestation": attestation,
        "findings": findings,
        "claim_boundary": {
            "proves": ["bounded Work Map binding and attestation relation"],
            "does_not_prove": [
                "external task closure",
                "semantic truth of evidence",
                "product or research outcomes",
            ],
        },
    }


def _envelope(model: dict, *, result: str, target: dict | None, checks: list[dict],
              proposed_fields: dict | None = None, patch: str | None = None) -> dict:
    return {
        "result": result,
        "source": {
            "path": model["source"]["path"],
            "heading": model["source"]["heading"],
            "digest": model["source_digest"],
        },
        "target": target,
        "checks": checks,
        "proposed_fields": proposed_fields or {},
        "patch": patch,
        "recovery_actions": [
            action for item in checks for action in item.get("recovery_actions", [])
        ],
        "claim_boundary": {
            "proves": ["mechanical eligibility of the proposed transition"],
            "does_not_prove": [
                "that project authority changed",
                "external task closure",
                "semantic truth of evidence",
            ],
        },
    }


def _patch_item(model: dict, item: dict, fields: dict, config: dict) -> str:
    lines = model["text"].splitlines(keepends=True)
    headers = _split_table_row(lines[model["table_range"][0]])
    raw = dict(item["raw"])
    for semantic, value in fields.items():
        raw[config["columns"][semantic]] = value
    replacement = "| " + " | ".join(raw[header] for header in headers) + " |\n"
    lines[item["source_line"] - 1] = replacement
    updated = "".join(lines)
    return "".join(difflib.unified_diff(
        model["text"].splitlines(keepends=True),
        updated.splitlines(keepends=True),
        fromfile=config["path"],
        tofile=config["path"],
    ))


def start_work_item(adapter: dict, workspace: Path, item_id: str, task_id: str) -> dict:
    config = adapter["work_map"]
    model = load_work_map(adapter, workspace)
    item = model["items"].get(item_id)
    if not item:
        finding = _check("work-map-item-missing", None, f"Choose an existing item; {item_id} was not found.", item_id=item_id)
        return _envelope(model, result="fail", target=None, checks=[finding])
    pattern = re.compile(config["task_identity"]["pattern"])
    if pattern.fullmatch(task_id) is None:
        finding = _check("work-map-task-id-invalid", item, "Supply an exact task ID matching the adapter pattern.")
        return _envelope(model, result="fail", target=item, checks=[finding])
    active = set(config["progress_states"]["active"])
    existing_ids = pattern.findall(item["owner_task"] or "")
    if item["progress"] in active:
        if existing_ids == [task_id]:
            return _envelope(model, result="pass", target=item, checks=[], patch=None)
        finding = _check(
            "work-map-task-conflict",
            item,
            "Resume the recorded task or obtain a separately governed reassignment.",
            recorded_task_ids=existing_ids,
            supplied_task_id=task_id,
        )
        return _envelope(model, result="fail", target=item, checks=[finding])
    if item["commitment"] not in set(config["commitment_states"]["approved"]):
        finding = _check("work-map-item-not-approved", item, "Obtain project approval before starting the item.")
        return _envelope(model, result="fail", target=item, checks=[finding])
    completed = set(config["progress_states"]["completed"])
    unsatisfied = [
        dependency for dependency in item["dependencies"]
        if model["items"].get(dependency, {}).get("progress") not in completed
    ]
    if unsatisfied:
        finding = _check(
            "work-map-dependency-unsatisfied",
            item,
            "Complete the named dependencies before starting.",
            dependencies=unsatisfied,
        )
        return _envelope(model, result="fail", target=item, checks=[finding])
    progress = config["progress_states"]["active"][0]
    fields = {"progress": progress, "owner_task": f"task `{task_id}`"}
    return _envelope(
        model,
        result="pass",
        target=item,
        checks=[],
        proposed_fields=fields,
        patch=_patch_item(model, item, fields, config),
    )


def finish_work_item(
    adapter: dict,
    workspace: Path,
    item_id: str,
    task_id: str,
    disposition: str,
) -> dict:
    config = adapter["work_map"]
    model = load_work_map(adapter, workspace)
    item = model["items"].get(item_id)
    if not item:
        finding = _check("work-map-item-missing", None, f"Choose an existing item; {item_id} was not found.", item_id=item_id)
        return _envelope(model, result="fail", target=None, checks=[finding])
    pattern = re.compile(config["task_identity"]["pattern"])
    recorded = pattern.findall(item["owner_task"] or "")
    if item["progress"] not in set(config["progress_states"]["active"]) or recorded != [task_id]:
        finding = _check(
            "work-map-task-conflict",
            item,
            "Finish only the item bound to the exact active task.",
            recorded_task_ids=recorded,
            supplied_task_id=task_id,
        )
        return _envelope(model, result="fail", target=item, checks=[finding])
    state_key = _DISPOSITION_PROGRESS_KEYS.get(disposition)
    if state_key is None or state_key not in config["progress_states"]:
        finding = _check("work-map-disposition-invalid", item, "Choose a disposition supported by the adapter.")
        return _envelope(model, result="fail", target=item, checks=[finding])
    if disposition == "completed" and not item["authority_evidence"]:
        finding = _check("work-map-completion-evidence-missing", item, "Bind completion evidence before completing the item.")
        return _envelope(model, result="fail", target=item, checks=[finding])
    if disposition in {"blocked", "deferred", "superseded"} and not item["next_reentry"]:
        finding = _check("work-map-disposition-evidence-missing", item, "Record recovery, re-entry, or successor information first.")
        return _envelope(model, result="fail", target=item, checks=[finding])
    progress = config["progress_states"][state_key][0]
    fields = {"progress": progress}
    return _envelope(
        model,
        result="pass",
        target=item,
        checks=[],
        proposed_fields=fields,
        patch=_patch_item(model, item, fields, config),
    )


def _mermaid_id(item_id: str) -> str:
    return "n_" + re.sub(r"[^A-Za-z0-9_]", "_", item_id)


def _mermaid_class_name(status: str) -> str:
    if status.isascii() and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", status):
        return status
    return "status_" + hashlib.sha256(status.encode("utf-8")).hexdigest()[:12]


def render_work_map(adapter: dict, workspace: Path, format_name: str) -> dict:
    model = load_work_map(adapter, workspace)
    if model["findings"]:
        return _envelope(model, result="fail", target=None, checks=[
            {**finding, "severity": "fail"} for finding in model["findings"]
        ])
    if format_name == "table":
        start, end = model["table_range"]
        rendered = "".join(model["text"].splitlines(keepends=True)[start:end])
    elif format_name == "mermaid":
        output = ["```mermaid", "flowchart TD"]
        statuses: dict[str, list[str]] = {}
        for item_id in model["order"]:
            item = model["items"][item_id]
            label = f"{item_id}: {item['result'] or ''}".replace('"', "'")
            output.append(f'  {_mermaid_id(item_id)}["{label}"]')
            statuses.setdefault(item["progress"] or "unknown", []).append(_mermaid_id(item_id))
        for item_id in model["order"]:
            item = model["items"][item_id]
            if item["parent"]:
                output.append(f"  {_mermaid_id(item_id)} -->|parent| {_mermaid_id(item['parent'])}")
            for dependency in item["dependencies"]:
                output.append(f"  {_mermaid_id(item_id)} -->|depends| {_mermaid_id(dependency)}")
        for index, (status, nodes) in enumerate(sorted(statuses.items())):
            class_name = _mermaid_class_name(status)
            output.append(f"  classDef {class_name} fill:#eef,stroke:#556")
            output.append(f"  class {','.join(nodes)} {class_name}")
        output.append("```")
        rendered = "\n".join(output) + "\n"
    else:
        finding = _check("work-map-render-format-invalid", None, "Use table or mermaid.")
        return _envelope(model, result="fail", target=None, checks=[finding])
    result = _envelope(model, result="pass", target=None, checks=[])
    result["rendered"] = rendered
    result["claim_boundary"]["proves"] = ["deterministic view derived from the configured source table"]
    return result
