"""Optional Markdown Work Map parsing and derived operations."""

from __future__ import annotations

from collections import Counter
import difflib
import hashlib
import json
from pathlib import Path
import re


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


def classify_attestation(path: Path, config: dict, binding: dict) -> dict:
    if not path.is_file():
        return {"status": "pending", "path": str(path)}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"status": "mismatch-unproven", "path": str(path)}
    schema = payload.get("schema")
    schemas = config.get("attestations", {})
    if schema in schemas.get("historical_schemas", []) and payload.get("result") == "pass":
        return {"status": "historical-pass", "path": str(path), "schema": schema}
    if (
        schema in schemas.get("current_schemas", [])
        and payload.get("result") == "pass"
        and payload.get("work_map_binding") == binding
    ):
        return {"status": "current-pass", "path": str(path), "schema": schema}
    return {"status": "mismatch-unproven", "path": str(path), "schema": schema}


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
    disposition_map = {
        "completed": "completed",
        "transferred": "not_started",
        "blocked": "blocked",
        "deferred": "deferred",
        "cancelled": "cancelled",
        "superseded": "superseded",
    }
    state_key = disposition_map.get(disposition)
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
