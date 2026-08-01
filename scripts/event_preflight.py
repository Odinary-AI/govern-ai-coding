"""Read-only conflict preflight for explicitly supplied event declarations."""

from __future__ import annotations

import importlib.util
from pathlib import Path, PurePosixPath
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

try:
    from work_map import load_work_map, validate_work_map_model
except ModuleNotFoundError:
    _work_map_path = Path(__file__).with_name("work_map.py")
    _work_map_spec = importlib.util.spec_from_file_location(
        "govern_ai_coding_work_map", _work_map_path,
    )
    if _work_map_spec is None or _work_map_spec.loader is None:
        raise
    _work_map_module = importlib.util.module_from_spec(_work_map_spec)
    _work_map_spec.loader.exec_module(_work_map_module)
    load_work_map = _work_map_module.load_work_map
    validate_work_map_model = _work_map_module.validate_work_map_model


MUTATION_SCOPE_KEYS = (
    "planned_paths",
    "actual_event_paths",
    "governed_authority_documents",
    "authorized_development_paths",
)
CURRENT_ATTESTATION_SCHEMAS = ["govern-ai-coding.closeout-attestation.v1"]


def _safe_path(value: object) -> bool:
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and path.parts
        and all(part not in {"", ".", ".."} for part in path.parts)
        and path.as_posix() == value
    )


def _declared_manifest(
    value: object, declared_workspace: Path,
) -> tuple[dict | None, set[str]]:
    if not isinstance(value, dict):
        return None, set()
    if (
        value.get("schema") != "govern-ai-coding.event-manifest.v1"
        or value.get("schema_version") != "1"
    ):
        return None, set()
    event = value.get("event")
    scope = value.get("scope")
    if not isinstance(event, dict) or not isinstance(scope, dict):
        return None, set()
    if not isinstance(event.get("id"), str) or not event["id"]:
        return None, set()
    raw_workspace = event.get("workspace")
    if not isinstance(raw_workspace, str) or not raw_workspace:
        return None, set()
    if Path(raw_workspace).resolve() != Path(declared_workspace).resolve():
        return None, set()
    paths: list[str] = []
    for key in MUTATION_SCOPE_KEYS:
        values = scope.get(key)
        if not isinstance(values, list) or not all(_safe_path(item) for item in values):
            return None, set()
        paths.extend(values)
    return value, set(paths)


def _binding(value: dict) -> dict | None:
    binding = value.get("work_map_binding")
    if binding is None:
        return None
    if not isinstance(binding, dict):
        return None
    if not all(
        isinstance(binding.get(key), str) and binding[key]
        for key in ("item_id", "task_id")
    ):
        return None
    return binding


def _matches(candidate: str, pattern: str) -> bool:
    candidate = candidate.rstrip("/")
    pattern = pattern.rstrip("/")
    return candidate == pattern or candidate.startswith(pattern + "/")


def _authority_relations(
    adapter: dict, paths: set[str],
) -> tuple[set[str], set[str]]:
    matched: set[str] = set()
    scopes: set[str] = set()
    rules = adapter.get("authority_rules")
    if not isinstance(rules, list):
        return matched, scopes
    for rule in rules:
        if not isinstance(rule, dict) or not isinstance(rule.get("id"), str):
            continue
        patterns = rule.get("paths", [])
        triggers = rule.get("triggers", []) or []
        if not isinstance(patterns, list) or not isinstance(triggers, list):
            continue
        declared_patterns = [
            item for item in patterns + triggers if isinstance(item, str) and item
        ]
        if any(
            _matches(path, pattern) or _matches(pattern, path)
            for path in paths for pattern in declared_patterns
        ):
            matched.add(rule["id"])
            if isinstance(rule.get("scope"), str) and rule["scope"]:
                scopes.add(rule["scope"])
    return matched, scopes


def _unfinished_dependencies(
    adapter: dict, workspace: Path, current: dict,
) -> tuple[list[str], bool]:
    binding = _binding(current)
    config = adapter.get("work_map")
    if binding is None or config is None:
        return [], True
    if not isinstance(config, dict):
        return [], False
    try:
        model = load_work_map(adapter, workspace)
        findings = validate_work_map_model(model, config)
    except (OSError, UnicodeError, KeyError, TypeError, ValueError):
        return [], False
    if findings:
        return [], False
    item = model.get("items", {}).get(binding["item_id"])
    completed = set((config.get("progress_states") or {}).get("completed", []))
    if not isinstance(item, dict) or not completed:
        return [], False
    unfinished = [
        dependency for dependency in item.get("dependencies", [])
        if model["items"].get(dependency, {}).get("progress") not in completed
    ]
    return sorted(unfinished), True


def _baseline_inputs(
    adapter: dict, workspace: Path, current: dict, current_paths: set[str],
) -> tuple[dict[str, dict] | None, set[str]]:
    receipts = current.get("receipts")
    impact = receipts.get("impact") if isinstance(receipts, dict) else None
    if not isinstance(impact, dict):
        return None, set()
    if (
        impact.get("schema") != "govern-ai-coding.receipt.v1"
        or (
            "schema_version" in impact
            and impact.get("schema_version") != "1"
        )
    ):
        return None, set()
    identity = impact.get("adapter")
    impact_workspace = impact.get("workspace")
    inventory_source = impact.get("inventory_source")
    capability = impact.get("verification_capability")
    if not (
        isinstance(identity, dict)
        and identity.get("project") == adapter.get("project")
        and identity.get("schema_version") == adapter.get("schema_version")
        and isinstance(impact_workspace, dict)
        and impact_workspace.get("path") == str(workspace.resolve())
        and isinstance(inventory_source, dict)
        and isinstance(inventory_source.get("kind"), str)
        and inventory_source.get("verified") is True
        and isinstance(capability, dict)
        and capability.get("baseline_inventory") is True
    ):
        return None, set()
    planned = impact.get("planned_paths")
    candidates = impact.get("candidate_authority_paths")
    inventory = impact.get("baseline_inventory")
    other_lists = (
        impact.get("affected_authorities"),
        impact.get("protected_paths"),
        impact.get("excluded_paths"),
        impact.get("human_approval_required"),
    )
    if not (
        isinstance(planned, list)
        and all(_safe_path(item) for item in planned)
        and set(planned).issubset(current_paths)
        and isinstance(candidates, list)
        and all(_safe_path(item) for item in candidates)
        and isinstance(inventory, dict)
        and isinstance(inventory.get("entries"), list)
        and all(
            isinstance(values, list)
            and all(isinstance(item, str) and item for item in values)
            for values in other_lists
        )
    ):
        return None, set()
    inventory_origin = inventory.get("source")
    if not (
        inventory.get("schema") == "govern-ai-coding.inventory.v1"
        and isinstance(inventory_origin, dict)
        and isinstance(inventory_origin.get("kind"), str)
        and inventory_origin.get("verified") is True
    ):
        return None, set()
    entries: dict[str, dict] = {}
    for entry in inventory["entries"]:
        if (
            not isinstance(entry, dict)
            or not _safe_path(entry.get("path"))
            or entry["path"] in entries
            or not isinstance(entry.get("inventory_source"), str)
            or entry.get("verified") is not True
            or not isinstance(entry.get("metadata"), dict)
        ):
            return None, set()
        existence = entry.get("existence")
        digest = entry.get("digest")
        if (
            not isinstance(existence, bool)
            or (
                existence
                and (
                    not isinstance(digest, str)
                    or re.fullmatch(r"[0-9a-f]{64}", digest) is None
                )
            )
            or (not existence and digest is not None)
        ):
            return None, set()
        entries[entry["path"]] = {
            "existence": existence,
            "digest": digest if existence else None,
        }
    return entries, current_paths | set(candidates)


def _bound_peer_payload(adapter: dict, descriptor: dict) -> tuple[dict | None, str]:
    manifest = descriptor["manifest"]
    workspace = Path(descriptor["workspace"])
    attestation = descriptor.get("attestation")
    if attestation is None:
        pointer = (manifest.get("receipts") or {}).get("closeout_attestation")
        attestation = pointer.get("path") if isinstance(pointer, dict) else None
    if not isinstance(attestation, (str, Path)):
        return None, "missing"
    config = adapter.get("work_map")
    schemas = config.get("attestations", {}) if isinstance(config, dict) else {}
    parsed = parse_closeout_attestation(
        Path(attestation),
        current_schemas=schemas.get(
            "current_schemas", CURRENT_ATTESTATION_SCHEMAS,
        ),
        historical_schemas=schemas.get("historical_schemas", []),
    )
    bound = bind_closeout_attestation(
        parsed,
        path=Path(attestation),
        adapter=adapter,
        workspace=workspace,
        manifest=manifest,
    )
    if bound.get("status") != "matching":
        return None, str(bound.get("status", "evidence-incomplete"))
    return bound["payload"], "matching"


def preflight_declared_events(
    *,
    adapter: dict,
    workspace: Path,
    current_manifest: dict,
    peers: list[dict],
) -> dict:
    """Compare only declared event facts and explicitly supplied evidence."""
    conflicts: list[dict] = []
    warnings: list[dict] = []
    current, current_paths = _declared_manifest(current_manifest, Path(workspace))
    if current is None:
        warnings.append({"code": "current-declaration-unproven"})
        valid_peers: list[tuple[dict, set[str], dict]] = []
    else:
        valid_peers = []
        for index, descriptor in enumerate(peers):
            if not isinstance(descriptor, dict):
                warnings.append({"code": "peer-declaration-unproven", "peer": index})
                continue
            peer_workspace = descriptor.get("workspace")
            peer_value = descriptor.get("manifest")
            if not isinstance(peer_workspace, (str, Path)):
                warnings.append({"code": "peer-declaration-unproven", "peer": index})
                continue
            declared, declared_paths = _declared_manifest(
                peer_value, Path(peer_workspace),
            )
            if declared is None:
                warnings.append({"code": "peer-declaration-unproven", "peer": index})
                continue
            valid_peers.append((declared, declared_paths, descriptor))

    if current is not None:
        current_binding = _binding(current)
        current_authorities, current_scopes = _authority_relations(
            adapter, current_paths,
        )
        for peer_manifest, peer_paths, descriptor in valid_peers:
            peer_id = peer_manifest["event"]["id"]
            peer_binding = _binding(peer_manifest)
            if (
                current_binding is not None
                and peer_binding is not None
                and current_binding["item_id"] == peer_binding["item_id"]
                and current_binding["task_id"] != peer_binding["task_id"]
            ):
                conflicts.append({
                    "code": "work-item-task-conflict",
                    "peer_event": peer_id,
                    "item_id": current_binding["item_id"],
                })
            overlap = sorted(current_paths & peer_paths)
            if overlap:
                conflicts.append({
                    "code": "exact-path-overlap",
                    "peer_event": peer_id,
                    "paths": overlap,
                })
            peer_authorities, peer_scopes = _authority_relations(
                adapter, peer_paths,
            )
            authority_overlap = sorted(current_authorities & peer_authorities)
            scope_overlap = sorted(current_scopes & peer_scopes)
            if (authority_overlap or scope_overlap) and not overlap:
                warnings.append({
                    "code": "authority-scope-overlap",
                    "peer_event": peer_id,
                    "authority_rules": authority_overlap,
                    "authority_scopes": scope_overlap,
                })

        unfinished, dependencies_proven = _unfinished_dependencies(
            adapter, Path(workspace), current,
        )
        if unfinished:
            conflicts.append({
                "code": "unfinished-dependency",
                "dependencies": unfinished,
            })
        elif not dependencies_proven:
            warnings.append({"code": "work-map-dependencies-unproven"})

        baseline, relevant_inputs = _baseline_inputs(
            adapter, Path(workspace), current, current_paths,
        )
        for peer_manifest, _, descriptor in valid_peers:
            has_attestation = descriptor.get("attestation") is not None or isinstance(
                (peer_manifest.get("receipts") or {}).get("closeout_attestation"),
                dict,
            )
            if not has_attestation:
                continue
            if baseline is None:
                warnings.append({
                    "code": "current-baseline-unproven",
                    "peer_event": peer_manifest["event"]["id"],
                })
                continue
            payload, evidence_status = _bound_peer_payload(adapter, descriptor)
            if payload is None:
                warnings.append({
                    "code": "peer-evidence-unproven",
                    "peer_event": peer_manifest["event"]["id"],
                    "reason": evidence_status,
                })
                continue
            changed = []
            for entry in payload["final_content"]:
                path = entry["path"]
                before = baseline.get(path)
                if path not in relevant_inputs or before is None:
                    continue
                if (
                    before["existence"] != entry["existence"]
                    or before["digest"] != entry["digest"]
                ):
                    changed.append(path)
            if changed:
                conflicts.append({
                    "code": "declared-baseline-input-changed",
                    "peer_event": peer_manifest["event"]["id"],
                    "paths": sorted(changed),
                })

    if conflicts:
        result = "fail"
    elif warnings:
        result = "unproven"
    else:
        result = "pass"
    return {
        "result": result,
        "conflicts": conflicts,
        "warnings": warnings,
        "visibility_boundary": (
            "Only the supplied manifests, configured Work Map facts, adapter "
            "rules, and explicitly bound peer evidence were inspected."
        ),
        "claim_boundary": {
            "proves": ["bounded conflicts derivable from supplied declarations"],
            "does_not_prove": [
                "absence of undisclosed concurrent work",
                "session or task scheduling",
                "branch, release, or product readiness",
            ],
        },
    }
