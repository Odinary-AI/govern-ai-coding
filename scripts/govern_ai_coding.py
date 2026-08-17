#!/usr/bin/env python3
"""Minimal deterministic checks for govern-ai-coding."""

from __future__ import annotations

import argparse
from contextvars import ContextVar
import hashlib
import importlib.util
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import unicodedata
from pathlib import Path
from urllib.parse import unquote, urlparse

try:
    import fcntl
except ImportError:  # pragma: no cover - exercised through simulated platform imports
    fcntl = None

try:
    from controlled_archive import (
        AMENDMENT_SCHEMA,
        EXECUTION_GRANT_SCHEMA,
        TASK_SCHEMA,
        TASK_GRANT_SCHEMA,
        archive_authorization_lifecycle,
        build_archive_preflight,
        canonical_archive_v1_digest,
        classify_archive_references,
        compact_archive_task_execution_results,
        global_archive_preflight,
        normalize_archive_result,
        reconcile_archive_task,
        runtime_capability_report,
        structured_archive_exception,
        validate_archive_task_manifest,
        validate_execution_grant,
        validate_task_execution_grant,
        validate_mapping_amendment,
        validate_receipt_grant_binding,
        validate_reference_rules,
    )
except ModuleNotFoundError:
    _archive_protocol_path = Path(__file__).with_name("controlled_archive.py")
    _archive_protocol_spec = importlib.util.spec_from_file_location(
        "govern_ai_coding_controlled_archive",
        _archive_protocol_path,
    )
    if _archive_protocol_spec is None or _archive_protocol_spec.loader is None:
        raise
    _archive_protocol_module = importlib.util.module_from_spec(
        _archive_protocol_spec
    )
    _archive_protocol_spec.loader.exec_module(_archive_protocol_module)
    AMENDMENT_SCHEMA = _archive_protocol_module.AMENDMENT_SCHEMA
    EXECUTION_GRANT_SCHEMA = _archive_protocol_module.EXECUTION_GRANT_SCHEMA
    TASK_SCHEMA = _archive_protocol_module.TASK_SCHEMA
    TASK_GRANT_SCHEMA = _archive_protocol_module.TASK_GRANT_SCHEMA
    archive_authorization_lifecycle = (
        _archive_protocol_module.archive_authorization_lifecycle
    )
    build_archive_preflight = _archive_protocol_module.build_archive_preflight
    canonical_archive_v1_digest = (
        _archive_protocol_module.canonical_archive_v1_digest
    )
    classify_archive_references = (
        _archive_protocol_module.classify_archive_references
    )
    compact_archive_task_execution_results = (
        _archive_protocol_module.compact_archive_task_execution_results
    )
    global_archive_preflight = _archive_protocol_module.global_archive_preflight
    normalize_archive_result = _archive_protocol_module.normalize_archive_result
    reconcile_archive_task = _archive_protocol_module.reconcile_archive_task
    runtime_capability_report = (
        _archive_protocol_module.runtime_capability_report
    )
    structured_archive_exception = (
        _archive_protocol_module.structured_archive_exception
    )
    validate_archive_task_manifest = (
        _archive_protocol_module.validate_archive_task_manifest
    )
    validate_execution_grant = (
        _archive_protocol_module.validate_execution_grant
    )
    validate_task_execution_grant = (
        _archive_protocol_module.validate_task_execution_grant
    )
    validate_mapping_amendment = (
        _archive_protocol_module.validate_mapping_amendment
    )
    validate_receipt_grant_binding = (
        _archive_protocol_module.validate_receipt_grant_binding
    )
    validate_reference_rules = _archive_protocol_module.validate_reference_rules

# Compatibility name retained for callers that already import the main CLI as a
# module. New protocol code uses the versioned owner name above.
archive_protocol_digest = canonical_archive_v1_digest

try:
    from work_map import (
        check_work_map,
        finish_work_item,
        observe_work_map_final,
        render_work_map,
        start_work_item,
        validate_work_map_config,
        verify_work_map_binding,
        work_map_status,
    )
except ModuleNotFoundError:
    _work_map_path = Path(__file__).with_name("work_map.py")
    _work_map_spec = importlib.util.spec_from_file_location(
        "govern_ai_coding_work_map",
        _work_map_path,
    )
    if _work_map_spec is None or _work_map_spec.loader is None:
        raise
    _work_map_module = importlib.util.module_from_spec(_work_map_spec)
    _work_map_spec.loader.exec_module(_work_map_module)
    validate_work_map_config = _work_map_module.validate_work_map_config
    check_work_map = _work_map_module.check_work_map
    start_work_item = _work_map_module.start_work_item
    finish_work_item = _work_map_module.finish_work_item
    observe_work_map_final = _work_map_module.observe_work_map_final
    render_work_map = _work_map_module.render_work_map
    verify_work_map_binding = _work_map_module.verify_work_map_binding
    work_map_status = _work_map_module.work_map_status

try:
    from integration_verification import verify_integration
except ModuleNotFoundError:
    _integration_path = Path(__file__).with_name("integration_verification.py")
    _integration_spec = importlib.util.spec_from_file_location(
        "govern_ai_coding_integration_verification", _integration_path,
    )
    if _integration_spec is None or _integration_spec.loader is None:
        raise
    _integration_module = importlib.util.module_from_spec(_integration_spec)
    _integration_spec.loader.exec_module(_integration_module)
    verify_integration = _integration_module.verify_integration

try:
    from event_preflight import preflight_declared_events
except ModuleNotFoundError:
    _event_preflight_path = Path(__file__).with_name("event_preflight.py")
    _event_preflight_spec = importlib.util.spec_from_file_location(
        "govern_ai_coding_event_preflight", _event_preflight_path,
    )
    if _event_preflight_spec is None or _event_preflight_spec.loader is None:
        raise
    _event_preflight_module = importlib.util.module_from_spec(
        _event_preflight_spec
    )
    _event_preflight_spec.loader.exec_module(_event_preflight_module)
    preflight_declared_events = (
        _event_preflight_module.preflight_declared_events
    )

try:
    from closeout_evidence import (
        CLOSEOUT_ATTESTATION_SCHEMA,
        bind_closeout_attestation,
        build_closeout_attestation as build_evidence_attestation,
        build_validation_receipt as build_evidence_validation_receipt,
        canonical_evidence_v1_digest,
        collect_validation_evidence_for_profile,
        current_closeout_attempt,
        parse_closeout_attestation,
        validate_event_manifest_closeout_ledger,
        validate_validation_receipt_for_profile,
    )
except ModuleNotFoundError:
    _closeout_evidence_path = Path(__file__).with_name("closeout_evidence.py")
    _closeout_evidence_spec = importlib.util.spec_from_file_location(
        "govern_ai_coding_closeout_evidence", _closeout_evidence_path,
    )
    if _closeout_evidence_spec is None or _closeout_evidence_spec.loader is None:
        raise
    _closeout_evidence_module = importlib.util.module_from_spec(
        _closeout_evidence_spec
    )
    _closeout_evidence_spec.loader.exec_module(_closeout_evidence_module)
    CLOSEOUT_ATTESTATION_SCHEMA = (
        _closeout_evidence_module.CLOSEOUT_ATTESTATION_SCHEMA
    )
    bind_closeout_attestation = (
        _closeout_evidence_module.bind_closeout_attestation
    )
    build_evidence_attestation = (
        _closeout_evidence_module.build_closeout_attestation
    )
    build_evidence_validation_receipt = (
        _closeout_evidence_module.build_validation_receipt
    )
    canonical_evidence_v1_digest = (
        _closeout_evidence_module.canonical_evidence_v1_digest
    )
    collect_validation_evidence_for_profile = (
        _closeout_evidence_module.collect_validation_evidence_for_profile
    )
    current_closeout_attempt = (
        _closeout_evidence_module.current_closeout_attempt
    )
    parse_closeout_attestation = (
        _closeout_evidence_module.parse_closeout_attestation
    )
    validate_event_manifest_closeout_ledger = (
        _closeout_evidence_module.validate_event_manifest_closeout_ledger
    )
    validate_validation_receipt_for_profile = (
        _closeout_evidence_module.validate_validation_receipt_for_profile
    )


CHANGE_KINDS = {"added", "modified", "deleted", "renamed"}
INVENTORY_SCHEMA = "govern-ai-coding.inventory.v1"
IMPACT_RECEIPT_SCHEMA = "govern-ai-coding.receipt.v1"
FREEZE_RECEIPT_SCHEMA = "govern-ai-coding.freeze-receipt.v1"
EVENT_MANIFEST_SCHEMA = "govern-ai-coding.event-manifest.v1"
EVENT_MANIFEST_V2_SCHEMA = "govern-ai-coding.event-manifest.v2"
AUDIT_EVENT_RESULT_SCHEMA = "govern-ai-coding.audit-event-result.v1"
ARCHIVE_REQUEST_SCHEMA = "govern-ai-coding.archive-request.v1"
ARCHIVE_RECEIPT_SCHEMA = "govern-ai-coding.archive-receipt.v1"
ADAPTER_SCHEMA_VERSION = "2"
NAVIGATION_ENTRYPOINT_PATH = "README.md"
DEFAULT_INVENTORY_EXCLUDES = [
    ".git/",
    "node_modules/",
    "__pycache__/",
    ".pytest_cache/",
    ".mypy_cache/",
    ".ruff_cache/",
    ".cache/",
    "dist/",
    "build/",
    "runtime-data/",
]
DEFAULT_INVENTORY_EXCLUDE_COMPONENTS = {
    pattern.rstrip("/")
    for pattern in DEFAULT_INVENTORY_EXCLUDES
    if "/" not in pattern.rstrip("/")
}
SKILL_ROOT = Path(__file__).resolve().parent.parent
PACKAGE_DIGEST_EXCLUDED_NAMES = {"__pycache__", ".DS_Store"}


def read_skill_version() -> str:
    version = (SKILL_ROOT / "VERSION").read_text(encoding="utf-8").strip()
    if not version:
        raise ValueError("Skill VERSION is empty")
    return version


def skill_package_digest() -> str:
    digest = hashlib.sha256()
    for path in sorted(SKILL_ROOT.rglob("*")):
        relative = path.relative_to(SKILL_ROOT)
        if (
            not path.is_file()
            or path.is_symlink()
            or any(part in PACKAGE_DIGEST_EXCLUDED_NAMES for part in relative.parts)
            or path.suffix == ".pyc"
        ):
            continue
        encoded_path = relative.as_posix().encode("utf-8")
        content = path.read_bytes()
        digest.update(len(encoded_path).to_bytes(8, "big"))
        digest.update(encoded_path)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def runtime_identity() -> str:
    return f"govern-ai-coding {read_skill_version()} sha256:{skill_package_digest()}"


def json_type_name(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "array"
    if isinstance(value, str):
        return "string"
    if isinstance(value, (int, float)):
        return "number"
    return type(value).__name__


def load_json_object(
    path: Path,
    *,
    input_name: str,
    category: str,
) -> tuple[dict | None, dict | None]:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise
    except UnicodeError as exc:
        actual = "invalid UTF-8"
        message = f"{input_name} is not readable UTF-8: {exc}"
        code = f"{input_name}-unreadable"
    except OSError as exc:
        actual = "unreadable"
        message = f"{input_name} could not be read: {exc}"
        code = f"{input_name}-unreadable"
    else:
        try:
            value = json.loads(text)
        except json.JSONDecodeError as exc:
            actual = "invalid JSON"
            message = f"{input_name} contains invalid JSON: {exc}"
            code = f"{input_name}-invalid-json"
        else:
            if isinstance(value, dict):
                return value, None
            actual = json_type_name(value)
            message = f"{input_name} root must be a JSON object, received {actual}"
            code = f"{input_name}-root-not-object"
    recovery = f"Provide a readable UTF-8 JSON object for {input_name} and rerun only this command."
    return None, {
        "code": code,
        "severity": "blocking",
        "category": category,
        "message": message,
        "field": input_name,
        "path": str(path),
        "expected": "JSON object",
        "actual": actual,
        "recovery_actions": [recovery],
    }


def load_json(path: Path) -> dict:
    value, finding = load_json_object(
        path,
        input_name="json-input",
        category="receipt_format",
    )
    if finding is not None:
        raise SystemExit(finding["message"])
    return value


def load_json_or_missing(path: Path) -> tuple[dict | None, dict | None]:
    try:
        adapter, finding = load_json_object(
            path,
            input_name="adapter",
            category="adapter_configuration",
        )
    except FileNotFoundError:
        return None, adapter_missing_result(path)
    if finding is None:
        return adapter, None
    return None, {
        "result": "fail",
        "adapter": {"path": str(path)},
        "mechanical_findings": [finding],
        "semantic_findings": [],
        "human_approval_required": [],
        "recovery": finding["recovery_actions"][0],
    }


RESULT_EXIT_CODES = {"pass": 0, "fail": 1, "unproven": 2}
COMPACT_RESULT_SCHEMA = "govern-ai-coding.compact-result.v1"
_COMPACT_OUTPUT = ContextVar("govern_ai_coding_compact_output", default=False)


def result_exit_code(payload: dict) -> int:
    result = payload.get("result", payload.get("verdict"))
    return RESULT_EXIT_CODES.get(result, 3)


def compact_result_payload(
    payload: dict,
    *,
    diagnostics_structured: bool = False,
) -> dict:
    structured = payload if diagnostics_structured else add_structured_diagnostics(payload)
    groups: dict[str, dict] = {}
    for diagnostic in structured.get("diagnostics", []) or []:
        if not isinstance(diagnostic, dict):
            continue
        recovery_actions = diagnostic.get("recovery_actions", [])
        key_fields = {
            "severity": diagnostic.get("severity"),
            "category": diagnostic.get("category"),
            "code": diagnostic.get("code"),
            "recovery_actions": recovery_actions,
        }
        key = json.dumps(key_fields, sort_keys=True, separators=(",", ":"))
        group = groups.setdefault(key, {
            **key_fields,
            "count": 0,
            "occurrences": [],
        })
        group["count"] += 1
        group["occurrences"].append(diagnostic)

    compact = {
        "schema": COMPACT_RESULT_SCHEMA,
        "result": structured.get("result", structured.get("verdict")),
        "diagnostic_groups": list(groups.values()),
    }
    preserved_fields = {"result", "verdict", "diagnostics"}
    if isinstance(structured.get("schema"), str):
        compact["source_schema"] = structured["schema"]
        preserved_fields.add("schema")
    for field in (
        "verdict",
        "phase",
        "operation_state",
        "changed",
        "atomicity",
        "authorization_state",
        "receipt_bindings",
        "human_approval_required",
        "approval_summary",
        "recovery",
        "recovery_actions",
    ):
        if field in structured:
            compact[field] = structured[field]
            preserved_fields.add(field)
    compact["claim_boundary"] = {
        "presentation_only": True,
        "producer_payload_unchanged": True,
        "diagnostic_occurrences_preserved": True,
        "full_output_available_without_compact": True,
        "omitted_top_level_fields": sorted(
            set(structured) - preserved_fields
        ),
    }
    return compact


def emit(payload: dict) -> int:
    structured = add_structured_diagnostics(payload)
    rendered = (
        compact_result_payload(structured, diagnostics_structured=True)
        if _COMPACT_OUTPUT.get()
        else structured
    )
    print(json.dumps(rendered, indent=2, sort_keys=True))
    return result_exit_code(structured)


def path_matches(candidate: str, pattern: str) -> bool:
    pattern = pattern.rstrip("/")
    candidate = candidate.rstrip("/")
    return candidate == pattern or candidate.startswith(pattern + "/")


def normalize_path_value(path: str, field: str = "path") -> tuple[str | None, dict | None]:
    raw = path.strip()
    if not raw:
        return None, {"code": "invalid-path-empty", "field": field, "path": path}
    if "\x00" in raw:
        return None, {"code": "invalid-path-nul", "field": field, "path": path}
    candidate = raw.replace("\\", "/")
    if (
        candidate.startswith("/")
        or re.match(r"^[A-Za-z]:", candidate)
        or Path(candidate).is_absolute()
    ):
        return None, {"code": "invalid-path-absolute", "field": field, "path": path}
    while candidate.startswith("./"):
        candidate = candidate[2:]
    candidate = candidate.rstrip("/")
    if not candidate:
        return None, {"code": "invalid-path-empty", "field": field, "path": path}
    parts = candidate.split("/")
    if any(part == ".." for part in parts):
        return None, {"code": "invalid-path-escape", "field": field, "path": path}
    candidate = "/".join(part for part in parts if part not in {"", "."})
    if not candidate:
        return None, {"code": "invalid-path-empty", "field": field, "path": path}
    return candidate, None


def normalize_path(path: str) -> str:
    normalized, _ = normalize_path_value(path)
    return normalized or path.strip().rstrip("/")


def normalize_paths_with_findings(paths: list[str], field: str) -> tuple[list[str], list[dict]]:
    normalized = []
    findings = []
    for path in paths:
        value, finding = normalize_path_value(path, field)
        if finding:
            findings.append(finding)
        elif value:
            normalized.append(value)
    return sorted(set(normalized)), findings


def normalize_paths(paths: list[str]) -> list[str]:
    normalized, _ = normalize_paths_with_findings(paths, "path")
    return normalized


def is_string_list(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def add_type_finding(findings: list[dict], code: str, field: str, expected: str) -> None:
    findings.append({"code": code, "field": field, "expected": expected})


def safe_rule_list(adapter: dict) -> list[dict]:
    rules = adapter.get("authority_rules", [])
    return rules if isinstance(rules, list) else []


def safe_section(adapter: dict, key: str) -> dict:
    value = adapter.get(key, {})
    return value if isinstance(value, dict) else {}


def validate_controlled_archive_config(adapter: dict) -> list[dict]:
    config = adapter.get("controlled_archive")
    if config is None:
        return []
    if not isinstance(config, dict):
        return [{
            "code": "invalid-controlled-archive-config",
            "field": "controlled_archive",
        }]

    findings: list[dict] = []
    normalized: dict[str, list[str]] = {}
    for field in ("source_roots", "archive_roots"):
        value = config.get(field)
        if not is_string_list(value) or not value:
            findings.append({
                "code": "invalid-controlled-archive-config",
                "field": f"controlled_archive.{field}",
            })
            normalized[field] = []
            continue
        for root in value:
            if re.search(r"[$*?{}\[\]~]", root):
                findings.append({
                    "code": "controlled-archive-root-unresolved",
                    "field": f"controlled_archive.{field}",
                    "path": root,
                })
        roots, root_findings = normalize_paths_with_findings(
            value,
            f"controlled_archive.{field}",
        )
        findings.extend(root_findings)
        normalized[field] = roots

    approval_type = config.get("approval_type")
    if not isinstance(approval_type, str) or not approval_type.strip():
        findings.append({
            "code": "invalid-controlled-archive-config",
            "field": "controlled_archive.approval_type",
        })
    elif approval_type not in (
        adapter.get("human_approval", [])
        if is_string_list(adapter.get("human_approval"))
        else []
    ):
        findings.append({
            "code": "controlled-archive-approval-type-not-declared",
            "type": approval_type,
        })

    boundaries = safe_section(adapter, "boundaries")
    entrypoints = safe_section(adapter, "entrypoints")
    excluded = (
        boundaries.get("excluded", [])
        if is_string_list(boundaries.get("excluded", []))
        else []
    )
    protected = (
        boundaries.get("protected", [])
        if is_string_list(boundaries.get("protected", []))
        else []
    )
    historical = (
        entrypoints.get("historical", [])
        if is_string_list(entrypoints.get("historical", []))
        else []
    )

    for root in normalized.get("archive_roots", []):
        if not any(path_matches(root, pattern) for pattern in excluded):
            findings.append({
                "code": "controlled-archive-root-not-excluded",
                "path": root,
            })
    for root in normalized.get("source_roots", []):
        matched = [
            pattern
            for pattern in [*excluded, *protected, *historical]
            if path_matches(root, pattern)
        ]
        if matched:
            findings.append({
                "code": "controlled-archive-source-root-not-active",
                "path": root,
                "matched": matched,
            })
    for source_root in normalized.get("source_roots", []):
        for archive_root in normalized.get("archive_roots", []):
            if path_matches(source_root, archive_root) or path_matches(
                archive_root,
                source_root,
            ):
                findings.append({
                    "code": "controlled-archive-roots-overlap",
                    "source_root": source_root,
                    "archive_root": archive_root,
                })
    archive_roots = normalized.get("archive_roots", [])
    for index, first in enumerate(archive_roots):
        for second in archive_roots[index + 1:]:
            if path_matches(first, second) or path_matches(second, first):
                findings.append({
                    "code": "controlled-archive-roots-overlap",
                    "archive_roots": [first, second],
                })
    findings.extend(validate_reference_rules(adapter))
    return findings


def resolve_rule_approval_type(
    adapter: dict,
    rule: dict,
) -> tuple[str | None, dict | None, dict | None]:
    if not rule.get("human"):
        return None, None, None
    precise = rule.get("human_approval_types")
    if precise is not None:
        if not is_string_list(precise):
            return None, None, None
        if not precise:
            return None, {
                "code": "human-approval-type-unmapped",
                "id": rule.get("id"),
            }, None
        if len(precise) > 1:
            return None, {
                "code": "ambiguous-human-approval-types",
                "id": rule.get("id"),
                "types": sorted(precise),
            }, None
        return precise[0], None, None
    declared = adapter.get("human_approval", [])
    if not is_string_list(declared) or not declared:
        return None, {
            "code": "human-approval-type-unmapped",
            "id": rule.get("id"),
        }, None
    if len(declared) > 1:
        return None, {
            "code": "ambiguous-human-approval-types",
            "id": rule.get("id"),
            "types": sorted(declared),
        }, None
    return declared[0], None, {
        "code": "legacy-human-approval-type-inference",
        "id": rule.get("id"),
        "type": declared[0],
        "message": "add one explicit human_approval_types value to this human rule",
    }


def adapter_missing_result(path: Path) -> dict:
    return {
        "result": "unproven",
        "adapter": {"path": str(path)},
        "mechanical_findings": [{"code": "adapter-missing", "path": str(path)}],
        "semantic_findings": [],
        "human_approval_required": [],
        "recovery": "No project adapter was found. Create a candidate adapter from project pointers and ask for human approval before treating it as governance authority.",
    }


def rule_map(adapter: dict) -> dict:
    return {
        rule["id"]: rule
        for rule in safe_rule_list(adapter)
        if isinstance(rule, dict) and rule.get("id")
    }


def make_semantic_finding(
    *,
    code: str,
    affected_question: str | None,
    evidence: str,
    confidence: str,
    human_boundary: bool,
) -> dict:
    if human_boundary:
        decision_boundary = "human"
        suggested = "route to human decision; do not auto-repair"
    else:
        decision_boundary = "semantic"
        suggested = "review authority and evidence; keep result unproven until reconciled"
    return {
        "code": code,
        "affected_question": affected_question,
        "evidence": evidence,
        "confidence": confidence,
        "decision_boundary": decision_boundary,
        "suggested_handling": suggested,
        "human_boundary": human_boundary,
    }


def validate_navigation_entrypoint_config(adapter: dict) -> list[dict]:
    findings: list[dict] = []
    configured = adapter.get("navigation_entrypoint")
    if not isinstance(configured, dict):
        return [{
            "code": "navigation-entrypoint-config-missing",
            "field": "navigation_entrypoint",
            "message": "navigation_entrypoint must be an object with path README.md",
        }]
    if configured.get("path") != NAVIGATION_ENTRYPOINT_PATH:
        findings.append({
            "code": "navigation-entrypoint-path-invalid",
            "field": "navigation_entrypoint.path",
            "path": configured.get("path"),
            "message": "navigation_entrypoint.path must be exactly README.md",
        })

    boundaries = safe_section(adapter, "boundaries")
    ordinary = (
        boundaries.get("ordinary_docs", [])
        if is_string_list(boundaries.get("ordinary_docs", []))
        else []
    )
    if not any(
        path_matches(NAVIGATION_ENTRYPOINT_PATH, pattern)
        for pattern in ordinary
    ):
        findings.append({
            "code": "navigation-entrypoint-boundary-missing",
            "path": NAVIGATION_ENTRYPOINT_PATH,
            "message": "README.md must be covered by boundaries.ordinary_docs",
        })

    conflicts: list[dict] = []
    for field in ("protected", "excluded"):
        patterns = boundaries.get(field, [])
        if not is_string_list(patterns):
            continue
        for pattern in patterns:
            if path_matches(NAVIGATION_ENTRYPOINT_PATH, pattern):
                conflicts.append({"field": f"boundaries.{field}", "pattern": pattern})
    historical = safe_section(adapter, "entrypoints").get("historical", [])
    if is_string_list(historical):
        for pattern in historical:
            if path_matches(NAVIGATION_ENTRYPOINT_PATH, pattern):
                conflicts.append({"field": "entrypoints.historical", "pattern": pattern})
    if conflicts:
        findings.append({
            "code": "navigation-entrypoint-boundary-conflict",
            "path": NAVIGATION_ENTRYPOINT_PATH,
            "conflicts": conflicts,
            "message": "README.md must not be protected, excluded, or historical",
        })
    return findings


def validate_adapter(adapter: dict) -> dict:
    findings = []
    warnings = []
    raw_rules = adapter.get("authority_rules", [])
    rules = raw_rules if isinstance(raw_rules, list) else []
    seen = set()

    schema_version = adapter.get("schema_version")
    if schema_version == "1":
        findings.append({
            "code": "adapter-schema-migration-required",
            "field": "schema_version",
            "message": "schema_version 1 must be explicitly migrated to schema_version 2",
        })
    elif schema_version != ADAPTER_SCHEMA_VERSION:
        findings.append({
            "code": "unsupported-schema-version",
            "field": "schema_version",
            "message": f"schema_version must be {ADAPTER_SCHEMA_VERSION}",
        })

    if not isinstance(adapter.get("project"), str) or not adapter.get("project"):
        add_type_finding(findings, "invalid-project", "project", "non-empty string")

    if not isinstance(raw_rules, list) or not raw_rules:
        findings.append({"code": "missing-authority-rules", "message": "authority_rules must be a non-empty list"})

    for rule in rules:
        if not isinstance(rule, dict):
            findings.append({"code": "invalid-authority-rule", "message": "authority rule must be an object"})
            continue
        rid = rule.get("id")
        if not rid:
            findings.append({"code": "missing-authority-rule-id", "message": "authority rule is missing id"})
            continue
        if rid in seen:
            findings.append({"code": "duplicate-authority-rule", "id": rid})
        seen.add(rid)
        if not rule.get("question") or not rule.get("scope"):
            findings.append({"code": "incomplete-authority-rule", "id": rid})
        if not isinstance(rule.get("paths"), list) or not rule.get("paths"):
            findings.append({"code": "missing-authority-paths", "id": rid})
        elif not is_string_list(rule.get("paths")):
            add_type_finding(findings, "invalid-authority-paths", f"authority_rules.{rid}.paths", "list of strings")
        if "triggers" in rule and not is_string_list(rule.get("triggers")):
            add_type_finding(findings, "invalid-authority-triggers", f"authority_rules.{rid}.triggers", "list of strings")
        if "human_approval_types" in rule:
            if not is_string_list(rule.get("human_approval_types")):
                add_type_finding(findings, "invalid-authority-human-approval-types", f"authority_rules.{rid}.human_approval_types", "list of strings")
            elif is_string_list(adapter.get("human_approval")):
                for approval_type in rule.get("human_approval_types"):
                    if approval_type not in adapter.get("human_approval", []):
                        findings.append({
                            "code": "undeclared-authority-human-approval-type",
                            "id": rid,
                            "type": approval_type,
                        })
        _, approval_finding, approval_warning = resolve_rule_approval_type(
            adapter,
            rule,
        )
        if approval_finding:
            findings.append(approval_finding)
        if approval_warning:
            warnings.append(approval_warning)

    entrypoints = adapter.get("entrypoints")
    if not isinstance(entrypoints, dict):
        findings.append({"code": "missing-entrypoints", "message": "entrypoints must be an object"})
        entrypoints = {}
    for key in ["current", "historical", "evidence"]:
        value = entrypoints.get(key)
        if not is_string_list(value):
            add_type_finding(findings, f"invalid-{key}-entrypoints", f"entrypoints.{key}", "list of strings")
    if is_string_list(entrypoints.get("current")) and not entrypoints.get("current"):
        findings.append({"code": "missing-current-entrypoints", "message": "entrypoints.current must not be empty"})
    if is_string_list(entrypoints.get("evidence")) and not entrypoints.get("evidence"):
        findings.append({"code": "missing-evidence-entrypoints", "message": "entrypoints.evidence must not be empty"})

    boundaries = adapter.get("boundaries")
    if not isinstance(boundaries, dict):
        findings.append({"code": "missing-boundaries", "message": "boundaries must be an object"})
        boundaries = {}
    for key in ["protected", "excluded", "ordinary_docs"]:
        value = boundaries.get(key)
        if not is_string_list(value):
            add_type_finding(findings, f"invalid-boundary-{key}", f"boundaries.{key}", "list of strings")

    findings.extend(validate_navigation_entrypoint_config(adapter))

    human_approval = adapter.get("human_approval")
    if human_approval is None:
        findings.append({"code": "missing-human-approval", "message": "human_approval must be a list"})
    elif not is_string_list(human_approval):
        add_type_finding(findings, "invalid-human-approval", "human_approval", "list of strings")

    checks = adapter.get("plan_status_checks", [])
    if checks is not None:
        if not isinstance(checks, list):
            add_type_finding(findings, "invalid-plan-status-checks", "plan_status_checks", "list")
        else:
            for index, check in enumerate(checks):
                if not isinstance(check, dict):
                    add_type_finding(findings, "invalid-plan-status-check", f"plan_status_checks.{index}", "object")
                    continue
                if not isinstance(check.get("status_path"), str):
                    add_type_finding(findings, "invalid-plan-status-path", f"plan_status_checks.{index}.status_path", "string")
                if not is_string_list(check.get("plan_paths")):
                    add_type_finding(findings, "invalid-plan-status-plan-paths", f"plan_status_checks.{index}.plan_paths", "list of strings")

    findings.extend(validate_work_map_config(adapter))
    findings.extend(validate_controlled_archive_config(adapter))

    return {
        "result": "fail" if findings else "pass",
        "adapter": {
            "schema_version": adapter.get("schema_version"),
            "project": adapter.get("project"),
            "authority_rule_count": len(rules),
        },
        "mechanical_findings": findings,
        "warnings": warnings,
        "semantic_findings": [],
        "human_approval_required": [],
        "recovery": "Adapter validation completed from declared pointers and rules.",
    }


def validate_inventory(
    inventory: object,
    *,
    require_entries: bool = False,
) -> list[dict]:
    findings: list[dict] = []
    if not isinstance(inventory, dict):
        return [{"code": "malformed-inventory", "field": "root"}]
    if inventory.get("schema") != INVENTORY_SCHEMA:
        findings.append({"code": "unsupported-inventory-schema", "schema": inventory.get("schema")})
    source = inventory.get("source")
    if not isinstance(source, dict) or not isinstance(source.get("kind"), str) or not isinstance(source.get("verified"), bool):
        findings.append({"code": "malformed-inventory", "field": "source"})
    entries = inventory.get("entries")
    if not isinstance(entries, list):
        return findings + [{"code": "malformed-inventory", "field": "entries"}]
    if require_entries and not entries:
        findings.append({"code": "empty-inventory"})
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            findings.append({"code": "malformed-inventory-entry", "entry": index})
            continue
        path, path_finding = normalize_path_value(str(entry.get("path", "")), "inventory.path")
        if path_finding:
            findings.append({"code": "malformed-inventory-entry", "entry": index, "field": "path"})
            continue
        if path in seen:
            findings.append({"code": "duplicate-inventory-path", "path": path})
        seen.add(path)
        kind = entry.get("kind")
        if kind is not None and kind not in CHANGE_KINDS:
            findings.append({"code": "unknown-change-kind", "entry": index, "kind": kind})
        if not isinstance(entry.get("existence"), bool):
            findings.append({"code": "malformed-inventory-entry", "entry": index, "field": "existence"})
        if "digest" not in entry:
            findings.append({"code": "malformed-inventory-entry", "entry": index, "field": "digest"})
        if kind == "renamed":
            if not all(isinstance(entry.get(key), str) and entry.get(key) for key in ("old_path", "new_path")):
                findings.append({"code": "malformed-inventory-entry", "entry": index, "field": "rename"})
    return findings


def validate_impact_receipt(receipt: object, adapter: dict, workspace: Path) -> list[dict]:
    if not isinstance(receipt, dict):
        return [{"code": "malformed-impact-receipt", "field": "root"}]
    required_objects = ["adapter", "workspace", "inventory_source", "baseline_inventory", "verification_capability"]
    required_lists = ["planned_paths", "affected_authorities", "candidate_authority_paths", "protected_paths", "excluded_paths", "human_approval_required"]
    findings: list[dict] = []
    if receipt.get("schema") != IMPACT_RECEIPT_SCHEMA:
        findings.append({"code": "malformed-impact-receipt", "field": "schema"})
    if "schema_version" in receipt and receipt.get("schema_version") != "1":
        findings.append({"code": "malformed-impact-receipt", "field": "schema_version"})
    for field in required_objects:
        if not isinstance(receipt.get(field), dict):
            findings.append({"code": "malformed-impact-receipt", "field": field})
    for field in required_lists:
        if not is_string_list(receipt.get(field)):
            findings.append({"code": "malformed-impact-receipt", "field": field})
    if findings:
        return findings
    identity_mismatch = (
        receipt["adapter"].get("project") != adapter.get("project")
        or receipt["adapter"].get("schema_version") != adapter.get("schema_version")
        or receipt["workspace"].get("path") != str(workspace.resolve())
    )
    if identity_mismatch:
        findings.append({
            "code": "impact-receipt-identity-mismatch",
            "expected_project": adapter.get("project"),
            "expected_workspace": str(workspace.resolve()),
        })
    findings.extend(validate_inventory(receipt["baseline_inventory"]))
    return findings


def extract_impact_receipt(payload: object) -> tuple[dict | None, list[dict]]:
    if not isinstance(payload, dict):
        return None, [{"code": "malformed-impact-receipt", "field": "root"}]
    if payload.get("schema") == IMPACT_RECEIPT_SCHEMA:
        return payload, []
    if "receipt" in payload:
        receipt = payload.get("receipt")
        if not isinstance(receipt, dict):
            return None, [{"code": "malformed-impact-receipt", "field": "receipt"}]
        return receipt, []
    return payload, []


def validate_adapter_command(args: argparse.Namespace) -> int:
    adapter, missing = load_json_or_missing(Path(args.adapter))
    if missing:
        return emit(missing)
    structural = validate_adapter(adapter)
    if structural["result"] == "fail":
        return emit(structural)
    if not args.workspace:
        structural["result"] = "unproven"
        structural["coverage"] = {
            "unverified": ["navigation-entrypoint-workspace-required"],
        }
        structural["recovery"] = (
            "Rerun validate-adapter with --workspace to verify the required root README.md."
        )
        return emit(structural)
    return emit(validate_live_adapter(adapter, Path(args.workspace)))


def work_map_command(args: argparse.Namespace) -> int:
    adapter, missing = load_json_or_missing(Path(args.adapter))
    if missing:
        return emit(missing)
    validation = validate_live_adapter(adapter, Path(args.workspace))
    if validation["result"] != "pass":
        return emit(validation)
    if "work_map" not in adapter:
        return emit({
            "result": "unproven",
            "mechanical_findings": [],
            "semantic_findings": [],
            "human_approval_required": [],
            "recovery": "Add an optional work_map adapter configuration before using Work Map commands.",
        })
    workspace = Path(args.workspace)
    if args.work_map_action == "status":
        manifest, findings = load_event_manifest(args.event_manifest)
        if manifest is not None:
            declared_workspace = Path(manifest["event"]["workspace"])
            if not declared_workspace.is_absolute():
                declared_workspace = Path(args.event_manifest).parent / declared_workspace
            if declared_workspace.resolve() != workspace.resolve():
                findings.append({
                    "code": "event-manifest-workspace-mismatch",
                    "expected": str(workspace.resolve()),
                    "actual": str(declared_workspace.resolve()),
                })
        if findings:
            return emit({
                "result": "fail",
                "mechanical_findings": findings,
                "semantic_findings": [],
                "human_approval_required": [],
                "recovery": "Correct the event manifest before deriving Work Map status.",
            })
        binding = manifest.get("work_map_binding") if manifest is not None else None
        if not isinstance(binding, dict):
            return emit({
                "result": "unproven",
                "mechanical_findings": [],
                "semantic_findings": [],
                "human_approval_required": [],
                "recovery": "Bind the event manifest to a Work Map item before deriving status.",
            })
        try:
            payload = work_map_status(
                adapter,
                workspace,
                binding,
                manifest,
                manifest_path=Path(args.event_manifest),
            )
        except (OSError, UnicodeError) as exc:
            payload = {
                "result": "unproven",
                "engineering_relation": "evidence-unreadable",
                "attestation_relation": "unproven",
                "observation": None,
                "attestation": None,
                "findings": [{
                    "code": "work-map-evidence-unreadable",
                    "message": str(exc),
                    "recovery_actions": [
                        "Restore readable Work Map evidence and rerun the read-only status command."
                    ],
                }],
                "claim_boundary": {
                    "proves": [],
                    "does_not_prove": [
                        "external task closure",
                        "semantic truth of evidence",
                    ],
                },
            }
    elif args.work_map_action == "check":
        payload = check_work_map(adapter, workspace)
    elif args.work_map_action == "start":
        payload = start_work_item(adapter, workspace, args.item, args.task_id)
    elif args.work_map_action == "finish":
        payload = finish_work_item(
            adapter,
            workspace,
            args.item,
            args.task_id,
            args.disposition,
        )
    else:
        payload = render_work_map(adapter, workspace, args.format)
    return emit(payload)


def assertion_finding(
    assertion: dict,
    adapter: dict,
    workspace: Path,
    affected_question: str | None,
) -> tuple[str | None, dict | None]:
    atype = assertion["type"]

    if atype == "path_exists":
        path = workspace / assertion["path"]
        if not path.exists():
            return "mechanical", {"code": "missing-required-path", "path": assertion["path"]}
        return None, None

    if atype == "path_missing":
        path = workspace / assertion["path"]
        if not path.exists():
            return "mechanical", {"code": "missing-required-path", "path": assertion["path"]}
        return None, None

    if atype == "distinct_authorities":
        rules = rule_map(adapter)
        ids = assertion["ids"]
        missing = [rid for rid in ids if rid not in rules]
        if missing:
            return "mechanical", {"code": "missing-authority-rule", "ids": missing}
        path_sets = [tuple(rules[rid].get("paths", [])) for rid in ids]
        if len(set(path_sets)) != len(path_sets):
            return "mechanical", {"code": "competing-authority", "ids": ids}
        return None, None

    if atype == "ordered_authority":
        rule = rule_map(adapter).get(assertion["id"])
        if not rule:
            return "mechanical", {"code": "missing-authority-rule", "id": assertion["id"]}
        if rule.get("paths") != assertion["paths"]:
            return "mechanical", {"code": "authority-order-mismatch", "id": assertion["id"]}
        return None, None

    if atype == "current_path_under_historical":
        return "mechanical", {"code": "historical-material-in-current-location", "path": assertion["path"]}

    if atype == "text_contains":
        path = workspace / assertion["path"]
        if not path.exists():
            return "mechanical", {"code": "missing-evidence-path", "path": assertion["path"]}
        text = path.read_text(encoding="utf-8")
        if assertion["text"] not in text:
            return "mechanical", {"code": "missing-evidence-text", "path": assertion["path"]}
        layer = assertion.get("layer", "none")
        if layer == "semantic":
            return "semantic", make_semantic_finding(
                code="semantic-review-required",
                affected_question=affected_question,
                evidence=assertion["path"],
                confidence="high",
                human_boundary=False,
            )
        if layer == "human":
            return "human", make_semantic_finding(
                code="human-decision-required",
                affected_question=affected_question,
                evidence=assertion["path"],
                confidence="high",
                human_boundary=True,
            )
        return None, None

    return "mechanical", {"code": "unknown-assertion-type", "type": atype}


def run_one_case(case: dict, adapter: dict, workspace: Path) -> dict:
    mechanical = []
    semantic = []
    human_required = []

    if case.get("question_id") not in rule_map(adapter):
        mechanical.append({"code": "unmapped-question", "id": case.get("question_id")})

    for assertion in case.get("assertions", []):
        layer, finding = assertion_finding(assertion, adapter, workspace, case.get("question_id"))
        if not finding:
            continue
        if layer == "mechanical":
            mechanical.append(finding)
        elif layer == "semantic":
            semantic.append(finding)
        elif layer == "human":
            semantic.append(finding)
            human_required.append(finding["code"])

    human_boundary = bool(case.get("human") or human_required)
    if mechanical:
        result = "fail"
    elif semantic or human_boundary:
        result = "unproven"
    else:
        result = "pass"

    return {
        "id": case["id"],
        "question_id": case.get("question_id"),
        "result": result,
        "expected": case.get("expected"),
        "mechanical_findings": mechanical,
        "semantic_findings": semantic,
        "human_boundary": human_boundary,
    }


def summarize(cases: list[dict]) -> dict:
    return {
        "total": len(cases),
        "pass": sum(1 for case in cases if case["result"] == "pass"),
        "fail": sum(1 for case in cases if case["result"] == "fail"),
        "unproven": sum(1 for case in cases if case["result"] == "unproven"),
        "mechanical": sum(1 for case in cases if case["mechanical_findings"]),
        "semantic": sum(1 for case in cases if case["semantic_findings"]),
        "human": sum(1 for case in cases if case["human_boundary"]),
    }


def run_cases(args: argparse.Namespace) -> dict:
    adapter, missing = load_json_or_missing(Path(args.adapter))
    if missing:
        return {
            **missing,
            "summary": {
                "total": 0,
                "pass": 0,
                "fail": 0,
                "unproven": 0,
                "mechanical": 0,
                "semantic": 0,
                "human": 0,
            },
            "cases": [],
        }
    cases_doc = load_json(Path(args.cases))
    workspace = Path(args.workspace)
    adapter_result = validate_adapter(adapter)
    cases = [run_one_case(case, adapter, workspace) for case in cases_doc.get("cases", [])]
    mismatches = [
        {"id": case["id"], "expected": case["expected"], "actual": case["result"]}
        for case in cases
        if case.get("expected") and case["expected"] != case["result"]
    ]
    summary = summarize(cases)
    all_cases_have_expectations = all(case.get("expected") for case in cases)
    if adapter_result["result"] == "fail" or mismatches:
        result = "fail"
    elif all_cases_have_expectations:
        result = "pass"
    elif summary["fail"]:
        result = "fail"
    elif summary["unproven"]:
        result = "unproven"
    else:
        result = "pass"
    return {
        "result": result,
        "summary": summary,
        "cases": cases,
        "mechanical_findings": adapter_result["mechanical_findings"] + mismatches,
        "semantic_findings": [finding for case in cases for finding in case["semantic_findings"]],
        "human_approval_required": sorted({finding for case in cases if case["human_boundary"] for finding in ["human decision"]}),
        "recovery": "Case validation completed; use failed and unproven cases as next-batch inputs.",
    }


def run_cases_command(args: argparse.Namespace) -> int:
    return emit(run_cases(args))


LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
REFERENCE_LINK_RE = re.compile(r"!?\[([^\]]+)\]\[([^\]]*)\]")
REFERENCE_DEFINITION_RE = re.compile(
    r"^\s{0,3}\[([^\]]+)\]:\s*(?:<([^>]+)>|(\S+))",
    flags=re.MULTILINE,
)


def markdown_links(text: str) -> list[str]:
    links = []
    for match in LINK_RE.finditer(text):
        raw = match.group(1).strip()
        if not raw:
            continue
        # Drop optional Markdown title after a whitespace separator.
        target = raw.split()[0]
        links.append(target.strip("<>"))
    definitions: dict[str, str] = {}
    for match in REFERENCE_DEFINITION_RE.finditer(text):
        label = " ".join(match.group(1).split()).casefold()
        target = match.group(2) or match.group(3)
        definitions[label] = target.strip("<>")
    for match in REFERENCE_LINK_RE.finditer(text):
        label = match.group(2) or match.group(1)
        normalized = " ".join(label.split()).casefold()
        if normalized in definitions:
            links.append(definitions[normalized])
    return links


def is_local_link(target: str) -> bool:
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc:
        return False
    return not target.startswith("#") and not target.startswith("mailto:")


def resolve_link(doc_path: Path, target: str) -> Path:
    clean = unquote(urlparse(target).path)
    return (doc_path.parent / clean).resolve()


def navigation_link_path(
    workspace: Path,
    doc_path: Path,
    target: str,
) -> tuple[Path | None, bool]:
    clean = unquote(urlparse(target).path)
    if not clean:
        return None, False
    lexical_workspace = Path(os.path.abspath(workspace))
    lexical_target = Path(os.path.abspath(doc_path.parent / clean))
    try:
        lexical_target.relative_to(lexical_workspace)
    except ValueError:
        return lexical_target, True
    resolved_workspace = workspace.resolve()
    resolved_target = lexical_target.resolve()
    try:
        resolved_target.relative_to(resolved_workspace)
    except ValueError:
        return resolved_target, True
    return resolved_target, False


def validate_navigation_entrypoint_live(
    adapter: dict,
    workspace: Path,
) -> tuple[dict, list[dict]]:
    findings: list[dict] = []
    link_check = {"checked": 0, "broken": 0, "outside_workspace": 0}
    coverage = {
        "path": NAVIGATION_ENTRYPOINT_PATH,
        "role": "navigation",
        "consumers": ["human", "ai"],
        "project_authority": False,
        "checked": True,
        "link_check": link_check,
    }
    workspace = workspace.resolve()
    try:
        exact_entries = os.listdir(workspace)
    except OSError as exc:
        findings.append({
            "code": "navigation-entrypoint-unreadable",
            "path": NAVIGATION_ENTRYPOINT_PATH,
            "reason": exc.__class__.__name__,
            "message": "workspace could not be read while checking README.md",
        })
        return coverage, findings
    if NAVIGATION_ENTRYPOINT_PATH not in exact_entries:
        findings.append({
            "code": "navigation-entrypoint-file-missing",
            "path": NAVIGATION_ENTRYPOINT_PATH,
            "message": "workspace root must contain an exact README.md entry",
        })
        return coverage, findings

    readme = workspace / NAVIGATION_ENTRYPOINT_PATH
    try:
        mode = readme.lstat().st_mode
    except OSError as exc:
        findings.append({
            "code": "navigation-entrypoint-unreadable",
            "path": NAVIGATION_ENTRYPOINT_PATH,
            "reason": exc.__class__.__name__,
            "message": "README.md metadata could not be read",
        })
        return coverage, findings
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        findings.append({
            "code": "navigation-entrypoint-file-not-regular",
            "path": NAVIGATION_ENTRYPOINT_PATH,
            "message": "README.md must be a non-symlink regular file",
        })
        return coverage, findings

    try:
        text = readme.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeDecodeError) as exc:
        findings.append({
            "code": "navigation-entrypoint-unreadable",
            "path": NAVIGATION_ENTRYPOINT_PATH,
            "reason": exc.__class__.__name__,
            "message": "README.md must be readable strict UTF-8 text",
        })
        return coverage, findings
    if not text.lstrip("\ufeff").strip():
        findings.append({
            "code": "navigation-entrypoint-empty",
            "path": NAVIGATION_ENTRYPOINT_PATH,
            "message": "README.md must contain non-whitespace navigation content",
        })
        return coverage, findings

    for target in markdown_links(text):
        if not is_local_link(target):
            continue
        resolved, outside = navigation_link_path(workspace, readme, target)
        if resolved is None:
            continue
        link_check["checked"] += 1
        if outside:
            link_check["outside_workspace"] += 1
            findings.append({
                "code": "navigation-entrypoint-link-outside-workspace",
                "path": NAVIGATION_ENTRYPOINT_PATH,
                "target": target,
                "message": "README.md local link must remain inside the workspace",
            })
        elif not resolved.exists():
            link_check["broken"] += 1
            findings.append({
                "code": "navigation-entrypoint-link-broken",
                "path": NAVIGATION_ENTRYPOINT_PATH,
                "target": target,
                "message": "README.md local link target does not exist",
            })
    return coverage, findings


def validate_live_adapter(adapter: dict, workspace: Path) -> dict:
    result = validate_adapter(adapter)
    if result["result"] == "fail":
        return result
    coverage, findings = validate_navigation_entrypoint_live(adapter, workspace)
    result["navigation_entrypoint"] = coverage
    result["mechanical_findings"].extend(findings)
    result["result"] = "fail" if result["mechanical_findings"] else "pass"
    result["recovery"] = (
        "Live adapter validation checked structure and the required root navigation entrypoint."
    )
    return result


def current_authority_docs(adapter: dict, workspace: Path) -> list[Path]:
    docs = []
    for entry in safe_section(adapter, "entrypoints").get("current", []):
        path = workspace / entry
        if path.is_file() and path.suffix.lower() == ".md":
            docs.append(path)
    for rule in safe_rule_list(adapter):
        for pointer in rule.get("paths", []):
            path = workspace / pointer
            if path.is_file() and path.suffix.lower() == ".md":
                docs.append(path)
    unique = []
    seen = set()
    for doc in docs:
        resolved = doc.resolve()
        if resolved not in seen:
            unique.append(doc)
            seen.add(resolved)
    return unique


def line_status(text: str) -> str | None:
    for line in text.splitlines():
        match = re.match(r"\s*Status:\s*(.+?)\s*$", line, flags=re.IGNORECASE)
        if match:
            return match.group(1).strip()
    return None


def says_no_active_batch(text: str) -> bool:
    return bool(re.search(r"\bno\b.+\b(batch|project batch|work|task)\b.+\bactive\b", text, flags=re.IGNORECASE))


def is_active_status(status: str | None) -> bool:
    return bool(status and re.search(r"\bactive\b", status, flags=re.IGNORECASE))


def check_plan_status(adapter: dict, workspace: Path) -> list[dict]:
    findings = []
    for check in adapter.get("plan_status_checks", []) or []:
        if not isinstance(check, dict):
            continue
        status_path = check.get("status_path")
        plan_paths = check.get("plan_paths", [])
        if not isinstance(status_path, str) or not is_string_list(plan_paths):
            continue
        status_file = workspace / status_path
        if not status_file.exists():
            findings.append({"code": "missing-plan-status-source", "path": status_path})
            continue
        try:
            status_text = status_file.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            findings.append({"code": "unreadable-plan-status-source", "path": status_path})
            continue
        if not says_no_active_batch(status_text):
            continue
        for plan_path in plan_paths:
            plan_file = workspace / plan_path
            if not plan_file.exists():
                findings.append({"code": "missing-plan-status-target", "path": plan_path})
                continue
            try:
                plan_text = plan_file.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                findings.append({"code": "unreadable-plan-status-target", "path": plan_path})
                continue
            if is_active_status(line_status(plan_text)):
                findings.append({
                    "code": "plan-status-conflict",
                    "status_path": status_path,
                    "plan_path": plan_path,
                    "message": "status says no active batch while a mapped plan says active",
                })
    return findings


def diagnose(adapter: dict, workspace: Path) -> dict:
    adapter_result = validate_live_adapter(adapter, workspace)
    findings = list(adapter_result["mechanical_findings"])

    checked_targets = set()
    for rule in safe_rule_list(adapter):
        for pointer in rule.get("paths", []):
            target = workspace / pointer
            checked_targets.add(pointer)
            if not target.exists():
                findings.append({"code": "missing-mapped-target", "path": pointer, "authority": rule.get("id")})

    entrypoints = safe_section(adapter, "entrypoints")
    for entry in entrypoints.get("current", []):
        target = workspace / entry
        checked_targets.add(entry)
        if not target.exists():
            findings.append({"code": "missing-current-entrypoint", "path": entry})
        if any(path_matches(entry, historical) for historical in entrypoints.get("historical", [])):
            findings.append({"code": "historical-material-configured-current", "path": entry})

    for entry in entrypoints.get("evidence", []):
        target = workspace / entry
        checked_targets.add(entry)
        if not target.exists():
            findings.append({"code": "missing-evidence-entrypoint", "path": entry})

    findings.extend(check_plan_status(adapter, workspace))

    link_checked = 0
    broken = 0
    for doc in current_authority_docs(adapter, workspace):
        try:
            text = doc.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            findings.append({"code": "unreadable-current-authority-doc", "path": str(doc.relative_to(workspace))})
            continue
        for target in markdown_links(text):
            if not is_local_link(target):
                continue
            link_checked += 1
            resolved = resolve_link(doc, target)
            if not resolved.exists():
                broken += 1
                findings.append({
                    "code": "broken-current-authority-link",
                    "path": str(doc.relative_to(workspace)),
                    "target": target,
                })

    return {
        "result": "fail" if findings else "pass",
        "coverage": {
            "workspace_mode": "live",
            "authority_rules": len(safe_rule_list(adapter)),
            "mapped_targets": len(checked_targets),
            "current_authority_docs": len(current_authority_docs(adapter, workspace)),
            "proves": [
                "adapter structure",
                "required README.md navigation for humans and AI",
                "mapped authority targets",
                "current and evidence entrypoints",
                "configured plan status checks",
                "local links in current authority markdown documents",
            ],
            "does_not_prove": [
                "semantic consistency between documents and implementation",
                "that the current task has completed Closeout",
                "that product, architecture, release, or human approval meaning is correct",
            ],
        },
        "link_check": {
            "checked": link_checked,
            "broken": broken,
            "scope": "current authority markdown only",
        },
        "navigation_entrypoint": adapter_result.get("navigation_entrypoint", {}),
        "mechanical_findings": findings,
        "semantic_findings": [],
        "human_approval_required": [],
        "recovery": "Live diagnostic completed without modifying the workspace.",
    }


def diagnose_command(args: argparse.Namespace) -> int:
    adapter, missing = load_json_or_missing(Path(args.adapter))
    return emit(missing if missing else diagnose(adapter, Path(args.workspace)))


def _audit_event_result(
    result: str,
    *,
    manifest_path: Path,
    checks: dict | None = None,
    findings: list[dict] | None = None,
    current_attempt: dict | None = None,
    supported_claims: list[str] | None = None,
    unsupported_claims: list[str] | None = None,
    recovery: list[str] | None = None,
) -> dict:
    actions = recovery or [
        "Correct the supplied evidence and rerun audit-event without modifying the event manifest."
    ]
    return {
        "schema": AUDIT_EVENT_RESULT_SCHEMA,
        "result": result,
        "event_manifest": str(manifest_path),
        "current_attempt": current_attempt,
        "checks": checks or {},
        "mechanical_findings": findings or [],
        "semantic_findings": [],
        "human_approval_required": [],
        "supported_claims": supported_claims or [],
        "unsupported_claims": unsupported_claims or [
            "actor identity",
            "semantic truth of project claims",
            "human approval",
            "release, deployment, product acceptance, or readiness",
        ],
        "recovery_actions": actions,
        "recovery": actions[0],
        "read_only": True,
    }


def audit_event(
    *,
    adapter_path: Path,
    workspace: Path,
    manifest_path: Path,
) -> dict:
    """Audit only the explicitly selected current Event Manifest v2 attempt."""
    workspace = workspace.resolve()
    checks: dict[str, dict] = {}
    unsupported = [
        "actor identity",
        "semantic truth of project claims",
        "human approval",
        "release, deployment, product acceptance, or readiness",
    ]
    try:
        manifest_stat = manifest_path.lstat()
    except OSError:
        return _audit_event_result(
            "unproven",
            manifest_path=manifest_path,
            checks={"manifest": {"status": "missing"}},
            findings=[{"code": "audit-event-manifest-missing", "path": str(manifest_path)}],
            unsupported_claims=unsupported,
            recovery=["Supply the exact Event Manifest v2 path and rerun audit-event."],
        )
    if manifest_path.is_symlink() or not stat.S_ISREG(manifest_stat.st_mode) or manifest_stat.st_nlink != 1:
        return _audit_event_result(
            "fail",
            manifest_path=manifest_path,
            checks={"manifest": {"status": "fail"}},
            findings=[{"code": "audit-event-manifest-path-unsafe", "path": str(manifest_path)}],
            unsupported_claims=unsupported,
            recovery=["Supply one canonical regular Event Manifest v2 file with no symlink or hardlink aliases."],
        )

    adapter, adapter_missing = load_json_or_missing(adapter_path)
    if adapter_missing is not None:
        return _audit_event_result(
            adapter_missing["result"],
            manifest_path=manifest_path,
            checks={"adapter": {"status": adapter_missing["result"]}},
            findings=list(adapter_missing.get("mechanical_findings", [])),
            unsupported_claims=unsupported,
            recovery=[adapter_missing["recovery"]],
        )
    adapter_validation = validate_live_adapter(adapter, workspace)
    if adapter_validation["result"] != "pass":
        return _audit_event_result(
            "fail",
            manifest_path=manifest_path,
            checks={"adapter": {"status": "fail"}},
            findings=list(adapter_validation.get("mechanical_findings", [])),
            unsupported_claims=unsupported,
            recovery=["Repair the supplied adapter or workspace navigation contract, then rerun audit-event."],
        )
    checks["adapter"] = {"status": "pass"}

    try:
        manifest, manifest_finding = load_json_object(
            manifest_path,
            input_name="event-manifest",
            category="receipt_format",
        )
    except FileNotFoundError:
        manifest = None
        manifest_finding = {"code": "audit-event-manifest-missing"}
    if manifest_finding is not None:
        return _audit_event_result(
            "fail",
            manifest_path=manifest_path,
            checks={**checks, "manifest": {"status": "fail"}},
            findings=[manifest_finding],
            unsupported_claims=unsupported,
            recovery=["Supply readable object JSON for the exact Event Manifest v2 path."],
        )
    if manifest.get("schema") == EVENT_MANIFEST_SCHEMA:
        return _audit_event_result(
            "unproven",
            manifest_path=manifest_path,
            checks={**checks, "manifest": {"status": "unsupported-v1"}},
            findings=[{"code": "audit-event-v1-unsupported"}],
            unsupported_claims=unsupported + [
                "Event Manifest v1 has no explicit append-only current-attempt ledger",
            ],
            recovery=["Create and close a new Event Manifest v2 event; do not infer or upgrade the v1 current attempt."],
        )
    normalized, manifest_findings = validate_event_manifest(
        manifest,
        manifest_path=manifest_path,
        workspace=workspace,
        adapter=adapter,
    )
    if normalized is None or manifest_findings:
        return _audit_event_result(
            "fail",
            manifest_path=manifest_path,
            checks={**checks, "manifest": {"status": "fail"}},
            findings=manifest_findings,
            unsupported_claims=unsupported,
            recovery=["Repair the exact Event Manifest v2 structure and bound attempt evidence, then rerun audit-event."],
        )
    event = normalized.get("event", {})
    try:
        recorded_workspace = Path(event.get("workspace", ""))
        if not recorded_workspace.is_absolute():
            recorded_workspace = manifest_path.parent / recorded_workspace
        workspace_matches = recorded_workspace.resolve() == workspace
    except (OSError, RuntimeError):
        workspace_matches = False
    if not workspace_matches:
        return _audit_event_result(
            "fail",
            manifest_path=manifest_path,
            checks={**checks, "manifest": {"status": "fail"}},
            findings=[{"code": "audit-event-workspace-mismatch"}],
            unsupported_claims=unsupported,
            recovery=["Use the workspace recorded by the Event Manifest v2 or supply the matching manifest."],
        )
    checks["manifest"] = {
        "status": "pass",
        "schema": normalized["schema"],
        "schema_version": normalized["schema_version"],
    }

    current = current_closeout_attempt(
        normalized,
        manifest_path=manifest_path,
        workspace=workspace,
        adapter=adapter,
    )
    if current.get("status") == "missing":
        return _audit_event_result(
            "unproven",
            manifest_path=manifest_path,
            checks={**checks, "current": {"status": "missing"}},
            findings=[{"code": "audit-event-current-missing"}],
            unsupported_claims=unsupported,
            recovery=["Complete a passing v2 Closeout attempt and set closeout.current through the Closeout command."],
        )
    if current.get("status") != "matching":
        return _audit_event_result(
            "fail",
            manifest_path=manifest_path,
            checks={**checks, "current": {"status": "fail"}},
            findings=list(current.get("findings", [])),
            unsupported_claims=unsupported,
            recovery=["Repair the explicit current attempt and its immutable evidence bindings; do not scan for a replacement."],
        )
    attempt = current["attempt"]
    receipt = current["receipt"]
    checks["current"] = {"status": "pass", "id": attempt["id"]}
    checks["receipt"] = {
        "status": "pass",
        "path": current["receipt_path"],
        "schema": current["receipt_binding"]["schema"],
        "digest": current["receipt_binding"]["digest"],
    }

    impact_binding = receipt.get("impact")
    impact = impact_binding.get("receipt") if isinstance(impact_binding, dict) else None
    impact_findings = validate_impact_receipt(impact, adapter, workspace)
    if isinstance(impact, dict):
        if not (
            impact.get("derived_evidence") is True
            and impact.get("generated") is True
            and impact.get("project_authority") is False
        ):
            impact_findings.append({
                "code": "audit-event-impact-provenance-invalid",
            })
        capability = impact.get("verification_capability")
        if not (
            isinstance(capability, dict)
            and capability.get("baseline_inventory") is True
            and capability.get("event_isolation") is True
        ):
            impact_findings.append({
                "code": "audit-event-impact-verification-capability-invalid",
            })
        inventory_source = impact.get("inventory_source")
        if not (
            isinstance(inventory_source, dict)
            and inventory_source.get("verified") is True
            and isinstance(inventory_source.get("kind"), str)
            and inventory_source["kind"] in {"git", "filesystem"}
            and isinstance(inventory_source.get("metadata"), dict)
        ):
            impact_findings.append({
                "code": "audit-event-impact-inventory-source-invalid",
            })
        planned_paths = impact.get("planned_paths")
        if isinstance(planned_paths, list):
            normalized_paths = []
            for path in planned_paths:
                normalized_path, path_finding = normalize_path_value(
                    path, "planned_paths",
                )
                if path_finding:
                    impact_findings.append({
                        "code": "audit-event-impact-path-invalid",
                        "path": path,
                    })
                else:
                    normalized_paths.append(normalized_path)
            if len(normalized_paths) != len(set(normalized_paths)):
                impact_findings.append({
                    "code": "audit-event-impact-path-duplicate",
                })
            recalculated_scope = analyze_impact_scope(adapter, normalized_paths)
            for field in (
                "affected_authorities",
                "candidate_authority_paths",
                "protected_paths",
                "excluded_paths",
                "human_approval_required",
            ):
                if sorted(impact.get(field, [])) != sorted(
                    recalculated_scope.get(field, [])
                ):
                    impact_findings.append({
                        "code": "audit-event-impact-scope-projection-mismatch",
                        "field": field,
                    })
    expected_adapter_binding = {
        "path": str(adapter_path.resolve()),
        "digest": canonical_evidence_v1_digest(adapter),
    }
    if isinstance(impact, dict) and impact.get("adapter_binding") != expected_adapter_binding:
        impact_findings.append({"code": "audit-event-impact-adapter-binding-mismatch"})
    impact_metadata = (
        (impact.get("inventory_source") or {}).get("metadata", {})
        if isinstance(impact, dict)
        else {}
    )
    baseline = event.get("baseline_ref")
    observed_baseline = impact_metadata.get("baseline_ref", impact_metadata.get("head"))
    if baseline is not None and observed_baseline != baseline:
        impact_findings.append({"code": "audit-event-impact-baseline-mismatch"})
    if impact_findings:
        return _audit_event_result(
            "fail",
            manifest_path=manifest_path,
            checks={**checks, "impact": {"status": "fail"}},
            findings=impact_findings,
            current_attempt={"id": attempt["id"]},
            unsupported_claims=unsupported,
            recovery=["Restore the exact adapter-, workspace-, and baseline-bound Impact snapshot referenced by the current receipt."],
        )
    checks["impact"] = {
        "status": "pass",
        "digest": impact_binding["digest"],
    }

    freeze_binding = receipt.get("freeze")
    freeze = freeze_binding.get("receipt") if isinstance(freeze_binding, dict) else None
    final_paths = (receipt.get("final_content") or {}).get("paths", [])
    freeze_summary, freeze_findings, freeze_unverified = evaluate_freeze_receipt(
        None,
        adapter=adapter,
        workspace=workspace,
        event_paths=final_paths,
        receipt_payload=freeze,
    )
    if freeze_findings:
        return _audit_event_result(
            "fail",
            manifest_path=manifest_path,
            checks={
                **checks,
                "freeze": {"status": "fail"},
                "current_content": {
                    "status": "fail",
                    "stale_paths": freeze_summary.get("stale_paths", []),
                },
            },
            findings=freeze_findings,
            current_attempt={"id": attempt["id"]},
            unsupported_claims=unsupported,
            recovery=["Restore or refreeze the exact current event content, rerun affected validation and Closeout, then rerun audit-event."],
        )
    if freeze_unverified:
        return _audit_event_result(
            "unproven",
            manifest_path=manifest_path,
            checks={**checks, "freeze": {"status": "unproven"}},
            findings=[{"code": "audit-event-freeze-unproven", "fields": freeze_unverified}],
            current_attempt={"id": attempt["id"]},
            unsupported_claims=unsupported,
            recovery=["Supply the complete Freeze snapshot bound by the current Closeout receipt."],
        )
    checks["freeze"] = {
        "status": "pass",
        "digest": freeze_binding["digest"],
        "paths": freeze_summary["paths"],
    }
    checks["current_content"] = {"status": "pass", "paths": freeze_summary["paths"]}

    attestation_binding = current.get("attestation_binding")
    supported = [
        "explicit Event Manifest v2 current attempt",
        "current Closeout receipt schema and canonical digest binding",
        "current receipt Impact and Freeze snapshots bind the supplied adapter and workspace",
        "current frozen event content matches the supplied workspace",
    ]
    if attestation_binding is None:
        checks["attestation"] = {"status": "not-bound"}
        unsupported.append(
            "portable attestation claims because the current attempt has no attestation binding"
        )
    else:
        attestation_path = Path(current["attestation_path"])
        parsed = parse_closeout_attestation(
            attestation_path,
            current_schemas=[CLOSEOUT_ATTESTATION_SCHEMA],
            historical_schemas=[],
        )
        bound = bind_closeout_attestation(
            parsed,
            path=attestation_path,
            adapter=adapter,
            workspace=workspace,
            manifest=normalized,
            manifest_path=manifest_path,
        )
        if bound.get("status") != "matching":
            return _audit_event_result(
                "fail",
                manifest_path=manifest_path,
                checks={**checks, "attestation": {"status": "fail", "binding_status": bound.get("status")}},
                findings=[{"code": "audit-event-attestation-binding-invalid", "status": bound.get("status")}],
                current_attempt={"id": attempt["id"]},
                supported_claims=supported,
                unsupported_claims=unsupported,
                recovery=["Restore the exact current attempt attestation and its complete source-context binding."],
            )
        checks["attestation"] = {
            "status": "pass",
            "path": current["attestation_path"],
            "schema": attestation_binding["schema"],
            "digest": attestation_binding["digest"],
        }
        supported.append(
            "current immutable Closeout attestation path, schema, canonical digest, and source context"
        )

    return _audit_event_result(
        "pass",
        manifest_path=manifest_path,
        checks=checks,
        current_attempt={"id": attempt["id"], "result": attempt["result"]},
        supported_claims=supported,
        unsupported_claims=unsupported,
        recovery=["Preserve the audited evidence; rerun audit-event whenever the workspace, adapter, manifest, receipt, or attestation bytes change."],
    )


def audit_event_command(args: argparse.Namespace) -> int:
    return emit(audit_event(
        adapter_path=Path(args.adapter),
        workspace=Path(args.workspace),
        manifest_path=Path(args.event_manifest),
    ))


EVENT_SCOPE_KEYS = {
    "planned_paths",
    "actual_event_paths",
    "governed_authority_documents",
    "authorized_development_paths",
    "evidence_only_paths",
}


def validate_event_manifest(
    manifest: object,
    *,
    manifest_path: Path | None = None,
    workspace: Path | None = None,
    adapter: dict | None = None,
) -> tuple[dict | None, list[dict]]:
    findings: list[dict] = []
    if not isinstance(manifest, dict):
        return None, [{"code": "event-manifest-invalid-field", "field": "root"}]
    schema = manifest.get("schema")
    schema_version = manifest.get("schema_version")
    if schema not in {EVENT_MANIFEST_SCHEMA, EVENT_MANIFEST_V2_SCHEMA}:
        findings.append({"code": "event-manifest-invalid-field", "field": "schema"})
    expected_version = "2" if schema == EVENT_MANIFEST_V2_SCHEMA else "1"
    if schema_version != expected_version:
        findings.append({"code": "event-manifest-invalid-field", "field": "schema_version"})
    is_v2 = schema == EVENT_MANIFEST_V2_SCHEMA and schema_version == "2"

    event = manifest.get("event")
    if not isinstance(event, dict):
        findings.append({"code": "event-manifest-invalid-field", "field": "event"})
        event = {}
    for key in ("id", "goal", "workspace"):
        if not isinstance(event.get(key), str) or not event.get(key).strip():
            findings.append({"code": "event-manifest-invalid-field", "field": f"event.{key}"})
    if event.get("baseline_ref") is not None and not isinstance(event.get("baseline_ref"), str):
        findings.append({"code": "event-manifest-invalid-field", "field": "event.baseline_ref"})

    scope = manifest.get("scope")
    if not isinstance(scope, dict):
        findings.append({"code": "event-manifest-invalid-field", "field": "scope"})
        scope = {}
    normalized_scope: dict[str, list[str]] = {}
    for key in sorted(EVENT_SCOPE_KEYS):
        raw_paths = scope.get(key)
        if not isinstance(raw_paths, list) or not all(isinstance(item, str) for item in raw_paths):
            findings.append({"code": "event-manifest-invalid-field", "field": f"scope.{key}"})
            normalized_scope[key] = []
            continue
        normalized, path_findings = normalize_paths_with_findings(raw_paths, f"scope.{key}")
        findings.extend(path_findings)
        normalized_scope[key] = normalized

    approvals = manifest.get("approvals")
    if not isinstance(approvals, list):
        findings.append({"code": "event-manifest-invalid-field", "field": "approvals"})
        approvals = []
    else:
        for index, approval in enumerate(approvals):
            if not isinstance(approval, dict) or approval.get("kind") not in {"human", "protected"}:
                findings.append({
                    "code": "event-manifest-invalid-field",
                    "field": f"approvals.{index}",
                })
                continue
            required = (
                ("type", "evidence")
                if approval.get("kind") == "human"
                else ("path", "evidence")
            )
            if any(
                not isinstance(approval.get(key), str) or not approval.get(key).strip()
                for key in required
            ):
                findings.append({
                    "code": "event-manifest-invalid-field",
                    "field": f"approvals.{index}",
                })
    if not isinstance(manifest.get("semantic_review"), dict):
        findings.append({"code": "event-manifest-invalid-field", "field": "semantic_review"})
    receipts = manifest.get("receipts")
    if not isinstance(receipts, dict):
        findings.append({"code": "event-manifest-invalid-field", "field": "receipts"})
        receipts = {}
    receipt_keys = ("impact", "freeze") if is_v2 else (
        "impact", "freeze", "closeout_attestation",
    )
    for key in receipt_keys:
        if key not in receipts or (
            receipts.get(key) is not None and not isinstance(receipts.get(key), dict)
        ):
            findings.append({"code": "event-manifest-invalid-field", "field": f"receipts.{key}"})
    if is_v2 and "closeout_attestation" in receipts:
        findings.append({
            "code": "event-manifest-invalid-field",
            "field": "receipts.closeout_attestation",
        })
    if not isinstance(receipts.get("validation"), list) or not all(
        isinstance(item, str) for item in receipts.get("validation", [])
    ):
        findings.append({"code": "event-manifest-invalid-field", "field": "receipts.validation"})
    closeout = manifest.get("closeout")
    if not isinstance(closeout, dict):
        findings.append({"code": "event-manifest-invalid-field", "field": "closeout"})
        closeout = {}
    if is_v2:
        if not isinstance(closeout.get("attempts"), list):
            findings.append({
                "code": "event-manifest-invalid-field",
                "field": "closeout.attempts",
            })
        if closeout.get("current") is not None and not isinstance(
            closeout.get("current"), str,
        ):
            findings.append({
                "code": "event-manifest-invalid-field",
                "field": "closeout.current",
            })
        for field in ("result", "result_reasons", "recovery_actions"):
            if field in closeout:
                findings.append({
                    "code": "event-manifest-invalid-field",
                    "field": f"closeout.{field}",
                })
        findings.extend(validate_event_manifest_closeout_ledger(
            manifest,
            manifest_path=manifest_path,
            workspace=workspace,
            adapter=adapter,
        ))
    else:
        if "result" not in closeout or closeout.get("result") not in {None, "pass", "fail", "unproven"}:
            findings.append({"code": "event-manifest-invalid-field", "field": "closeout.result"})
        if not isinstance(closeout.get("result_reasons"), list) or not all(
            isinstance(item, str) for item in closeout.get("result_reasons", [])
        ):
            findings.append({
                "code": "event-manifest-invalid-field",
                "field": "closeout.result_reasons",
            })
        if not isinstance(closeout.get("recovery_actions"), list) or not all(
            isinstance(item, str) for item in closeout.get("recovery_actions", [])
        ):
            findings.append({
                "code": "event-manifest-invalid-field",
                "field": "closeout.recovery_actions",
            })

    binding = manifest.get("work_map_binding")
    if binding is not None:
        required_binding = {
            "item_id",
            "task_id",
            "source_digest",
            "expected_disposition",
            "attestation_path",
        }
        valid = (
            isinstance(binding, dict)
            and required_binding.issubset(binding)
            and all(isinstance(binding.get(key), str) and binding.get(key).strip() for key in required_binding)
            and re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", binding.get("task_id", ""))
            and re.fullmatch(r"[0-9a-f]{64}", binding.get("source_digest", ""))
            and Path(binding.get("attestation_path", "")).is_absolute()
        )
        if not valid:
            findings.append({
                "code": "event-manifest-work-map-binding-invalid",
                "field": "work_map_binding",
            })

    if findings:
        return None, findings
    normalized = json.loads(json.dumps(manifest))
    normalized["scope"] = normalized_scope
    normalized["approvals"] = sorted(
        normalized["approvals"],
        key=lambda item: json.dumps(item, sort_keys=True),
    )
    normalized["receipts"]["validation"] = sorted(set(normalized["receipts"]["validation"]))
    if not is_v2:
        normalized["closeout"]["result_reasons"] = sorted(
            set(normalized["closeout"]["result_reasons"])
        )
        normalized["closeout"]["recovery_actions"] = sorted(
            set(normalized["closeout"]["recovery_actions"])
        )
    return normalized, []


def load_event_manifest(
    path: str | None,
    *,
    workspace: Path | None = None,
    adapter: dict | None = None,
) -> tuple[dict | None, list[dict]]:
    manifest, findings, _digest = load_event_manifest_snapshot(
        path,
        workspace=workspace,
        adapter=adapter,
    )
    return manifest, findings


def load_event_manifest_snapshot(
    path: str | None,
    *,
    workspace: Path | None = None,
    adapter: dict | None = None,
) -> tuple[dict | None, list[dict], str | None]:
    if not path:
        return None, [], None
    manifest_path = Path(path)
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, [{"code": "event-manifest-missing", "path": path}], None
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None, [{"code": "event-manifest-invalid-json", "path": path}], None
    manifest, findings = validate_event_manifest(
        raw,
        manifest_path=manifest_path,
        workspace=workspace,
        adapter=adapter,
    )
    return manifest, findings, canonical_evidence_v1_digest(raw)


def load_paths_from(path: str) -> tuple[list[str], list[dict]]:
    path_file = Path(path)
    try:
        text = path_file.read_text(encoding="utf-8")
    except FileNotFoundError:
        return [], [{"code": "paths-from-missing", "path": path}]
    except UnicodeDecodeError:
        return [], [{"code": "paths-from-invalid", "path": path, "field": "encoding"}]
    stripped = text.strip()
    if not stripped:
        return [], [{"code": "paths-from-invalid", "path": path, "field": "empty"}]
    raw_paths: object
    if path_file.suffix.lower() == ".json" or stripped.startswith(("[", "{")):
        try:
            raw_paths = json.loads(text)
        except json.JSONDecodeError:
            return [], [{"code": "paths-from-invalid", "path": path, "field": "json"}]
        if isinstance(raw_paths, dict):
            for key in ("paths", "changed_paths", "planned_paths", "actual_event_paths"):
                if key in raw_paths:
                    raw_paths = raw_paths[key]
                    break
    else:
        raw_paths = [line.strip() for line in text.splitlines() if line.strip()]
    if not isinstance(raw_paths, list) or not all(isinstance(item, str) for item in raw_paths):
        return [], [{"code": "paths-from-invalid", "path": path, "field": "paths"}]
    return normalize_paths_with_findings(raw_paths, "paths_from")


def resolve_git_baseline(workspace: Path, ref: str) -> tuple[str | None, list[dict]]:
    completed = subprocess.run(
        ["git", "rev-parse", "--verify", f"{ref}^{{commit}}"],
        cwd=workspace,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        return None, [{"code": "baseline-ref-unresolved", "baseline_ref": ref}]
    return completed.stdout.strip(), []


def prepare_event_manifest(
    args: argparse.Namespace,
    *,
    phase: str,
) -> tuple[dict | None, list[dict]]:
    manifest, findings, raw_digest = load_event_manifest_snapshot(
        getattr(args, "event_manifest", None),
    )
    args.event_manifest_expected_digest = raw_digest
    workspace = Path(args.workspace).resolve() if getattr(args, "workspace", None) else None
    if getattr(args, "event_manifest", None) and workspace is None:
        findings.append({"code": "event-manifest-workspace-required"})
    manifest_ref = manifest["event"].get("baseline_ref") if manifest is not None else None
    cli_ref = getattr(args, "baseline_ref", None)
    if workspace is not None:
        if manifest is not None:
            declared_workspace = Path(manifest["event"]["workspace"])
            if not declared_workspace.is_absolute():
                declared_workspace = Path(args.event_manifest).parent / declared_workspace
            declared_workspace = declared_workspace.resolve()
            if declared_workspace != workspace:
                findings.append({
                    "code": "event-manifest-workspace-mismatch",
                    "expected": str(workspace),
                    "actual": str(declared_workspace),
                })
        selected_ref = cli_ref or manifest_ref
        if selected_ref and getattr(args, "change_source", "git") in {"git", "auto"}:
            resolved, baseline_findings = resolve_git_baseline(workspace, selected_ref)
            findings.extend(baseline_findings)
            if resolved:
                head, head_findings = resolve_git_baseline(workspace, "HEAD")
                findings.extend(head_findings)
                if head and head != resolved:
                    findings.append({
                        "code": "baseline-ref-head-mismatch",
                        "baseline_ref": resolved,
                        "head": head,
                    })
            if resolved and manifest_ref and manifest is not None:
                manifest_resolved, manifest_findings = resolve_git_baseline(workspace, manifest_ref)
                findings.extend(manifest_findings)
                if manifest_resolved is None or manifest_resolved != resolved:
                    findings.append({
                        "code": "event-manifest-baseline-mismatch",
                        "manifest": manifest_resolved,
                        "requested": resolved,
                    })
            if resolved:
                args.resolved_baseline_ref = resolved

    paths: list[str] = list(getattr(args, "changed_path", []) or [])
    for path_file in getattr(args, "paths_from", []) or []:
        loaded_paths, path_findings = load_paths_from(path_file)
        paths.extend(loaded_paths)
        findings.extend(path_findings)
    if manifest is not None:
        scope_key = "planned_paths" if phase == "impact" else "actual_event_paths"
        paths.extend(manifest["scope"].get(scope_key, []))
    if phase == "freeze":
        normalized_paths = []
        path_findings = []
        for raw_path in paths:
            normalized_path, path_finding = normalize_path_value(raw_path, "changed_path")
            if path_finding:
                path_findings.append(path_finding)
            elif normalized_path:
                normalized_paths.append(normalized_path)
        normalized_paths.sort()
    else:
        normalized_paths, path_findings = normalize_paths_with_findings(paths, "changed_path")
    findings.extend(path_findings)
    args.changed_path = normalized_paths
    args.loaded_event_manifest = manifest
    return manifest, findings


def write_event_manifest(
    manifest: dict,
    path: str,
    workspace: Path,
    adapter: dict,
    *,
    expected_digest: str | None = None,
) -> list[dict]:
    destination, findings = resolve_receipt_output_path(path, workspace, adapter)
    if findings or destination is None:
        return [
            {
                **finding,
                "code": "unsafe-event-manifest-output-path",
            }
            for finding in findings
        ]
    try:
        candidate_declares_v2 = (
            isinstance(manifest, dict)
            and manifest.get("schema") == EVENT_MANIFEST_V2_SCHEMA
        )
        destination_declares_v2 = False
        if not candidate_declares_v2 and destination.exists():
            persisted, persisted_finding = load_json_object(
                destination,
                input_name="event-manifest",
                category="receipt_format",
            )
            if (
                isinstance(persisted_finding, dict)
                and persisted_finding.get("code") == "event-manifest-unreadable"
            ):
                return [{
                    **persisted_finding,
                    "code": "event-manifest-destination-unreadable",
                    "message": (
                        "The existing event manifest cannot be read, so its schema "
                        "cannot be proven safe for a legacy replacement."
                    ),
                }]
            destination_declares_v2 = (
                isinstance(persisted, dict)
                and persisted.get("schema") == EVENT_MANIFEST_V2_SCHEMA
            )
        requires_v2_guard = candidate_declares_v2 or destination_declares_v2
        if requires_v2_guard and fcntl is None:
            return [{
                "code": "event-manifest-lock-unavailable",
                "path": path,
                "message": (
                    "Event Manifest v2 publication requires an inter-process "
                    "file lock, but this runtime does not provide fcntl."
                ),
                "diagnostic": {
                    "severity": "blocking",
                    "category": "blocking",
                    "recovery_actions": [
                        "Retry the v2 write on a runtime with the required lock "
                        "capability, without an unlocked fallback."
                    ],
                },
            }]
        if requires_v2_guard and expected_digest is None:
            return [{
                "code": "event-manifest-cas-required",
                "path": path,
                "message": (
                    "Event Manifest v2 publication requires the canonical digest "
                    "of the exact manifest snapshot being replaced."
                ),
                "diagnostic": {
                    "severity": "blocking",
                    "category": "blocking",
                    "recovery_actions": [
                        "Reload the v2 manifest and retry with its raw canonical "
                        "digest; do not publish without compare-and-swap."
                    ],
                },
            }]
        if expected_digest is None:
            atomic_write_json(manifest, destination)
            return []
        if fcntl is None:
            atomic_write_json(manifest, destination)
            return []
        lock_fd = os.open(destination.parent, os.O_RDONLY)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            try:
                persisted = load_json(destination)
                actual_digest = canonical_evidence_v1_digest(persisted)
                if actual_digest != expected_digest:
                    return [{
                        "code": "event-manifest-concurrent-update",
                        "path": path,
                        "expected_digest": expected_digest,
                        "actual_digest": actual_digest,
                    }]
                atomic_write_json(manifest, destination)
            finally:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)
    except (OSError, FileNotFoundError, SystemExit) as exc:
        return [{"code": "event-manifest-write-failed", "path": path, "message": str(exc)}]
    return []


def event_manifest_is_v2(manifest: dict | None) -> bool:
    return bool(
        isinstance(manifest, dict)
        and manifest.get("schema") == EVENT_MANIFEST_V2_SCHEMA
        and manifest.get("schema_version") == "2"
    )


def event_manifest_evidence_binding(
    path: str,
    payload: dict,
    *,
    schema: str,
    manifest_path: str,
) -> dict:
    destination = Path(path).resolve()
    manifest_parent = Path(manifest_path).resolve().parent
    try:
        stored_path = destination.relative_to(manifest_parent).as_posix()
    except ValueError:
        stored_path = str(destination)
    return {
        "path": stored_path,
        "schema": schema,
        "digest": canonical_evidence_v1_digest(payload),
    }


def write_or_reuse_json_evidence(
    payload: dict,
    output_path: str,
    workspace: Path,
    adapter: dict,
    *,
    kind: str,
) -> tuple[str | None, list[dict]]:
    destination, findings = resolve_receipt_output_path(
        output_path, workspace, adapter,
    )
    if findings or destination is None:
        return None, [
            {
                **finding,
                "code": f"unsafe-{kind}-output-path",
            }
            for finding in findings
        ]
    if destination.exists() or destination.is_symlink():
        if destination.is_symlink() or not destination.is_file():
            return None, [{
                "code": f"{kind}-already-exists",
                "path": str(destination),
            }]
        try:
            existing = load_json(destination)
        except (FileNotFoundError, SystemExit):
            existing = None
        if (
            isinstance(existing, dict)
            and existing == payload
            and canonical_evidence_v1_digest(existing)
            == canonical_evidence_v1_digest(payload)
        ):
            if not recover_interrupted_create_only_aliases(destination):
                return None, [{
                    "code": f"{kind}-already-exists",
                    "path": str(destination),
                }]
            return str(destination), []
        return None, [{
            "code": f"{kind}-already-exists",
            "path": str(destination),
        }]
    try:
        atomic_write_json(payload, destination, overwrite=False)
        persisted = load_json(destination)
    except (OSError, FileNotFoundError, SystemExit) as exc:
        return None, [{
            "code": f"{kind}-write-failed",
            "path": str(destination),
            "message": str(exc),
        }]
    if (
        persisted != payload
        or canonical_evidence_v1_digest(persisted)
        != canonical_evidence_v1_digest(payload)
    ):
        return None, [{
            "code": f"{kind}-reread-mismatch",
            "path": str(destination),
        }]
    return str(destination), []


def recover_interrupted_create_only_aliases(destination: Path) -> bool:
    """Remove only recognized post-link/pre-unlink temp aliases."""
    try:
        destination_stat = destination.stat()
    except OSError:
        return False
    if destination_stat.st_nlink == 1:
        return True
    pattern = re.compile(
        rf"^\.{re.escape(destination.name)}\.[0-9a-f]{{64}}\.tmp$",
    )
    aliases: list[Path] = []
    try:
        for candidate in destination.parent.iterdir():
            if not pattern.fullmatch(candidate.name):
                continue
            candidate_stat = candidate.lstat()
            if (
                stat.S_ISREG(candidate_stat.st_mode)
                and (candidate_stat.st_dev, candidate_stat.st_ino)
                == (destination_stat.st_dev, destination_stat.st_ino)
            ):
                aliases.append(candidate)
    except OSError:
        return False
    if not aliases or destination_stat.st_nlink != len(aliases) + 1:
        return False
    try:
        for alias in aliases:
            alias.unlink()
        return destination.stat().st_nlink == 1
    except OSError:
        return False


def append_v2_closeout_attempt(
    *,
    manifest: dict,
    manifest_path: str,
    attempt_id: str,
    payload: dict,
    receipt_path: str,
    attestation: dict | None,
    attestation_path: str | None,
    freeze_receipt: dict,
    workspace: Path,
    adapter: dict,
) -> tuple[dict | None, list[dict]]:
    candidate = json.loads(json.dumps(manifest))
    attempt = {
        "id": attempt_id,
        "result": payload["result"],
        "result_reasons": list(payload.get("result_reasons", [])),
        "recovery_actions": list(payload.get("recovery_actions", [])),
        "receipt": event_manifest_evidence_binding(
            receipt_path,
            payload["closeout_receipt"],
            schema="govern-ai-coding.closeout-receipt.v1",
            manifest_path=manifest_path,
        ),
        "freeze_digest": canonical_evidence_v1_digest(freeze_receipt),
        "attestation": (
            event_manifest_evidence_binding(
                attestation_path,
                attestation,
                schema=CLOSEOUT_ATTESTATION_SCHEMA,
                manifest_path=manifest_path,
            )
            if attestation is not None and attestation_path is not None
            else None
        ),
    }
    candidate["closeout"]["attempts"].append(attempt)
    if payload["result"] == "pass":
        candidate["closeout"]["current"] = attempt_id
    normalized, findings = validate_event_manifest(
        candidate,
        manifest_path=Path(manifest_path),
        workspace=workspace,
        adapter=adapter,
    )
    return normalized, findings


def evaluate_impact_path_reconciliation(
    impact_receipt: dict,
    actual_paths: list[str],
) -> tuple[list[dict], list[dict]]:
    planned = set(normalize_paths(impact_receipt.get("planned_paths", [])))
    actual = set(normalize_paths(actual_paths))
    findings = [
        {
            "code": "impact-unplanned-actual-path",
            "path": path,
            "recovery_actions": [
                "If the preserved original Impact observed this path cleanly, use "
                "impact --extend-receipt with that receipt before Closeout. Otherwise "
                "preserve current edits and split the path into a separate event from "
                "an isolated clean worktree or known clean filesystem copy."
            ],
            "diagnostic": {
                "severity": "blocking",
                "category": "scope_mismatch",
                "message": "An actual event path was absent from the Impact plan.",
                "recovery_actions": [
                    "If the preserved original Impact observed this path cleanly, use "
                    "impact --extend-receipt with that receipt before Closeout. Otherwise "
                    "preserve current edits and split the path into a separate event from "
                    "an isolated clean worktree or known clean filesystem copy."
                ],
            },
        }
        for path in sorted(actual - planned)
    ]
    warnings = [
        {
            "code": "impact-planned-path-unused",
            "path": path,
            "message": "Impact planned path was not changed in this event.",
            "diagnostic": {
                "severity": "warning",
                "category": "scope_mismatch",
                "message": "Impact planned path was not changed in this event.",
                "recovery_actions": [
                    "No recovery is required; remove the unused path from a future plan if it is no longer expected."
                ],
            },
        }
        for path in sorted(planned - actual)
    ]
    return findings, warnings


def analyze_impact_scope(adapter: dict, changed_paths: list[str]) -> dict:
    rules = safe_rule_list(adapter)
    boundary_rules = safe_section(adapter, "boundaries")
    protected_patterns = boundary_rules.get("protected", [])
    excluded_patterns = boundary_rules.get("excluded", [])
    affected: list[str] = []
    protected: list[str] = []
    excluded: list[str] = []

    for changed in changed_paths:
        for pattern in protected_patterns:
            if path_matches(changed, pattern):
                protected.append(changed)
        for pattern in excluded_patterns:
            if path_matches(changed, pattern):
                excluded.append(changed)
        for rule in rules:
            if any(
                path_matches(changed, path) or path_matches(path, changed)
                for path in rule.get("paths", [])
            ):
                affected.append(rule["id"])
            if any(
                path_matches(changed, trigger)
                for trigger in rule.get("triggers", []) or []
            ):
                affected.append(rule["id"])

    affected = sorted(set(affected))
    human: list[str] = []
    approval_requirements: list[dict] = []
    for rule in rules:
        if rule.get("id") not in affected:
            continue
        approval_types = list(rule.get("human_approval_types", []) or [])
        if rule.get("human") and not approval_types:
            resolved_type, _, _ = resolve_rule_approval_type(adapter, rule)
            approval_types = [resolved_type] if resolved_type else []
        human.extend(approval_types)
        for approval_type in approval_types:
            approval_requirements.append({
                "authority_rule_id": rule.get("id"),
                "object": rule.get("question"),
                "approval_type": approval_type,
                "scope": rule.get("scope"),
                "target_paths": sorted(set(rule.get("paths", []))),
                "does_not_approve": {
                    "approval_types": sorted(
                        set(adapter.get("human_approval", [])) - {approval_type}
                    ),
                    "protected_paths": sorted(set(protected_patterns)),
                    "excluded_paths": sorted(set(excluded_patterns)),
                },
            })
    return {
        "affected_authorities": affected,
        "candidate_authority_paths": sorted({
            path
            for rule in rules
            if rule.get("id") in affected
            for path in rule.get("paths", [])
        }),
        "protected_paths": sorted(set(protected)),
        "excluded_paths": sorted(set(excluded)),
        "human_approval_required": sorted(set(human)),
        "approval_requirements": sorted(
            approval_requirements,
            key=lambda item: (
                item["authority_rule_id"],
                item["approval_type"],
            ),
        ),
    }


def impact_extension_payload(
    *,
    adapter: dict,
    adapter_path: Path,
    workspace: Path,
    parent_receipt: dict,
    added_paths: list[str],
) -> tuple[dict | None, list[dict], list[str], list[str]]:
    findings = validate_impact_receipt(parent_receipt, adapter, workspace)
    unverified: list[str] = []
    recovery_actions: list[str] = []
    expected_binding = {
        "path": str(adapter_path.resolve()),
        "digest": canonical_evidence_v1_digest(adapter),
    }
    if parent_receipt.get("adapter_binding") != expected_binding:
        unverified.append("impact-extension-parent-adapter-unbound")
        recovery_actions.append(
            "Use an original Impact receipt created by this adapter version; "
            "otherwise return to a clean isolated worktree or known clean filesystem "
            "copy and begin a separate governed event without discarding current edits."
        )

    source = parent_receipt.get("inventory_source", {})
    baseline = parent_receipt.get("baseline_inventory", {})
    source_kind = source.get("kind")
    source_verified = source.get("verified") is True
    baseline_verified = baseline.get("source", {}).get("verified") is True
    if source_kind not in {"git", "filesystem"} or not (
        source_verified and baseline_verified
    ):
        unverified.append("impact-extension-parent-baseline-unverified")
        recovery_actions.append(
            "Use the verified original Git or explicit filesystem Impact receipt. "
            "If none exists, preserve current edits and establish a separate event from "
            "an isolated clean worktree or known clean filesystem copy."
        )

    observations: list[dict] = []
    baseline_entries = inventory_map(baseline)
    for path in added_paths:
        entry = baseline_entries.get(path)
        if not isinstance(entry, dict) or entry.get("verified") is not True:
            unverified.append("impact-extension-path-not-observed")
            recovery_actions.append(
                f"The original baseline did not observe {path}. Preserve current edits; "
                "either split that path into a separate event from an isolated clean "
                "boundary, or reproduce the original clean boundary in a known clean "
                "filesystem copy and rerun Impact there."
            )
            continue
        if source_kind == "git" and (
            entry.get("metadata", {}).get("dirty_at_baseline") is True
        ):
            unverified.append("impact-extension-path-dirty-at-baseline")
            recovery_actions.append(
                f"The original Git baseline already marked {path} dirty, so this event "
                "cannot claim its attribution. Preserve the edit and split it into a "
                "separate event at a demonstrably clean boundary."
            )
            continue
        observations.append(entry)

    if findings or unverified:
        return None, findings, sorted(set(unverified)), list(dict.fromkeys(recovery_actions))

    planned_paths = sorted(set(parent_receipt["planned_paths"]) | set(added_paths))
    scope = analyze_impact_scope(adapter, planned_paths)
    extended = json.loads(json.dumps(parent_receipt))
    extended.update({
        "planned_paths": planned_paths,
        "affected_authorities": scope["affected_authorities"],
        "candidate_authority_paths": scope["candidate_authority_paths"],
        "protected_paths": scope["protected_paths"],
        "excluded_paths": scope["excluded_paths"],
        "human_approval_required": scope["human_approval_required"],
        "approval_requirements": scope["approval_requirements"],
    })
    extensions = list(extended.get("scope_extensions", []))
    extensions.append({
        "parent_receipt_digest": canonical_evidence_v1_digest(parent_receipt),
        "added_paths": added_paths,
        "baseline_observations": sorted(
            observations,
            key=lambda item: item["path"],
        ),
        "source_semantics": (
            "git-baseline-with-dirty-state"
            if source_kind == "git"
            else "explicit-filesystem-snapshot"
        ),
    })
    extended["scope_extensions"] = extensions
    return extended, [], [], []


def impact_command(args: argparse.Namespace) -> int:
    manifest, manifest_findings = prepare_event_manifest(args, phase="impact")
    manifest_expected_digest = (
        args.event_manifest_expected_digest
        if event_manifest_is_v2(manifest)
        else None
    )
    adapter, missing = load_json_or_missing(Path(args.adapter))
    changed_paths, path_findings = normalize_paths_with_findings(args.changed_path, "changed_path")
    if missing:
        missing["impact"] = {
            "changed_paths": changed_paths,
            "affected_authorities": [],
            "protected_paths": [],
            "excluded_paths": [],
            "evidence_entrypoints": [],
            "approval_requirements": [],
        }
        return emit(missing)

    adapter_result = (
        validate_live_adapter(adapter, Path(args.workspace))
        if args.workspace
        else validate_adapter(adapter)
    )
    if adapter_result["result"] == "fail":
        return emit({
            "result": "fail",
            "impact": {
                "changed_paths": changed_paths,
                "affected_authorities": [],
                "protected_paths": [],
                "excluded_paths": [],
                "evidence_entrypoints": [],
                "approval_requirements": [],
            },
            "mechanical_findings": adapter_result["mechanical_findings"],
            "semantic_findings": [],
            "human_approval_required": [],
            "recovery": "Impact cannot run until the project adapter validates.",
        })
    if manifest is not None and args.workspace:
        manifest, contextual_findings = validate_event_manifest(
            manifest,
            manifest_path=Path(args.event_manifest),
            workspace=Path(args.workspace),
            adapter=adapter,
        )
        manifest_findings.extend(contextual_findings)

    scope = analyze_impact_scope(adapter, changed_paths)
    affected = scope["affected_authorities"]
    candidate_authority_paths = scope["candidate_authority_paths"]
    protected = scope["protected_paths"]
    excluded = scope["excluded_paths"]
    human = scope["human_approval_required"]
    approval_requirements = scope["approval_requirements"]

    if args.extend_receipt:
        if not args.workspace:
            return emit({
                "result": "fail",
                "coverage": {"unverified": []},
                "impact": {"changed_paths": changed_paths},
                "receipt": None,
                "mechanical_findings": [{
                    "code": "impact-extension-workspace-required",
                }],
                "semantic_findings": [],
                "human_approval_required": [],
                "recovery": "Supply the workspace bound to the original Impact receipt.",
                "recovery_actions": [],
            })
        workspace = Path(args.workspace)
        try:
            parent_payload = load_json(Path(args.extend_receipt))
        except OSError as exc:
            return emit({
                "result": "fail",
                "coverage": {"unverified": []},
                "impact": {"changed_paths": changed_paths},
                "receipt": None,
                "mechanical_findings": [{
                    "code": "impact-extension-parent-unreadable",
                    "path": args.extend_receipt,
                    "message": str(exc),
                }],
                "semantic_findings": [],
                "human_approval_required": [],
                "recovery": "Restore readable original Impact evidence and retry.",
                "recovery_actions": [
                    "Do not replace the original receipt with a new post-edit baseline."
                ],
            })
        parent_receipt, extract_findings = extract_impact_receipt(parent_payload)
        if parent_receipt is None:
            parent_receipt = {}
        added_paths = sorted(
            set(changed_paths) - set(parent_receipt.get("planned_paths", []))
        )
        receipt, extension_findings, extension_unverified, recovery_actions = (
            impact_extension_payload(
                adapter=adapter,
                adapter_path=Path(args.adapter),
                workspace=workspace,
                parent_receipt=parent_receipt,
                added_paths=added_paths,
            )
        )
        extension_findings = extract_findings + extension_findings
        extension_scope = (
            analyze_impact_scope(adapter, receipt["planned_paths"])
            if receipt is not None
            else scope
        )
        result = (
            "fail"
            if path_findings or manifest_findings or extension_findings
            else "unproven"
            if extension_unverified
            or extension_scope["human_approval_required"]
            or extension_scope["protected_paths"]
            or extension_scope["excluded_paths"]
            else "pass"
        )
        if manifest is not None:
            embedded_parent = manifest.get("receipts", {}).get("impact")
            if (
                not isinstance(embedded_parent, dict)
                or canonical_evidence_v1_digest(embedded_parent)
                != canonical_evidence_v1_digest(parent_receipt)
            ):
                extension_findings.append({
                    "code": "event-manifest-impact-parent-mismatch",
                    "message": (
                        "The event manifest must embed the exact parent Impact receipt "
                        "before it can adopt an extension."
                    ),
                })
                result = "fail"
        output_path = None
        if args.write_receipt and receipt is not None and result != "fail":
            output_path, write_findings = write_receipt_file(
                receipt,
                args.write_receipt,
                workspace,
                adapter,
                overwrite=False,
            )
            if write_findings:
                extension_findings.extend(write_findings)
                result = "fail"
        if manifest is not None and receipt is not None and result != "fail":
            manifest["scope"]["planned_paths"] = receipt["planned_paths"]
            manifest["receipts"]["impact"] = receipt
            write_findings = write_event_manifest(
                manifest,
                args.event_manifest,
                workspace,
                adapter,
                expected_digest=manifest_expected_digest,
            )
            if write_findings:
                extension_findings.extend(write_findings)
                result = "fail"
        return emit({
            "result": result,
            "coverage": {"unverified": extension_unverified},
            "impact": {
                "changed_paths": receipt["planned_paths"] if receipt else changed_paths,
                **extension_scope,
                "evidence_entrypoints": safe_section(adapter, "entrypoints").get("evidence", []),
            },
            "receipt": receipt,
            "mechanical_findings": path_findings + manifest_findings + extension_findings,
            "semantic_findings": [],
            "human_approval_required": extension_scope["human_approval_required"],
            "warnings": adapter_result.get("warnings", []),
            "recovery": (
                "Impact scope extension completed from the preserved original baseline."
                if result == "pass"
                else "The original baseline cannot prove this scope extension."
            ),
            "recovery_actions": recovery_actions,
            "receipt_output": output_path,
        })
    receipt = None
    receipt_findings = []
    impact_unverified = ["empty-impact-scope"] if not changed_paths else []
    work_map_baseline = None
    work_map_findings: list[dict] = []
    recovery_actions: list[str] = []
    binding = manifest.get("work_map_binding") if manifest is not None else None
    if binding is not None:
        if not isinstance(adapter.get("work_map"), dict):
            work_map_findings.append({
                "code": "work-map-config-required",
                "message": "A Work Map binding requires adapter work_map configuration.",
            })
        elif args.workspace:
            _, destination_findings = resolve_receipt_output_path(
                binding["attestation_path"],
                Path(args.workspace),
                adapter,
            )
            work_map_findings.extend({
                **finding,
                "code": "unsafe-attestation-output-path",
            } for finding in destination_findings)
            try:
                work_map_baseline, binding_findings = verify_work_map_binding(
                    adapter,
                    Path(args.workspace),
                    binding,
                )
            except (OSError, UnicodeError) as exc:
                impact_unverified.append("work-map-baseline-unreadable")
                recovery_actions.append(
                    "Restore readable baseline Work Map evidence and rerun Impact before edits."
                )
                work_map_baseline = None
            else:
                work_map_findings.extend(binding_findings)
    if args.workspace:
        workspace = Path(args.workspace)
        source = args.change_source
        if source == "auto":
            git_inventory, git_findings = git_status_inventory(workspace, adapter)
            if git_findings:
                source = "auto"
                impact_unverified.append("git-change-source-unavailable")
                baseline_inventory = {
                    "schema": INVENTORY_SCHEMA,
                    "source": {"kind": "auto", "verified": False},
                    "entries": [],
                }
                source_metadata = {
                    "git_unavailable": git_findings[0].get("message", "Git unavailable"),
                }
            else:
                source = "git"
        if source == "git":
            receipt_output_path = workspace_relative_output_path(
                args.write_receipt,
                workspace,
            )
            baseline_inventory, receipt_findings = scan_git_baseline_inventory(
                workspace,
                adapter,
                source_kind="git-baseline",
                suppressed_paths=[receipt_output_path] if receipt_output_path else [],
            )
            source_metadata = baseline_inventory.get("source", {}).get("metadata", {})
            if getattr(args, "resolved_baseline_ref", None):
                source_metadata["baseline_ref"] = args.resolved_baseline_ref
        elif source == "filesystem":
            baseline_inventory, receipt_findings = scan_filesystem_inventory(workspace, adapter, source_kind="filesystem")
            source_metadata = {}
        elif source != "auto":
            baseline_inventory = {"schema": "govern-ai-coding.inventory.v1", "source": {"kind": source, "verified": False}, "entries": []}
            source_metadata = {}
        receipt = {
            "schema": "govern-ai-coding.receipt.v1",
            "schema_version": "1",
            "adapter": {"project": adapter.get("project"), "schema_version": adapter.get("schema_version")},
            "adapter_binding": {
                "path": str(Path(args.adapter).resolve()),
                "digest": canonical_evidence_v1_digest(adapter),
            },
            "workspace": {"path": str(workspace.resolve())},
            "inventory_source": {
                "kind": source,
                "verified": not receipt_findings and source in {"git", "filesystem"},
                "metadata": source_metadata,
            },
            "baseline_inventory": baseline_inventory,
            "planned_paths": changed_paths,
            "affected_authorities": affected,
            "candidate_authority_paths": candidate_authority_paths,
            "protected_paths": sorted(set(protected)),
            "excluded_paths": sorted(set(excluded)),
            "human_approval_required": human,
            "approval_requirements": approval_requirements,
            "verification_capability": {
                "baseline_inventory": source in {"git", "filesystem"},
                "event_isolation": source in {"git", "filesystem"},
            },
            "derived_evidence": True,
            "generated": True,
            "project_authority": False,
            "recovery": "Pass this receipt to Closeout with --receipt, plus actual changed paths and event-authorized documents.",
        }
        if binding is not None:
            receipt["work_map_baseline"] = work_map_baseline

    recovery = "Impact completed; run Closeout before declaring completion."
    if "git-change-source-unavailable" in impact_unverified:
        recovery = (
            "Git inventory is unavailable. Select --change-source filesystem "
            "explicitly for a filesystem baseline, or use supplied/explicit mode "
            "and retain the resulting unproven boundary."
        )
    payload = {
        "result": "fail" if path_findings or receipt_findings or manifest_findings or work_map_findings else "unproven" if impact_unverified or human or protected or excluded else "pass",
        "coverage": {
            "unverified": impact_unverified,
        },
        "impact": {
            "changed_paths": changed_paths,
            "affected_authorities": affected,
            "candidate_authority_paths": candidate_authority_paths,
            "protected_paths": sorted(set(protected)),
            "excluded_paths": sorted(set(excluded)),
            "evidence_entrypoints": safe_section(adapter, "entrypoints").get("evidence", []),
            "approval_requirements": approval_requirements,
        },
        "receipt": receipt,
        "mechanical_findings": path_findings + receipt_findings + manifest_findings + work_map_findings,
        "semantic_findings": [],
        "human_approval_required": human,
        "warnings": adapter_result.get("warnings", []),
        "recovery": recovery,
        "recovery_actions": recovery_actions,
    }
    output_path = None
    if args.write_receipt and receipt is not None and payload["result"] != "fail":
        output_path, write_findings = write_receipt_file(
            receipt,
            args.write_receipt,
            Path(args.workspace),
            adapter,
        )
        if write_findings:
            payload["mechanical_findings"].extend(write_findings)
            payload["result"] = "fail"
            payload["recovery"] = "Fix receipt output findings and rerun Impact."
    if manifest is not None and payload["result"] != "fail":
        manifest["scope"]["planned_paths"] = changed_paths
        manifest["receipts"]["impact"] = receipt
        if getattr(args, "resolved_baseline_ref", None):
            manifest["event"]["baseline_ref"] = args.resolved_baseline_ref
        write_findings = write_event_manifest(
            manifest,
            args.event_manifest,
            Path(args.workspace),
            adapter,
            expected_digest=manifest_expected_digest,
        )
        if write_findings:
            payload["mechanical_findings"].extend(write_findings)
            payload["result"] = "fail"
            payload["recovery"] = "Fix event manifest output findings and rerun Impact."
    payload["receipt_output"] = output_path
    return emit(payload)


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def snapshot_declared_paths(workspace: Path, paths: list[str]) -> tuple[list[dict], list[dict]]:
    workspace = workspace.resolve()
    findings: list[dict] = []
    snapshots: list[dict] = []
    seen: set[str] = set()
    for raw_path in paths:
        relative, finding = normalize_path_value(raw_path, "changed_path")
        if finding:
            findings.append(finding)
            continue
        if relative in seen:
            findings.append({"code": "duplicate-freeze-path", "path": relative})
            continue
        seen.add(relative)
        target = (workspace / relative).resolve()
        try:
            target.relative_to(workspace)
        except ValueError:
            findings.append({"code": "freeze-path-outside-workspace", "path": relative})
            continue
        if target.exists() and not target.is_file():
            findings.append({"code": "freeze-path-not-file", "path": relative})
            continue
        exists = target.is_file()
        snapshots.append({
            "path": relative,
            "existence": exists,
            "digest": file_digest(target) if exists else None,
        })
    return sorted(snapshots, key=lambda item: item["path"]), findings


def resolve_receipt_output_path(
    output_path: str,
    workspace: Path,
    adapter: dict,
) -> tuple[Path | None, list[dict]]:
    lexical_workspace = Path(os.path.abspath(workspace))
    workspace = workspace.resolve()
    raw_destination = Path(output_path)
    if not raw_destination.is_absolute():
        raw_destination = lexical_workspace / raw_destination
    lexical_destination = Path(os.path.abspath(raw_destination))
    try:
        lexical_relative = lexical_destination.relative_to(lexical_workspace)
    except ValueError:
        lexical_relative = None
    if lexical_relative is not None:
        current = lexical_workspace
        for part in lexical_relative.parts:
            current = current / part
            if current.is_symlink():
                return None, [{
                    "code": "unsafe-receipt-output-path",
                    "path": str(lexical_destination),
                    "message": "receipt output must not traverse a symlink inside the workspace",
                }]
    destination = lexical_destination.resolve()
    if lexical_relative is not None:
        try:
            destination.relative_to(workspace)
        except ValueError:
            return None, [{
                "code": "unsafe-receipt-output-path",
                "path": str(lexical_destination),
                "message": "receipt output must not escape the workspace through a symlink",
            }]
    try:
        relative = destination.relative_to(workspace).as_posix()
    except ValueError:
        return destination, []
    excluded_patterns = safe_section(adapter, "boundaries").get("excluded", [])
    if any(path_matches(relative, pattern) for pattern in excluded_patterns):
        return destination, []
    return None, [{
        "code": "unsafe-receipt-output-path",
        "path": str(destination),
        "message": "receipt output must be outside the workspace or under an excluded boundary",
    }]


def atomic_write_json(
    payload: dict,
    destination: Path,
    *,
    overwrite: bool = True,
    parent_descriptor: int | None = None,
) -> tuple[int, int]:
    destination = Path(destination)
    temporary: Path | None = None
    temporary_name: str
    if parent_descriptor is None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not overwrite and destination.exists():
            raise FileExistsError(f"destination already exists: {destination}")
        while True:
            temporary = destination.parent / (
                f".{destination.name}.{secrets.token_hex(32)}.tmp"
            )
            temporary_name = str(temporary)
            try:
                descriptor = os.open(
                    temporary,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
                break
            except FileExistsError:
                continue
    else:
        if not overwrite:
            try:
                os.stat(
                    destination.name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                pass
            else:
                raise FileExistsError(
                    f"destination already exists: {destination}"
                )
        temporary_name = (
            f".{destination.name}.{secrets.token_hex(32)}.tmp"
        )
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=parent_descriptor,
        )
    published = False
    payload_identity: tuple[int, int] | None = None
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
            payload_stat = os.fstat(handle.fileno())
            payload_identity = (payload_stat.st_dev, payload_stat.st_ino)
        if parent_descriptor is None:
            if overwrite:
                os.replace(temporary, destination)
                published = True
            else:
                os.link(temporary, destination, follow_symlinks=False)
                published = True
                temporary.unlink()
        else:
            if overwrite:
                os.rename(
                    temporary_name,
                    destination.name,
                    src_dir_fd=parent_descriptor,
                    dst_dir_fd=parent_descriptor,
                )
                published = True
            else:
                os.link(
                    temporary_name,
                    destination.name,
                    src_dir_fd=parent_descriptor,
                    dst_dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                published = True
                os.unlink(temporary_name, dir_fd=parent_descriptor)
    except BaseException:
        if not published and not overwrite:
            try:
                if parent_descriptor is None:
                    published = os.path.samefile(temporary, destination)
                else:
                    temporary_stat = os.stat(
                        temporary_name,
                        dir_fd=parent_descriptor,
                        follow_symlinks=False,
                    )
                    destination_stat = os.stat(
                        destination.name,
                        dir_fd=parent_descriptor,
                        follow_symlinks=False,
                    )
                    published = (
                        temporary_stat.st_dev,
                        temporary_stat.st_ino,
                    ) == (
                        destination_stat.st_dev,
                        destination_stat.st_ino,
                    )
            except (FileNotFoundError, OSError):
                pass
        try:
            if parent_descriptor is None:
                temporary.unlink(missing_ok=True)
            else:
                os.unlink(temporary_name, dir_fd=parent_descriptor)
        except FileNotFoundError:
            pass
        if published and payload_identity is not None:
            return payload_identity
        raise
    if payload_identity is None:
        raise OSError("atomic JSON payload identity was not captured")
    return payload_identity


def write_receipt_file(
    receipt: dict,
    output_path: str | None,
    workspace: Path,
    adapter: dict,
    *,
    overwrite: bool = True,
) -> tuple[str | None, list[dict]]:
    if not output_path:
        return None, []
    destination, findings = resolve_receipt_output_path(output_path, workspace, adapter)
    if findings or destination is None:
        return None, findings
    try:
        atomic_write_json(receipt, destination, overwrite=overwrite)
    except OSError as exc:
        return None, [{
            "code": "receipt-write-failed",
            "path": str(destination),
            "message": str(exc),
        }]
    return str(destination), []


def archive_path(
    workspace: Path,
    relative: str,
    field: str,
) -> tuple[Path | None, dict | None]:
    if re.search(r"[$*?{}\[\]~]", relative):
        return None, {
            "code": "archive-path-unresolved",
            "field": field,
            "path": relative,
        }
    normalized, finding = normalize_path_value(relative, field)
    if finding or normalized is None:
        return None, finding
    workspace = workspace.resolve()
    candidate = workspace / normalized
    current = workspace
    for part in Path(normalized).parts:
        current = current / part
        if current.is_symlink():
            return None, {
                "code": "archive-path-traverses-symlink",
                "field": field,
                "path": normalized,
            }
    resolved = candidate.resolve()
    try:
        resolved.relative_to(workspace)
    except ValueError:
        return None, {
            "code": "archive-path-outside-workspace",
            "field": field,
            "path": normalized,
        }
    return candidate, None


def active_reference_docs(
    adapter: dict,
    workspace: Path,
) -> tuple[list[dict], list[dict]]:
    workspace = workspace.resolve()
    excluded = safe_section(adapter, "boundaries").get("excluded", [])
    historical = safe_section(adapter, "entrypoints").get("historical", [])
    archive_roots = safe_section(adapter, "controlled_archive").get(
        "archive_roots",
        [],
    )
    inactive_patterns = [*excluded, *historical, *archive_roots]
    pointers: list[tuple[str, str, bool]] = []
    current = safe_section(adapter, "entrypoints").get("current", [])
    if is_string_list(current):
        pointers.extend(
            (pointer, "entrypoints.current", False)
            for pointer in current
        )
    for rule in safe_rule_list(adapter):
        if is_string_list(rule.get("paths")):
            pointers.extend(
                (
                    pointer,
                    f"authority_rules.{rule.get('id', 'unidentified')}",
                    False,
                )
                for pointer in rule["paths"]
            )

    configured_rules = safe_section(
        adapter,
        "controlled_archive",
    ).get("reference_rules", [])
    if isinstance(configured_rules, list):
        for reference_rule in configured_rules:
            if not isinstance(reference_rule, dict):
                continue
            for selector in reference_rule.get("selectors", []):
                selector_pointers: list[str] = []
                if selector.startswith("entrypoints."):
                    key = selector.split(".", 1)[1]
                    value = safe_section(adapter, "entrypoints").get(key, [])
                    if is_string_list(value):
                        selector_pointers.extend(value)
                elif selector == "authority_rules":
                    for authority_rule in safe_rule_list(adapter):
                        if is_string_list(authority_rule.get("paths")):
                            selector_pointers.extend(authority_rule["paths"])
                elif selector.startswith("authority_rules."):
                    identifier = selector.split(".", 1)[1]
                    for authority_rule in safe_rule_list(adapter):
                        if (
                            authority_rule.get("id") == identifier
                            and is_string_list(authority_rule.get("paths"))
                        ):
                            selector_pointers.extend(authority_rule["paths"])
                allow_inactive = selector in {
                    "entrypoints.evidence",
                    "entrypoints.historical",
                }
                pointers.extend(
                    (pointer, selector, allow_inactive)
                    for pointer in selector_pointers
                )

    document_selectors: dict[Path, set[str]] = {}
    findings: list[dict] = []
    for pointer, selector, allow_inactive in sorted(set(pointers)):
        normalized_pointer, pointer_finding = normalize_path_value(
            pointer,
            "reference_root",
        )
        if pointer_finding or normalized_pointer is None:
            findings.append(pointer_finding or {
                "code": "invalid-reference-root",
                "path": pointer,
            })
            continue
        if not allow_inactive and any(
            path_matches(normalized_pointer, pattern)
            for pattern in inactive_patterns
        ):
            continue
        path, finding = archive_path(workspace, pointer, "reference_root")
        if finding or path is None:
            findings.append(finding or {
                "code": "invalid-reference-root",
                "path": pointer,
            })
            continue
        pointer_is_file = path.is_file()
        if not path.exists():
            findings.append({
                "code": (
                    "active-reference-pointer-missing"
                    if selector == "entrypoints.current"
                    or selector.startswith("authority_rules.")
                    else "reference-pointer-missing"
                ),
                "path": normalized_pointer,
                "selector": selector,
            })
            continue
        candidates = [path] if pointer_is_file else (
            sorted(candidate for candidate in path.rglob("*") if candidate.is_file())
            if path.is_dir()
            else []
        )
        for candidate in candidates:
            try:
                relative = candidate.relative_to(workspace).as_posix()
            except ValueError:
                continue
            if not allow_inactive and any(
                path_matches(relative, pattern)
                for pattern in inactive_patterns
            ):
                continue
            safe_candidate, candidate_finding = archive_path(
                workspace,
                relative,
                "reference_path",
            )
            if candidate_finding or safe_candidate is None:
                findings.append(candidate_finding or {
                    "code": "invalid-reference-path",
                    "path": relative,
                })
                continue
            if not safe_candidate.is_file():
                continue
            resolved = safe_candidate.resolve()
            document_selectors.setdefault(resolved, set()).add(selector)
    documents = [
        {
            "path": path,
            "selectors": sorted(selectors),
        }
        for path, selectors in sorted(
            document_selectors.items(),
            key=lambda item: str(item[0]),
        )
    ]
    return documents, findings


def discover_active_references(
    adapter: dict,
    workspace: Path,
    source: str,
    source_path: Path,
) -> tuple[list[dict], list[dict], list[str]]:
    documents, findings = active_reference_docs(adapter, workspace)
    references: list[dict] = []
    for record in documents:
        document = record["path"]
        selectors = record["selectors"]
        if document.resolve() == source_path.resolve():
            continue
        relative_doc = document.relative_to(workspace.resolve()).as_posix()
        try:
            lines = document.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            findings.append({
                "code": "active-reference-document-not-utf8",
                "path": relative_doc,
            })
            continue
        except OSError as exc:
            findings.append({
                "code": "active-reference-document-unreadable",
                "path": relative_doc,
                "message": str(exc),
            })
            continue
        for line_number, line in enumerate(lines, start=1):
            matched = source in line
            match_form = "text"
            column = line.find(source) + 1 if matched else 0
            if not matched:
                for link in markdown_links(line):
                    if not is_local_link(link):
                        continue
                    if resolve_link(document, link) == source_path.resolve():
                        matched = True
                        match_form = "link"
                        column = line.find(link) + 1
                        break
            if matched:
                references.append({
                    "path": relative_doc,
                    "line": line_number,
                    "column": column,
                    "match_form": match_form,
                    "selector": selectors[0],
                    "selectors": selectors,
                })
    unique = {
        (reference["path"], reference["line"]): reference
        for reference in references
    }
    scanned = sorted(
        record["path"].relative_to(workspace.resolve()).as_posix()
        for record in documents
        if record["path"].resolve() != source_path.resolve()
    )
    return [unique[key] for key in sorted(unique)], findings, scanned


def validate_archive_references(
    request: dict,
    discovered: list[dict],
    scanned_paths: list[str],
) -> tuple[dict, list[dict], list[str]]:
    declaration = request.get("references")
    if not isinstance(declaration, dict):
        return {}, [{
            "code": "invalid-archive-request",
            "field": "references",
        }], []
    status = declaration.get("status")
    legacy = declaration.get("legacy")
    if status not in {"updated", "legacy-dispositions"} or not isinstance(legacy, list):
        return {}, [{
            "code": "invalid-archive-request",
            "field": "references",
        }], []

    dispositions: list[dict] = []
    findings: list[dict] = []
    for index, item in enumerate(legacy):
        if not isinstance(item, dict):
            findings.append({
                "code": "invalid-archive-request",
                "field": f"references.legacy.{index}",
            })
            continue
        path = item.get("path")
        line = item.get("line")
        resolution = item.get("resolution")
        normalized, path_finding = normalize_path_value(
            path if isinstance(path, str) else "",
            f"references.legacy.{index}.path",
        )
        if (
            path_finding
            or normalized is None
            or not isinstance(line, int)
            or line < 1
            or not isinstance(resolution, str)
            or not resolution.strip()
        ):
            findings.append({
                "code": "invalid-archive-request",
                "field": f"references.legacy.{index}",
            })
            continue
        dispositions.append({
            "path": normalized,
            "line": line,
            "resolution": resolution.strip(),
        })

    declared = {
        (item["path"], item["line"])
        for item in dispositions
    }
    required = {
        (item["path"], item["line"])
        for item in discovered
    }
    unverified: list[str] = []
    if discovered and (
        status == "updated"
        or not required.issubset(declared)
    ):
        unverified.append("archive-references-unresolved")
    return {
        "status": status,
        "scanned_paths": scanned_paths,
        "discovered": discovered,
        "dispositions": dispositions,
    }, findings, unverified


def archive_failure(
    *,
    result: str,
    mechanical: list[dict],
    unverified: list[str],
    human_required: list[str],
    mapping: dict | None = None,
    references: dict | None = None,
    runtime: dict | None = None,
    recovery: str,
) -> dict:
    return {
        "result": result,
        "mechanical_findings": mechanical,
        "semantic_findings": [],
        "human_approval_required": human_required,
        "coverage": {"unverified": sorted(set(unverified))},
        "controlled_archive": {
            "mapping": mapping,
            "moved": False,
            "references": references or {},
            "runtime": runtime,
        },
        "archive_receipt": None,
        "receipt_output": None,
        "recovery": recovery,
    }


def legacy_archive_receipt_v1_request_digest(payload: object) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def open_directory_no_symlinks(root: Path, parts: tuple[str, ...]) -> int:
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    directory_only = getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(root, os.O_RDONLY | directory_only | no_follow)
    try:
        for part in parts:
            next_descriptor = os.open(
                part,
                os.O_RDONLY | directory_only | no_follow,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def descriptor_digest(descriptor: int) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest()


def descriptor_matches_path(
    descriptor: int,
    path: Path,
) -> bool:
    try:
        path_stat = os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        return False
    descriptor_stat = os.fstat(descriptor)
    return (
        path_stat.st_dev,
        path_stat.st_ino,
    ) == (
        descriptor_stat.st_dev,
        descriptor_stat.st_ino,
    )


def descriptor_matches_name(
    descriptor: int,
    parent_descriptor: int,
    name: str,
) -> bool:
    try:
        path_stat = os.stat(
            name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return False
    descriptor_stat = os.fstat(descriptor)
    return (
        path_stat.st_dev,
        path_stat.st_ino,
    ) == (
        descriptor_stat.st_dev,
        descriptor_stat.st_ino,
    )


def unlink_descriptor_name(
    descriptor: int,
    parent_descriptor: int,
    name: str,
) -> None:
    if not descriptor_matches_name(descriptor, parent_descriptor, name):
        raise OSError(f"refusing to unlink replaced transaction path: {name}")
    os.unlink(name, dir_fd=parent_descriptor)


def copy_descriptor_exclusive(
    source_descriptor: int,
    destination_parent_descriptor: int,
    destination_name: str,
) -> int:
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    destination_descriptor = None
    destination_created = False
    try:
        source_mode = os.fstat(source_descriptor).st_mode & 0o777
        destination_descriptor = os.open(
            destination_name,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | no_follow,
            source_mode,
            dir_fd=destination_parent_descriptor,
        )
        destination_created = True
        os.lseek(source_descriptor, 0, os.SEEK_SET)
        while True:
            chunk = os.read(source_descriptor, 1024 * 1024)
            if not chunk:
                break
            offset = 0
            while offset < len(chunk):
                written = os.write(destination_descriptor, chunk[offset:])
                if written <= 0:
                    raise OSError("archive copy made no forward progress")
                offset += written
        os.fsync(destination_descriptor)
        os.lseek(source_descriptor, 0, os.SEEK_SET)
        return destination_descriptor
    except BaseException:
        if (
            destination_created
            and destination_descriptor is not None
            and descriptor_matches_name(
                destination_descriptor,
                destination_parent_descriptor,
                destination_name,
            )
        ):
            os.unlink(
                destination_name,
                dir_fd=destination_parent_descriptor,
            )
        if destination_descriptor is not None:
            os.close(destination_descriptor)
        raise


def execute_controlled_archive(
    adapter: dict,
    workspace: Path,
    request: dict,
    receipt_destination: Path,
    execution_grant: dict | None = None,
    amendment: dict | None = None,
    original_execution_grant: dict | None = None,
    *,
    read_only: bool = False,
) -> dict:
    workspace = workspace.resolve()
    config = safe_section(adapter, "controlled_archive")
    mechanical = validate_controlled_archive_config(adapter)
    unverified: list[str] = []
    human_required: list[str] = []

    if request.get("schema") != ARCHIVE_REQUEST_SCHEMA:
        mechanical.append({
            "code": "unsupported-archive-request-schema",
            "schema": request.get("schema"),
        })
    if request.get("schema_version") != "1":
        mechanical.append({
            "code": "unsupported-archive-request-version",
            "schema_version": request.get("schema_version"),
        })

    mapping = request.get("mapping")
    source = mapping.get("source") if isinstance(mapping, dict) else None
    target = mapping.get("target") if isinstance(mapping, dict) else None
    if not isinstance(source, str) or not isinstance(target, str):
        mechanical.append({
            "code": "invalid-archive-request",
            "field": "mapping",
        })
        source = source if isinstance(source, str) else ""
        target = target if isinstance(target, str) else ""
    normalized_source, source_finding = normalize_path_value(
        source,
        "mapping.source",
    )
    normalized_target, target_finding = normalize_path_value(
        target,
        "mapping.target",
    )
    if source_finding:
        mechanical.append(source_finding)
    if target_finding:
        mechanical.append(target_finding)
    source = normalized_source or source
    target = normalized_target or target
    normalized_mapping = {"source": source, "target": target}

    reason = request.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        mechanical.append({
            "code": "invalid-archive-request",
            "field": "reason",
        })

    disposition = request.get("authority_disposition")
    disposition_kind = disposition.get("kind") if isinstance(disposition, dict) else None
    disposition_statement = (
        disposition.get("statement")
        if isinstance(disposition, dict)
        else None
    )
    replacement = (
        disposition.get("replacement")
        if isinstance(disposition, dict)
        else None
    )
    if (
        disposition_kind
        not in {"replacement", "authority-transfer", "no-replacement"}
        or not isinstance(disposition_statement, str)
        or not disposition_statement.strip()
    ):
        mechanical.append({
            "code": "invalid-archive-request",
            "field": "authority_disposition",
        })
    if disposition_kind in {"replacement", "authority-transfer"}:
        if not isinstance(replacement, str) or not replacement.strip():
            mechanical.append({
                "code": "invalid-archive-request",
                "field": "authority_disposition.replacement",
            })
    elif disposition_kind == "no-replacement" and replacement is not None:
        mechanical.append({
            "code": "invalid-archive-request",
            "field": "authority_disposition.replacement",
        })

    source_roots = config.get("source_roots", [])
    archive_roots = config.get("archive_roots", [])
    if source and not any(path_matches(source, root) for root in source_roots):
        mechanical.append({
            "code": "archive-source-outside-configured-root",
            "path": source,
        })
    if target and not any(path_matches(target, root) for root in archive_roots):
        mechanical.append({
            "code": "archive-target-outside-configured-root",
            "path": target,
        })
    matched_archive_roots = [
        root for root in archive_roots
        if target and path_matches(target, root)
    ]
    if target and len(matched_archive_roots) != 1:
        mechanical.append({
            "code": "archive-target-root-identity-ambiguous",
            "path": target,
            "matched_roots": matched_archive_roots,
        })
    archive_root_sha256 = (
        canonical_archive_v1_digest({
            "archive_root": matched_archive_roots[0],
        })
        if len(matched_archive_roots) == 1
        else None
    )
    if source == target and source:
        mechanical.append({
            "code": "archive-source-equals-target",
            "path": source,
        })

    source_path, archive_source_finding = archive_path(
        workspace,
        source,
        "mapping.source",
    )
    target_path, archive_target_finding = archive_path(
        workspace,
        target,
        "mapping.target",
    )
    if archive_source_finding:
        mechanical.append(archive_source_finding)
    if archive_target_finding:
        mechanical.append(archive_target_finding)

    boundaries = safe_section(adapter, "boundaries")
    entrypoints = safe_section(adapter, "entrypoints")
    for pattern in boundaries.get("excluded", []):
        if source and path_matches(source, pattern):
            mechanical.append({
                "code": "archive-source-not-active",
                "path": source,
                "matched": pattern,
            })
    for pattern in boundaries.get("protected", []):
        if source and path_matches(source, pattern):
            mechanical.append({
                "code": "archive-source-not-active",
                "path": source,
                "matched": pattern,
            })
    for pattern in entrypoints.get("historical", []):
        if source and path_matches(source, pattern):
            mechanical.append({
                "code": "archive-source-not-active",
                "path": source,
                "matched": pattern,
            })

    if source_path is not None and (
        not source_path.is_file()
        or source_path.is_symlink()
    ):
        mechanical.append({
            "code": "archive-source-not-regular-file",
            "path": source,
        })
    if target_path is not None:
        if target_path.exists() or target_path.is_symlink():
            mechanical.append({
                "code": "archive-target-exists",
                "path": target,
            })
        if not target_path.parent.is_dir():
            mechanical.append({
                "code": "archive-target-parent-missing",
                "path": target_path.parent.relative_to(workspace).as_posix(),
            })

    normalized_replacement = None
    if isinstance(replacement, str) and replacement.strip():
        normalized_replacement, replacement_finding = normalize_path_value(
            replacement,
            "authority_disposition.replacement",
        )
        if replacement_finding:
            mechanical.append(replacement_finding)
        if normalized_replacement:
            if normalized_replacement in {source, target}:
                mechanical.append({
                    "code": "archive-replacement-conflicts-with-mapping",
                    "path": normalized_replacement,
                })
            replacement_path, replacement_path_finding = archive_path(
                workspace,
                normalized_replacement,
                "authority_disposition.replacement",
            )
            if replacement_path_finding:
                mechanical.append(replacement_path_finding)
            elif (
                replacement_path is None
                or not replacement_path.is_file()
                or replacement_path.is_symlink()
            ):
                mechanical.append({
                    "code": "archive-replacement-not-active-file",
                    "path": normalized_replacement,
                })
            if any(
                path_matches(normalized_replacement, pattern)
                for pattern in [
                    *boundaries.get("excluded", []),
                    *boundaries.get("protected", []),
                    *entrypoints.get("historical", []),
                ]
            ):
                mechanical.append({
                    "code": "archive-replacement-not-active-file",
                    "path": normalized_replacement,
                })

    approval_type = config.get("approval_type")
    approval = request.get("approval")
    approval_evidence = (
        approval.get("evidence")
        if isinstance(approval, dict)
        else None
    )
    approval_digest = None
    normalized_evidence = None
    approval_source = source
    approval_target = target
    if isinstance(amendment, dict):
        amendment_original = amendment.get("original_mapping")
        if (
            isinstance(amendment_original, dict)
            and amendment_original.get("source") == source
            and isinstance(amendment_original.get("target"), str)
        ):
            approval_target = amendment_original["target"]
    if (
        not isinstance(approval, dict)
        or approval.get("type") != approval_type
        or not isinstance(approval_evidence, str)
        or not approval_evidence.strip()
    ):
        unverified.append("archive-approval-missing")
        if isinstance(approval_type, str):
            human_required.append(approval_type)
    else:
        normalized_evidence, evidence_finding = normalize_path_value(
            approval_evidence,
            "approval.evidence",
        )
        if evidence_finding:
            mechanical.append(evidence_finding)
        if normalized_evidence:
            evidence_path, evidence_path_finding = archive_path(
                workspace,
                normalized_evidence,
                "approval.evidence",
            )
            if evidence_path_finding:
                mechanical.append(evidence_path_finding)
            evidence_ordinary = any(
                path_matches(normalized_evidence, pattern)
                for pattern in boundaries.get("ordinary_docs", [])
            )
            evidence_forbidden = any(
                path_matches(normalized_evidence, pattern)
                for pattern in [
                    *boundaries.get("excluded", []),
                    *boundaries.get("protected", []),
                    *entrypoints.get("historical", []),
                ]
            )
            if (
                evidence_path is None
                or not evidence_path.is_file()
                or evidence_path.is_symlink()
                or not evidence_ordinary
                or evidence_forbidden
            ):
                unverified.append("archive-approval-evidence-invalid")
                human_required.append(approval_type)
            else:
                try:
                    evidence_text = evidence_path.read_text(encoding="utf-8")
                except UnicodeDecodeError:
                    mechanical.append({
                        "code": "archive-approval-evidence-not-utf8",
                        "path": normalized_evidence,
                    })
                else:
                    if (
                        generated_non_authority_evidence(evidence_text)
                        or not text_records_archive_approval(
                            evidence_text,
                            approval_type,
                            approval_source,
                            approval_target,
                        )
                    ):
                        unverified.append("archive-approval-scope-mismatch")
                        human_required.append(approval_type)
                    else:
                        approval_digest = file_digest(evidence_path)
                if approval_digest is None and not any(
                    finding.get("code") == "archive-approval-evidence-not-utf8"
                    and finding.get("path") == normalized_evidence
                    for finding in mechanical
                ):
                    human_required.append(approval_type)

    discovered: list[dict] = []
    scanned_paths: list[str] = []
    reference_summary: dict = {}
    if source_path is not None and source_path.is_file() and not source_path.is_symlink():
        discovered, reference_findings, scanned_paths = discover_active_references(
            adapter,
            workspace,
            source,
            source_path,
        )
        mechanical.extend(reference_findings)
    reference_summary, declaration_findings, reference_unverified = (
        validate_archive_references(request, discovered, scanned_paths)
    )
    mechanical.extend(declaration_findings)
    configured_reference_rules = config.get("reference_rules", [])
    if configured_reference_rules:
        classified = classify_archive_references(
            adapter,
            discovered,
            [
                {
                    "selector": selector,
                    "paths": scanned_paths,
                    "files_scanned": len(scanned_paths),
                }
                for selector in sorted({
                    selector
                    for item in discovered
                    for selector in item.get(
                        "selectors",
                        [item.get("selector")],
                    )
                    if isinstance(selector, str)
                } or {"entrypoints.current"})
            ],
        )
        dispositions = {
            (item.get("path"), item.get("line"))
            for item in reference_summary.get("dispositions", [])
        }
        for item in classified["discovered"]:
            if (item.get("path"), item.get("line")) in dispositions:
                item["disposition"] = "provided"
                item["required_action"] = "none"
        classified["blocking"] = [
            item for item in classified["discovered"]
            if item.get("handling") != "trace-only"
            and item.get("disposition") != "provided"
        ]
        classified["required_actions"] = [
            {
                "path": item.get("path"),
                "line": item.get("line"),
                "column": item.get("column"),
                "category": item.get("category"),
                "action": item.get("required_action"),
            }
            for item in classified["blocking"]
        ]
        reference_summary.update(classified)
        if classified["blocking"]:
            unverified.append("archive-references-unresolved")
    else:
        declared_locations = {
            (item.get("path"), item.get("line"))
            for item in reference_summary.get("dispositions", [])
        }
        for item in reference_summary.get("discovered", []):
            item["category"] = "current-dependency"
            item["handling"] = "disposition-required"
            item["disposition"] = (
                "provided"
                if (item.get("path"), item.get("line")) in declared_locations
                else "unresolved"
            )
            item["required_action"] = (
                "none"
                if item["disposition"] == "provided"
                else "provide an exact disposition for this current dependency"
            )
        reference_summary["scanned_scopes"] = [{
            "selector": "entrypoints.current",
            "paths": scanned_paths,
            "files_scanned": len(scanned_paths),
        }]
        reference_summary["required_actions"] = [
            {
                "path": item.get("path"),
                "line": item.get("line"),
                "column": item.get("column"),
                "category": item.get("category"),
                "action": item.get("required_action"),
            }
            for item in reference_summary.get("discovered", [])
            if item.get("disposition") != "provided"
        ]
        unverified.extend(reference_unverified)

    destination, receipt_findings = resolve_receipt_output_path(
        str(receipt_destination),
        workspace,
        adapter,
    )
    mechanical.extend(receipt_findings)
    if destination is not None:
        if destination.exists() or destination.is_symlink():
            mechanical.append({
                "code": "archive-receipt-exists",
                "path": str(destination),
            })
        if not destination.parent.is_dir():
            mechanical.append({
                "code": "archive-receipt-parent-missing",
                "path": str(destination.parent),
            })

    normalized_disposition = {
        "kind": disposition_kind,
        "replacement": normalized_replacement,
        "statement": (
            disposition_statement.strip()
            if isinstance(disposition_statement, str)
            else ""
        ),
    }
    source_sha256 = None
    source_size = None
    if (
        source_path is not None
        and source_path.is_file()
        and not source_path.is_symlink()
    ):
        try:
            source_sha256 = file_digest(source_path)
            source_size = os.stat(
                source_path,
                follow_symlinks=False,
            ).st_size
        except OSError as exc:
            mechanical.append({
                "code": "archive-source-identity-unavailable",
                "path": source,
                "message": str(exc),
            })
    receipt_binding = str(receipt_destination)
    if destination is not None:
        try:
            receipt_binding = destination.relative_to(workspace).as_posix()
        except ValueError:
            receipt_binding = str(destination)
    operation = {
        "source": source,
        "target": target,
        "receipt": receipt_binding,
        "source_sha256": source_sha256,
        "source_size": source_size,
        "archive_root_sha256": archive_root_sha256,
        "authority_disposition_sha256": canonical_archive_v1_digest(
            normalized_disposition
        ),
    }
    runtime = runtime_capability_report(
        workspace,
        [operation],
        read_only=True,
    )
    if runtime["result"] != "pass":
        mechanical.extend(runtime["diagnostics"])
    preflight = build_archive_preflight(
        request=request,
        mapping=normalized_mapping,
        runtime=runtime,
        references=reference_summary,
        findings=mechanical,
        unverified=unverified,
        approval_digest=approval_digest,
    )
    preflight["operation"] = operation
    preflight["preflight_sha256"] = canonical_archive_v1_digest({
        "base_preflight_sha256": preflight["preflight_sha256"],
        "operation": operation,
    })

    if mechanical:
        failure = archive_failure(
            result="fail",
            mechanical=mechanical,
            unverified=unverified,
            human_required=human_required,
            mapping=normalized_mapping,
            references=reference_summary,
            runtime=runtime,
            recovery="Fix the controlled archive request and adapter findings; no file was moved.",
        )
        failure["preflight"] = preflight
        return failure
    if unverified:
        failure = archive_failure(
            result="unproven",
            mechanical=[],
            unverified=unverified,
            human_required=human_required,
            mapping=normalized_mapping,
            references=reference_summary,
            runtime=runtime,
            recovery="Provide the missing approval or reference dispositions; no file was moved.",
        )
        failure["preflight"] = preflight
        return failure
    if source_path is None or target_path is None or destination is None:
        return archive_failure(
            result="fail",
            mechanical=[{"code": "archive-preflight-incomplete"}],
            unverified=[],
            human_required=[],
            mapping=normalized_mapping,
            references=reference_summary,
            runtime=runtime,
            recovery="Rerun preflight with fully resolved paths; no file was moved.",
        )

    amendment_digest = None
    if amendment is not None:
        if not isinstance(original_execution_grant, dict):
            failure = archive_failure(
                result="unproven",
                mechanical=[],
                unverified=["archive-amendment-original-grant-required"],
                human_required=human_required,
                mapping=normalized_mapping,
                references=reference_summary,
                runtime=runtime,
                recovery=(
                    "Provide the immutable original execution grant named by "
                    "the amendment; no file was moved."
                ),
            )
            failure["preflight"] = preflight
            return failure
        original_mapping = amendment.get("original_mapping")
        corrected_mapping = amendment.get("corrected_mapping")
        original_grant_operation = original_execution_grant.get("operation")
        if (
            corrected_mapping != normalized_mapping
            or not isinstance(original_mapping, dict)
            or not isinstance(original_grant_operation, dict)
            or {
                "source": original_grant_operation.get("source"),
                "target": original_grant_operation.get("target"),
            } != original_mapping
        ):
            failure = archive_failure(
                result="fail",
                mechanical=[{
                    "code": "archive-amendment-operation-binding-mismatch",
                }],
                unverified=[],
                human_required=human_required,
                mapping=normalized_mapping,
                references=reference_summary,
                runtime=runtime,
                recovery=(
                    "Bind the original grant, original mapping, and corrected "
                    "request exactly; no file was moved."
                ),
            )
            failure["preflight"] = preflight
            return failure
        original_operation = {
            "mapping": original_mapping,
            "authority_disposition_sha256": operation[
                "authority_disposition_sha256"
            ],
            "archive_root_sha256": original_grant_operation.get(
                "archive_root_sha256"
            ),
            "corrected_archive_root_sha256": operation.get(
                "archive_root_sha256"
            ),
            "archive_visibility": "excluded",
            "archive_root_class": "configured-archive-root",
            "recovery_boundary": "copy-to-unoccupied-active-path",
            "approval_type": approval_type,
        }
        amendment_normalized, amendment_findings, amendment_unverified = (
            validate_mapping_amendment(
                adapter,
                amendment,
                original_operation=original_operation,
                original_grant_digest=canonical_archive_v1_digest(
                    original_execution_grant
                ),
            )
        )
        if amendment_findings or amendment_unverified:
            failure = archive_failure(
                result="fail" if amendment_findings else "unproven",
                mechanical=amendment_findings,
                unverified=amendment_unverified,
                human_required=human_required,
                mapping=normalized_mapping,
                references=reference_summary,
                runtime=runtime,
                recovery=(
                    "Provide a separately bound mechanical amendment or obtain "
                    "new explicit approval; no file was moved."
                ),
            )
            failure["preflight"] = preflight
            return failure
        supplemental = amendment_normalized["supplemental_evidence"]
        supplemental_path, supplemental_finding = archive_path(
            workspace,
            supplemental["path"],
            "amendment.supplemental_evidence.path",
        )
        supplemental_ordinary = any(
            path_matches(supplemental["path"], pattern)
            for pattern in boundaries.get("ordinary_docs", [])
        )
        supplemental_forbidden = any(
            path_matches(supplemental["path"], pattern)
            for pattern in [
                *boundaries.get("excluded", []),
                *boundaries.get("protected", []),
                *entrypoints.get("historical", []),
            ]
        )
        evidence_valid = (
            supplemental_finding is None
            and supplemental_path is not None
            and supplemental_path.is_file()
            and not supplemental_path.is_symlink()
            and supplemental_ordinary
            and not supplemental_forbidden
        )
        if evidence_valid:
            try:
                supplemental_text = supplemental_path.read_text(
                    encoding="utf-8"
                )
            except (OSError, UnicodeDecodeError):
                evidence_valid = False
            else:
                evidence_valid = (
                    file_digest(supplemental_path) == supplemental["sha256"]
                    and not generated_non_authority_evidence(supplemental_text)
                    and text_records_archive_amendment(
                        supplemental_text,
                        supplemental["type"],
                        amendment_normalized["original_mapping"],
                        amendment_normalized["corrected_mapping"],
                        amendment_normalized["reason"],
                    )
                )
        if not evidence_valid:
            failure = archive_failure(
                result="unproven",
                mechanical=(
                    [supplemental_finding]
                    if supplemental_finding is not None
                    else []
                ),
                unverified=[
                    "archive-amendment-supplemental-evidence-invalid"
                ],
                human_required=[supplemental["type"]],
                mapping=normalized_mapping,
                references=reference_summary,
                runtime=runtime,
                recovery=(
                    "Provide active ordinary supplemental evidence bound to "
                    "both mappings and the correction reason; no file was moved."
                ),
            )
            failure["preflight"] = preflight
            return failure
        amendment_digest = canonical_archive_v1_digest(amendment_normalized)
        preflight["amendment_sha256"] = amendment_digest
        preflight["preflight_sha256"] = canonical_archive_v1_digest({
            "base_preflight_sha256": preflight["preflight_sha256"],
            "amendment_sha256": amendment_digest,
        })

    if read_only:
        return preflight

    normalized_grant, grant_findings, grant_unverified = (
        validate_execution_grant(
            execution_grant,
            request_digest=preflight["request_sha256"],
            preflight_digest=preflight["preflight_sha256"],
            operation=operation,
            approval_digest=approval_digest,
            amendment_digest=amendment_digest,
        )
    )
    if grant_findings or grant_unverified:
        failure = archive_failure(
            result="fail" if grant_findings else "unproven",
            mechanical=grant_findings,
            unverified=grant_unverified,
            human_required=human_required,
            mapping=normalized_mapping,
            references=reference_summary,
            runtime=runtime,
            recovery=(
                "Provide an exact execution grant bound to this preflight, "
                "mapping, receipt, disposition, and approval; no file was moved."
            ),
        )
        failure["preflight"] = preflight
        return failure

    before_digest = file_digest(source_path)
    receipt = {
        "schema": ARCHIVE_RECEIPT_SCHEMA,
        "schema_version": "1",
        "kind": "controlled-archive",
        "immutable": True,
        "derived_evidence": True,
        "generated": True,
        "project_authority": False,
        "adapter": {
            "project": adapter.get("project"),
            "schema_version": adapter.get("schema_version"),
        },
        "workspace": {"path": str(workspace)},
        "request_sha256": legacy_archive_receipt_v1_request_digest(request),
        "mapping": normalized_mapping,
        "archive_reason": reason.strip(),
        "authority_disposition": normalized_disposition,
        "approval": {
            "type": approval_type,
            "evidence": normalized_evidence,
            "evidence_sha256": approval_digest,
        },
        "content": {
            "before_sha256": before_digest,
            "after_sha256": None,
            "source_size": source_size,
            "unchanged": False,
        },
        "references": reference_summary,
        "execution": {
            "result": "pass",
            "operation": "single-file active-to-immutable-archive move",
            "authorization": {
                "grant_schema": EXECUTION_GRANT_SCHEMA,
                "grant_sha256": canonical_archive_v1_digest(normalized_grant),
                "preflight_sha256": preflight["preflight_sha256"],
                "amendment_sha256": amendment_digest,
            },
        },
        "recovery": {
            "instructions": (
                f"To recover, obtain separate explicit approval and copy the "
                f"verified bytes from {target} to an unoccupied active path. "
                "Do not modify or remove the archived target; preserve this receipt."
            ),
        },
    }

    source_parent_descriptor = None
    target_parent_descriptor = None
    receipt_parent_descriptor = None
    staging_descriptor = None
    target_descriptor = None
    receipt_descriptor = None
    staging_name = None
    staging_present = False
    target_present = False
    receipt_present = False
    try:
        source_parts = Path(source).parts
        target_parts = Path(target).parts
        source_parent_descriptor = open_directory_no_symlinks(
            workspace,
            source_parts[:-1],
        )
        target_parent_descriptor = open_directory_no_symlinks(
            workspace,
            target_parts[:-1],
        )
        receipt_root = Path(destination.anchor)
        receipt_parent_descriptor = open_directory_no_symlinks(
            receipt_root,
            destination.parent.relative_to(receipt_root).parts,
        )
        if not descriptor_matches_path(
            source_parent_descriptor,
            source_path.parent,
        ) or not descriptor_matches_path(
            target_parent_descriptor,
            target_path.parent,
        ) or not descriptor_matches_path(
            receipt_parent_descriptor,
            destination.parent,
        ):
            raise OSError("archive parent changed after preflight")
        if file_digest(source_path) != before_digest:
            raise OSError("archive source changed after preflight")

        staging_name = (
            f".{source_parts[-1]}.controlled-archive-"
            f"{secrets.token_hex(32)}.tmp"
        )
        os.rename(
            source_parts[-1],
            staging_name,
            src_dir_fd=source_parent_descriptor,
            dst_dir_fd=source_parent_descriptor,
        )
        staging_present = True
        staging_descriptor = os.open(
            staging_name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=source_parent_descriptor,
        )
        if not stat.S_ISREG(os.fstat(staging_descriptor).st_mode):
            raise OSError("archive source is no longer a regular file")
        if descriptor_digest(staging_descriptor) != before_digest:
            raise OSError("archive source changed during retirement")

        target_descriptor = copy_descriptor_exclusive(
            staging_descriptor,
            target_parent_descriptor,
            target_parts[-1],
        )
        target_present = True
        after_digest = descriptor_digest(target_descriptor)
        if after_digest != before_digest:
            raise OSError("archive content digest changed during copy")
        if not descriptor_matches_path(
            source_parent_descriptor,
            source_path.parent,
        ) or not descriptor_matches_path(
            target_parent_descriptor,
            target_path.parent,
        ) or not descriptor_matches_path(
            receipt_parent_descriptor,
            destination.parent,
        ):
            raise OSError("archive parent changed during execution")

        receipt["content"]["after_sha256"] = after_digest
        receipt["content"]["unchanged"] = True
        receipt_identity = atomic_write_json(
            receipt,
            destination,
            overwrite=False,
            parent_descriptor=receipt_parent_descriptor,
        )
        receipt_descriptor = os.open(
            destination.name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=receipt_parent_descriptor,
        )
        receipt_stat = os.fstat(receipt_descriptor)
        if (
            receipt_stat.st_dev,
            receipt_stat.st_ino,
        ) != receipt_identity:
            raise OSError("archive receipt changed during publication")
        receipt_present = True
        if not descriptor_matches_name(
            target_descriptor,
            target_parent_descriptor,
            target_parts[-1],
        ):
            raise OSError("archive target changed during commit")
        if descriptor_digest(target_descriptor) != before_digest:
            raise OSError("archive target content changed during commit")
        if not descriptor_matches_path(
            source_parent_descriptor,
            source_path.parent,
        ) or not descriptor_matches_path(
            target_parent_descriptor,
            target_path.parent,
        ) or not descriptor_matches_path(
            receipt_parent_descriptor,
            destination.parent,
        ):
            raise OSError("archive parent changed during commit")
        try:
            os.stat(
                source_parts[-1],
                dir_fd=source_parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        else:
            raise OSError("archive source path was recreated during commit")
        unlink_descriptor_name(
            staging_descriptor,
            source_parent_descriptor,
            staging_name,
        )
        staging_present = False
    except BaseException as exc:
        rollback_errors: list[str] = []
        if (
            receipt_present
            and receipt_descriptor is not None
            and receipt_parent_descriptor is not None
        ):
            try:
                unlink_descriptor_name(
                    receipt_descriptor,
                    receipt_parent_descriptor,
                    destination.name,
                )
                receipt_present = False
            except OSError as rollback_exc:
                rollback_errors.append(str(rollback_exc))
        source_restored = False
        restore_descriptor = None
        restore_source_descriptor = (
            staging_descriptor
            if staging_present and staging_descriptor is not None
            else target_descriptor
        )
        if (
            restore_source_descriptor is not None
            and source_parent_descriptor is not None
        ):
            try:
                restore_descriptor = copy_descriptor_exclusive(
                    restore_source_descriptor,
                    source_parent_descriptor,
                    Path(source).name,
                )
                source_restored = True
            except OSError as rollback_exc:
                rollback_errors.append(str(rollback_exc))
            finally:
                if restore_descriptor is not None:
                    os.close(restore_descriptor)
        if (
            staging_present
            and staging_descriptor is not None
            and source_parent_descriptor is not None
            and source_restored
        ):
            try:
                unlink_descriptor_name(
                    staging_descriptor,
                    source_parent_descriptor,
                    staging_name,
                )
                staging_present = False
            except OSError as rollback_exc:
                rollback_errors.append(str(rollback_exc))
        original_preserved = source_restored or staging_present
        if (
            target_present
            and target_descriptor is not None
            and target_parent_descriptor is not None
            and original_preserved
        ):
            try:
                unlink_descriptor_name(
                    target_descriptor,
                    target_parent_descriptor,
                    Path(target).name,
                )
                target_present = False
            except OSError as rollback_exc:
                rollback_errors.append(str(rollback_exc))
        failure = {
            "code": "controlled-archive-execution-failed",
            "message": str(exc),
        }
        mechanical = [failure]
        for rollback_error in rollback_errors:
            mechanical.append({
                "code": "controlled-archive-rollback-failed",
                "message": rollback_error,
            })
        if not isinstance(exc, OSError):
            raise
        return archive_failure(
            result="fail",
            mechanical=mechanical,
            unverified=[],
            human_required=[],
            mapping=normalized_mapping,
            recovery=(
                "The move failed and rollback was attempted. Inspect the listed "
                "source and target before retrying."
            ),
        )
    finally:
        for descriptor in (
            receipt_descriptor,
            target_descriptor,
            staging_descriptor,
            receipt_parent_descriptor,
            target_parent_descriptor,
            source_parent_descriptor,
        ):
            if descriptor is not None:
                os.close(descriptor)

    result = {
        "result": "pass",
        "mechanical_findings": [],
        "semantic_findings": [],
        "human_approval_required": [],
        "coverage": {"unverified": []},
        "controlled_archive": {
            "mapping": normalized_mapping,
            "moved": True,
        },
        "archive_receipt": receipt,
        "receipt_output": str(destination),
        "recovery": receipt["recovery"]["instructions"],
        "preflight": preflight,
    }
    result["normalized_result"] = normalize_archive_result(result)
    return result


def preflight_controlled_archive(
    adapter: dict,
    workspace: Path,
    request: dict,
    receipt_destination: Path,
) -> dict:
    return execute_controlled_archive(
        adapter,
        workspace,
        request,
        receipt_destination,
        read_only=True,
    )


def controlled_archive_command(args: argparse.Namespace) -> int:
    try:
        adapter, missing = load_json_or_missing(Path(args.adapter))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return emit(structured_archive_exception(
            exc,
            phase="adapter-input",
            mapping=None,
        ))
    if missing:
        return emit(missing)
    if not isinstance(adapter, dict):
        return emit(archive_failure(
            result="fail",
            mechanical=[{
                "code": "invalid-adapter",
                "field": "root",
            }],
            unverified=[],
            human_required=[],
            recovery="Provide one adapter JSON object; no file was moved.",
        ))
    adapter_result = validate_live_adapter(adapter, Path(args.workspace))
    if adapter_result["result"] != "pass":
        return emit({
            "result": "fail",
            "mechanical_findings": adapter_result["mechanical_findings"],
            "semantic_findings": [],
            "human_approval_required": [],
            "coverage": {"unverified": []},
            "controlled_archive": {"mapping": None, "moved": False},
            "archive_receipt": None,
            "receipt_output": None,
            "recovery": "Fix adapter findings before requesting controlled archive intake.",
        })
    try:
        request = json.loads(Path(args.request).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        return emit({
            "result": "fail",
            "mechanical_findings": [{
                "code": "invalid-archive-request-file",
                "path": str(args.request),
                "message": str(exc),
            }],
            "semantic_findings": [],
            "human_approval_required": [],
            "coverage": {"unverified": []},
            "controlled_archive": {"mapping": None, "moved": False},
            "archive_receipt": None,
            "receipt_output": None,
            "recovery": "Provide one valid controlled archive request JSON file.",
        })
    if not isinstance(request, dict):
        return emit({
            "result": "fail",
            "mechanical_findings": [{
                "code": "invalid-archive-request",
                "field": "root",
            }],
            "semantic_findings": [],
            "human_approval_required": [],
            "coverage": {"unverified": []},
            "controlled_archive": {"mapping": None, "moved": False},
            "archive_receipt": None,
            "receipt_output": None,
            "recovery": "Provide one controlled archive request object.",
        })
    execution_grant = None
    amendment = None
    original_execution_grant = None
    for field, attribute in (
        ("execution_grant", "execution_grant"),
        ("amendment", "amendment"),
        ("original_execution_grant", "original_execution_grant"),
    ):
        raw_path = getattr(args, attribute, None)
        if raw_path is None:
            continue
        try:
            loaded = json.loads(Path(raw_path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            payload = archive_failure(
                result="fail",
                mechanical=[{
                    "code": f"invalid-archive-{field.replace('_', '-')}-file",
                    "path": str(raw_path),
                    "message": str(exc),
                }],
                unverified=[],
                human_required=[],
                recovery=(
                    "Provide one valid immutable archive authorization input; "
                    "no file was moved."
                ),
            )
            payload["normalized_result"] = normalize_archive_result(payload)
            return emit(payload)
        if not isinstance(loaded, dict):
            payload = archive_failure(
                result="fail",
                mechanical=[{
                    "code": f"invalid-archive-{field.replace('_', '-')}",
                    "field": "root",
                }],
                unverified=[],
                human_required=[],
                recovery=(
                    "Provide one JSON object for the archive authorization "
                    "input; no file was moved."
                ),
            )
            payload["normalized_result"] = normalize_archive_result(payload)
            return emit(payload)
        if field == "execution_grant":
            execution_grant = loaded
        elif field == "amendment":
            amendment = loaded
        else:
            original_execution_grant = loaded
    try:
        payload = execute_controlled_archive(
            adapter,
            Path(args.workspace),
            request,
            Path(args.write_receipt),
            execution_grant=execution_grant,
            amendment=amendment,
            original_execution_grant=original_execution_grant,
            read_only=bool(getattr(args, "preflight", False)),
        )
    except BaseException as exc:
        payload = structured_archive_exception(
            exc,
            phase="execution",
            mapping=(
                request.get("mapping")
                if isinstance(request.get("mapping"), dict)
                else None
            ),
            state_changes={
                "source_moved": False,
                "target_created": False,
                "receipt_created": False,
                "temporary_artifacts": [],
                "recovery_attempted": True,
                "state_requires_inspection": True,
            },
        )
    if "normalized_result" not in payload:
        payload["normalized_result"] = normalize_archive_result(payload)
    return emit(payload)


def _archive_task_preflight_payload(
    adapter: dict,
    workspace: Path,
    manifest: dict,
    *,
    completed_receipts: dict[str, dict] | None = None,
    summary_destination: str | None = None,
    previous_summary: str | None = None,
) -> tuple[dict, list[dict]]:
    normalized, manifest_findings = validate_archive_task_manifest(manifest)
    if normalized is None:
        payload = {
            "schema": "govern-ai-coding.archive-task-preflight.v1",
            "schema_version": "1",
            "result": "fail",
            "phase": "task-preflight",
            "analysis_only": True,
            "execution_approved": False,
            "files_moved": [],
            "atomicity": "none-read-only",
            "task_atomicity": "non-atomic-independent-operations",
            "operation_preflights": [],
            "mechanical_findings": manifest_findings,
            "recovery": (
                "Correct the task manifest; no file was moved and this result "
                "is not execution approval."
            ),
        }
        payload["normalized_result"] = normalize_archive_result(payload)
        return payload, []

    completed_receipts = completed_receipts or {}
    operation_preflights: list[dict] = []
    runtime_operations: list[dict] = []
    for operation in normalized["operations"]:
        request = operation["request"]
        mapping = request.get("mapping", {})
        runtime_operations.append({
            "source": mapping.get("source"),
            "target": mapping.get("target"),
            "receipt": operation["receipt"],
        })
        if operation["id"] in completed_receipts:
            receipt = completed_receipts[operation["id"]]
            operation_preflights.append({
                "result": "pass",
                "phase": "receipt-reconciliation",
                "task_operation_id": operation["id"],
                "request_sha256": canonical_archive_v1_digest(request),
                "mapping": mapping,
                "preflight_sha256": (
                    receipt.get("execution", {})
                    .get("authorization", {})
                    .get("preflight_sha256")
                ),
                "operation": {
                    "source": mapping.get("source"),
                    "target": mapping.get("target"),
                    "receipt": operation["receipt"],
                    "source_sha256": (
                        receipt.get("content", {}).get("before_sha256")
                    ),
                    "source_size": (
                        receipt.get("content", {}).get("source_size")
                    ),
                },
                "completed_receipt_verified": True,
            })
            continue
        operation_preflight = execute_controlled_archive(
            adapter,
            workspace,
            request,
            workspace / operation["receipt"],
            amendment=operation.get("amendment"),
            original_execution_grant=operation.get(
                "original_execution_grant"
            ),
            read_only=True,
        )
        operation_preflight["task_operation_id"] = operation["id"]
        operation_preflights.append(operation_preflight)
    runtime = runtime_capability_report(
        workspace,
        runtime_operations,
        read_only=True,
    )
    payload = global_archive_preflight(
        normalized,
        operation_preflights,
        runtime,
    )
    output_findings: list[dict] = []
    output_binding = {
        "summary_destination": summary_destination,
        "previous_summary": previous_summary,
        "previous_summary_sha256": None,
    }
    resolved_summary = None
    if previous_summary is not None and summary_destination is None:
        output_findings.append({
            "code": "archive-task-summary-predecessor-without-output",
        })
    if summary_destination is not None:
        resolved_summary, summary_findings = resolve_receipt_output_path(
            summary_destination,
            workspace,
            adapter,
        )
        output_findings.extend(summary_findings)
        if resolved_summary is not None:
            if resolved_summary.exists() or resolved_summary.is_symlink():
                output_findings.append({
                    "code": "archive-task-summary-exists",
                    "path": str(resolved_summary),
                })
            if not resolved_summary.parent.is_dir():
                output_findings.append({
                    "code": "archive-task-summary-parent-missing",
                    "path": str(resolved_summary.parent),
                })
            summary_value = (
                resolved_summary.relative_to(workspace).as_posix()
                if resolved_summary.is_relative_to(workspace)
                else str(resolved_summary)
            )
            for operation in normalized["operations"]:
                mapping = operation["request"].get("mapping", {})
                for role, value in (
                    ("source", mapping.get("source")),
                    ("target", mapping.get("target")),
                    ("receipt", operation.get("receipt")),
                ):
                    if (
                        isinstance(value, str)
                        and unicodedata.normalize("NFC", value).casefold()
                        == unicodedata.normalize(
                            "NFC",
                            summary_value,
                        ).casefold()
                    ):
                        output_findings.append({
                            "code": "archive-task-summary-path-alias",
                            "operation": operation["id"],
                            "role": role,
                            "path": summary_value,
                        })
    if previous_summary is not None:
        previous_path, previous_findings = resolve_receipt_output_path(
            previous_summary,
            workspace,
            adapter,
        )
        output_findings.extend(previous_findings)
        if (
            previous_path is None
            or not previous_path.is_file()
            or previous_path.is_symlink()
        ):
            output_findings.append({
                "code": "archive-task-summary-predecessor-unavailable",
                "path": previous_summary,
            })
        else:
            try:
                output_binding["previous_summary_sha256"] = file_digest(
                    previous_path
                )
            except OSError as exc:
                output_findings.append({
                    "code": "archive-task-summary-predecessor-unreadable",
                    "path": previous_summary,
                    "message": str(exc),
                })
    output_binding["resolved_summary_destination"] = (
        str(resolved_summary) if resolved_summary is not None else None
    )
    payload["task_summary_binding"] = output_binding
    payload["mechanical_findings"].extend(output_findings)
    if output_findings:
        payload["result"] = "fail"
    payload["preflight_sha256"] = canonical_archive_v1_digest({
        "base_preflight_sha256": payload["preflight_sha256"],
        "task_summary_binding": output_binding,
        "output_findings": output_findings,
    })
    payload["normalized_result"] = normalize_archive_result(payload)
    return payload, operation_preflights


def _load_archive_task_receipts(
    workspace: Path,
    manifest: dict,
) -> tuple[dict[str, dict], list[dict]]:
    receipts: dict[str, dict] = {}
    findings: list[dict] = []
    operations = manifest.get("operations", [])
    if not isinstance(operations, list):
        return receipts, findings
    for operation in operations:
        if not isinstance(operation, dict):
            continue
        identifier = operation.get("id")
        receipt = operation.get("receipt")
        if not isinstance(identifier, str) or not isinstance(receipt, str):
            continue
        path = workspace / receipt
        if not path.exists():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            findings.append({
                "code": "archive-task-receipt-unreadable",
                "operation": identifier,
                "path": receipt,
                "message": str(exc),
            })
            continue
        if not isinstance(payload, dict):
            findings.append({
                "code": "archive-task-receipt-invalid",
                "operation": identifier,
                "path": receipt,
            })
            continue
        receipts[identifier] = payload
    return receipts, findings


def archive_task_command(args: argparse.Namespace) -> int:
    try:
        adapter, missing = load_json_or_missing(Path(args.adapter))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return emit(structured_archive_exception(
            exc,
            phase="task-adapter-input",
            mapping=None,
        ))
    if missing:
        return emit(missing)
    if not isinstance(adapter, dict):
        return emit({
            "result": "fail",
            "phase": "task-adapter-preflight",
            "mechanical_findings": [{
                "code": "invalid-adapter",
                "field": "root",
            }],
            "files_moved": [],
            "atomicity": "none-read-only",
            "recovery": "Provide one adapter JSON object; no file was moved.",
        })
    adapter_result = validate_live_adapter(adapter, Path(args.workspace))
    if adapter_result["result"] != "pass":
        return emit({
            "result": "fail",
            "phase": "task-adapter-preflight",
            "mechanical_findings": adapter_result["mechanical_findings"],
            "files_moved": [],
            "atomicity": "none-read-only",
            "recovery": (
                "Fix adapter findings before archive task analysis or "
                "execution; no file was moved."
            ),
        })
    workspace = Path(args.workspace).resolve()
    try:
        manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return emit({
            "result": "fail",
            "phase": "task-preflight",
            "mechanical_findings": [{
                "code": "invalid-archive-task-file",
                "path": str(args.manifest),
                "message": str(exc),
            }],
            "files_moved": [],
            "atomicity": "none-read-only",
            "recovery": "Provide one valid archive task manifest; no file was moved.",
        })
    if not isinstance(manifest, dict):
        return emit({
            "result": "fail",
            "phase": "task-preflight",
            "mechanical_findings": [{
                "code": "invalid-archive-task",
                "field": "root",
            }],
            "files_moved": [],
            "atomicity": "none-read-only",
            "recovery": "Provide one archive task object; no file was moved.",
        })

    receipts, receipt_findings = _load_archive_task_receipts(
        workspace,
        manifest,
    )
    provisional_summary = reconcile_archive_task(
        manifest,
        [],
        receipts,
        workspace=workspace,
    )
    completed_ids = {
        item["id"]
        for item in provisional_summary.get("operations", [])
        if item.get("state") == "completed-receipt-verified"
    }
    completed_receipts = {
        identifier: payload
        for identifier, payload in receipts.items()
        if identifier in completed_ids
    }
    if args.archive_task_action == "status":
        preflight, operation_preflights = _archive_task_preflight_payload(
            adapter,
            workspace,
            manifest,
            completed_receipts=completed_receipts,
            summary_destination=getattr(args, "write_summary", None),
            previous_summary=getattr(args, "previous_summary", None),
        )
        summary = reconcile_archive_task(
            manifest,
            operation_preflights,
            receipts,
            workspace=workspace,
        )
        summary["mechanical_findings"].extend(receipt_findings)
        if receipt_findings:
            summary["result"] = "fail"
        summary["preflight"] = preflight
        summary["normalized_result"] = normalize_archive_result(summary)
        return emit(summary)

    preflight, operation_preflights = _archive_task_preflight_payload(
        adapter,
        workspace,
        manifest,
        completed_receipts=completed_receipts,
        summary_destination=getattr(args, "write_summary", None),
        previous_summary=getattr(args, "previous_summary", None),
    )
    if args.archive_task_action == "preflight":
        if receipt_findings:
            preflight["mechanical_findings"].extend(receipt_findings)
            preflight["result"] = "fail"
            preflight["normalized_result"] = normalize_archive_result(preflight)
        return emit(preflight)

    if preflight["result"] != "pass":
        return emit(preflight)
    try:
        grant = json.loads(Path(args.execution_grant).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return emit({
            "result": "fail",
            "phase": "task-execution",
            "mechanical_findings": [{
                "code": "invalid-archive-task-execution-grant-file",
                "path": str(args.execution_grant),
                "message": str(exc),
            }],
            "files_moved": [],
            "atomicity": "non-atomic-independent-operations",
            "recovery": "Provide the exact task execution grant; no pending file was moved.",
        })
    operation_ids = [
        item.get("id")
        for item in manifest.get("operations", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    ]
    _, grant_findings, grant_unverified = validate_task_execution_grant(
        grant if isinstance(grant, dict) else None,
        manifest_digest=preflight["manifest_sha256"],
        preflight_digest=preflight["preflight_sha256"],
        operation_ids=operation_ids,
    )
    if completed_ids:
        grant_findings = [
            finding for finding in grant_findings
            if not (
                finding.get("code") == "archive-task-grant-binding-mismatch"
                and finding.get("field") == "preflight_sha256"
            )
        ]
        operation_grants = (
            grant.get("operation_grants", {})
            if isinstance(grant, dict)
            else {}
        )
        for operation in manifest.get("operations", []):
            identifier = operation.get("id")
            if identifier not in completed_ids:
                continue
            receipt = receipts.get(identifier)
            original = operation_grants.get(identifier)
            receipt_grant_findings = validate_receipt_grant_binding(
                receipt if isinstance(receipt, dict) else {},
                original if isinstance(original, dict) else {},
            )
            for finding in receipt_grant_findings:
                finding["operation"] = identifier
            grant_findings.extend(receipt_grant_findings)
        for operation, current in zip(
            manifest.get("operations", []),
            operation_preflights,
        ):
            if operation.get("id") in completed_ids:
                continue
            original = operation_grants.get(operation.get("id"))
            for field in ("request_sha256", "approval_sha256", "operation"):
                if (
                    not isinstance(original, dict)
                    or original.get(field) != current.get(field)
                ):
                    grant_findings.append({
                        "code": "archive-task-resume-binding-mismatch",
                        "operation": operation.get("id"),
                        "field": field,
                    })
    if grant_findings or grant_unverified:
        return emit({
            "result": "fail" if grant_findings else "unproven",
            "phase": "task-execution",
            "mechanical_findings": grant_findings,
            "coverage": {"unverified": grant_unverified},
            "files_moved": [],
            "atomicity": "non-atomic-independent-operations",
            "recovery": (
                "Provide a task grant bound to this exact manifest, global "
                "preflight, and complete operation set."
            ),
        })

    summary_destination = None
    if args.write_summary:
        summary_destination, summary_findings = resolve_receipt_output_path(
            args.write_summary,
            workspace,
            adapter,
        )
        if (
            summary_destination is not None
            and (
                summary_destination.exists()
                or summary_destination.is_symlink()
            )
        ):
            summary_findings.append({
                "code": "archive-task-summary-exists",
                "path": str(summary_destination),
            })
        if summary_destination is not None and not summary_destination.parent.is_dir():
            summary_findings.append({
                "code": "archive-task-summary-parent-missing",
                "path": str(summary_destination.parent),
            })
        if summary_findings or summary_destination is None:
            return emit({
                "result": "fail",
                "phase": "task-execution-preflight",
                "mechanical_findings": summary_findings,
                "files_moved": [],
                "atomicity": "none-read-only",
                "task_atomicity": "non-atomic-independent-operations",
                "recovery": (
                    "Choose one unused persistent task-summary destination; "
                    "no file was moved."
                ),
            })

    operation_grants = grant["operation_grants"]
    results: list[dict] = []
    for operation in manifest["operations"]:
        identifier = operation["id"]
        if identifier in completed_ids:
            results.append({
                "id": identifier,
                "state": "completed-receipt-verified",
                "skipped": True,
            })
            continue
        original_operation_grant = operation_grants.get(identifier)
        current_preflight = execute_controlled_archive(
            adapter,
            workspace,
            operation["request"],
            workspace / operation["receipt"],
            amendment=operation.get("amendment"),
            original_execution_grant=operation.get(
                "original_execution_grant"
            ),
            read_only=True,
        )
        refreshed_operation_grant = original_operation_grant
        if (
            current_preflight.get("result") == "pass"
            and isinstance(original_operation_grant, dict)
            and original_operation_grant.get("request_sha256")
            == current_preflight.get("request_sha256")
            and original_operation_grant.get("approval_sha256")
            == current_preflight.get("approval_sha256")
            and original_operation_grant.get("operation")
            == current_preflight.get("operation")
        ):
            refreshed_operation_grant = json.loads(
                json.dumps(original_operation_grant)
            )
            refreshed_operation_grant["preflight_sha256"] = (
                current_preflight["preflight_sha256"]
            )
        try:
            result = execute_controlled_archive(
                adapter,
                workspace,
                operation["request"],
                workspace / operation["receipt"],
                execution_grant=refreshed_operation_grant,
                amendment=operation.get("amendment"),
                original_execution_grant=operation.get(
                    "original_execution_grant"
                ),
            )
        except BaseException as exc:
            result = structured_archive_exception(
                exc,
                phase="task-operation-execution",
                mapping=operation["request"].get("mapping"),
                state_changes={
                    "source_moved": False,
                    "target_created": False,
                    "receipt_created": False,
                    "temporary_artifacts": [],
                    "recovery_attempted": True,
                    "state_requires_inspection": True,
                },
            )
        state_changes = result.get("controlled_archive", {}).get(
            "state_changes",
            {},
        )
        outcome_requires_inspection = (
            isinstance(state_changes, dict)
            and state_changes.get("state_requires_inspection") is True
        )
        results.append({
            "id": identifier,
            "state": (
                "completed-receipt-verified"
                if result.get("result") == "pass"
                else "execution-outcome-unknown"
                if outcome_requires_inspection
                else "execution-failed"
            ),
            "skipped": False,
            "result": result,
        })
        if result.get("result") != "pass":
            break

    refreshed_receipts, refreshed_findings = _load_archive_task_receipts(
        workspace,
        manifest,
    )
    summary = reconcile_archive_task(
        manifest,
        operation_preflights,
        refreshed_receipts,
        workspace=workspace,
    )
    summary["execution_results"] = results
    execution_states = {
        item["id"]: item["state"]
        for item in results
        if isinstance(item, dict)
    }
    for item in summary["operations"]:
        execution_state = execution_states.get(item["id"])
        if execution_state == "execution-failed":
            item["state"] = "execution-failed"
            item["authorization_state"] = "exact-grant-bound"
            item["resumable"] = True
        elif execution_state == "execution-outcome-unknown":
            item["state"] = "execution-outcome-unknown"
            item["authorization_state"] = "outcome-reconciliation-required"
            item["resumable"] = False
            item["recovery_actions"] = [
                (
                    "Run archive-task status as a read-only reconciliation; "
                    "retry only after it proves this operation did not complete."
                )
            ]
    summary["mechanical_findings"].extend(refreshed_findings)
    unknown_outcome = any(
        item.get("state") == "execution-outcome-unknown"
        for item in summary["operations"]
    )
    summary["result"] = (
        "unproven"
        if unknown_outcome
        else "pass"
        if all(
            item.get("state") == "completed-receipt-verified"
            for item in summary["operations"]
        )
        else "fail"
    )
    if unknown_outcome:
        summary["recovery"] = (
            "Run archive-task status as a read-only reconciliation. Retry only "
            "if it proves the source remains unchanged and the target and "
            "receipt were not created; otherwise preserve the observed state "
            "and resolve its findings without re-execution."
        )
    summary["authorization_state"] = "exact-task-grant-bound"
    summary["global_preflight_sha256"] = preflight["preflight_sha256"]
    summary["task_grant_sha256"] = canonical_archive_v1_digest(grant)
    summary["previous_summary_sha256"] = preflight.get(
        "task_summary_binding",
        {},
    ).get("previous_summary_sha256")
    summary["receipt_bindings"] = []
    verified_operation_ids = {
        item.get("id")
        for item in summary["operations"]
        if item.get("state") == "completed-receipt-verified"
    }
    for operation in manifest["operations"]:
        if operation["id"] not in verified_operation_ids:
            continue
        receipt_path = workspace / operation["receipt"]
        if receipt_path.is_file() and not receipt_path.is_symlink():
            summary["receipt_bindings"].append({
                "operation": operation["id"],
                "path": operation["receipt"],
                "sha256": file_digest(receipt_path),
            })
    summary["execution_results"] = compact_archive_task_execution_results(
        results,
        summary["receipt_bindings"],
    )
    summary["execution_results_mode"] = "receipt-references-for-success"
    summary["normalized_result"] = normalize_archive_result(summary)
    if summary_destination is not None:
        try:
            atomic_write_json(summary, summary_destination, overwrite=False)
            summary["summary_output"] = str(summary_destination)
        except (OSError, TypeError, ValueError) as exc:
            summary["mechanical_findings"].append({
                "code": "archive-task-summary-write-failed",
                "path": str(summary_destination),
                "message": str(exc),
            })
            summary["result"] = "fail"
    summary["normalized_result"] = normalize_archive_result(summary)
    return emit(summary)


def archive_authorization_status_command(args: argparse.Namespace) -> int:
    adapter, missing = load_json_or_missing(Path(args.adapter))
    if missing:
        return emit(missing)
    validation = validate_live_adapter(adapter, Path(args.workspace))
    if validation["result"] != "pass":
        return emit({
            "result": "fail",
            "mechanical_findings": validation["mechanical_findings"],
            "semantic_findings": [],
            "human_approval_required": [],
            "authorization_lifecycle": None,
            "recovery": (
                "Fix adapter and root navigation entrypoint findings before "
                "reading archive authorization lifecycle status."
            ),
        })
    payload = archive_authorization_lifecycle(
        adapter,
        Path(args.workspace).resolve(),
        authorization_id=args.authorization_id,
    )
    payload["normalized_result"] = normalize_archive_result(payload)
    return emit(payload)


def normalize_archive_result_command(args: argparse.Namespace) -> int:
    try:
        payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return emit({
            "schema": "govern-ai-coding.normalized-result.v1",
            "schema_version": "1",
            "verdict": "unproven",
            "phase": "parsing",
            "operation_state": "unreadable",
            "changed": False,
            "atomicity": "unknown",
            "authorization_state": "unknown",
            "receipt_bindings": [],
            "diagnostics": [{
                "code": "result-input-unreadable",
                "message": str(exc),
            }],
            "recovery": "Provide one readable JSON result or receipt.",
        })
    return emit(normalize_archive_result(payload))


def freeze_command(args: argparse.Namespace) -> int:
    manifest, manifest_findings = prepare_event_manifest(args, phase="freeze")
    manifest_expected_digest = (
        args.event_manifest_expected_digest
        if event_manifest_is_v2(manifest)
        else None
    )
    adapter, missing = load_json_or_missing(Path(args.adapter))
    if missing:
        missing["freeze_receipt"] = None
        return emit(missing)
    adapter_result = validate_live_adapter(adapter, Path(args.workspace))
    if adapter_result["result"] == "fail":
        return emit({
            "result": "fail",
            "freeze_receipt": None,
            "mechanical_findings": adapter_result["mechanical_findings"],
            "semantic_findings": [],
            "human_approval_required": [],
            "recovery": "Freeze cannot run until the project adapter validates.",
        })

    workspace = Path(args.workspace).resolve()
    if manifest is not None:
        manifest, contextual_findings = validate_event_manifest(
            manifest,
            manifest_path=Path(args.event_manifest),
            workspace=workspace,
            adapter=adapter,
        )
        manifest_findings.extend(contextual_findings)
    snapshots, findings = snapshot_declared_paths(workspace, args.changed_path)
    findings.extend(manifest_findings)
    if not args.changed_path:
        findings.append({"code": "empty-freeze-scope"})
    receipt = {
        "schema": FREEZE_RECEIPT_SCHEMA,
        "kind": "final-content-freeze",
        "adapter": {
            "project": adapter.get("project"),
            "schema_version": adapter.get("schema_version"),
        },
        "workspace": {"path": str(workspace)},
        "paths": snapshots,
        "derived_evidence": True,
        "generated": True,
        "project_authority": False,
        "capability": {
            "proves": ["existence and SHA-256 fingerprints for declared paths at freeze time"],
            "does_not_prove": ["that project validation ran", "which actor changed a path"],
        },
        "recovery": "Run project-selected final validation, then pass this receipt to live Closeout with --freeze-receipt.",
    }
    git_commit = _attested_final_git_commit(workspace, snapshots)
    if git_commit is not None:
        receipt["git_commit"] = git_commit
    output_path = None
    if not findings:
        output_path, write_findings = write_receipt_file(
            receipt,
            args.write_receipt,
            workspace,
            adapter,
        )
        findings.extend(write_findings)
    if manifest is not None and not findings:
        manifest["scope"]["actual_event_paths"] = sorted(set(args.changed_path))
        manifest["receipts"]["freeze"] = receipt
        validation_receipts = list(manifest["receipts"].get("validation", []))
        validation_receipts.extend(getattr(args, "validation_receipt", []) or [])
        manifest["receipts"]["validation"] = sorted(
            set(validation_receipts),
        )
        findings.extend(
            write_event_manifest(
                manifest,
                args.event_manifest,
                workspace,
                adapter,
                expected_digest=manifest_expected_digest,
            )
        )
    return emit({
        "result": "fail" if findings else "pass",
        "freeze_receipt": receipt,
        "receipt_output": output_path,
        "mechanical_findings": findings,
        "semantic_findings": [],
        "human_approval_required": [],
        "recovery": "Fix mechanical findings before validation." if findings else receipt["recovery"],
    })


def inventory_entry_paths(entry: dict) -> list[str]:
    if entry.get("kind") == "renamed":
        return [entry["old_path"], entry["new_path"]]
    return [entry["path"]]


def inventory_event_paths(entries: list[dict]) -> list[str]:
    paths = []
    for entry in entries:
        paths.extend(inventory_entry_paths(entry))
    return sorted(set(paths))


def scan_filesystem_inventory(
    workspace: Path,
    adapter: dict,
    *,
    source_kind: str = "filesystem",
    extra_excluded: list[str] | None = None,
) -> tuple[dict, list[dict]]:
    workspace = workspace.resolve()
    excluded_patterns = list(safe_section(adapter, "boundaries").get("excluded", []))
    excluded_patterns.extend(extra_excluded or [])
    normalized_excluded, excluded_findings = normalize_paths_with_findings(excluded_patterns, "excluded")
    findings = list(excluded_findings)
    entries = []

    for path in sorted(workspace.rglob("*")):
        if path.is_dir():
            continue
        try:
            relative = path.relative_to(workspace).as_posix()
        except ValueError:
            continue
        normalized, finding = normalize_path_value(relative, "inventory.path")
        if finding:
            findings.append(finding)
            continue
        if any(path_matches(normalized, pattern) for pattern in normalized_excluded):
            continue
        if path.is_symlink():
            target = path.resolve()
            try:
                target.relative_to(workspace)
            except ValueError:
                findings.append({"code": "symlink-target-outside-workspace", "path": normalized})
                continue
            digest = f"symlink:{target.relative_to(workspace).as_posix()}"
        else:
            try:
                digest = file_digest(path)
            except OSError as exc:
                findings.append({"code": "unreadable-inventory-path", "path": normalized, "message": str(exc)})
                continue
        entries.append({
            "path": normalized,
            "existence": True,
            "digest": digest,
            "inventory_source": source_kind,
            "verified": True,
            "metadata": {},
        })

    return {
        "schema": "govern-ai-coding.inventory.v1",
        "source": {"kind": source_kind, "verified": not findings},
        "entries": entries,
    }, findings


def inventory_exclusion_patterns(
    adapter: dict,
    extra_excluded: list[str] | None = None,
) -> tuple[list[str], list[dict]]:
    configured = list(safe_section(adapter, "boundaries").get("excluded", []))
    return normalize_paths_with_findings(
        DEFAULT_INVENTORY_EXCLUDES + configured + list(extra_excluded or []),
        "excluded",
    )


def inventory_path_is_excluded(path: str, patterns: list[str]) -> bool:
    path_components = set(path.split("/"))
    return any(
        path_matches(path, pattern)
        or (
            pattern.rstrip("/") in DEFAULT_INVENTORY_EXCLUDE_COMPONENTS
            and pattern.rstrip("/") in path_components
        )
        for pattern in patterns
    )


def inventory_path_is_suppressed(path: str, patterns: list[str]) -> bool:
    return any(
        path_matches(path, pattern) or path_matches(pattern, path)
        for pattern in patterns
    )


def workspace_relative_output_path(
    output_path: str | None,
    workspace: Path,
) -> str | None:
    if not output_path:
        return None
    lexical_workspace = Path(os.path.abspath(workspace))
    raw_destination = Path(output_path)
    if not raw_destination.is_absolute():
        raw_destination = lexical_workspace / raw_destination
    lexical_destination = Path(os.path.abspath(raw_destination))
    try:
        relative = lexical_destination.relative_to(lexical_workspace).as_posix()
    except ValueError:
        return None
    normalized, finding = normalize_path_value(relative, "output_path")
    return None if finding else normalized


def snapshot_git_paths(
    workspace: Path,
    paths: list[str],
    *,
    source_kind: str,
    dirty_paths: set[str],
) -> tuple[list[dict], list[dict]]:
    workspace = workspace.resolve()
    entries: list[dict] = []
    findings: list[dict] = []
    for raw_path in sorted(set(paths)):
        path, finding = normalize_path_value(raw_path, "git.path")
        if finding:
            findings.append(finding)
            continue
        target = workspace / path
        if target.is_symlink():
            resolved = target.resolve()
            try:
                relative_target = resolved.relative_to(workspace).as_posix()
            except ValueError:
                findings.append({
                    "code": "symlink-target-outside-workspace",
                    "path": path,
                })
                continue
            exists = True
            digest = f"symlink:{relative_target}"
        elif target.exists():
            if not target.is_file():
                findings.append({"code": "inventory-path-not-file", "path": path})
                continue
            exists = True
            try:
                digest = file_digest(target)
            except OSError as exc:
                findings.append({
                    "code": "unreadable-inventory-path",
                    "path": path,
                    "message": str(exc),
                })
                continue
        else:
            exists = False
            digest = None
        entries.append({
            "path": path,
            "existence": exists,
            "digest": digest,
            "inventory_source": source_kind,
            "verified": True,
            "metadata": {"dirty_at_baseline": True} if path in dirty_paths else {},
        })
    return entries, findings


def inventory_map(inventory: dict) -> dict[str, dict]:
    result = {}
    for entry in inventory.get("entries", []) or []:
        if not isinstance(entry, dict):
            continue
        path, finding = normalize_path_value(str(entry.get("path", "")), "inventory.path")
        if finding or not path:
            continue
        normalized = dict(entry)
        normalized["path"] = path
        result[path] = normalized
    return result


def compare_inventories(
    baseline: dict,
    final: dict,
    *,
    excluded_patterns: list[str] | None = None,
) -> tuple[list[dict], list[str]]:
    before = inventory_map(baseline)
    after = inventory_map(final)
    if excluded_patterns:
        before = {
            path: entry
            for path, entry in before.items()
            if not inventory_path_is_excluded(path, excluded_patterns)
        }
        after = {
            path: entry
            for path, entry in after.items()
            if not inventory_path_is_excluded(path, excluded_patterns)
        }
    paths = sorted(set(before) | set(after))
    changes = []
    pre_existing_unchanged = []
    for path in paths:
        old = before.get(path)
        new = after.get(path)
        if old and not new:
            changes.append({
                "path": path,
                "kind": "deleted",
                "existence": False,
                "digest": old.get("digest"),
                "inventory_source": final.get("source", {}).get("kind", "inventory"),
                "verified": final.get("source", {}).get("verified", True),
                "metadata": {"dirty_at_baseline": bool((old.get("metadata") or {}).get("dirty_at_baseline"))},
            })
        elif new and not old:
            changes.append({
                "path": path,
                "kind": "added",
                "existence": True,
                "digest": new.get("digest"),
                "inventory_source": final.get("source", {}).get("kind", "inventory"),
                "verified": final.get("source", {}).get("verified", True),
                "metadata": {},
            })
        elif old and new and old.get("digest") != new.get("digest"):
            changes.append({
                "path": path,
                "kind": "modified",
                "existence": True,
                "digest": new.get("digest"),
                "inventory_source": final.get("source", {}).get("kind", "inventory"),
                "verified": final.get("source", {}).get("verified", True),
                "metadata": {"dirty_at_baseline": bool((old.get("metadata") or {}).get("dirty_at_baseline"))},
            })
        elif old and new:
            if (old.get("metadata") or {}).get("dirty_at_baseline"):
                pre_existing_unchanged.append(path)
    return changes, pre_existing_unchanged


def load_inventory_file(path: str | None) -> tuple[dict | None, list[dict]]:
    if not path:
        return None, []
    try:
        inventory = load_json(Path(path))
    except FileNotFoundError:
        return None, [{"code": "inventory-file-missing", "path": path}]
    findings = validate_inventory(inventory)
    return (None, findings) if findings else (inventory, [])


def make_actual_inventory(paths: list[str], source_kind: str) -> tuple[dict, list[dict]]:
    normalized, findings = normalize_paths_with_findings(paths, "actual_path")
    entries = [
        {
            "path": path,
            "kind": "modified",
            "existence": True,
            "digest": None,
            "inventory_source": source_kind,
            "verified": True,
            "metadata": {},
        }
        for path in normalized
    ]
    return {
        "schema": "govern-ai-coding.inventory.v1",
        "source": {"kind": source_kind, "verified": not findings},
        "entries": entries,
    }, findings


def git_status_inventory(
    workspace: Path,
    adapter: dict | None = None,
    *,
    extra_excluded: list[str] | None = None,
    suppressed_paths: list[str] | None = None,
) -> tuple[dict, list[dict]]:
    try:
        subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=workspace,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        return {
            "schema": "govern-ai-coding.inventory.v1",
            "source": {"kind": "git", "verified": False},
            "entries": [],
        }, [{"code": "git-change-source-unavailable", "message": str(exc)}]

    completed = subprocess.run(
        [
            "git",
            "status",
            "--porcelain=v2",
            "-z",
            "--untracked-files=all",
            "--ignored=matching",
        ],
        cwd=workspace,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    fields = completed.stdout.decode("utf-8", errors="surrogateescape").split("\0")
    entries: list[dict] = []
    findings: list[dict] = []
    exclusions, exclusion_findings = inventory_exclusion_patterns(
        adapter or {},
        extra_excluded,
    )
    findings.extend(exclusion_findings)
    classifications: dict[str, set[str]] = {
        "tracked_changes": set(),
        "staged": set(),
        "unstaged": set(),
        "eligible_untracked": set(),
        "ignored": set(),
        "excluded": set(),
    }
    normalized_suppressed, suppressed_findings = normalize_paths_with_findings(
        list(suppressed_paths or []),
        "suppressed_path",
    )
    findings.extend(suppressed_findings)
    index = 0
    while index < len(fields):
        record = fields[index]
        index += 1
        if not record:
            continue
        record_type = record[0]
        if record_type in {"?", "!"}:
            path, finding = normalize_path_value(record[2:], "git.path")
            if finding:
                findings.append(finding)
                continue
            if inventory_path_is_suppressed(path, normalized_suppressed):
                continue
            if record_type == "!":
                classifications["ignored"].add(path)
                continue
            if inventory_path_is_excluded(path, exclusions):
                classifications["excluded"].add(path)
                continue
            classifications["eligible_untracked"].add(path)
            entries.append({
                "path": path,
                "kind": "added",
                "existence": True,
                "digest": None,
                "inventory_source": "git",
                "verified": True,
                "metadata": {"status": "??"},
            })
            continue

        if record_type not in {"1", "2", "u"}:
            findings.append({"code": "unknown-git-status-record", "record": record_type})
            continue
        field_limit = 9 if record_type == "2" else 8
        parts = record.split(" ", field_limit)
        if len(parts) <= field_limit:
            findings.append({"code": "malformed-git-status-record", "record": record_type})
            continue
        status = parts[1]
        raw_path = parts[field_limit]
        path, finding = normalize_path_value(raw_path, "git.path")
        if finding:
            findings.append(finding)
            continue

        old_path = None
        if record_type == "2":
            raw_old = fields[index] if index < len(fields) else ""
            index += 1
            old_path, old_finding = normalize_path_value(raw_old, "git.old_path")
            if old_finding:
                findings.append(old_finding)
                continue

        event_paths = [path] + ([old_path] if old_path else [])
        if any(
            inventory_path_is_suppressed(item, normalized_suppressed)
            for item in event_paths
        ):
            continue
        if any(inventory_path_is_excluded(item, exclusions) for item in event_paths):
            classifications["excluded"].update(event_paths)
            continue
        classifications["tracked_changes"].update(event_paths)
        if status[0] != ".":
            classifications["staged"].update(event_paths)
        if status[1] != ".":
            classifications["unstaged"].update(event_paths)

        if record_type == "2":
            entry = {
                "path": path,
                "kind": "renamed",
                "old_path": old_path,
                "new_path": path,
                "existence": True,
                "digest": None,
                "inventory_source": "git",
                "verified": True,
                "metadata": {"status": status},
            }
        elif "D" in status:
            entry = {
                "path": path,
                "kind": "deleted",
                "existence": False,
                "digest": None,
                "inventory_source": "git",
                "verified": True,
                "metadata": {"status": status},
            }
        else:
            entry = {
                "path": path,
                "kind": "modified",
                "existence": True,
                "digest": None,
                "inventory_source": "git",
                "verified": True,
                "metadata": {"status": status},
            }
        entries.append(entry)

    head = subprocess.run(
        ["git", "rev-parse", "--verify", "HEAD"],
        cwd=workspace,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return {
        "schema": "govern-ai-coding.inventory.v1",
        "source": {
            "kind": "git",
            "verified": not findings,
            "metadata": {
                "head": head.stdout.strip() if head.returncode == 0 else None,
                "classifications": {
                    key: sorted(values)
                    for key, values in classifications.items()
                },
            },
        },
        "entries": entries,
    }, findings


def scan_git_baseline_inventory(
    workspace: Path,
    adapter: dict,
    *,
    source_kind: str,
    extra_excluded: list[str] | None = None,
    suppressed_paths: list[str] | None = None,
) -> tuple[dict, list[dict]]:
    workspace = workspace.resolve()
    status_inventory, findings = git_status_inventory(
        workspace,
        adapter,
        extra_excluded=extra_excluded,
        suppressed_paths=suppressed_paths,
    )
    if findings:
        return {
            "schema": INVENTORY_SCHEMA,
            "source": {
                "kind": source_kind,
                "verified": False,
                "metadata": status_inventory.get("source", {}).get("metadata", {}),
            },
            "entries": [],
        }, findings

    completed = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=workspace,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    raw_paths = completed.stdout.decode(
        "utf-8",
        errors="surrogateescape",
    ).split("\0")
    exclusions, exclusion_findings = inventory_exclusion_patterns(
        adapter,
        extra_excluded,
    )
    findings.extend(exclusion_findings)
    normalized_suppressed, suppressed_findings = normalize_paths_with_findings(
        list(suppressed_paths or []),
        "suppressed_path",
    )
    findings.extend(suppressed_findings)
    eligible_paths: list[str] = []
    excluded = set(
        status_inventory.get("source", {})
        .get("metadata", {})
        .get("classifications", {})
        .get("excluded", [])
    )
    for raw_path in raw_paths:
        if not raw_path:
            continue
        path, finding = normalize_path_value(raw_path, "git.path")
        if finding:
            findings.append(finding)
            continue
        if inventory_path_is_suppressed(path, normalized_suppressed):
            continue
        if inventory_path_is_excluded(path, exclusions):
            excluded.add(path)
            continue
        eligible_paths.append(path)

    dirty_paths = set(inventory_event_paths(status_inventory.get("entries", [])))
    entries, snapshot_findings = snapshot_git_paths(
        workspace,
        eligible_paths,
        source_kind=source_kind,
        dirty_paths=dirty_paths,
    )
    findings.extend(snapshot_findings)
    metadata = dict(status_inventory.get("source", {}).get("metadata", {}))
    metadata.setdefault("classifications", {})["excluded"] = sorted(excluded)
    return {
        "schema": INVENTORY_SCHEMA,
        "source": {
            "kind": source_kind,
            "verified": not findings,
            "metadata": metadata,
        },
        "entries": entries,
    }, findings


def git_changed_paths(workspace: Path) -> tuple[list[str], dict | None]:
    inventory, findings = git_status_inventory(workspace)
    if findings:
        return [], findings[0]
    return inventory_event_paths(inventory.get("entries", [])), None


def change_verification(
    workspace: Path,
    declared_paths: list[str],
    actual_paths: list[str],
    change_source: str,
    *,
    change_entries: list[dict] | None = None,
    event_isolation_verified: bool = False,
    source_metadata: dict | None = None,
) -> tuple[dict, list[dict]]:
    declared, declared_findings = normalize_paths_with_findings(declared_paths, "changed_path")
    requested_actual, actual_findings = normalize_paths_with_findings(actual_paths, "actual_path")
    findings = declared_findings + actual_findings

    if change_entries is not None:
        actual = inventory_event_paths(change_entries)
        source = change_source
        verified = True
    elif change_source == "supplied" or (change_source == "auto" and requested_actual):
        actual = requested_actual
        source = "supplied"
        verified = True
    elif change_source in {"git", "auto"}:
        actual, git_error = git_changed_paths(workspace)
        if git_error:
            if change_source == "git":
                findings.append(git_error)
                actual = []
                source = "git"
                verified = False
            else:
                actual = declared
                source = "explicit"
                verified = False
        else:
            source = "git"
            verified = True
    else:
        actual = declared
        source = "explicit"
        verified = False

    if verified:
        undeclared = sorted(set(actual) - set(declared))
        not_actual = sorted(set(declared) - set(actual))
        for path in undeclared:
            findings.append({"code": "actual-path-not-declared", "path": path, "source": source})
        for path in not_actual:
            findings.append({"code": "declared-path-not-actually-changed", "path": path, "source": source})

    return {
        "source": source,
        "verified": verified,
        "declared_paths": declared,
        "actual_paths": actual,
        "event_isolation_verified": event_isolation_verified,
        "source_metadata": source_metadata or {},
        "unverified_reason": None if verified else "actual changed paths were not independently verified",
    }, findings


def resolve_change_inventory(
    adapter: dict,
    workspace: Path,
    args: argparse.Namespace | None,
    *,
    changed_paths: list[str],
    actual_paths: list[str],
    change_source: str,
) -> tuple[list[dict] | None, list[str], dict | None, list[dict], bool, str, dict]:
    findings: list[dict] = []
    pre_existing_unchanged: list[str] = []
    receipt = None
    event_isolation_verified = False
    source_metadata: dict = {}
    extra_excluded: list[str] = []

    receipt_path = getattr(args, "receipt", None) if args else None
    manifest_receipt = getattr(args, "impact_receipt_payload", None) if args else None
    if manifest_receipt is not None:
        receipt, extract_findings = extract_impact_receipt(manifest_receipt)
        findings.extend(extract_findings)
    elif receipt_path:
        try:
            receipt_file = Path(receipt_path)
            loaded_receipt = load_json(receipt_file)
            receipt, extract_findings = extract_impact_receipt(loaded_receipt)
            findings.extend(extract_findings)
            try:
                extra_excluded.append(str(receipt_file.resolve().relative_to(workspace.resolve())))
            except ValueError:
                pass
        except FileNotFoundError:
            findings.append({"code": "receipt-missing", "path": receipt_path})
        except SystemExit:
            findings.append({"code": "malformed-impact-receipt", "path": receipt_path, "field": "json"})

    if receipt is not None:
        receipt_findings = validate_impact_receipt(receipt, adapter, workspace)
        findings.extend(receipt_findings)
        if receipt_findings:
            receipt = None

    freeze_receipt_path = getattr(args, "freeze_receipt", None) if args else None
    if freeze_receipt_path:
        try:
            freeze_file = Path(freeze_receipt_path)
            extra_excluded.append(str(freeze_file.resolve().relative_to(workspace.resolve())))
        except ValueError:
            pass

    baseline_inventory = None
    final_inventory = None
    if receipt and isinstance(receipt.get("baseline_inventory"), dict):
        baseline_inventory = receipt["baseline_inventory"]
        change_source = receipt.get("inventory_source", {}).get("kind", change_source)
        source_metadata.update(receipt.get("inventory_source", {}).get("metadata", {}))

    if args:
        loaded, load_findings = load_inventory_file(getattr(args, "baseline_inventory", None))
        findings.extend(load_findings)
        if loaded:
            baseline_inventory = loaded
            change_source = loaded.get("source", {}).get("kind", change_source)
        loaded, load_findings = load_inventory_file(getattr(args, "final_inventory", None))
        findings.extend(load_findings)
        if loaded:
            final_inventory = loaded

    if baseline_inventory and not final_inventory:
        if change_source == "git":
            final_inventory, scan_findings = scan_git_baseline_inventory(
                workspace,
                adapter,
                source_kind="git-final",
                extra_excluded=extra_excluded,
                suppressed_paths=extra_excluded,
            )
            findings.extend(scan_findings)
        elif change_source == "filesystem":
            final_inventory, scan_findings = scan_filesystem_inventory(
                workspace,
                adapter,
                source_kind=f"{change_source}-final",
                extra_excluded=extra_excluded,
            )
            findings.extend(scan_findings)
        elif change_source == "supplied":
            findings.append({"code": "missing-final-inventory", "source": "supplied"})

    if baseline_inventory and final_inventory:
        comparison_exclusions, exclusion_findings = inventory_exclusion_patterns(
            adapter,
            extra_excluded,
        )
        findings.extend(exclusion_findings)
        change_entries, pre_existing_unchanged = compare_inventories(
            baseline_inventory,
            final_inventory,
            excluded_patterns=comparison_exclusions,
        )
        event_isolation_verified = True
        source_metadata.update(final_inventory.get("source", {}).get("metadata", {}))
        return change_entries, pre_existing_unchanged, receipt, findings, event_isolation_verified, change_source, source_metadata

    if change_source == "filesystem":
        inventory, scan_findings = scan_filesystem_inventory(workspace, adapter, source_kind="filesystem")
        findings.extend(scan_findings)
        entries = inventory.get("entries", [])
        return entries, [], receipt, findings, False, "filesystem", inventory.get("source", {}).get("metadata", {})

    if change_source in {"git", "auto"}:
        inventory, git_findings = git_status_inventory(workspace, adapter)
        if not git_findings:
            entries = [
                entry
                for entry in inventory.get("entries", [])
                if not any(
                    path_matches(path, excluded_receipt)
                    for path in inventory_entry_paths(entry)
                    for excluded_receipt in extra_excluded
                )
            ]
            return entries, [], receipt, findings, False, "git", inventory.get("source", {}).get("metadata", {})
        if change_source == "git":
            findings.extend(git_findings)
            return [], [], receipt, findings, False, "git", {}

    if change_source == "supplied" or actual_paths:
        inventory, actual_findings = make_actual_inventory(actual_paths, "supplied")
        findings.extend(actual_findings)
        entries = inventory.get("entries", [])
        return entries, [], receipt, findings, False, "supplied", {}

    return None, [], receipt, findings, False, "explicit", {}


def parse_protected_approvals(bindings: list[str]) -> tuple[list[dict], list[dict]]:
    approvals = []
    findings = []
    seen = set()
    for binding in bindings:
        if "=" not in binding:
            findings.append({"code": "invalid-protected-approval", "value": binding})
            continue
        path, evidence = (part.strip().rstrip("/") for part in binding.split("=", 1))
        if not path or not evidence:
            findings.append({"code": "invalid-protected-approval", "value": binding})
            continue
        if path in seen:
            findings.append({"code": "duplicate-protected-approval", "path": path})
            continue
        seen.add(path)
        approvals.append({"path": path, "evidence": evidence})
    return approvals, findings


def parse_human_approvals(bindings: list[str]) -> tuple[list[dict], list[dict]]:
    approvals = []
    findings = []
    seen = set()
    for binding in bindings:
        if "=" not in binding:
            findings.append({"code": "invalid-human-approval", "value": binding})
            continue
        approval_type, evidence = (part.strip().rstrip("/") for part in binding.split("=", 1))
        if not approval_type or not evidence:
            findings.append({"code": "invalid-human-approval", "value": binding})
            continue
        key = (approval_type, evidence)
        if key in seen:
            findings.append({"code": "duplicate-human-approval", "type": approval_type, "evidence": evidence})
            continue
        seen.add(key)
        approvals.append({"type": approval_type, "evidence": evidence})
    return approvals, findings


def text_words(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", text.lower()))


def path_scope_tokens(path: str) -> set[str]:
    words = text_words(Path(path).as_posix())
    return {word for word in words if len(word) >= 3 and not word.isdigit()}


HUMAN_APPROVAL_FIELDS = (
    "approval type",
    "object",
    "scope",
    "does not approve",
)


def parse_human_approval_blocks(text: str) -> list[dict]:
    records: list[dict] = []
    current: dict | None = None
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        field = key.strip().lower()
        field_value = value.strip()
        if field == "approval type":
            if current is not None:
                records.append(current)
            current = {
                "fields": {field: field_value},
                "ambiguous_fields": [],
                "sealed": False,
            }
            continue
        if (
            current is None
            or current["sealed"]
            or field not in HUMAN_APPROVAL_FIELDS
        ):
            continue
        if field in current["fields"]:
            if field not in current["ambiguous_fields"]:
                current["ambiguous_fields"].append(field)
            continue
        current["fields"][field] = field_value
        current["sealed"] = all(
            current["fields"].get(required_field)
            for required_field in HUMAN_APPROVAL_FIELDS
        )
    if current is not None:
        records.append(current)
    return records


def human_approval_evidence_finding(
    code: str,
    message: str,
    recovery: str,
    **fields: object,
) -> dict:
    return {
        "code": code,
        **fields,
        "diagnostic": {
            "severity": "blocking",
            "category": "approval_evidence",
            "message": message,
            "recovery_actions": [recovery],
        },
    }


def evaluate_human_approval_evidence(
    text: str,
    approval_type: str,
    targets: list[str],
) -> dict | None:
    normalized_type = approval_type.rstrip(". ").casefold()
    candidates = [
        record
        for record in parse_human_approval_blocks(text)
        if record["fields"].get("approval type", "").rstrip(". ").casefold()
        == normalized_type
    ]
    if not candidates:
        return human_approval_evidence_finding(
            "human-approval-type-not-recorded",
            "No approval block records the exact bound approval type.",
            "Add one complete block for the exact bound approval type to the in-event evidence, then rerun Closeout.",
            type=approval_type,
            targets=targets,
        )

    complete = [
        record
        for record in candidates
        if record["sealed"] and not record["ambiguous_fields"]
    ]
    for record in complete:
        object_scope = record["fields"]["object"]
        if all(
            re.search(
                rf"(?<![A-Za-z0-9_./-]){re.escape(target)}"
                rf"(?![A-Za-z0-9_/-]|\.[A-Za-z0-9_/-])",
                object_scope,
            )
            for target in targets
        ):
            return None

    ambiguous_fields = sorted({
        field
        for record in candidates
        for field in record["ambiguous_fields"]
    })
    if ambiguous_fields:
        return human_approval_evidence_finding(
            "human-approval-block-ambiguous",
            "A matching approval block contains repeated protocol fields.",
            "Remove or disambiguate repeated fields within one matching approval block, then rerun Closeout.",
            type=approval_type,
            targets=targets,
            ambiguous_fields=ambiguous_fields,
        )
    if complete:
        return human_approval_evidence_finding(
            "human-approval-target-not-covered",
            "No complete matching approval block covers every target in its own Object field.",
            "Update one matching block's Object field to cover every required target, then rerun Closeout.",
            type=approval_type,
            targets=targets,
        )

    missing_fields = sorted({
        field
        for record in candidates
        for field in HUMAN_APPROVAL_FIELDS
        if not record["fields"].get(field)
    })
    return human_approval_evidence_finding(
        "human-approval-block-incomplete",
        "No matching approval block contains all required non-empty fields.",
        "Complete one matching approval block without borrowing fields from another block, then rerun Closeout.",
        type=approval_type,
        targets=targets,
        missing_fields=missing_fields,
    )


def text_records_archive_approval(
    text: str,
    approval_type: str,
    source: str,
    target: str,
) -> bool:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        fields[key.strip().lower()] = value.strip()
    required = {"approval type", "object", "scope", "does not approve"}
    if not required.issubset(fields) or any(not fields[key] for key in required):
        return False
    if (
        fields["approval type"].rstrip(". ").casefold()
        != approval_type.rstrip(". ").casefold()
    ):
        return False
    object_scope = fields["object"]
    for path in (source, target):
        if not re.search(
            rf"(?<![A-Za-z0-9_./-]){re.escape(path)}(?![A-Za-z0-9_./-])",
            object_scope,
        ):
            return False
    return True


def text_records_archive_amendment(
    text: str,
    approval_type: str,
    original_mapping: dict,
    corrected_mapping: dict,
    reason: str,
) -> bool:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        fields[key.strip().lower()] = value.strip()
    required = {
        "approval type",
        "original object",
        "corrected object",
        "reason",
        "does not approve",
    }
    if not required.issubset(fields) or any(not fields[key] for key in required):
        return False
    if fields["approval type"].rstrip(". ").casefold() != approval_type.rstrip(
        ". "
    ).casefold():
        return False
    for field, mapping in (
        ("original object", original_mapping),
        ("corrected object", corrected_mapping),
    ):
        for path in (mapping.get("source"), mapping.get("target")):
            if not isinstance(path, str) or not re.search(
                rf"(?<![A-Za-z0-9_./-]){re.escape(path)}(?![A-Za-z0-9_./-])",
                fields[field],
            ):
                return False
    return fields["reason"].rstrip(". ").casefold() == reason.rstrip(
        ". "
    ).casefold()


def generated_non_authority_evidence(text: str) -> bool:
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return False
    return bool(
        isinstance(payload, dict)
        and payload.get("derived_evidence") is True
        and payload.get("generated") is True
        and payload.get("project_authority") is False
    )


def rule_event_targets(rule: dict, event_paths: list[str]) -> list[str]:
    rule_paths = rule.get("paths", []) if is_string_list(rule.get("paths")) else []
    triggers = rule.get("triggers", []) if is_string_list(rule.get("triggers")) else []
    return sorted({
        path
        for path in event_paths
        if any(path_matches(path, pattern) or path_matches(pattern, path) for pattern in rule_paths)
        or any(path_matches(path, trigger) for trigger in triggers)
    })


def affected_authority_rules(adapter: dict, event_paths: list[str]) -> list[dict]:
    return [rule for rule in safe_rule_list(adapter) if rule_event_targets(rule, event_paths)]


def rule_human_approval_types(adapter: dict, rule: dict) -> tuple[list[str], list[str]]:
    precise = rule.get("human_approval_types")
    if is_string_list(precise) and precise:
        return sorted(set(precise)), []
    if rule.get("human"):
        declared = adapter.get("human_approval", [])
        if is_string_list(declared) and len(set(declared)) == 1:
            return list(dict.fromkeys(declared)), []
        return [], [f"human-approval-type-unmapped:{rule.get('id', 'unknown')}"]
    return [], []


def required_human_approval_types(
    adapter: dict,
    event_paths: list[str],
    historical_patterns: list[str] | None = None,
) -> tuple[list[str], list[str]]:
    required: set[str] = set()
    uncertainty: set[str] = set()
    affected = affected_authority_rules(adapter, event_paths)
    for rule in affected:
        types, rule_uncertainty = rule_human_approval_types(adapter, rule)
        required.update(types)
        uncertainty.update(rule_uncertainty)

    for path in event_paths:
        if not any(path_matches(path, pattern) for pattern in historical_patterns or []):
            continue
        matching = [rule for rule in affected if path in rule_event_targets(rule, [path])]
        mapped = []
        for rule in matching:
            types, _ = rule_human_approval_types(adapter, rule)
            mapped.extend(types)
        if not mapped:
            uncertainty.add(f"human-approval-type-unmapped:{path}")
    return sorted(required), sorted(uncertainty)


def approval_targets_by_type(adapter: dict, event_paths: list[str]) -> dict[str, list[str]]:
    targets: dict[str, set[str]] = {}
    for rule in affected_authority_rules(adapter, event_paths):
        types, _ = rule_human_approval_types(adapter, rule)
        rule_targets = rule_event_targets(rule, event_paths)
        for approval_type in types:
            targets.setdefault(approval_type, set()).update(rule_targets)
    return {approval_type: sorted(paths) for approval_type, paths in targets.items()}


SEMANTIC_ANSWER_KEYS = {
    "important_claims_changed",
    "affected_questions",
    "documents_agree_with_evidence",
    "remaining_uncertainty",
}

SEMANTIC_FINDING_KEYS = {
    "code",
    "affected_question",
    "evidence",
    "confidence",
    "decision_boundary",
    "suggested_handling",
    "human_boundary",
    "status",
}


def semantic_review_shape_finding(
    review_path: str,
    *,
    field: str,
    expected: str,
    actual: object,
    actual_type: str | None = None,
) -> dict:
    actual_name = actual_type or json_type_name(actual)
    return {
        "code": "malformed-semantic-review",
        "path": review_path,
        "field": field,
        "expected": expected,
        "actual": actual_name,
        "diagnostic": {
            "severity": "blocking",
            "category": "semantic_review",
            "message": (
                f"Semantic Review field {field} must be {expected}; "
                f"received {actual_name}."
            ),
            "recovery_actions": [
                f"Correct only {field} in the Semantic Review and rerun Closeout; retain still-valid Impact, Freeze, and validation evidence."
            ],
        },
    }


def validate_semantic_review_shape(
    review: object,
    review_path: str,
) -> tuple[dict, list[dict]]:
    mechanical: list[dict] = []
    if not isinstance(review, dict):
        mechanical.append(semantic_review_shape_finding(
            review_path,
            field="root",
            expected="JSON object",
            actual=review,
        ))
        review = {}

    if review.get("schema") != "govern-ai-coding.semantic-review.v1":
        mechanical.append(semantic_review_shape_finding(
            review_path,
            field="schema",
            expected="govern-ai-coding.semantic-review.v1",
            actual=review.get("schema"),
            actual_type=str(review.get("schema")),
        ))

    answers = review.get("answers")
    if not isinstance(answers, dict):
        mechanical.append(semantic_review_shape_finding(
            review_path,
            field="answers",
            expected="object",
            actual=answers,
        ))
        answers = {}
    normalized_answers: dict[str, object] = {}
    for key in sorted(SEMANTIC_ANSWER_KEYS):
        value = answers.get(key)
        valid = (
            isinstance(value, str) and bool(value.strip())
        ) or (
            isinstance(value, list)
            and bool(value)
            and all(isinstance(item, str) and bool(item.strip()) for item in value)
        )
        if not valid:
            mechanical.append(semantic_review_shape_finding(
                review_path,
                field=f"answers.{key}",
                expected="non-empty string or non-empty string list",
                actual=value,
            ))
        else:
            normalized_answers[key] = value

    raw_findings = review.get("findings")
    if not isinstance(raw_findings, list):
        mechanical.append(semantic_review_shape_finding(
            review_path,
            field="findings",
            expected="array",
            actual=raw_findings,
        ))
        raw_findings = []

    normalized_findings: list[dict] = []
    for index, finding in enumerate(raw_findings):
        if not isinstance(finding, dict):
            mechanical.append(semantic_review_shape_finding(
                review_path,
                field=f"findings[{index}]",
                expected="object",
                actual=finding,
            ))
            continue
        malformed = False
        for key in sorted(SEMANTIC_FINDING_KEYS):
            value = finding.get(key)
            valid = (
                isinstance(value, bool)
                if key == "human_boundary"
                else isinstance(value, str) and bool(value.strip())
            )
            if not valid:
                mechanical.append(semantic_review_shape_finding(
                    review_path,
                    field=f"findings[{index}].{key}",
                    expected="boolean" if key == "human_boundary" else "non-empty string",
                    actual=value,
                ))
                malformed = True
        status = finding.get("status")
        if isinstance(status, str) and status not in {"resolved", "unresolved"}:
            mechanical.append(semantic_review_shape_finding(
                review_path,
                field=f"findings[{index}].status",
                expected="resolved or unresolved",
                actual=status,
                actual_type=status,
            ))
            malformed = True
        if status == "resolved":
            for field in ("resolution", "resolution_evidence"):
                value = finding.get(field)
                if not isinstance(value, str) or not value.strip():
                    mechanical.append(semantic_review_shape_finding(
                        review_path,
                        field=f"findings[{index}].{field}",
                        expected="non-empty string",
                        actual=value,
                    ))
                    malformed = True
        elif status == "unresolved":
            for field in ("resolution", "resolution_evidence"):
                if field in finding and (
                    not isinstance(finding[field], str) or not finding[field].strip()
                ):
                    mechanical.append(semantic_review_shape_finding(
                        review_path,
                        field=f"findings[{index}].{field}",
                        expected="non-empty string when supplied",
                        actual=finding[field],
                    ))
                    malformed = True
        if not malformed:
            normalized_findings.append(finding)

    return {
        "schema": review.get("schema"),
        "source": review.get("source"),
        "answers": normalized_answers,
        "findings": normalized_findings,
    }, mechanical


def validate_semantic_review_command(args: argparse.Namespace) -> int:
    review_path = str(args.review)
    try:
        review, input_finding = load_json_object(
            Path(args.review),
            input_name="semantic-review",
            category="semantic_review",
        )
    except FileNotFoundError:
        review = None
        input_finding = {"actual": "missing"}
    if input_finding is not None:
        normalized = {
            "schema": None,
            "source": None,
            "answers": {},
            "findings": [],
        }
        findings = [semantic_review_shape_finding(
            review_path,
            field="root",
            expected="readable UTF-8 JSON object",
            actual=input_finding.get("actual"),
            actual_type=str(input_finding.get("actual")),
        )]
    else:
        normalized, findings = validate_semantic_review_shape(
            review,
            review_path,
        )
    result = "fail" if findings else "pass"
    return emit({
        "result": result,
        "semantic_review": {
            "status": "malformed" if findings else "valid-shape",
            "source": review_path,
            **normalized,
        },
        "mechanical_findings": findings,
        "semantic_findings": [],
        "human_approval_required": [],
        "claim_boundary": {
            "shape_validated": not findings,
            "context_bound": False,
            "does_not_prove": [
                "resolution evidence belongs to the governed event",
                "review findings are resolved in Closeout context",
                "human approval, product acceptance, release, or readiness",
            ],
        },
        "recovery": (
            "Correct only the reported Semantic Review shape fields and rerun this preflight."
            if findings
            else "Bind this review to Closeout for event-context and resolution-evidence checks."
        ),
    })


def load_command_json_object(
    path: Path,
    *,
    input_name: str,
    category: str,
) -> tuple[dict | None, list[dict]]:
    try:
        value, finding = load_json_object(
            path,
            input_name=input_name,
            category=category,
        )
    except FileNotFoundError:
        return None, [{
            "code": f"{input_name}-missing",
            "severity": "blocking",
            "category": category,
            "message": f"{input_name} does not exist: {path}",
            "field": input_name,
            "path": str(path),
            "expected": "readable UTF-8 JSON object",
            "actual": "missing",
            "recovery_actions": [
                f"Restore the exact {input_name} input and rerun only this command."
            ],
        }]
    return value, [finding] if finding is not None else []


def build_validation_receipt_command(args: argparse.Namespace) -> int:
    adapter, missing = load_json_or_missing(Path(args.adapter))
    if missing:
        missing.update({
            "validation_receipt": None,
            "receipt_output": None,
            "execution": {"performed": False},
        })
        return emit(missing)

    workspace = Path(args.workspace)
    adapter_result = validate_live_adapter(adapter, workspace)
    if adapter_result["result"] == "fail":
        return emit({
            "result": "fail",
            "validation_receipt": None,
            "receipt_output": None,
            "mechanical_findings": adapter_result["mechanical_findings"],
            "semantic_findings": [],
            "human_approval_required": [],
            "execution": {"performed": False},
            "recovery": "Repair the adapter or live navigation entrypoint and retry.",
        })

    freeze, freeze_findings = load_command_json_object(
        Path(args.freeze),
        input_name="freeze-receipt",
        category="receipt_format",
    )
    facts, facts_findings = load_command_json_object(
        Path(args.facts),
        input_name="validation-facts",
        category="validation_evidence",
    )
    findings = freeze_findings + facts_findings
    receipt = None
    if not findings:
        receipt, build_findings = build_evidence_validation_receipt(
            freeze,
            facts,
        )
        findings.extend(build_findings)

    output_path = None
    if receipt is not None and not findings:
        output_path, write_findings = write_receipt_file(
            receipt,
            args.write_receipt,
            workspace,
            adapter,
            overwrite=False,
        )
        findings.extend(write_findings)

    result = "fail" if findings else "pass"
    return emit({
        "result": result,
        "validation_receipt": receipt,
        "receipt_output": output_path,
        "mechanical_findings": findings,
        "semantic_findings": [],
        "human_approval_required": [],
        "execution": {
            "performed": False,
            "recorded_commands_executed": False,
        },
        "claim_boundary": {
            "facts_copied": receipt is not None,
            "does_not_prove": [
                "recorded commands were executed by this command",
                "test framework output was parsed or independently verified",
                "human approval, product acceptance, release, or readiness",
            ],
        },
        "recovery": (
            "Correct only the reported input or output issue and rerun this builder."
            if findings
            else "Bind this receipt to its exact Freeze in validation and Closeout."
        ),
    })


def validate_validation_receipt_command(args: argparse.Namespace) -> int:
    receipt_path = Path(args.receipt)
    receipt, receipt_findings = load_command_json_object(
        receipt_path,
        input_name="validation-receipt",
        category="validation_evidence",
    )
    freeze, freeze_findings = load_command_json_object(
        Path(args.freeze),
        input_name="freeze-receipt",
        category="receipt_format",
    )
    findings = receipt_findings + freeze_findings
    if not findings:
        validation_report = validate_validation_receipt_for_profile(
            receipt,
            receipt_path,
            profile="standalone-freeze-bound-v1",
            freeze=freeze,
        )
        findings.extend(validation_report["findings"])
    result = "fail" if findings else "pass"
    return emit({
        "result": result,
        "validation_receipt": {
            "status": "invalid" if findings else "valid",
            "source": str(receipt_path),
            "freeze_source": str(args.freeze),
        },
        "mechanical_findings": findings,
        "semantic_findings": [],
        "human_approval_required": [],
        "execution": {"performed": False},
        "claim_boundary": {
            "structure_validated": not findings,
            "freeze_bound": not findings,
            "does_not_prove": [
                "recorded commands were executed by this command",
                "human approval, product acceptance, release, or readiness",
            ],
        },
        "recovery": (
            "Correct only the reported receipt or Freeze mismatch and rerun validation."
            if findings
            else "Use this exact receipt and Freeze together in Closeout."
        ),
    })


def evaluate_semantic_review(
    review_path: str | None,
    *,
    required: bool,
    workspace: Path,
    event_paths: list[str],
    authorized_docs: list[str],
) -> tuple[dict, list[dict], list[dict], list[str]]:
    if not review_path:
        return {
            "status": "not supplied or not bound",
            "required": required,
            "findings": [],
        }, [], [], ["semantic review not supplied or not bound"] if required else []

    mechanical: list[dict] = []
    unverified: list[str] = []
    review_file = Path(review_path)
    try:
        review, input_finding = load_json_object(
            review_file,
            input_name="semantic-review",
            category="semantic_review",
        )
    except FileNotFoundError:
        return {
            "status": "missing",
            "required": required,
            "findings": [],
        }, [{"code": "semantic-review-missing", "path": review_path}], [], []
    if input_finding is not None:
        return {
            "status": "malformed",
            "required": required,
            "findings": [],
        }, [semantic_review_shape_finding(
            review_path,
            field="root",
            expected="JSON object",
            actual=input_finding.get("actual"),
            actual_type=str(input_finding.get("actual")),
        )], [], []

    normalized_review, shape_findings = validate_semantic_review_shape(
        review,
        review_path,
    )
    mechanical.extend(shape_findings)
    answers = normalized_review["answers"]
    findings = normalized_review["findings"]

    normalized_event = set(event_paths)
    normalized_authorized, auth_findings = normalize_paths_with_findings(authorized_docs, "authorized_doc")
    mechanical.extend(auth_findings)
    semantic_findings = []
    for finding in findings:
        semantic_findings.append(finding)
        status = finding.get("status")
        if status == "unresolved":
            unverified.append("unresolved-semantic-finding")
            continue
        evidence, evidence_finding = normalize_path_value(
            finding["resolution_evidence"],
            "semantic_resolution_evidence",
        )
        if evidence_finding:
            mechanical.append(evidence_finding)
            continue
        evidence_authorized = any(path_matches(evidence, pattern) for pattern in normalized_authorized)
        if evidence not in normalized_event or not evidence_authorized:
            unverified.append("semantic-resolution-evidence-missing")

    status = "bound" if not mechanical and not unverified else "unresolved"
    return {
        "status": status,
        "required": required,
        "source": str(review_path),
        "binding": {
            "source": str(review_path),
            "digest": canonical_evidence_v1_digest(review),
        },
        "answers": answers if isinstance(answers, dict) else {},
        "findings": semantic_findings,
    }, mechanical, semantic_findings, sorted(set(unverified))


def evaluate_freeze_receipt(
    receipt_path: str | None,
    *,
    adapter: dict,
    workspace: Path,
    event_paths: list[str],
    receipt_payload: dict | None = None,
) -> tuple[dict, list[dict], list[str]]:
    if not receipt_path and receipt_payload is None:
        return {
            "status": "not supplied",
            "verified": False,
            "source": None,
            "paths": [],
            "stale_paths": [],
        }, [], ["final-content-freeze"]
    if receipt_payload is not None:
        receipt = receipt_payload
        receipt_source = "event-manifest"
    else:
        receipt_source = receipt_path
        try:
            receipt = load_json(Path(receipt_path))
        except FileNotFoundError:
            return {
                "status": "missing",
                "verified": False,
                "source": receipt_path,
                "paths": [],
                "stale_paths": [],
            }, [{"code": "freeze-receipt-missing", "path": receipt_path}], []
        except SystemExit:
            return {
                "status": "malformed",
                "verified": False,
                "source": receipt_path,
                "paths": [],
                "stale_paths": [],
            }, [{"code": "malformed-freeze-receipt", "path": receipt_path, "field": "json"}], []

    mechanical: list[dict] = []
    if not isinstance(receipt, dict):
        mechanical.append({"code": "malformed-freeze-receipt", "field": "root"})
        receipt = {}
    if receipt.get("schema") != FREEZE_RECEIPT_SCHEMA or receipt.get("kind") != "final-content-freeze":
        mechanical.append({"code": "malformed-freeze-receipt", "field": "schema"})
    if not isinstance(receipt.get("adapter"), dict) or not isinstance(receipt.get("workspace"), dict):
        mechanical.append({"code": "malformed-freeze-receipt", "field": "identity"})
    if not isinstance(receipt.get("paths"), list) or not receipt.get("paths"):
        mechanical.append({"code": "malformed-freeze-receipt", "field": "paths"})
    if not all(receipt.get(key) is expected for key, expected in {
        "derived_evidence": True,
        "generated": True,
        "project_authority": False,
    }.items()):
        mechanical.append({"code": "malformed-freeze-receipt", "field": "authority-markers"})
    if mechanical:
        return {
            "status": "malformed",
            "verified": False,
            "source": receipt_source,
            "paths": [],
            "stale_paths": [],
        }, mechanical, []

    identity_mismatch = (
        receipt["adapter"].get("project") != adapter.get("project")
        or receipt["adapter"].get("schema_version") != adapter.get("schema_version")
        or receipt["workspace"].get("path") != str(workspace.resolve())
    )
    if identity_mismatch:
        mechanical.append({
            "code": "freeze-receipt-identity-mismatch",
            "expected_project": adapter.get("project"),
            "expected_workspace": str(workspace.resolve()),
        })

    frozen: dict[str, dict] = {}
    for index, entry in enumerate(receipt["paths"]):
        if not isinstance(entry, dict):
            mechanical.append({"code": "malformed-freeze-receipt", "field": f"paths.{index}"})
            continue
        path, path_finding = normalize_path_value(str(entry.get("path", "")), "freeze.path")
        if path_finding or not isinstance(entry.get("existence"), bool) or "digest" not in entry:
            mechanical.append({"code": "malformed-freeze-receipt", "field": f"paths.{index}"})
            continue
        if path in frozen:
            mechanical.append({"code": "duplicate-freeze-path", "path": path})
            continue
        frozen[path] = entry

    missing_coverage = sorted(set(event_paths) - set(frozen))
    if missing_coverage:
        mechanical.append({"code": "freeze-receipt-missing-event-path", "paths": missing_coverage})

    stale_paths: list[str] = []
    for path, entry in frozen.items():
        target = (workspace / path).resolve()
        try:
            target.relative_to(workspace.resolve())
        except ValueError:
            mechanical.append({"code": "freeze-path-outside-workspace", "path": path})
            continue
        current_exists = target.is_file()
        current_digest = file_digest(target) if current_exists else None
        if current_exists != entry.get("existence") or current_digest != entry.get("digest"):
            stale_paths.append(path)
    if stale_paths:
        mechanical.append({"code": "final-content-changed-after-freeze", "paths": sorted(stale_paths)})

    verified = not mechanical
    return {
        "status": "verified" if verified else "invalid",
        "verified": verified,
            "source": receipt_source,
        "paths": sorted(frozen),
        "stale_paths": sorted(stale_paths),
    }, mechanical, []


def live_closeout(
    adapter: dict,
    workspace: Path,
    changed_paths: list[str],
    actual_paths: list[str],
    change_source: str,
    authorized_docs: list[str],
    protected_approval_bindings: list[str],
    human_approval_bindings: list[str],
    args: argparse.Namespace | None = None,
    adapter_validation: dict | None = None,
) -> dict:
    adapter_result = adapter_validation or validate_live_adapter(adapter, workspace)
    mechanical = list(adapter_result["mechanical_findings"])
    path_warnings: list[dict] = []
    human_required = []
    boundary_rules = safe_section(adapter, "boundaries")
    entrypoint_rules = safe_section(adapter, "entrypoints")
    protected_patterns = boundary_rules.get("protected", [])
    excluded_patterns = boundary_rules.get("excluded", [])
    ordinary_patterns = boundary_rules.get("ordinary_docs", [])
    historical_patterns = entrypoint_rules.get("historical", [])
    change_entries, pre_existing_unchanged, receipt, inventory_findings, event_isolation_verified, resolved_source, source_metadata = resolve_change_inventory(
        adapter,
        workspace,
        args,
        changed_paths=changed_paths,
        actual_paths=actual_paths,
        change_source=change_source,
    )
    mechanical.extend(inventory_findings)
    verification, verification_findings = change_verification(
        workspace,
        changed_paths,
        actual_paths,
        resolved_source,
        change_entries=change_entries,
        event_isolation_verified=event_isolation_verified,
        source_metadata=source_metadata,
    )
    mechanical.extend(verification_findings)
    approvals, approval_findings = parse_protected_approvals(protected_approval_bindings)
    human_approvals, human_approval_findings = parse_human_approvals(human_approval_bindings)
    mechanical.extend(approval_findings)
    mechanical.extend(human_approval_findings)
    normalized_changed = set(verification["actual_paths"] if verification["verified"] else verification["declared_paths"])
    event_paths = sorted(normalized_changed)
    event_manifest = (
        getattr(args, "loaded_event_manifest", None)
        if args is not None
        else None
    )
    if receipt is not None:
        reconciliation_findings, reconciliation_warnings = (
            evaluate_impact_path_reconciliation(receipt, event_paths)
        )
        mechanical.extend(reconciliation_findings)
        path_warnings.extend(reconciliation_warnings)
    declared_human_types = adapter.get("human_approval", []) if is_string_list(adapter.get("human_approval")) else []
    valid_approvals = []
    valid_approval_paths = set()
    valid_human_approvals = []

    changed_historical_paths = [
        changed
        for changed in event_paths
        if any(path_matches(changed, pattern) for pattern in historical_patterns)
    ]
    required_types, approval_mapping_uncertainty = required_human_approval_types(
        adapter,
        event_paths,
        historical_patterns,
    )
    human_required.extend(required_types)
    targets_by_type = approval_targets_by_type(adapter, event_paths)
    dirty_changed_paths = sorted({
        path
        for entry in change_entries or []
        if (entry.get("metadata") or {}).get("dirty_at_baseline")
        for path in inventory_entry_paths(entry)
    })
    freeze_summary, freeze_mechanical, freeze_unverified = evaluate_freeze_receipt(
        getattr(args, "freeze_receipt", None) if args else None,
        adapter=adapter,
        workspace=workspace,
        event_paths=event_paths,
        receipt_payload=getattr(args, "freeze_receipt_payload", None) if args else None,
    )
    mechanical.extend(freeze_mechanical)
    semantic_review, semantic_mechanical, bound_semantic_findings, semantic_unverified = evaluate_semantic_review(
        getattr(args, "semantic_review", None) if args else None,
        required=bool(getattr(args, "require_semantic_review", False)) if args else False,
        workspace=workspace,
        event_paths=event_paths,
        authorized_docs=authorized_docs,
    )
    mechanical.extend(semantic_mechanical)

    for approval in approvals:
        path = approval["path"]
        evidence = approval["evidence"]
        before = len(mechanical)
        path_protected = any(path_matches(path, pattern) for pattern in protected_patterns)
        path_excluded = any(path_matches(path, pattern) for pattern in excluded_patterns)
        path_historical = any(path_matches(path, pattern) for pattern in historical_patterns)
        path_authorized = any(path_matches(path, pattern) for pattern in authorized_docs)
        evidence_authorized = any(path_matches(evidence, pattern) for pattern in authorized_docs)
        evidence_ordinary = any(path_matches(evidence, pattern) for pattern in ordinary_patterns)
        evidence_protected = any(path_matches(evidence, pattern) for pattern in protected_patterns)
        evidence_excluded = any(path_matches(evidence, pattern) for pattern in excluded_patterns)
        evidence_historical = any(path_matches(evidence, pattern) for pattern in historical_patterns)

        if path not in normalized_changed:
            mechanical.append({"code": "protected-approval-path-not-changed", "path": path})
        if not path_protected:
            mechanical.append({"code": "protected-approval-path-not-protected", "path": path})
        if not path_authorized:
            mechanical.append({"code": "protected-approval-path-not-authorized", "path": path})
        if path_excluded:
            mechanical.append({"code": "protected-approval-path-excluded", "path": path})
        if path_historical:
            mechanical.append({"code": "protected-approval-path-historical", "path": path})

        if evidence not in normalized_changed or not evidence_authorized:
            mechanical.append({
                "code": "protected-approval-evidence-not-in-event",
                "path": path,
                "evidence": evidence,
            })
        if not evidence_ordinary or evidence_protected or evidence_excluded or evidence_historical:
            mechanical.append({
                "code": "invalid-protected-approval-evidence-boundary",
                "path": path,
                "evidence": evidence,
            })

        evidence_path = (workspace / evidence).resolve()
        try:
            evidence_path.relative_to(workspace.resolve())
        except ValueError:
            mechanical.append({
                "code": "protected-approval-evidence-outside-workspace",
                "path": path,
                "evidence": evidence,
            })
        else:
            if not evidence_path.is_file():
                mechanical.append({
                    "code": "missing-protected-approval-evidence",
                    "path": path,
                    "evidence": evidence,
                })

        if len(mechanical) == before:
            valid_approvals.append(approval)
            valid_approval_paths.add(path)

    for approval in human_approvals:
        approval_type = approval["type"]
        evidence = approval["evidence"]
        approval_targets = targets_by_type.get(approval_type, [])
        before = len(mechanical)

        if approval_type not in declared_human_types:
            mechanical.append({"code": "human-approval-type-not-declared", "type": approval_type})

        evidence_authorized = any(path_matches(evidence, pattern) for pattern in authorized_docs)
        evidence_ordinary = any(path_matches(evidence, pattern) for pattern in ordinary_patterns)
        evidence_protected = any(path_matches(evidence, pattern) for pattern in protected_patterns)
        evidence_excluded = any(path_matches(evidence, pattern) for pattern in excluded_patterns)
        evidence_historical = any(path_matches(evidence, pattern) for pattern in historical_patterns)

        if evidence not in normalized_changed:
            mechanical.append({
                "code": "human-approval-evidence-not-in-event",
                "type": approval_type,
                "evidence": evidence,
            })
        if not evidence_authorized:
            mechanical.append({
                "code": "human-approval-evidence-not-authorized",
                "type": approval_type,
                "evidence": evidence,
            })
        if not evidence_ordinary or evidence_protected or evidence_excluded or evidence_historical:
            mechanical.append({
                "code": "invalid-human-approval-evidence-boundary",
                "type": approval_type,
                "evidence": evidence,
            })

        evidence_path = (workspace / evidence).resolve()
        try:
            evidence_path.relative_to(workspace.resolve())
        except ValueError:
            mechanical.append({
                "code": "human-approval-evidence-outside-workspace",
                "type": approval_type,
                "evidence": evidence,
            })
            evidence_text = ""
        else:
            if not evidence_path.is_file():
                mechanical.append({
                    "code": "missing-human-approval-evidence",
                    "type": approval_type,
                    "evidence": evidence,
                })
                evidence_text = ""
            else:
                evidence_text = evidence_path.read_text(encoding="utf-8")

        if evidence_text and generated_non_authority_evidence(evidence_text):
            mechanical.append({
                "code": "generated-human-approval-evidence",
                "type": approval_type,
                "evidence": evidence,
            })

        if approval_targets:
            authorized_targets = [
                path
                for path in approval_targets
                if any(path_matches(path, pattern) for pattern in authorized_docs)
            ]
        else:
            authorized_targets = []
        if approval_targets and sorted(authorized_targets) != sorted(approval_targets):
            mechanical.append({
                "code": "human-approval-target-not-authorized",
                "type": approval_type,
                "targets": sorted(set(approval_targets) - set(authorized_targets)),
            })

        if evidence_text and not approval_targets:
            mechanical.append({
                "code": "human-approval-scope-unmapped",
                "type": approval_type,
                "evidence": evidence,
            })
        elif evidence_text:
            evidence_finding = evaluate_human_approval_evidence(
                evidence_text,
                approval_type,
                approval_targets,
            )
            if evidence_finding is not None:
                mechanical.append({
                    **evidence_finding,
                    "evidence": evidence,
                })

        if len(mechanical) == before:
            accepted = {
                "type": approval_type,
                "evidence": evidence,
                "targets": approval_targets,
            }
            valid_human_approvals.append(accepted)
            human_required = [item for item in human_required if item != approval_type]

    for changed in event_paths:
        changed_protected = [pattern for pattern in protected_patterns if path_matches(changed, pattern)]
        changed_excluded = [pattern for pattern in excluded_patterns if path_matches(changed, pattern)]
        changed_historical = [pattern for pattern in historical_patterns if path_matches(changed, pattern)]
        changed_ordinary = [pattern for pattern in ordinary_patterns if path_matches(changed, pattern)]
        authorized = any(path_matches(changed, pattern) for pattern in authorized_docs)

        normalized = changed.rstrip("/")

        if changed_excluded:
            mechanical.append({
                "code": "excluded-path-changed",
                "path": changed,
                "matched": changed_excluded,
            })
            continue
        if changed_protected and normalized not in valid_approval_paths:
            mechanical.append({
                "code": "protected-path-changed",
                "path": changed,
                "matched": changed_protected,
            })
            continue
        if changed_protected:
            continue
        if changed_historical:
            if not authorized:
                mechanical.append({
                    "code": "unauthorized-historical-change",
                    "path": changed,
                    "matched": changed_historical,
                })
            continue
        if changed_ordinary and not authorized:
            mechanical.append({
                "code": "unauthorized-ordinary-doc-change",
                "path": changed,
                "matched": changed_ordinary,
            })
            continue
        if not authorized:
            mechanical.append({"code": "unauthorized-change", "path": changed})

    empty_event = verification["verified"] and not event_paths
    if mechanical:
        result = "fail"
    elif human_required:
        result = "unproven"
    elif not verification["verified"] or not verification["event_isolation_verified"]:
        result = "unproven"
    elif dirty_changed_paths:
        result = "unproven"
    elif semantic_unverified or freeze_unverified or approval_mapping_uncertainty or empty_event:
        result = "unproven"
    else:
        result = "pass"

    unverified = []
    if not verification["verified"]:
        unverified.append("actual-change-set")
    if not verification["event_isolation_verified"]:
        unverified.append("event-isolation")
    if dirty_changed_paths:
        unverified.append("dirty-baseline-attribution-unproven")
    if empty_event:
        unverified.append("empty-event-change-set")
    unverified.extend(semantic_unverified)
    unverified.extend(freeze_unverified)
    if approval_mapping_uncertainty:
        unverified.append("human-approval-type-unmapped")

    closeout_receipt = {
        "schema": "govern-ai-coding.closeout-receipt.v1",
        "kind": "live-closeout",
        "adapter": {
            "project": adapter.get("project"),
            "schema_version": adapter.get("schema_version"),
        },
        "workspace": {"path": str(workspace.resolve())},
        "result": result,
        "final_content": {
            "freeze_receipt": freeze_summary.get("source"),
            "verified": freeze_summary.get("verified", False),
            "paths": freeze_summary.get("paths", []),
            "stale_paths": freeze_summary.get("stale_paths", []),
        },
        "derived_evidence": True,
        "generated": True,
        "project_authority": False,
    }

    return {
        "result": result,
        "coverage": {
            "inventory_source": verification["source"],
            "actual_change_set_verified": verification["verified"],
            "baseline_receipt_used": bool(receipt),
            "event_isolation_verified": verification["event_isolation_verified"],
            "semantic_review_bound": semantic_review["status"] == "bound",
            "human_boundary_complete": not bool(human_required),
            "final_content_frozen": freeze_summary["verified"],
            "stale_frozen_paths": freeze_summary["stale_paths"],
            "actor_identity_verified": False,
            "actor_identity_reason": "filesystem and Git inventories do not identify which human or AI actor changed a path",
            "unverified": sorted(set(unverified)),
            "cannot_prove": [
                "which AI or human actor modified a file",
                "semantic truth of document claims",
            ],
        },
        "closeout": {
            "mode": "live",
            "workspace": str(workspace),
            "changed_paths": verification["declared_paths"],
            "actual_paths": verification["actual_paths"],
            "change_inventory": change_entries or [],
            "pre_existing_unchanged": pre_existing_unchanged,
            "change_verification": verification,
            "authorized_docs": authorized_docs,
            "authorized_paths": authorized_docs,
            "protected_approvals": valid_approvals,
            "verified_human_approvals": valid_human_approvals,
            "approval_mapping_uncertainty": approval_mapping_uncertainty,
        },
        "mechanical_findings": mechanical,
        "semantic_review": semantic_review,
        "freeze_receipt": freeze_summary,
        "closeout_receipt": closeout_receipt,
        "semantic_findings": bound_semantic_findings,
        "human_approval_required": sorted(set(human_required)),
        "warnings": list(adapter_result.get("warnings", [])) + path_warnings,
        "recovery": "Live Closeout checked adapter, receipt/baseline, change source, actual event paths, affected governed questions, unresolved semantic findings, unresolved human boundaries, and next inputs needed for recovery.",
    }


def add_structured_closeout_recovery(payload: dict) -> dict:
    mechanical_codes = [
        finding.get("code", "mechanical-finding")
        for finding in payload.get("mechanical_findings", [])
    ]
    unverified = list((payload.get("coverage") or {}).get("unverified", []))
    missing = sorted(set(payload.get("human_approval_required", [])))
    verified = sorted({
        approval.get("type")
        for approval in (payload.get("closeout") or {}).get("verified_human_approvals", [])
        if approval.get("type")
    })
    required = sorted(set(missing + verified))

    reasons: list[str] = []
    reasons.extend(f"mechanical:{code}" for code in mechanical_codes)
    reasons.extend(f"unverified:{item}" for item in unverified)
    reasons.extend(f"human-approval-missing:{item}" for item in missing)
    if not reasons:
        reasons.append("all-closeout-gates-satisfied")

    actions: list[str] = []
    stale_paths = (payload.get("coverage") or {}).get("stale_frozen_paths", [])
    if stale_paths:
        actions.append(f"Refreeze final content for: {', '.join(stale_paths)}; rerun project validation and Closeout.")
    if any(code.startswith("human-approval-") or code == "generated-human-approval-evidence" for code in mechanical_codes):
        actions.append("Correct the exact human approval binding and its in-event ordinary evidence document.")
    other_mechanical = [
        code
        for code in mechanical_codes
        if code != "final-content-changed-after-freeze"
        and not code.startswith("human-approval-")
        and code != "generated-human-approval-evidence"
    ]
    if other_mechanical:
        actions.append(f"Resolve mechanical findings: {', '.join(sorted(set(other_mechanical)))}.")
    if "actual-change-set" in unverified or "event-isolation" in unverified:
        actions.append("Run Impact before edits and pass its baseline receipt to Closeout with the exact event paths.")
    if "final-content-freeze" in unverified:
        actions.append("Freeze the final event paths, run project validation, then rerun Closeout with the freeze receipt.")
    if any(item.startswith("semantic-") for item in unverified):
        actions.append("Complete or resolve the semantic review and bind its authorized resolution evidence.")
    if "human-approval-type-unmapped" in unverified:
        actions.append("Map each affected authority rule to an exact adapter human_approval_types value.")
    if missing:
        actions.append(f"Obtain and bind exact human approval for: {', '.join(missing)}.")
    if payload.get("result") == "pass":
        actions.append("Preserve the derived receipt outside project authority and make no further governed edits; if content changes, refreeze, revalidate, and rerun Closeout.")
    if not actions:
        actions.append("Resolve the listed reasons and rerun Closeout.")

    payload["result_reasons"] = reasons
    payload["recovery_actions"] = actions
    payload["approval_summary"] = {
        "required": required,
        "verified": verified,
        "missing": missing,
    }
    return payload


def diagnostic_category(code: str) -> str:
    if any(token in code for token in ("adapter", "authority-rule", "entrypoint")) or code in {
        "invalid-project",
        "unsupported-schema-version",
    }:
        return "adapter_configuration"
    if "receipt" in code and "freeze" not in code and "validation" not in code:
        return "receipt_format"
    if "approval" in code:
        return "approval_evidence"
    if any(token in code for token in (
        "actual-path",
        "declared-path",
        "scope",
        "unauthorized-change",
        "event-manifest-workspace",
        "event-manifest-baseline",
    )):
        return "scope_mismatch"
    if "freeze" in code or "final-content" in code:
        return "freeze_invalidation"
    if "validation" in code:
        return "validation_missing"
    if "semantic" in code:
        return "semantic_review"
    return "blocking"


def diagnostic_recovery(code: str, category: str) -> str:
    navigation_recovery = {
        "adapter-schema-migration-required": (
            "Migrate explicitly to schema_version 2, declare navigation_entrypoint.path as README.md, "
            "cover README.md with boundaries.ordinary_docs, then validate with --workspace."
        ),
        "navigation-entrypoint-config-missing": (
            "Declare navigation_entrypoint as an object with path README.md; do not add an implicit authority rule."
        ),
        "navigation-entrypoint-path-invalid": (
            "Set navigation_entrypoint.path to the exact root-relative value README.md."
        ),
        "navigation-entrypoint-boundary-missing": (
            "Add README.md to boundaries.ordinary_docs and retain normal event authorization."
        ),
        "navigation-entrypoint-boundary-conflict": (
            "Remove README.md from protected, excluded, and historical coverage while preserving ordinary_docs coverage."
        ),
        "navigation-entrypoint-workspace-required": (
            "Rerun the command with --workspace pointing to the exact governed workspace; no file was changed."
        ),
        "navigation-entrypoint-file-missing": (
            "Manually create the approved root README.md content, then rerun live validation; do not generate project facts automatically."
        ),
        "navigation-entrypoint-file-not-regular": (
            "Replace the root entry with a non-symlink regular README.md after explicit project-authorized editing."
        ),
        "navigation-entrypoint-unreadable": (
            "Make README.md readable strict UTF-8 without changing its claims automatically, then rerun live validation."
        ),
        "navigation-entrypoint-empty": (
            "Add human-approved navigation content to README.md through the normal governed edit workflow."
        ),
        "navigation-entrypoint-link-broken": (
            "Correct or remove the exact broken local README.md link through an authorized governed edit."
        ),
        "navigation-entrypoint-link-outside-workspace": (
            "Change the local README.md link to a destination inside the governed workspace."
        ),
    }
    if code in navigation_recovery:
        return navigation_recovery[code]
    if category == "adapter_configuration":
        return "Correct the adapter field or mapping before continuing the event."
    if category == "receipt_format":
        return "Provide a valid Impact receipt or complete Impact envelope."
    if category == "scope_mismatch":
        return "Correct the declared and actual event scope; retain the existing baseline when it remains valid."
    if category == "approval_evidence":
        return "Bind the exact declared approval type to valid in-event evidence; do not infer approval from path authorization."
    if category == "freeze_invalidation":
        return "Freeze the affected final paths, run only the validation invalidated by those inputs, then rerun Closeout."
    if category == "validation_missing":
        return "Provide the project-selected validation receipt without restarting unrelated event steps."
    if category == "semantic_review":
        return "Complete or correct the Semantic Review for the affected claims."
    if code == "authorized-doc-deprecated":
        return "Use --authorized-path on the next invocation; the alias remains compatible."
    return "Resolve this finding and rerun only the affected governance step."


DIAGNOSTIC_SEVERITIES = {"blocking", "unproven", "warning"}
DIAGNOSTIC_CATEGORIES = {
    "adapter_configuration",
    "receipt_format",
    "scope_mismatch",
    "approval_evidence",
    "freeze_invalidation",
    "validation_missing",
    "semantic_review",
    "blocking",
}


def diagnostic_context(item: dict) -> tuple[dict, list[str]]:
    fields = dict(item.get("fields", {})) if isinstance(item.get("fields"), dict) else {}
    excluded = {
        "category",
        "code",
        "diagnostic",
        "fields",
        "message",
        "path",
        "paths",
        "recovery_actions",
        "severity",
    }
    for key, value in item.items():
        if key in excluded:
            continue
        try:
            json.dumps(value, sort_keys=True)
        except (TypeError, ValueError):
            continue
        fields[key] = value
    paths: list[str] = []
    if isinstance(item.get("path"), str):
        paths.append(item["path"])
    if isinstance(item.get("paths"), list):
        paths.extend(str(path) for path in item["paths"])
    return fields, sorted(set(paths))


def normalize_diagnostic(value: object) -> dict | None:
    if not isinstance(value, dict):
        return None
    severity = value.get("severity")
    category = value.get("category")
    code = value.get("code")
    message = value.get("message")
    recovery_actions = value.get("recovery_actions")
    if (
        severity not in DIAGNOSTIC_SEVERITIES
        or category not in DIAGNOSTIC_CATEGORIES
        or not isinstance(code, str)
        or not code
        or not isinstance(message, str)
        or not message
        or not isinstance(recovery_actions, list)
        or not recovery_actions
        or not all(isinstance(action, str) and action for action in recovery_actions)
    ):
        return None
    diagnostic = dict(value)
    if "fields" in diagnostic and not isinstance(diagnostic["fields"], dict):
        return None
    if "paths" in diagnostic and (
        not isinstance(diagnostic["paths"], list)
        or not all(isinstance(path, str) and path for path in diagnostic["paths"])
    ):
        return None
    if "paths" in diagnostic:
        diagnostic["paths"] = sorted(set(diagnostic["paths"]))
    if "fields" not in diagnostic and "paths" not in diagnostic:
        diagnostic["fields"] = {}
    return diagnostic


def make_diagnostic(
    *,
    severity: str,
    category: str,
    code: str,
    message: str,
    source: dict | None = None,
) -> dict:
    fields, paths = diagnostic_context(source or {})
    explicit = (source or {}).get("diagnostic")
    if isinstance(explicit, dict):
        candidate = {
            "code": code,
            "message": message,
            **explicit,
        }
        explicit_fields = candidate.get("fields")
        if isinstance(explicit_fields, dict):
            fields = {**fields, **explicit_fields}
        if fields:
            candidate["fields"] = fields
        explicit_paths = candidate.get("paths")
        if isinstance(explicit_paths, list):
            paths = sorted(set(paths + explicit_paths))
        if paths:
            candidate["paths"] = paths
        normalized = normalize_diagnostic(candidate)
        if normalized is not None:
            return normalized
    diagnostic = {
        "severity": severity,
        "category": category,
        "code": code,
        "message": message,
        "recovery_actions": [diagnostic_recovery(code, category)],
    }
    if paths:
        diagnostic["paths"] = paths
    if fields or not paths:
        diagnostic["fields"] = fields
    return diagnostic


def add_structured_diagnostics(payload: dict) -> dict:
    if not isinstance(payload, dict):
        return payload
    if (
        payload.get("schema") == "govern-ai-coding.normalized-result.v1"
        and isinstance(payload.get("diagnostics"), list)
    ):
        return payload
    diagnostics = [
        diagnostic
        for item in payload.get("diagnostics", []) or []
        if (diagnostic := normalize_diagnostic(item)) is not None
    ]
    for finding in payload.get("mechanical_findings", []) or []:
        if not isinstance(finding, dict):
            continue
        code = str(finding.get("code", "mechanical-finding"))
        category = diagnostic_category(code)
        diagnostics.append(make_diagnostic(
            severity="blocking",
            category=category,
            code=code,
            message=str(finding.get("message") or code.replace("-", " ")),
            source=finding,
        ))
    for reason in (payload.get("coverage") or {}).get("unverified", []) or []:
        code = str(reason)
        category = diagnostic_category(code)
        diagnostics.append(make_diagnostic(
            severity="unproven",
            category=category,
            code=code,
            message=code.replace("-", " "),
        ))
    for approval_type in payload.get("human_approval_required", []) or []:
        code = "human-approval-missing"
        category = "approval_evidence"
        diagnostics.append(make_diagnostic(
            severity="unproven",
            category=category,
            code=code,
            message=f"human approval missing: {approval_type}",
            source={"type": approval_type},
        ))
    for warning in payload.get("warnings", []) or []:
        if not isinstance(warning, dict):
            continue
        code = str(warning.get("code", "warning"))
        category = diagnostic_category(code)
        diagnostics.append(make_diagnostic(
            severity="warning",
            category=category,
            code=code,
            message=str(warning.get("message") or code.replace("-", " ")),
            source=warning,
        ))
    unique_diagnostics = {
        json.dumps(diagnostic, sort_keys=True, separators=(",", ":")): diagnostic
        for diagnostic in diagnostics
    }
    payload["diagnostics"] = sorted(
        unique_diagnostics.values(),
        key=lambda item: (
            item["severity"],
            item["category"],
            item["code"],
            json.dumps(item.get("fields", {}), sort_keys=True),
            json.dumps(item.get("paths", []), sort_keys=True),
        ),
    )
    return payload


def receipt_payload_from_args(
    args: argparse.Namespace,
    *,
    kind: str,
) -> dict | None:
    embedded = getattr(args, f"{kind}_receipt_payload", None)
    if isinstance(embedded, dict):
        return embedded
    path = getattr(args, "receipt" if kind == "impact" else "freeze_receipt", None)
    if not path:
        return None
    try:
        loaded = load_json(Path(path))
    except (FileNotFoundError, SystemExit):
        return None
    if kind == "impact":
        receipt, findings = extract_impact_receipt(loaded)
        return receipt if not findings else None
    return loaded if isinstance(loaded, dict) else None


def evaluate_work_map_closeout(
    payload: dict,
    args: argparse.Namespace,
    manifest: dict | None,
    workspace: Path,
    adapter: dict,
) -> tuple[dict | None, list[dict]]:
    """Verify a bound final Work Map using already-validated event receipts."""
    binding = manifest.get("work_map_binding") if manifest is not None else None
    if binding is None:
        return None, []
    if not isinstance(adapter.get("work_map"), dict):
        return None, [{
            "code": "work-map-config-required",
            "message": "A Work Map binding requires adapter work_map configuration.",
        }]

    work_map_path = adapter["work_map"]["path"]
    findings: list[dict] = []
    actual_paths = set((payload.get("closeout") or {}).get("actual_paths", []))
    if work_map_path not in actual_paths:
        findings.append({
            "code": "work-map-path-not-actual",
            "path": work_map_path,
        })

    freeze_receipt = receipt_payload_from_args(args, kind="freeze")
    frozen_entry = next((
        entry
        for entry in (freeze_receipt or {}).get("paths", [])
        if isinstance(entry, dict) and entry.get("path") == work_map_path
    ), None)
    frozen_paths = {
        entry.get("path")
        for entry in (freeze_receipt or {}).get("paths", [])
        if isinstance(entry, dict)
    }
    if work_map_path not in frozen_paths:
        findings.append({
            "code": "work-map-path-not-frozen",
            "path": work_map_path,
        })

    expected_baseline = {
        "item_id": binding.get("item_id"),
        "task_id": binding.get("task_id"),
        "source_digest": binding.get("source_digest"),
        "expected_disposition": binding.get("expected_disposition"),
        "path": work_map_path,
    }
    external_impact_receipt = None
    impact_receipt_destination = None
    if not args.receipt:
        findings.append({
            "code": "work-map-impact-receipt-required",
            "message": "Bound Work Map Closeout requires the preserved external Impact receipt.",
        })
    else:
        impact_receipt_destination, input_path_findings = (
            resolve_receipt_output_path(args.receipt, workspace, adapter)
        )
        findings.extend({
            **finding,
            "code": "unsafe-work-map-impact-receipt-path",
        } for finding in input_path_findings)
        if impact_receipt_destination is not None:
            try:
                external_payload = load_json(impact_receipt_destination)
            except FileNotFoundError:
                findings.append({
                    "code": "work-map-impact-receipt-missing",
                    "path": str(impact_receipt_destination),
                })
            except (OSError, SystemExit, UnicodeError) as exc:
                findings.append({
                    "code": "work-map-impact-receipt-invalid",
                    "path": str(impact_receipt_destination),
                    "message": str(exc),
                })
            else:
                external_impact_receipt, external_findings = extract_impact_receipt(
                    external_payload
                )
                findings.extend({
                    **finding,
                    "code": "work-map-impact-receipt-invalid",
                    "path": str(impact_receipt_destination),
                } for finding in external_findings)

    if args.write_receipt:
        closeout_receipt_destination, output_path_findings = (
            resolve_receipt_output_path(args.write_receipt, workspace, adapter)
        )
        findings.extend({
            **finding,
            "code": "unsafe-closeout-receipt-output-path",
            "diagnostic": {
                "severity": "blocking",
                "category": "receipt_format",
                "message": "The Closeout receipt output path is not a safe generated-evidence destination.",
                "recovery_actions": [
                    "Choose a new Closeout receipt output path outside governed authority or under an adapter-excluded generated-evidence directory."
                ],
            },
        } for finding in output_path_findings)
        same_receipt_identity = (
            impact_receipt_destination is not None
            and closeout_receipt_destination is not None
            and impact_receipt_destination == closeout_receipt_destination
        )
        if (
            not same_receipt_identity
            and impact_receipt_destination is not None
            and closeout_receipt_destination is not None
            and impact_receipt_destination.exists()
            and closeout_receipt_destination.exists()
        ):
            try:
                same_receipt_identity = os.path.samefile(
                    impact_receipt_destination,
                    closeout_receipt_destination,
                )
            except OSError:
                same_receipt_identity = False
        if same_receipt_identity:
            findings.append({
                "code": "work-map-impact-receipt-output-alias",
                "path": str(impact_receipt_destination),
                "output_path": args.write_receipt,
            })

    manifest_impact_receipt = (manifest.get("receipts") or {}).get("impact")
    if not isinstance(manifest_impact_receipt, dict):
        findings.append({
            "code": "work-map-manifest-impact-receipt-missing",
        })
    elif (
        external_impact_receipt is not None
        and (
            external_impact_receipt != manifest_impact_receipt
            or canonical_evidence_v1_digest(external_impact_receipt)
            != canonical_evidence_v1_digest(manifest_impact_receipt)
        )
    ):
        findings.append({
            "code": "work-map-impact-receipt-mismatch",
            "path": str(impact_receipt_destination),
        })

    if (external_impact_receipt or {}).get("work_map_baseline") != expected_baseline:
        findings.append({
            "code": "work-map-impact-baseline-mismatch",
            "path": work_map_path,
        })

    if args.write_attestation != binding.get("attestation_path"):
        findings.append({
            "code": "work-map-attestation-destination-mismatch",
            "expected": binding.get("attestation_path"),
            "actual": args.write_attestation,
        })

    if findings:
        return None, findings
    try:
        observation, observation_findings = observe_work_map_final(
            adapter,
            workspace,
            binding,
        )
    except (OSError, UnicodeError) as exc:
        return None, [{
            "code": "work-map-final-unreadable",
            "path": work_map_path,
            "message": str(exc),
        }]
    if observation is not None and isinstance(frozen_entry, dict):
        observation = {
            **observation,
            "frozen_file_digest": frozen_entry.get("digest"),
        }
    return observation, observation_findings


def _attested_final_git_commit(workspace: Path, final_content: list[dict]) -> str | None:
    commit, _ = resolve_git_baseline(workspace, "HEAD")
    if commit is None:
        return None
    for entry in final_content:
        object_name = f"{commit}:{entry['path']}"
        blob = subprocess.run(
            ["git", "show", object_name], cwd=workspace, check=False,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        if entry["existence"]:
            if blob.returncode != 0 or hashlib.sha256(blob.stdout).hexdigest() != entry["digest"]:
                return None
        elif blob.returncode == 0:
            return None
    return commit


def write_closeout_attestation(
    attestation: dict,
    output_path: str,
    workspace: Path,
    adapter: dict,
) -> tuple[dict, list[dict]]:
    destination, findings = resolve_receipt_output_path(
        output_path,
        workspace,
        adapter,
    )
    if findings or destination is None:
        return {}, [
            {
                **finding,
                "code": "unsafe-attestation-output-path",
            }
            for finding in findings
        ]
    if destination.exists():
        return {}, [{
            "code": "attestation-already-exists",
            "path": str(destination),
        }]
    try:
        atomic_write_json(attestation, destination, overwrite=False)
    except FileExistsError:
        return {}, [{
            "code": "attestation-already-exists",
            "path": str(destination),
        }]
    except OSError as exc:
        return {}, [{
            "code": "attestation-write-failed",
            "path": str(destination),
            "message": str(exc),
        }]
    return {
        "status": "created",
        "path": str(destination),
        "digest": canonical_evidence_v1_digest(attestation),
        "schema": CLOSEOUT_ATTESTATION_SCHEMA,
    }, []


def event_manifest_v2_closeout_input_findings(
    manifest: dict | None,
    *,
    attempt_id: str | None,
    write_receipt: str | None,
) -> list[dict]:
    if not event_manifest_is_v2(manifest):
        if attempt_id is not None:
            return [{"code": "event-manifest-attempt-id-v1-unsupported"}]
        return []
    findings: list[dict] = []
    if attempt_id is None:
        findings.append({"code": "event-manifest-attempt-id-required"})
    elif re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", attempt_id) is None:
        findings.append({
            "code": "event-manifest-attempt-id-invalid",
            "attempt_id": attempt_id,
        })
    elif any(
        isinstance(item, dict) and item.get("id") == attempt_id
        for item in manifest.get("closeout", {}).get("attempts", [])
    ):
        findings.append({
            "code": "event-manifest-attempt-id-duplicate",
            "attempt_id": attempt_id,
        })
    if not write_receipt:
        findings.append({"code": "event-manifest-attempt-receipt-required"})
    return findings


def closeout_not_run_payload(
    args: argparse.Namespace,
    findings: list[dict],
) -> dict:
    return add_structured_closeout_recovery({
        "result": "fail",
        "coverage": {
            "workspace_mode": "live",
            "unverified": ["closeout-not-run"],
        },
        "closeout": {
            "mode": "live",
            "workspace": args.workspace,
            "changed_paths": args.changed_path,
            "actual_paths": args.actual_path,
            "authorized_docs": args.authorized_paths,
            "authorized_paths": args.authorized_paths,
            "protected_approvals": [],
            "verified_human_approvals": [],
        },
        "mechanical_findings": findings,
        "semantic_review": {
            "status": "not run",
            "required": bool(args.require_semantic_review),
            "findings": [],
        },
        "semantic_findings": [],
        "human_approval_required": [],
        "closeout_receipt": None,
        "receipt_output": None,
        "attestation": {"status": "not-created", "reason": "closeout-not-run"},
        "recovery": "Correct the Event Manifest Closeout inputs and retry.",
    })


def closeout_command(args: argparse.Namespace) -> int:
    manifest, manifest_findings = prepare_event_manifest(args, phase="closeout")
    manifest_expected_digest = args.event_manifest_expected_digest
    compatibility_warnings = []
    if args.authorized_doc:
        compatibility_warnings.append({
            "code": "authorized-doc-deprecated",
            "message": "--authorized-doc is a compatibility alias; use --authorized-path.",
        })
    loaded_authorized_paths: list[str] = []
    authorized_path_findings: list[dict] = []
    for path_file in args.authorized_paths_from:
        loaded_paths, path_findings = load_paths_from(path_file)
        loaded_authorized_paths.extend(loaded_paths)
        authorized_path_findings.extend(path_findings)
    manifest_findings.extend(authorized_path_findings)
    args.authorized_paths = sorted(set(
        args.authorized_path
        + args.authorized_doc
        + loaded_authorized_paths
    ))
    if manifest is not None:
        args.impact_receipt_payload = manifest["receipts"].get("impact")
        args.freeze_receipt_payload = manifest["receipts"].get("freeze")
        args.authorized_paths = sorted(set(
            args.authorized_paths
            + manifest["scope"].get("governed_authority_documents", [])
            + manifest["scope"].get("authorized_development_paths", [])
        ))
        semantic_path = manifest.get("semantic_review", {}).get("path")
        if not args.semantic_review and isinstance(semantic_path, str):
            args.semantic_review = semantic_path
        for approval in manifest.get("approvals", []):
            if approval.get("kind") == "human":
                args.human_approval.append(
                    f"{approval.get('type', '')}={approval.get('evidence', '')}"
                )
            elif approval.get("kind") == "protected":
                args.protected_approval.append(
                    f"{approval.get('path', '')}={approval.get('evidence', '')}"
                )
    if authorized_path_findings:
        return emit(add_structured_closeout_recovery({
            "result": "fail",
            "coverage": {
                "workspace_mode": "live",
                "unverified": ["closeout-not-run"],
            },
            "closeout": {
                "mode": "live",
                "workspace": args.workspace,
                "changed_paths": args.changed_path,
                "actual_paths": args.actual_path,
                "authorized_docs": args.authorized_paths,
                "authorized_paths": args.authorized_paths,
                "protected_approvals": [],
                "verified_human_approvals": [],
            },
            "mechanical_findings": authorized_path_findings,
            "semantic_review": {
                "status": "not run",
                "required": bool(args.require_semantic_review),
                "findings": [],
            },
            "semantic_findings": [],
            "human_approval_required": [],
            "closeout_receipt": None,
            "receipt_output": None,
            "attestation": {
                "status": "not-created",
                "reason": "authorized-paths-input-invalid",
            },
            "recovery": (
                "Correct only the reported authorization path file input; "
                "no receipt or attestation was written."
            ),
        }))
    live_requested = bool(
        args.changed_path
        or args.receipt
        or args.freeze_receipt
        or args.baseline_inventory
        or args.final_inventory
        or args.actual_path
        or args.write_receipt
        or args.write_attestation
        or args.event_manifest
    )
    if live_requested:
        adapter, missing = load_json_or_missing(Path(args.adapter))
        if missing:
            if authorized_path_findings:
                missing["result"] = "fail"
                missing["mechanical_findings"].extend(authorized_path_findings)
            missing["closeout"] = {
                "mode": "live",
                "workspace": args.workspace,
                "changed_paths": args.changed_path,
                "actual_paths": args.actual_path,
                "authorized_docs": args.authorized_paths,
                "authorized_paths": args.authorized_paths,
                "protected_approvals": [],
                "verified_human_approvals": [],
            }
            missing["semantic_review"] = {
                "status": "not supplied or not bound",
                "required": bool(args.require_semantic_review),
                "findings": [],
            }
            return emit(add_structured_closeout_recovery(missing))
        live_validation = validate_live_adapter(adapter, Path(args.workspace))
        if live_validation["result"] != "pass":
            return emit(add_structured_closeout_recovery({
                "result": "fail",
                "coverage": {
                    "workspace_mode": "live",
                    "unverified": ["closeout-not-run"],
                },
                "closeout": {
                    "mode": "live",
                    "workspace": args.workspace,
                    "changed_paths": args.changed_path,
                    "actual_paths": args.actual_path,
                    "authorized_docs": args.authorized_paths,
                    "authorized_paths": args.authorized_paths,
                    "protected_approvals": [],
                    "verified_human_approvals": [],
                },
                "mechanical_findings": live_validation["mechanical_findings"],
                "semantic_review": {
                    "status": "not run",
                    "required": bool(args.require_semantic_review),
                    "findings": [],
                },
                "semantic_findings": [],
                "human_approval_required": [],
                "closeout_receipt": None,
                "receipt_output": None,
                "attestation": {
                    "status": "not-created",
                    "reason": "live-adapter-validation-failed",
                },
                "recovery": (
                    "Fix adapter and root navigation entrypoint findings before "
                    "Closeout; no receipt or attestation was written."
                ),
            }))
        if manifest is not None:
            manifest, contextual_findings = validate_event_manifest(
                manifest,
                manifest_path=Path(args.event_manifest),
                workspace=Path(args.workspace),
                adapter=adapter,
            )
            manifest_findings.extend(contextual_findings)
        if args.event_manifest and manifest is None and manifest_findings:
            return emit(closeout_not_run_payload(args, manifest_findings))
        v2_input_findings = event_manifest_v2_closeout_input_findings(
            manifest,
            attempt_id=args.attempt_id,
            write_receipt=args.write_receipt,
        )
        if v2_input_findings:
            return emit(closeout_not_run_payload(args, v2_input_findings))
        payload = live_closeout(
            adapter,
            Path(args.workspace),
            args.changed_path,
            args.actual_path,
            args.change_source,
            args.authorized_paths,
            args.protected_approval,
            args.human_approval,
            args,
            adapter_validation=live_validation,
        )
        payload["warnings"] = list(payload.get("warnings", [])) + compatibility_warnings
        work_map_observation, work_map_findings = evaluate_work_map_closeout(
            payload,
            args,
            manifest,
            Path(args.workspace),
            adapter,
        )
        if work_map_findings:
            payload["mechanical_findings"].extend(work_map_findings)
            payload["result"] = "fail"
            payload["closeout_receipt"]["result"] = "fail"
        validation_receipts = list(args.validation_receipt)
        if manifest is not None:
            validation_receipts.extend(manifest["receipts"].get("validation", []))
        freeze_payload = receipt_payload_from_args(args, kind="freeze")
        validation_profile = (
            "work-map-closeout-v1"
            if manifest is not None
            and manifest.get("work_map_binding") is not None
            else "closeout-compatible-v1"
        )
        validation_evidence, validation_findings = (
            collect_validation_evidence_for_profile(
                validation_receipts,
                Path(args.workspace),
                profile=validation_profile,
                freeze_receipt=freeze_payload,
            )
        )
        if validation_findings:
            payload["mechanical_findings"].extend(validation_findings)
            payload["result"] = "fail"
            payload["closeout_receipt"]["result"] = "fail"
        if manifest_findings:
            payload["mechanical_findings"].extend(manifest_findings)
            payload["result"] = "fail"
            payload["closeout_receipt"]["result"] = "fail"
        impact_receipt_output_alias = any(
            finding.get("code") == "work-map-impact-receipt-output-alias"
            for finding in work_map_findings
        )
        if payload["result"] == "pass" and work_map_observation is not None:
            payload["work_map_observation"] = work_map_observation
        else:
            payload.pop("work_map_observation", None)
        payload = add_structured_closeout_recovery(payload)
        if event_manifest_is_v2(manifest):
            if not isinstance(freeze_payload, dict):
                payload["mechanical_findings"].append({
                    "code": "event-manifest-attempt-freeze-required",
                })
                payload["result"] = "fail"
                payload["closeout_receipt"]["result"] = "fail"
                payload = add_structured_closeout_recovery(payload)
            else:
                impact_payload = receipt_payload_from_args(args, kind="impact")
                if not isinstance(impact_payload, dict):
                    payload["mechanical_findings"].append({
                        "code": "event-manifest-attempt-impact-required",
                    })
                    payload["result"] = "fail"
                    payload["closeout_receipt"]["result"] = "fail"
                    payload = add_structured_closeout_recovery(payload)
                    impact_payload = {}
                payload["closeout_receipt"]["freeze"] = {
                    "schema": "govern-ai-coding.freeze-receipt.v1",
                    "digest": canonical_evidence_v1_digest(freeze_payload),
                    "receipt": freeze_payload,
                }
                payload["closeout_receipt"]["impact"] = {
                    "digest": canonical_evidence_v1_digest(impact_payload),
                    "receipt": impact_payload,
                }
                receipt_path, receipt_write_findings = write_or_reuse_json_evidence(
                    payload["closeout_receipt"],
                    args.write_receipt,
                    Path(args.workspace),
                    adapter,
                    kind="receipt",
                )
                payload["receipt_output"] = receipt_path
                if receipt_write_findings:
                    payload["mechanical_findings"].extend(receipt_write_findings)
                    payload["result"] = "fail"
                    payload = add_structured_closeout_recovery(payload)
                else:
                    attestation = None
                    attestation_path = None
                    if args.write_attestation and payload["result"] == "pass":
                        attestation = build_evidence_attestation(
                            payload,
                            adapter=adapter,
                            workspace=Path(args.workspace),
                            manifest=manifest,
                            impact_receipt=receipt_payload_from_args(
                                args, kind="impact",
                            ),
                            freeze_receipt=freeze_payload,
                            validation_evidence=validation_evidence,
                        )
                        attestation_path, attestation_findings = (
                            write_or_reuse_json_evidence(
                                attestation,
                                args.write_attestation,
                                Path(args.workspace),
                                adapter,
                                kind="attestation",
                            )
                        )
                        if attestation_findings:
                            payload["mechanical_findings"].extend(
                                attestation_findings,
                            )
                            payload["result"] = "fail"
                            payload["attestation"] = {
                                "status": "not-created",
                                "path": args.write_attestation,
                            }
                            payload = add_structured_closeout_recovery(payload)
                        else:
                            payload["attestation"] = {
                                "status": "created",
                                "path": attestation_path,
                                "digest": canonical_evidence_v1_digest(attestation),
                                "schema": CLOSEOUT_ATTESTATION_SCHEMA,
                            }
                    elif args.write_attestation:
                        payload["attestation"] = {
                            "status": "not-created",
                            "path": args.write_attestation,
                            "reason": "closeout-result-not-pass",
                        }
                    if not (
                        args.write_attestation
                        and payload.get("attestation", {}).get("status")
                        == "not-created"
                        and payload["closeout_receipt"].get("result") == "pass"
                    ):
                        validation_paths = list(
                            manifest["receipts"].get("validation", []),
                        )
                        validation_paths.extend(args.validation_receipt)
                        manifest["receipts"]["validation"] = sorted(
                            set(validation_paths),
                        )
                        candidate, candidate_findings = append_v2_closeout_attempt(
                            manifest=manifest,
                            manifest_path=args.event_manifest,
                            attempt_id=args.attempt_id,
                            payload=payload,
                            receipt_path=receipt_path,
                            attestation=attestation,
                            attestation_path=attestation_path,
                            freeze_receipt=freeze_payload,
                            workspace=Path(args.workspace),
                            adapter=adapter,
                        )
                        if candidate_findings or candidate is None:
                            payload["mechanical_findings"].extend(candidate_findings)
                            payload["result"] = "fail"
                            payload = add_structured_closeout_recovery(payload)
                        else:
                            manifest_write_findings = write_event_manifest(
                                candidate,
                                args.event_manifest,
                                Path(args.workspace),
                                adapter,
                                expected_digest=manifest_expected_digest,
                            )
                            if manifest_write_findings:
                                payload["mechanical_findings"].extend(
                                    manifest_write_findings,
                                )
                                payload["result"] = "fail"
                                payload = add_structured_closeout_recovery(payload)
                            else:
                                persisted, persisted_findings = load_event_manifest(
                                    args.event_manifest,
                                    workspace=Path(args.workspace),
                                    adapter=adapter,
                                )
                                if persisted_findings or persisted is None:
                                    payload["mechanical_findings"].extend(
                                        persisted_findings or [{
                                            "code": "event-manifest-reread-failed",
                                        }],
                                    )
                                    payload["result"] = "fail"
                                    payload = add_structured_closeout_recovery(payload)
                                elif not any(
                                    isinstance(item, dict)
                                    and item.get("id") == args.attempt_id
                                    for item in persisted["closeout"]["attempts"]
                                ):
                                    payload["mechanical_findings"].append({
                                        "code": "event-manifest-attempt-reread-missing",
                                        "attempt_id": args.attempt_id,
                                    })
                                    payload["result"] = "fail"
                                    payload = add_structured_closeout_recovery(payload)
                                elif payload["closeout_receipt"]["result"] == "pass":
                                    resolved = current_closeout_attempt(
                                        persisted,
                                        manifest_path=Path(args.event_manifest),
                                        workspace=Path(args.workspace),
                                        adapter=adapter,
                                    )
                                    if (
                                        resolved.get("status") != "matching"
                                        or resolved.get("attempt", {}).get("id")
                                        != args.attempt_id
                                    ):
                                        payload["mechanical_findings"].append({
                                            "code": "event-manifest-current-reread-mismatch",
                                        })
                                        payload["result"] = "fail"
                                        payload = add_structured_closeout_recovery(payload)
        else:
            if args.write_receipt and not impact_receipt_output_alias:
                output_path, write_findings = write_receipt_file(
                    payload["closeout_receipt"],
                    args.write_receipt,
                    Path(args.workspace),
                    adapter,
                )
                payload["receipt_output"] = output_path
                if write_findings:
                    payload["mechanical_findings"].extend(write_findings)
                    payload["result"] = "fail"
                    payload["closeout_receipt"]["result"] = "fail"
            elif args.write_receipt:
                payload["receipt_output"] = None
            if args.write_attestation:
                if payload["result"] == "pass":
                    attestation = build_evidence_attestation(
                        payload,
                        adapter=adapter,
                        workspace=Path(args.workspace),
                        manifest=manifest,
                        impact_receipt=receipt_payload_from_args(
                            args, kind="impact",
                        ),
                        freeze_receipt=freeze_payload,
                        validation_evidence=validation_evidence,
                    )
                    attestation_summary, attestation_findings = write_closeout_attestation(
                        attestation,
                        args.write_attestation,
                        Path(args.workspace),
                        adapter,
                    )
                    if attestation_findings:
                        payload["mechanical_findings"].extend(attestation_findings)
                        payload["result"] = "fail"
                        payload["closeout_receipt"]["result"] = "fail"
                        payload["attestation"] = {
                            "status": "not-created",
                            "path": args.write_attestation,
                        }
                        payload = add_structured_closeout_recovery(payload)
                    else:
                        payload["attestation"] = attestation_summary
                else:
                    payload["attestation"] = {
                        "status": "not-created",
                        "path": args.write_attestation,
                        "reason": "closeout-result-not-pass",
                    }
            if manifest is not None:
                validation_receipts = list(manifest["receipts"].get("validation", []))
                validation_receipts.extend(args.validation_receipt)
                manifest["receipts"]["validation"] = sorted(set(validation_receipts))
                manifest["closeout"] = {
                    "result": payload["result"],
                    "result_reasons": list(payload.get("result_reasons", [])),
                    "recovery_actions": list(payload.get("recovery_actions", [])),
                }
                if payload.get("attestation", {}).get("status") == "created":
                    manifest["receipts"]["closeout_attestation"] = {
                        "path": payload["attestation"]["path"],
                        "digest": payload["attestation"]["digest"],
                    }
                write_findings = write_event_manifest(
                    manifest,
                    args.event_manifest,
                    Path(args.workspace),
                    adapter,
                )
                if write_findings:
                    payload["mechanical_findings"].extend(write_findings)
                    payload["result"] = "fail"
                    payload["closeout_receipt"]["result"] = "fail"
    else:
        if not args.cases:
            raise SystemExit("closeout requires either --changed-path for live mode or a cases file for fixture mode")
        payload = run_cases(args)
        payload["closeout"] = {
            "mode": "fixture",
            "adapter": args.adapter,
            "cases": args.cases,
            "workspace": args.workspace,
        }
    if payload.get("result") != "pass":
        payload.pop("work_map_observation", None)
    return emit(add_structured_closeout_recovery(payload))


def verify_integration_command(args: argparse.Namespace) -> int:
    return emit(verify_integration(
        adapter_path=args.adapter,
        source_workspace=Path(args.workspace),
        source_repository=(
            Path(args.source_repository)
            if args.source_repository is not None
            else None
        ),
        source_ref=args.source_ref,
        manifest_path=Path(args.event_manifest),
        attestation_path=Path(args.attestation),
        target_workspace=Path(args.target_workspace),
        target_adapter=args.target_adapter,
        target_ref=args.target_ref,
    ))


def preflight_event_command(args: argparse.Namespace) -> int:
    try:
        adapter = load_json(Path(args.adapter))
        current = load_json(Path(args.event_manifest))
    except (FileNotFoundError, SystemExit):
        return emit({
            "result": "unproven",
            "conflicts": [],
            "warnings": [{"code": "current-declaration-unproven"}],
            "visibility_boundary": "Only supplied paths were inspected.",
        })
    peers = []
    for raw_path in args.peer_manifest:
        path = Path(raw_path)
        try:
            peer_manifest = load_json(path)
        except (FileNotFoundError, SystemExit):
            peer_manifest = {}
        event = peer_manifest.get("event")
        raw_workspace = event.get("workspace") if isinstance(event, dict) else None
        if isinstance(raw_workspace, str) and raw_workspace:
            peer_workspace = Path(raw_workspace)
            if not peer_workspace.is_absolute():
                peer_workspace = path.parent / peer_workspace
        else:
            peer_workspace = Path(args.workspace)
        pointer = (peer_manifest.get("receipts") or {}).get(
            "closeout_attestation"
        )
        attestation = pointer.get("path") if isinstance(pointer, dict) else None
        peers.append({
            "manifest": peer_manifest,
            "manifest_path": path,
            "workspace": peer_workspace,
            "attestation": attestation,
        })
    return emit(preflight_declared_events(
        adapter=adapter,
        workspace=Path(args.workspace),
        current_manifest=current,
        current_manifest_path=Path(args.event_manifest),
        peers=peers,
    ))


class CliArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(3, f"{self.prog}: error: {message}\n")


class RuntimeVersionAction(argparse.Action):
    def __init__(self, option_strings, dest=argparse.SUPPRESS, default=argparse.SUPPRESS, **kwargs):
        super().__init__(
            option_strings=option_strings,
            dest=dest,
            nargs=0,
            default=default,
            **kwargs,
        )

    def __call__(self, parser, namespace, values, option_string=None) -> None:
        print(runtime_identity())
        parser.exit(0)


def build_parser() -> argparse.ArgumentParser:
    parser = CliArgumentParser(
        description=(
            "govern-ai-coding deterministic checker with required root "
            "README.md navigation for humans and AI"
        )
    )
    parser.add_argument(
        "--legacy-zero-exit",
        action="store_true",
        help=(
            "temporarily return status 0 for result-bearing commands without "
            "changing their JSON result"
        ),
    )
    parser.add_argument(
        "--version",
        action=RuntimeVersionAction,
        help="show the installed Skill base version and package SHA-256 digest",
    )
    sub = parser.add_subparsers(required=True, dest="command")

    validate = sub.add_parser(
        "validate-adapter",
        help="validate schema 2 and the live root README.md entrypoint",
    )
    validate.add_argument("adapter")
    validate.add_argument(
        "--workspace",
        help="live workspace required to prove the schema-2 root README.md navigation entrypoint",
    )
    validate.set_defaults(func=validate_adapter_command)

    validate_semantic_review_parser = sub.add_parser(
        "validate-semantic-review",
        help="validate Semantic Review JSON shape without event-context binding",
    )
    validate_semantic_review_parser.add_argument("review")
    validate_semantic_review_parser.set_defaults(
        func=validate_semantic_review_command,
    )

    build_validation_receipt_parser = sub.add_parser(
        "build-validation-receipt",
        help="build a Freeze-bound receipt from explicit validation facts without execution",
    )
    build_validation_receipt_parser.add_argument("adapter")
    build_validation_receipt_parser.add_argument("--workspace", required=True)
    build_validation_receipt_parser.add_argument("--freeze", required=True)
    build_validation_receipt_parser.add_argument("--facts", required=True)
    build_validation_receipt_parser.add_argument("--write-receipt", required=True)
    build_validation_receipt_parser.set_defaults(
        func=build_validation_receipt_command,
    )

    validate_validation_receipt_parser = sub.add_parser(
        "validate-validation-receipt",
        help="validate receipt structure and binding to an exact Freeze",
    )
    validate_validation_receipt_parser.add_argument("receipt")
    validate_validation_receipt_parser.add_argument("--freeze", required=True)
    validate_validation_receipt_parser.set_defaults(
        func=validate_validation_receipt_command,
    )

    audit_event_parser = sub.add_parser(
        "audit-event",
        help="read only the explicit current Event Manifest v2 Closeout attempt",
    )
    audit_event_parser.add_argument("adapter")
    audit_event_parser.add_argument("--workspace", required=True)
    audit_event_parser.add_argument("--event-manifest", required=True)
    audit_event_parser.set_defaults(func=audit_event_command)

    impact = sub.add_parser("impact")
    impact.add_argument("adapter")
    impact.add_argument("--changed-path", action="append", default=[])
    impact.add_argument("--workspace")
    impact.add_argument(
        "--change-source",
        choices=["auto", "git", "filesystem", "supplied", "explicit"],
        default="auto",
    )
    impact.add_argument("--write-receipt")
    impact.add_argument(
        "--extend-receipt",
        help="extend scope only from paths observed by a preserved original Impact receipt",
    )
    impact.add_argument("--event-manifest")
    impact.add_argument("--paths-from", action="append", default=[])
    impact.add_argument("--baseline-ref")
    impact.set_defaults(func=impact_command)

    freeze = sub.add_parser("freeze")
    freeze.add_argument("adapter")
    freeze.add_argument("--workspace", required=True)
    freeze.add_argument("--changed-path", action="append", default=[])
    freeze.add_argument("--write-receipt")
    freeze.add_argument("--event-manifest")
    freeze.add_argument("--paths-from", action="append", default=[])
    freeze.add_argument("--baseline-ref")
    freeze.add_argument("--validation-receipt", action="append", default=[])
    freeze.set_defaults(func=freeze_command)

    run = sub.add_parser("run-cases")
    run.add_argument("adapter")
    run.add_argument("cases")
    run.add_argument("--workspace", required=True)
    run.set_defaults(func=run_cases_command)

    closeout = sub.add_parser("closeout")
    closeout.add_argument("adapter")
    closeout.add_argument("cases", nargs="?")
    closeout.add_argument("--workspace", required=True)
    closeout.add_argument("--changed-path", action="append", default=[])
    closeout.add_argument("--actual-path", action="append", default=[])
    closeout.add_argument(
        "--change-source",
        choices=["auto", "git", "filesystem", "supplied", "explicit"],
        default="auto",
    )
    closeout.add_argument("--receipt")
    closeout.add_argument("--freeze-receipt")
    closeout.add_argument("--write-receipt")
    closeout.add_argument("--write-attestation")
    closeout.add_argument("--event-manifest")
    closeout.add_argument(
        "--attempt-id",
        help="explicit stable Closeout attempt id required by Event Manifest v2",
    )
    closeout.add_argument("--paths-from", action="append", default=[])
    closeout.add_argument("--baseline-ref")
    closeout.add_argument("--validation-receipt", action="append", default=[])
    closeout.add_argument("--baseline-inventory")
    closeout.add_argument("--final-inventory")
    closeout.add_argument("--authorized-doc", action="append", default=[])
    closeout.add_argument("--authorized-path", action="append", default=[])
    closeout.add_argument(
        "--authorized-paths-from",
        action="append",
        default=[],
        help="load authorization-only paths with the strict --paths-from file contract",
    )
    closeout.add_argument("--compact", action="store_true")
    closeout.add_argument("--semantic-review")
    closeout.add_argument("--require-semantic-review", action="store_true")
    closeout.add_argument(
        "--protected-approval",
        action="append",
        default=[],
        metavar="PATH=EVIDENCE",
    )
    closeout.add_argument(
        "--human-approval",
        action="append",
        default=[],
        metavar="TYPE=EVIDENCE",
    )
    closeout.set_defaults(func=closeout_command)

    verify_integration_parser = sub.add_parser("verify-integration")
    verify_integration_parser.add_argument("adapter")
    verify_integration_parser.add_argument("--workspace", required=True)
    verify_integration_parser.add_argument("--event-manifest", required=True)
    verify_integration_parser.add_argument("--attestation", required=True)
    verify_integration_parser.add_argument("--source-repository")
    verify_integration_parser.add_argument("--source-ref")
    verify_integration_parser.add_argument("--target-workspace", required=True)
    verify_integration_parser.add_argument("--target-adapter", required=True)
    verify_integration_parser.add_argument("--target-ref")
    verify_integration_parser.set_defaults(func=verify_integration_command)

    preflight_event = sub.add_parser("preflight-event")
    preflight_event.add_argument("adapter")
    preflight_event.add_argument("--workspace", required=True)
    preflight_event.add_argument("--event-manifest", required=True)
    preflight_event.add_argument(
        "--peer-manifest", action="append", default=[], required=True,
    )
    preflight_event.set_defaults(func=preflight_event_command)

    controlled_archive = sub.add_parser("controlled-archive")
    controlled_archive.add_argument("adapter")
    controlled_archive.add_argument("--workspace", required=True)
    controlled_archive.add_argument("--request", required=True)
    controlled_archive.add_argument("--write-receipt", required=True)
    controlled_archive.add_argument("--preflight", action="store_true")
    controlled_archive.add_argument("--execution-grant")
    controlled_archive.add_argument("--amendment")
    controlled_archive.add_argument("--original-execution-grant")
    controlled_archive.add_argument("--compact", action="store_true")
    controlled_archive.set_defaults(func=controlled_archive_command)

    archive_task = sub.add_parser("archive-task")
    archive_task_sub = archive_task.add_subparsers(
        required=True,
        dest="archive_task_action",
    )
    for action in ("preflight", "status", "execute"):
        action_parser = archive_task_sub.add_parser(action)
        action_parser.add_argument("adapter")
        action_parser.add_argument("--workspace", required=True)
        action_parser.add_argument("--manifest", required=True)
        if action in {"preflight", "status", "execute"}:
            action_parser.add_argument("--write-summary")
            action_parser.add_argument("--previous-summary")
        if action == "execute":
            action_parser.add_argument("--execution-grant", required=True)
        action_parser.add_argument("--compact", action="store_true")
        action_parser.set_defaults(func=archive_task_command)

    archive_authorization_status = sub.add_parser(
        "archive-authorization-status"
    )
    archive_authorization_status.add_argument("adapter")
    archive_authorization_status.add_argument("--workspace", required=True)
    archive_authorization_status.add_argument("--authorization-id")
    archive_authorization_status.add_argument("--compact", action="store_true")
    archive_authorization_status.set_defaults(
        func=archive_authorization_status_command
    )

    normalize_archive = sub.add_parser("normalize-archive-result")
    normalize_archive.add_argument("--input", required=True)
    normalize_archive.add_argument("--compact", action="store_true")
    normalize_archive.set_defaults(func=normalize_archive_result_command)

    diagnose_parser = sub.add_parser(
        "diagnose",
        help="run read-only live governance and README navigation checks",
    )
    diagnose_parser.add_argument("adapter")
    diagnose_parser.add_argument("--workspace", required=True)
    diagnose_parser.set_defaults(func=diagnose_command)

    work_map = sub.add_parser("work-map")
    work_map_sub = work_map.add_subparsers(
        required=True,
        dest="work_map_action",
    )
    work_map_check = work_map_sub.add_parser("check")
    work_map_check.add_argument("adapter")
    work_map_check.add_argument("--workspace", required=True)
    work_map_check.set_defaults(func=work_map_command)

    work_map_status_parser = work_map_sub.add_parser("status")
    work_map_status_parser.add_argument("adapter")
    work_map_status_parser.add_argument("--workspace", required=True)
    work_map_status_parser.add_argument("--event-manifest", required=True)
    work_map_status_parser.set_defaults(func=work_map_command)

    work_map_start = work_map_sub.add_parser("start")
    work_map_start.add_argument("adapter")
    work_map_start.add_argument("--workspace", required=True)
    work_map_start.add_argument("--item", required=True)
    work_map_start.add_argument("--task-id", required=True)
    work_map_start.set_defaults(func=work_map_command)

    work_map_finish = work_map_sub.add_parser("finish")
    work_map_finish.add_argument("adapter")
    work_map_finish.add_argument("--workspace", required=True)
    work_map_finish.add_argument("--item", required=True)
    work_map_finish.add_argument("--task-id", required=True)
    work_map_finish.add_argument(
        "--disposition",
        required=True,
        choices=[
            "completed",
            "transferred",
            "blocked",
            "deferred",
            "cancelled",
            "superseded",
        ],
    )
    work_map_finish.set_defaults(func=work_map_command)

    work_map_render = work_map_sub.add_parser("render")
    work_map_render.add_argument("adapter")
    work_map_render.add_argument("--workspace", required=True)
    work_map_render.add_argument("--format", required=True, choices=["table", "mermaid"])
    work_map_render.set_defaults(func=work_map_command)

    return parser


def emit_internal_error() -> int:
    emit({
        "result": "fail",
        "mechanical_findings": [{
            "code": "internal-error",
            "severity": "blocking",
            "category": "runtime",
            "message": "The command stopped at an unexpected internal failure.",
            "recovery_actions": [
                "Preserve the inputs and rerun with a repaired or known-good GAC package."
            ],
        }],
        "semantic_findings": [],
        "human_approval_required": [],
        "recovery": (
            "Preserve the inputs and rerun with a repaired or known-good GAC package."
        ),
    })
    return 3


def main(argv: list[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
    except Exception:
        return emit_internal_error()
    compact_token = _COMPACT_OUTPUT.set(bool(getattr(args, "compact", False)))
    try:
        status = args.func(args)
    except Exception:
        return emit_internal_error()
    finally:
        _COMPACT_OUTPUT.reset(compact_token)
    return 0 if args.legacy_zero_exit else status


if __name__ == "__main__":
    sys.exit(main())
