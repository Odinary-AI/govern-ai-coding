#!/usr/bin/env python3
"""Pure protocol helpers for generic controlled archive operations."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import platform
import re
import stat
import sys
import unicodedata
from pathlib import Path


EXECUTION_GRANT_SCHEMA = "govern-ai-coding.archive-execution-grant.v1"
TASK_SCHEMA = "govern-ai-coding.archive-task.v1"
TASK_GRANT_SCHEMA = "govern-ai-coding.archive-task-execution-grant.v1"
TASK_SUMMARY_SCHEMA = "govern-ai-coding.archive-task-summary.v1"
AMENDMENT_SCHEMA = "govern-ai-coding.archive-mapping-amendment.v1"
NORMALIZED_RESULT_SCHEMA = "govern-ai-coding.normalized-result.v1"
VERDICTS = {"pass", "fail", "unproven"}
REFERENCE_HANDLINGS = {
    "disposition-required",
    "trace-only",
    "human-review",
}
HEX_256 = re.compile(r"^[0-9a-f]{64}$")


def canonical_json_digest(payload: object) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_intent_evidence(
    evidence: object,
    *,
    expected_scope_digest: str,
    code_prefix: str,
) -> tuple[list[dict], list[str]]:
    findings: list[dict] = []
    unverified: list[str] = []
    if not isinstance(evidence, dict):
        return [], [f"{code_prefix}-intent-evidence-required"]
    if evidence.get("kind") != "explicit-user-execution-instruction":
        findings.append({
            "code": f"invalid-{code_prefix}-intent-evidence",
            "field": "intent_evidence.kind",
        })
    statement = evidence.get("statement")
    if not isinstance(statement, str) or not statement.strip():
        unverified.append(f"{code_prefix}-intent-statement-required")
    if evidence.get("scope_sha256") != expected_scope_digest:
        findings.append({
            "code": f"{code_prefix}-intent-scope-mismatch",
            "field": "intent_evidence.scope_sha256",
            "expected": expected_scope_digest,
            "actual": evidence.get("scope_sha256"),
        })
    if evidence.get("not_inferred") is not True:
        unverified.append(f"{code_prefix}-intent-must-not-be-inferred")
    return findings, unverified


def _state_changes() -> dict:
    return {
        "source_moved": False,
        "target_created": False,
        "receipt_created": False,
        "temporary_artifacts": [],
    }


def _is_relative_safe_path(value: object) -> bool:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        return False
    normalized = value.replace("\\", "/")
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        return False
    parts = [part for part in normalized.split("/") if part not in {"", "."}]
    return bool(parts) and ".." not in parts


def _path_within(candidate: str, root: str) -> bool:
    candidate = candidate.replace("\\", "/").rstrip("/")
    root = root.replace("\\", "/").rstrip("/")
    return candidate == root or candidate.startswith(root + "/")


def _operation_parent(
    workspace: Path,
    value: object,
    *,
    allow_absolute: bool = False,
) -> Path | None:
    if (
        allow_absolute
        and isinstance(value, str)
        and Path(value).is_absolute()
    ):
        return Path(value).parent
    if not _is_relative_safe_path(value):
        return None
    path = workspace.joinpath(*[
        part
        for part in str(value).replace("\\", "/").split("/")
        if part not in {"", "."}
    ])
    try:
        path.resolve(strict=False).relative_to(workspace.resolve())
    except ValueError:
        return None
    return path.parent


def runtime_capability_report(
    workspace: Path,
    operations: list[dict],
    *,
    read_only: bool,
) -> dict:
    """Report required runtime and filesystem capabilities without probing writes."""
    diagnostics: list[dict] = []
    capabilities: list[dict] = []
    python_supported = tuple(sys.version_info[:2]) >= (3, 9)
    capabilities.append({
        "interface": "python",
        "capability": "minimum-version-3.9",
        "supported": python_supported,
    })
    if not python_supported:
        diagnostics.append({
            "code": "runtime-python-version-unsupported",
            "required": "3.9",
            "actual": platform.python_version(),
        })
    required_dir_fd = ("open", "stat", "rename", "unlink")
    for name in required_dir_fd:
        function = getattr(os, name, None)
        supported = (
            callable(function)
            and function in getattr(os, "supports_dir_fd", set())
        )
        capabilities.append({
            "interface": f"os.{name}",
            "capability": "dir_fd",
            "supported": supported,
        })
        if not supported:
            diagnostics.append({
                "code": "runtime-dir-fd-unsupported",
                "interface": f"os.{name}",
            })

    stat_function = getattr(os, "stat", None)
    follow_supported = (
        callable(stat_function)
        and stat_function in getattr(os, "supports_follow_symlinks", set())
    )
    capabilities.append({
        "interface": "os.stat",
        "capability": "follow_symlinks",
        "supported": follow_supported,
    })
    if not follow_supported:
        diagnostics.append({
            "code": "runtime-follow-symlinks-unsupported",
            "interface": "os.stat",
        })

    for flag in ("O_DIRECTORY", "O_NOFOLLOW", "O_CREAT", "O_EXCL"):
        supported = hasattr(os, flag)
        capabilities.append({
            "interface": f"os.{flag}",
            "capability": "descriptor-flag",
            "supported": supported,
        })
        if not supported:
            diagnostics.append({
                "code": "runtime-descriptor-flag-unsupported",
                "interface": f"os.{flag}",
            })

    lexical_workspace = Path(os.path.abspath(workspace))
    workspace = lexical_workspace.resolve()
    if not lexical_workspace.is_dir():
        diagnostics.append({
            "code": "runtime-workspace-unavailable",
            "path": str(lexical_workspace),
        })
    elif lexical_workspace.is_symlink():
        diagnostics.append({
            "code": "runtime-workspace-symlink",
            "path": str(lexical_workspace),
        })

    checked_parents: set[str] = set()
    for index, operation in enumerate(operations):
        if not isinstance(operation, dict):
            diagnostics.append({
                "code": "runtime-operation-invalid",
                "operation_index": index,
            })
            continue
        for field in ("source", "target", "receipt"):
            parent = _operation_parent(
                workspace,
                operation.get(field),
                allow_absolute=field == "receipt",
            )
            if parent is None:
                diagnostics.append({
                    "code": "runtime-operation-path-invalid",
                    "operation_index": index,
                    "field": field,
                })
                continue
            key = str(parent)
            if key in checked_parents:
                continue
            checked_parents.add(key)
            if not parent.is_dir():
                diagnostics.append({
                    "code": "runtime-parent-unavailable",
                    "operation_index": index,
                    "field": field,
                    "path": key,
                })
            elif parent.is_symlink():
                diagnostics.append({
                    "code": "runtime-parent-symlink",
                    "operation_index": index,
                    "field": field,
                    "path": key,
                })
            else:
                writable = os.access(
                    parent,
                    os.R_OK | os.W_OK | os.X_OK,
                )
                capabilities.append({
                    "interface": "filesystem-parent",
                    "capability": "read-write-search-access",
                    "path": key,
                    "supported": writable,
                })
                if not writable:
                    diagnostics.append({
                        "code": "runtime-parent-access-insufficient",
                        "operation_index": index,
                        "field": field,
                        "path": key,
                    })
                statvfs_function = getattr(os, "statvfs", None)
                try:
                    if not callable(statvfs_function):
                        raise OSError("os.statvfs is unavailable")
                    filesystem = statvfs_function(parent)
                except OSError as exc:
                    diagnostics.append({
                        "code": "runtime-filesystem-capability-unavailable",
                        "operation_index": index,
                        "field": field,
                        "path": key,
                        "message": str(exc),
                    })
                else:
                    read_only_flag = getattr(os, "ST_RDONLY", 1)
                    read_only_mount = bool(
                        filesystem.f_flag & read_only_flag
                    )
                    free_bytes = (
                        filesystem.f_bavail * filesystem.f_frsize
                    )
                    capabilities.append({
                        "interface": "filesystem-parent",
                        "capability": "writable-mounted-storage",
                        "path": key,
                        "supported": not read_only_mount and free_bytes > 0,
                        "read_only_mount": read_only_mount,
                        "available_bytes": free_bytes,
                    })
                    if read_only_mount:
                        diagnostics.append({
                            "code": "runtime-filesystem-read-only",
                            "operation_index": index,
                            "field": field,
                            "path": key,
                        })
                    if free_bytes <= 0:
                        diagnostics.append({
                            "code": "runtime-filesystem-space-unavailable",
                            "operation_index": index,
                            "field": field,
                            "path": key,
                        })

    return {
        "result": "fail" if diagnostics else "pass",
        "phase": "runtime-preflight",
        "read_only": read_only,
        "runtime": {
            "implementation": platform.python_implementation(),
            "version": platform.python_version(),
            "supported_policy": "Python 3.9+ with required descriptor capabilities",
        },
        "capabilities": capabilities,
        "diagnostics": diagnostics,
        "operations_not_performed": [
            "no source was moved",
            "no target or receipt was created",
            "no temporary probe was created",
        ],
        "state_changes": _state_changes(),
        "recovery_actions": [
            (
                "Use a Python 3.9 or newer runtime and filesystem that exposes "
                "all listed descriptor-relative and no-follow capabilities."
            )
        ] if diagnostics else [],
        "residual_risks": [
            (
                "Read-only checks cannot eliminate permission, capacity, "
                "mount, or path-identity changes between preflight and the "
                "descriptor-relative execution gate."
            )
        ],
    }


def structured_archive_exception(
    exc: BaseException,
    *,
    phase: str,
    mapping: dict | None,
    state_changes: dict | None = None,
) -> dict:
    return {
        "result": "fail",
        "mechanical_findings": [{
            "code": "controlled-archive-runtime-exception",
            "phase": phase,
            "exception_type": type(exc).__name__,
            "message": str(exc),
        }],
        "semantic_findings": [],
        "human_approval_required": [],
        "coverage": {"unverified": []},
        "controlled_archive": {
            "mapping": mapping,
            "moved": False,
            "state_changes": state_changes or _state_changes(),
        },
        "archive_receipt": None,
        "receipt_output": None,
        "recovery": (
            "Inspect the structured phase and filesystem facts, preserve every "
            "existing source and target, then rerun read-only preflight."
        ),
    }


def _collect_verdicts(payload: dict) -> list[tuple[str, str]]:
    candidates: list[tuple[str, str]] = []
    if payload.get("result") in VERDICTS:
        candidates.append(("result", payload["result"]))
    execution = payload.get("execution")
    if isinstance(execution, dict) and execution.get("result") in VERDICTS:
        candidates.append(("execution.result", execution["result"]))
    for key in ("archive_receipt", "closeout_receipt", "impact_receipt", "freeze_receipt"):
        nested = payload.get(key)
        if not isinstance(nested, dict):
            continue
        if nested.get("result") in VERDICTS:
            candidates.append((f"{key}.result", nested["result"]))
        nested_execution = nested.get("execution")
        if (
            isinstance(nested_execution, dict)
            and nested_execution.get("result") in VERDICTS
        ):
            candidates.append((
                f"{key}.execution.result",
                nested_execution["result"],
            ))
    return candidates


def _archive_result_requires_inspection(payload: dict) -> bool:
    controlled = payload.get("controlled_archive")
    state_changes = (
        controlled.get("state_changes")
        if isinstance(controlled, dict)
        else None
    )
    if (
        isinstance(state_changes, dict)
        and state_changes.get("state_requires_inspection") is True
    ):
        return True
    if any(
        isinstance(item, dict)
        and item.get("state") == "execution-outcome-unknown"
        for item in payload.get("operations", [])
    ):
        return True
    for item in payload.get("execution_results", []):
        if not isinstance(item, dict):
            continue
        if item.get("state") == "execution-outcome-unknown":
            return True
        nested = item.get("result")
        nested_controlled = (
            nested.get("controlled_archive")
            if isinstance(nested, dict)
            else None
        )
        nested_state_changes = (
            nested_controlled.get("state_changes")
            if isinstance(nested_controlled, dict)
            else None
        )
        if (
            isinstance(nested_state_changes, dict)
            and nested_state_changes.get("state_requires_inspection") is True
        ):
            return True
    return False


def normalize_archive_result(payload: dict) -> dict:
    if not isinstance(payload, dict):
        return {
            "schema": NORMALIZED_RESULT_SCHEMA,
            "schema_version": "1",
            "verdict": "unproven",
            "phase": "parsing",
            "operation_state": "unreadable",
            "changed": False,
            "atomicity": "unknown",
            "authorization_state": "unknown",
            "receipt_bindings": [],
            "diagnostics": [{"code": "result-root-not-object"}],
            "recovery": "Provide one JSON result or receipt object.",
        }
    outcome_requires_inspection = _archive_result_requires_inspection(payload)
    existing = payload.get("normalized_result")
    if (
        isinstance(existing, dict)
        and existing.get("schema") == NORMALIZED_RESULT_SCHEMA
        and not outcome_requires_inspection
    ):
        return json.loads(json.dumps(existing))

    candidates = _collect_verdicts(payload)
    verdicts = {value for _, value in candidates}
    diagnostics: list[dict] = []
    if len(verdicts) > 1:
        verdict = "unproven"
        diagnostics.append({
            "code": "conflicting-result-fields",
            "fields": [
                {"field": field, "value": value}
                for field, value in candidates
            ],
        })
    elif verdicts:
        verdict = next(iter(verdicts))
    else:
        verdict = "unproven"
        diagnostics.append({"code": "result-field-not-found"})
    if outcome_requires_inspection:
        verdict = "unproven"
        diagnostics.append({
            "code": "archive-execution-outcome-unknown",
            "recovery_actions": [
                (
                    "Run archive-task status as a read-only reconciliation; "
                    "retry only after it proves the operation did not complete."
                )
            ],
        })

    archive_receipt = (
        payload.get("archive_receipt")
        if isinstance(payload.get("archive_receipt"), dict)
        else payload
    )
    is_archive_receipt = (
        isinstance(archive_receipt, dict)
        and (
            archive_receipt.get("kind") == "controlled-archive"
            or archive_receipt.get("schema") == "govern-ai-coding.archive-receipt.v1"
        )
    )
    controlled = payload.get("controlled_archive")
    moved = (
        isinstance(controlled, dict)
        and controlled.get("moved") is True
    )
    changed = moved or (is_archive_receipt and verdict == "pass")
    is_task = (
        payload.get("schema") in {TASK_SCHEMA, TASK_SUMMARY_SCHEMA}
        or payload.get("task_atomicity")
        == "non-atomic-independent-operations"
        or isinstance(payload.get("operations"), list)
        and payload.get("atomicity") == "non-atomic-independent-operations"
    )
    if is_task and any(
        isinstance(item, dict)
        and item.get("state") == "completed-receipt-verified"
        for item in payload.get("operations", [])
    ):
        changed = True
    phase = payload.get("phase")
    if not isinstance(phase, str):
        phase = "task-summary" if is_task else (
            "execution" if changed else "parsing"
        )
    operation_state = payload.get("operation_state")
    if not isinstance(operation_state, str):
        if outcome_requires_inspection:
            operation_state = "execution-outcome-unknown"
        elif payload.get("analysis_only") is True or phase in {
            "preflight",
            "task-preflight",
            "runtime-preflight",
        }:
            operation_state = (
                "preflight-passed"
                if verdict == "pass"
                else "preflight-not-passed"
            )
        else:
            operation_state = (
                "completed"
                if verdict == "pass" and changed
                else "requires-attention"
            )
    authorization_state = payload.get("authorization_state")
    if not isinstance(authorization_state, str):
        if (
            payload.get("analysis_only") is True
            or payload.get("execution_approved") is False
        ):
            authorization_state = "not-granted"
        else:
            authorization_state = "bound" if changed else "unknown"
    return {
        "schema": NORMALIZED_RESULT_SCHEMA,
        "schema_version": "1",
        "verdict": verdict,
        "phase": phase,
        "operation_state": operation_state,
        "changed": changed,
        "atomicity": (
            "non-atomic-independent-operations"
            if is_task
            else "single-file" if is_archive_receipt or moved else "none"
        ),
        "authorization_state": authorization_state,
        "receipt_bindings": payload.get("receipt_bindings", []),
        "source_fields": [
            {"field": field, "value": value}
            for field, value in candidates
        ],
        "diagnostics": diagnostics,
        "recovery": payload.get("recovery") or (
            "Run archive-task status before any retry."
            if outcome_requires_inspection
            else None
        ),
    }


def validate_execution_grant(
    grant: dict | None,
    *,
    request_digest: str,
    preflight_digest: str,
    operation: dict,
    approval_digest: str,
    amendment_digest: str | None,
) -> tuple[dict | None, list[dict], list[str]]:
    findings: list[dict] = []
    unverified: list[str] = []
    if grant is None:
        return None, [], ["archive-execution-intent-required"]
    if not isinstance(grant, dict):
        return None, [{"code": "invalid-archive-execution-grant", "field": "root"}], []
    if grant.get("schema") != EXECUTION_GRANT_SCHEMA:
        findings.append({
            "code": "invalid-archive-execution-grant",
            "field": "schema",
        })
    if grant.get("schema_version") != "1":
        findings.append({
            "code": "invalid-archive-execution-grant",
            "field": "schema_version",
        })
    if grant.get("mode") != "execute":
        unverified.append("archive-execution-intent-required")

    expected = {
        "request_sha256": request_digest,
        "preflight_sha256": preflight_digest,
        "approval_sha256": approval_digest,
        "amendment_sha256": amendment_digest,
        "operation": operation,
    }
    for field, value in expected.items():
        if grant.get(field) != value:
            findings.append({
                "code": "archive-execution-grant-binding-mismatch",
                "field": field,
                "expected": value,
                "actual": grant.get(field),
            })
    intent_findings, intent_unverified = _validate_intent_evidence(
        grant.get("intent_evidence"),
        expected_scope_digest=canonical_json_digest(operation),
        code_prefix="archive-execution",
    )
    findings.extend(intent_findings)
    unverified.extend(intent_unverified)
    boundaries = grant.get("boundaries")
    required_boundaries = (
        "irreversible_move_acknowledged",
        "single_file_independent_transaction",
        "no_multi_file_atomicity",
        "no_overwrite",
    )
    if not isinstance(boundaries, dict):
        findings.append({
            "code": "invalid-archive-execution-grant",
            "field": "boundaries",
        })
    else:
        for field in required_boundaries:
            if boundaries.get(field) is not True:
                unverified.append(f"archive-boundary-unacknowledged:{field}")
    if findings or unverified:
        return None, findings, sorted(set(unverified))
    return json.loads(json.dumps(grant)), [], []


def validate_reference_rules(adapter: dict) -> list[dict]:
    config = adapter.get("controlled_archive", {})
    if not isinstance(config, dict):
        return [{"code": "invalid-controlled-archive-config"}]
    rules = config.get("reference_rules", [])
    if rules is None:
        return []
    if not isinstance(rules, list):
        return [{
            "code": "invalid-archive-reference-rules",
            "field": "controlled_archive.reference_rules",
        }]
    findings: list[dict] = []
    identifiers: set[str] = set()
    for index, rule in enumerate(rules):
        field = f"controlled_archive.reference_rules.{index}"
        if not isinstance(rule, dict):
            findings.append({"code": "invalid-archive-reference-rule", "field": field})
            continue
        identifier = rule.get("id")
        if not isinstance(identifier, str) or not identifier.strip():
            findings.append({"code": "invalid-archive-reference-rule", "field": f"{field}.id"})
        elif identifier in identifiers:
            findings.append({"code": "duplicate-archive-reference-rule", "id": identifier})
        else:
            identifiers.add(identifier)
        selectors = rule.get("selectors")
        patterns = rule.get("patterns", [])
        if (
            not isinstance(selectors, list)
            or not selectors
            or not all(isinstance(item, str) and item for item in selectors)
        ):
            findings.append({"code": "invalid-archive-reference-rule", "field": f"{field}.selectors"})
        if (
            not isinstance(patterns, list)
            or not all(isinstance(item, str) and item for item in patterns)
        ):
            findings.append({"code": "invalid-archive-reference-rule", "field": f"{field}.patterns"})
        if not isinstance(rule.get("category"), str) or not rule.get("category"):
            findings.append({"code": "invalid-archive-reference-rule", "field": f"{field}.category"})
        if rule.get("handling") not in REFERENCE_HANDLINGS:
            findings.append({"code": "invalid-archive-reference-rule", "field": f"{field}.handling"})
    policies = config.get("mapping_amendment_policies", [])
    if not isinstance(policies, list):
        findings.append({
            "code": "invalid-archive-amendment-policies",
            "field": "controlled_archive.mapping_amendment_policies",
        })
    else:
        policy_ids: set[str] = set()
        for index, policy in enumerate(policies):
            field = f"controlled_archive.mapping_amendment_policies.{index}"
            if not isinstance(policy, dict):
                findings.append({
                    "code": "invalid-archive-amendment-policy",
                    "field": field,
                })
                continue
            identifier = policy.get("id")
            allowed = policy.get("allowed_changed_fields")
            supplemental_type = policy.get("supplemental_approval_type")
            if (
                not isinstance(identifier, str)
                or not identifier
                or identifier in policy_ids
            ):
                findings.append({
                    "code": "invalid-archive-amendment-policy",
                    "field": f"{field}.id",
                })
            else:
                policy_ids.add(identifier)
            if (
                not isinstance(allowed, list)
                or not allowed
                or not all(item == "target" for item in allowed)
            ):
                findings.append({
                    "code": "invalid-archive-amendment-policy",
                    "field": f"{field}.allowed_changed_fields",
                })
            if (
                not isinstance(supplemental_type, str)
                or not supplemental_type
                or supplemental_type not in adapter.get("human_approval", [])
            ):
                findings.append({
                    "code": "invalid-archive-amendment-policy",
                    "field": f"{field}.supplemental_approval_type",
                })

    scopes = config.get("authorization_scopes", [])
    if not isinstance(scopes, list):
        findings.append({
            "code": "invalid-archive-authorization-scopes",
            "field": "controlled_archive.authorization_scopes",
        })
    else:
        scope_ids: set[str] = set()
        for index, scope in enumerate(scopes):
            field = f"controlled_archive.authorization_scopes.{index}"
            if not isinstance(scope, dict):
                findings.append({
                    "code": "invalid-archive-authorization-scope",
                    "field": field,
                })
                continue
            identifier = scope.get("id")
            roots = scope.get("source_roots")
            if (
                not isinstance(identifier, str)
                or not identifier
                or identifier in scope_ids
            ):
                findings.append({
                    "code": "invalid-archive-authorization-scope",
                    "field": f"{field}.id",
                })
            else:
                scope_ids.add(identifier)
            if (
                not isinstance(roots, list)
                or not roots
                or not all(_is_relative_safe_path(root) for root in roots)
            ):
                findings.append({
                    "code": "invalid-archive-authorization-scope",
                    "field": f"{field}.source_roots",
                })
            else:
                source_roots = config.get("source_roots", [])
                boundaries = adapter.get("boundaries", {})
                entrypoints = adapter.get("entrypoints", {})
                forbidden = [
                    *(
                        boundaries.get("excluded", [])
                        if isinstance(boundaries, dict)
                        and isinstance(boundaries.get("excluded", []), list)
                        else []
                    ),
                    *(
                        boundaries.get("protected", [])
                        if isinstance(boundaries, dict)
                        and isinstance(boundaries.get("protected", []), list)
                        else []
                    ),
                    *(
                        entrypoints.get("historical", [])
                        if isinstance(entrypoints, dict)
                        and isinstance(entrypoints.get("historical", []), list)
                        else []
                    ),
                    *(
                        config.get("archive_roots", [])
                        if isinstance(config.get("archive_roots", []), list)
                        else []
                    ),
                ]
                for root in roots:
                    if (
                        not isinstance(source_roots, list)
                        or not any(
                            isinstance(source_root, str)
                            and _path_within(root, source_root)
                            for source_root in source_roots
                        )
                    ):
                        findings.append({
                            "code": "archive-authorization-scope-not-active",
                            "field": f"{field}.source_roots",
                            "path": root,
                        })
                    overlaps = [
                        pattern
                        for pattern in forbidden
                        if isinstance(pattern, str)
                        and (
                            _path_within(root, pattern)
                            or _path_within(pattern, root)
                        )
                    ]
                    if overlaps:
                        findings.append({
                            "code": "archive-authorization-scope-boundary-overlap",
                            "field": f"{field}.source_roots",
                            "path": root,
                            "matched": overlaps,
                        })
    return findings


def _reference_rule_matches(rule: dict, reference: dict) -> bool:
    reference_selectors = reference.get("selectors")
    if not isinstance(reference_selectors, list):
        reference_selectors = [reference.get("selector")]
    if not set(reference_selectors).intersection(rule.get("selectors", [])):
        return False
    patterns = rule.get("patterns", [])
    return not patterns or any(
        fnmatch.fnmatchcase(str(reference.get("path", "")), pattern)
        for pattern in patterns
    )


def classify_archive_references(
    adapter: dict,
    discovered: list[dict],
    scanned_scopes: list[dict],
) -> dict:
    config = adapter.get("controlled_archive", {})
    rules = config.get("reference_rules", []) if isinstance(config, dict) else []
    classified: list[dict] = []
    blocking: list[dict] = []
    for raw in discovered:
        reference = dict(raw)
        matches = [
            rule for rule in rules
            if isinstance(rule, dict) and _reference_rule_matches(rule, raw)
        ]
        if len(matches) == 1:
            rule = matches[0]
            reference["category"] = rule["category"]
            reference["handling"] = rule["handling"]
            reference["classification_rule"] = rule["id"]
        else:
            reference["category"] = "unclassified"
            reference["handling"] = "human-review"
            reference["classification_rule"] = None
            reference["classification_conflict"] = [
                rule.get("id") for rule in matches
            ]
        reference.setdefault("disposition", "unresolved")
        if reference["handling"] == "trace-only":
            reference["required_action"] = "preserve trace; no current-dependency disposition required"
        elif reference["handling"] == "disposition-required":
            reference["required_action"] = "provide an exact disposition for this current dependency"
            blocking.append(reference)
        else:
            reference["required_action"] = "classify or obtain explicit human review before execution"
            blocking.append(reference)
        classified.append(reference)
    return {
        "scanned_scopes": scanned_scopes,
        "discovered": classified,
        "blocking": blocking,
        "required_actions": [
            {
                "path": item.get("path"),
                "line": item.get("line"),
                "column": item.get("column"),
                "category": item.get("category"),
                "action": item.get("required_action"),
            }
            for item in blocking
        ],
    }


def build_archive_preflight(
    *,
    request: dict,
    mapping: dict | None,
    runtime: dict,
    references: dict,
    findings: list[dict],
    unverified: list[str],
    approval_digest: str | None,
) -> dict:
    verdict = "fail" if findings else "unproven" if unverified else "pass"
    stable = {
        "request_sha256": canonical_json_digest(request),
        "mapping": mapping,
        "runtime_result": runtime.get("result"),
        "references": references,
        "approval_sha256": approval_digest,
        "findings": findings,
        "unverified": sorted(set(unverified)),
    }
    return {
        "schema": "govern-ai-coding.archive-preflight.v1",
        "schema_version": "1",
        "result": verdict,
        "phase": "preflight",
        "analysis_only": True,
        "execution_approved": False,
        "files_moved": [],
        "atomicity": "none-read-only",
        "request_sha256": stable["request_sha256"],
        "preflight_sha256": canonical_json_digest(stable),
        "mapping": mapping,
        "approval_sha256": approval_digest,
        "runtime": runtime,
        "references": references,
        "mechanical_findings": findings,
        "coverage": {"unverified": sorted(set(unverified))},
        "recovery": (
            "Resolve every finding, then obtain a separately bound execution "
            "grant; this read-only result is not execution approval."
        ),
    }


def validate_archive_task_manifest(
    manifest: dict,
) -> tuple[dict | None, list[dict]]:
    findings: list[dict] = []
    if not isinstance(manifest, dict):
        return None, [{"code": "invalid-archive-task", "field": "root"}]
    if manifest.get("schema") != TASK_SCHEMA:
        findings.append({"code": "invalid-archive-task", "field": "schema"})
    if manifest.get("schema_version") != "1":
        findings.append({"code": "invalid-archive-task", "field": "schema_version"})
    operations = manifest.get("operations")
    if not isinstance(operations, list) or not operations:
        findings.append({"code": "invalid-archive-task", "field": "operations"})
        return None if findings else manifest, findings
    seen_ids: set[str] = set()
    for index, operation in enumerate(operations):
        field = f"operations.{index}"
        if not isinstance(operation, dict):
            findings.append({"code": "invalid-archive-task-operation", "field": field})
            continue
        identifier = operation.get("id")
        if not isinstance(identifier, str) or not identifier:
            findings.append({"code": "invalid-archive-task-operation", "field": f"{field}.id"})
        elif identifier in seen_ids:
            findings.append({"code": "duplicate-archive-task-operation", "id": identifier})
        else:
            seen_ids.add(identifier)
        request = operation.get("request")
        if not isinstance(request, dict):
            findings.append({"code": "invalid-archive-task-operation", "field": f"{field}.request"})
        if not _is_relative_safe_path(operation.get("receipt")):
            findings.append({"code": "invalid-archive-task-operation", "field": f"{field}.receipt"})
    if findings:
        return None, findings
    return json.loads(json.dumps(manifest)), []


def global_archive_preflight(
    manifest: dict,
    operation_preflights: list[dict],
    runtime: dict,
) -> dict:
    normalized, findings = validate_archive_task_manifest(manifest)
    operations = normalized.get("operations", []) if normalized else []
    if len(operation_preflights) != len(operations):
        findings.append({
            "code": "archive-task-preflight-count-mismatch",
            "expected": len(operations),
            "actual": len(operation_preflights),
        })
    seen: dict[str, dict[str, str]] = {
        "source": {},
        "target": {},
        "receipt": {},
    }
    path_owners: dict[str, list[dict[str, str]]] = {}
    portable_path_owners: dict[str, list[dict[str, str]]] = {}
    for operation in operations:
        request = operation.get("request", {})
        mapping = request.get("mapping", {}) if isinstance(request, dict) else {}
        values = {
            "source": mapping.get("source"),
            "target": mapping.get("target"),
            "receipt": operation.get("receipt"),
        }
        for field, value in values.items():
            if not isinstance(value, str):
                findings.append({
                    "code": "invalid-archive-task-operation",
                    "operation": operation.get("id"),
                    "field": field,
                })
                continue
            previous = seen[field].get(value)
            if previous is not None:
                findings.append({
                    "code": f"duplicate-archive-task-{field}",
                    "path": value,
                    "operations": [previous, operation.get("id")],
                })
            else:
                seen[field][value] = operation.get("id")
            path_owners.setdefault(value, []).append({
                "operation": operation.get("id"),
                "role": field,
            })
            portable_key = unicodedata.normalize("NFC", value).casefold()
            portable_path_owners.setdefault(portable_key, []).append({
                "operation": operation.get("id"),
                "role": field,
                "path": value,
            })
        target = values.get("target")
        if isinstance(target, str) and target in seen["source"]:
            findings.append({
                "code": "archive-task-source-target-alias",
                "path": target,
                "operations": [
                    seen["source"][target],
                    operation.get("id"),
                ],
            })
    for path, owners in path_owners.items():
        roles = {item["role"] for item in owners}
        if len(roles) > 1:
            findings.append({
                "code": "archive-task-cross-role-path-alias",
                "path": path,
                "owners": owners,
            })
    for owners in portable_path_owners.values():
        distinct_paths = {item["path"] for item in owners}
        if len(distinct_paths) > 1:
            findings.append({
                "code": "archive-task-portable-path-collision",
                "paths": sorted(distinct_paths),
                "owners": owners,
                "normalization": "unicode-nfc-casefold",
            })
    if runtime.get("result") != "pass":
        findings.extend(runtime.get("diagnostics", []))
    preflights_by_id: dict[str, dict] = {}
    for index, preflight in enumerate(operation_preflights):
        identifier = preflight.get("task_operation_id")
        if not isinstance(identifier, str) or identifier in preflights_by_id:
            findings.append({
                "code": "archive-task-preflight-operation-id-invalid",
                "operation_index": index,
                "operation_id": identifier,
            })
            continue
        preflights_by_id[identifier] = preflight
        if preflight.get("result") != "pass":
            findings.append({
                "code": "archive-task-operation-preflight-not-pass",
                "operation": identifier,
                "result": preflight.get("result"),
            })
    for operation in operations:
        identifier = operation.get("id")
        preflight = preflights_by_id.get(identifier)
        if preflight is None:
            findings.append({
                "code": "archive-task-operation-preflight-missing",
                "operation": identifier,
            })
            continue
        request = operation["request"]
        mapping = request.get("mapping", {})
        expected_operation = {
            "source": mapping.get("source"),
            "target": mapping.get("target"),
            "receipt": operation.get("receipt"),
        }
        bindings = {
            "request_sha256": canonical_json_digest(request),
            "mapping": mapping,
        }
        for field, expected in bindings.items():
            if preflight.get(field) != expected:
                findings.append({
                    "code": "archive-task-operation-preflight-binding-mismatch",
                    "operation": identifier,
                    "field": field,
                })
        actual_operation = preflight.get("operation")
        for field, expected in expected_operation.items():
            if (
                not isinstance(actual_operation, dict)
                or actual_operation.get(field) != expected
            ):
                findings.append({
                    "code": "archive-task-operation-preflight-binding-mismatch",
                    "operation": identifier,
                    "field": f"operation.{field}",
                })
        if (
            not isinstance(actual_operation, dict)
            or HEX_256.match(
                str(actual_operation.get("source_sha256", ""))
            ) is None
            or not isinstance(actual_operation.get("source_size"), int)
            or actual_operation.get("source_size") < 0
        ):
            findings.append({
                "code": "archive-task-operation-preflight-binding-mismatch",
                "operation": identifier,
                "field": "operation.source_identity",
            })
    result = "fail" if findings else "pass"
    stable = {
        "manifest_sha256": canonical_json_digest(manifest),
        "operation_preflight_sha256": [
            item.get("preflight_sha256") for item in operation_preflights
        ],
        "runtime_result": runtime.get("result"),
        "findings": findings,
    }
    return {
        "schema": "govern-ai-coding.archive-task-preflight.v1",
        "schema_version": "1",
        "result": result,
        "phase": "task-preflight",
        "analysis_only": True,
        "execution_approved": False,
        "files_moved": [],
        "atomicity": "none-read-only",
        "task_atomicity": "non-atomic-independent-operations",
        "manifest_sha256": stable["manifest_sha256"],
        "preflight_sha256": canonical_json_digest(stable),
        "operation_preflights": operation_preflights,
        "runtime": runtime,
        "mechanical_findings": findings,
        "recovery": (
            "Resolve every global and per-operation finding. A passing task "
            "preflight still requires an exact execution grant."
        ),
    }


def validate_task_execution_grant(
    grant: dict | None,
    *,
    manifest_digest: str,
    preflight_digest: str,
    operation_ids: list[str],
) -> tuple[dict | None, list[dict], list[str]]:
    if grant is None:
        return None, [], ["archive-task-execution-intent-required"]
    findings: list[dict] = []
    unverified: list[str] = []
    if not isinstance(grant, dict):
        return None, [{"code": "invalid-archive-task-execution-grant"}], []
    if grant.get("schema") != TASK_GRANT_SCHEMA:
        findings.append({
            "code": "invalid-archive-task-execution-grant",
            "field": "schema",
        })
    if grant.get("schema_version") != "1":
        findings.append({
            "code": "invalid-archive-task-execution-grant",
            "field": "schema_version",
        })
    if grant.get("mode") != "execute":
        unverified.append("archive-task-execution-intent-required")
    if grant.get("manifest_sha256") != manifest_digest:
        findings.append({
            "code": "archive-task-grant-binding-mismatch",
            "field": "manifest_sha256",
        })
    if grant.get("preflight_sha256") != preflight_digest:
        findings.append({
            "code": "archive-task-grant-binding-mismatch",
            "field": "preflight_sha256",
        })
    intent_scope = {
        "manifest_sha256": manifest_digest,
        "operation_ids": sorted(operation_ids),
    }
    intent_findings, intent_unverified = _validate_intent_evidence(
        grant.get("intent_evidence"),
        expected_scope_digest=canonical_json_digest(intent_scope),
        code_prefix="archive-task-execution",
    )
    findings.extend(intent_findings)
    unverified.extend(intent_unverified)
    grants = grant.get("operation_grants")
    if not isinstance(grants, dict) or sorted(grants) != sorted(operation_ids):
        findings.append({
            "code": "archive-task-grant-operation-scope-mismatch",
            "expected": sorted(operation_ids),
            "actual": sorted(grants) if isinstance(grants, dict) else None,
        })
    boundaries = grant.get("boundaries")
    if not isinstance(boundaries, dict):
        findings.append({
            "code": "invalid-archive-task-execution-grant",
            "field": "boundaries",
        })
    else:
        for field in (
            "independent_single_file_transactions",
            "no_multi_file_atomicity",
            "no_completed_operation_rollback",
            "no_scope_extension",
        ):
            if boundaries.get(field) is not True:
                unverified.append(f"archive-task-boundary-unacknowledged:{field}")
    if findings or unverified:
        return None, findings, sorted(set(unverified))
    return json.loads(json.dumps(grant)), [], []


def validate_receipt_grant_binding(
    receipt: dict,
    original_grant: dict,
) -> list[dict]:
    execution = receipt.get("execution")
    authorization = (
        execution.get("authorization")
        if isinstance(execution, dict)
        else None
    )
    if not isinstance(authorization, dict) or not isinstance(
        original_grant,
        dict,
    ):
        return [{"code": "archive-task-receipt-grant-mismatch"}]
    refreshed = json.loads(json.dumps(original_grant))
    refreshed["preflight_sha256"] = authorization.get("preflight_sha256")
    if (
        authorization.get("amendment_sha256")
        != refreshed.get("amendment_sha256")
        or authorization.get("grant_sha256")
        != canonical_json_digest(refreshed)
    ):
        return [{"code": "archive-task-receipt-grant-mismatch"}]
    return []


def reconcile_archive_task(
    manifest: dict,
    operation_preflights: list[dict],
    receipt_payloads: dict[str, dict],
    *,
    workspace: Path | None = None,
) -> dict:
    normalized, findings = validate_archive_task_manifest(manifest)
    states: list[dict] = []
    if normalized is not None:
        for index, operation in enumerate(normalized["operations"]):
            identifier = operation["id"]
            preflight = (
                operation_preflights[index]
                if index < len(operation_preflights)
                else {}
            )
            receipt = receipt_payloads.get(identifier)
            if receipt is None:
                state = (
                    "preflight-passed"
                    if preflight.get("result") == "pass"
                    else "not-started"
                )
            else:
                view = normalize_archive_result(receipt)
                request = operation["request"]
                expected_mapping = request.get("mapping")
                receipt_mapping = (
                    receipt.get("mapping")
                    if isinstance(receipt, dict)
                    else None
                )
                receipt_findings = _archive_receipt_completion_findings(
                    receipt,
                    operation,
                    workspace=workspace,
                )
                if (
                    view["verdict"] == "pass"
                    and view["changed"]
                    and receipt_mapping == expected_mapping
                    and receipt.get("request_sha256") == canonical_json_digest(request)
                    and not receipt_findings
                ):
                    state = "completed-receipt-verified"
                else:
                    state = "revision-required"
                    findings.extend(receipt_findings or [{
                        "code": "archive-task-receipt-binding-mismatch",
                        "operation": identifier,
                    }])
            preflight_passed = preflight.get("result") == "pass"
            states.append({
                "id": identifier,
                "request_sha256": canonical_json_digest(
                    operation["request"]
                ),
                "receipt_sha256": (
                    canonical_json_digest(receipt)
                    if isinstance(receipt, dict)
                    else None
                ),
                "state": state,
                "preflight_state": (
                    "passed"
                    if preflight_passed
                    else "not-passed"
                ),
                "authorization_state": (
                    "completed-receipt-bound"
                    if state == "completed-receipt-verified"
                    else "revision-required"
                    if state == "revision-required"
                    else "awaiting-explicit-authorization"
                ),
                "resumable": (
                    state == "execution-failed"
                    or preflight_passed
                    and state in {"not-started", "preflight-passed"}
                ),
            })
    if findings or any(
        item["state"] in {"revision-required", "execution-failed"}
        or item["preflight_state"] == "not-passed"
        for item in states
    ):
        result = "fail"
    elif states and all(
        item["state"] == "completed-receipt-verified"
        for item in states
    ):
        result = "pass"
    else:
        result = "unproven"
    return {
        "schema": TASK_SUMMARY_SCHEMA,
        "schema_version": "1",
        "result": result,
        "phase": "task-summary",
        "manifest_sha256": canonical_json_digest(manifest),
        "atomicity": "non-atomic-independent-operations",
        "rollback_completed_operations": False,
        "operations": states,
        "mechanical_findings": findings,
    }


def _archive_receipt_completion_findings(
    receipt: dict,
    operation: dict,
    *,
    workspace: Path | None,
) -> list[dict]:
    identifier = operation.get("id")
    findings: list[dict] = []
    if workspace is None:
        return [{
            "code": "archive-task-receipt-workspace-required",
            "operation": identifier,
        }]
    request = operation.get("request", {})
    mapping = request.get("mapping", {}) if isinstance(request, dict) else {}
    source = mapping.get("source")
    target = mapping.get("target")
    receipt_path_value = operation.get("receipt")
    for field, value in (
        ("mapping.source", source),
        ("mapping.target", target),
        ("receipt", receipt_path_value),
    ):
        if not _is_relative_safe_path(value):
            findings.append({
                "code": "archive-task-receipt-state-mismatch",
                "operation": identifier,
                "field": field,
            })
    if findings:
        return findings

    workspace = workspace.resolve()

    def resolved_child(value: str) -> Path | None:
        candidate = (workspace / value).resolve()
        try:
            candidate.relative_to(workspace)
        except ValueError:
            return None
        return candidate

    source_path = resolved_child(source)
    target_path = resolved_child(target)
    receipt_path = resolved_child(receipt_path_value)
    if source_path is None or target_path is None or receipt_path is None:
        return [{
            "code": "archive-task-receipt-state-mismatch",
            "operation": identifier,
            "field": "workspace-boundary",
        }]
    try:
        actual_receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        actual_receipt = None
    content = receipt.get("content")
    execution = receipt.get("execution")
    authorization = (
        execution.get("authorization")
        if isinstance(execution, dict)
        else None
    )
    before = content.get("before_sha256") if isinstance(content, dict) else None
    after = content.get("after_sha256") if isinstance(content, dict) else None
    structurally_valid = (
        receipt.get("schema") == "govern-ai-coding.archive-receipt.v1"
        and receipt.get("schema_version") == "1"
        and receipt.get("kind") == "controlled-archive"
        and receipt.get("immutable") is True
        and receipt.get("derived_evidence") is True
        and receipt.get("generated") is True
        and receipt.get("project_authority") is False
        and receipt.get("request_sha256") == canonical_json_digest(request)
        and receipt.get("mapping") == mapping
        and isinstance(content, dict)
        and content.get("unchanged") is True
        and isinstance(before, str)
        and HEX_256.match(before) is not None
        and before == after
        and isinstance(execution, dict)
        and execution.get("result") == "pass"
        and isinstance(authorization, dict)
        and authorization.get("grant_schema") == EXECUTION_GRANT_SCHEMA
        and HEX_256.match(str(authorization.get("grant_sha256", ""))) is not None
        and HEX_256.match(str(authorization.get("preflight_sha256", ""))) is not None
        and actual_receipt == receipt
    )
    state_valid = (
        not source_path.exists()
        and not source_path.is_symlink()
        and target_path.is_file()
        and not target_path.is_symlink()
        and receipt_path.is_file()
        and not receipt_path.is_symlink()
    )
    digest_valid = False
    if state_valid and isinstance(after, str):
        try:
            digest_valid = (
                _file_sha256(target_path) == after
                and content.get("source_size") == target_path.stat().st_size
            )
        except OSError:
            digest_valid = False
    if not structurally_valid or not state_valid or not digest_valid:
        findings.append({
            "code": "archive-task-receipt-state-mismatch",
            "operation": identifier,
            "receipt": receipt_path_value,
            "source_absent": (
                not source_path.exists() and not source_path.is_symlink()
            ),
            "target_verified": state_valid and digest_valid,
            "receipt_verified": structurally_valid,
        })
    return findings


def validate_mapping_amendment(
    adapter: dict,
    amendment: dict,
    *,
    original_operation: dict,
    original_grant_digest: str,
) -> tuple[dict | None, list[dict], list[str]]:
    findings: list[dict] = []
    unverified: list[str] = []
    if not isinstance(amendment, dict):
        return None, [{"code": "invalid-archive-mapping-amendment", "field": "root"}], []
    if amendment.get("schema") != AMENDMENT_SCHEMA:
        findings.append({"code": "invalid-archive-mapping-amendment", "field": "schema"})
    if amendment.get("schema_version") != "1":
        findings.append({"code": "invalid-archive-mapping-amendment", "field": "schema_version"})
    if amendment.get("original_grant_sha256") != original_grant_digest:
        findings.append({
            "code": "archive-amendment-binding-mismatch",
            "field": "original_grant_sha256",
        })
    original = amendment.get("original_mapping")
    corrected = amendment.get("corrected_mapping")
    if original != original_operation.get("mapping"):
        findings.append({
            "code": "archive-amendment-binding-mismatch",
            "field": "original_mapping",
        })
    if not isinstance(corrected, dict):
        findings.append({
            "code": "invalid-archive-mapping-amendment",
            "field": "corrected_mapping",
        })
        corrected = {}
    material_fields: list[str] = []
    if isinstance(original, dict):
        if corrected.get("source") != original.get("source"):
            material_fields.append("source")
    if amendment.get("authority_disposition_sha256") != original_operation.get(
        "authority_disposition_sha256"
    ):
        material_fields.append("authority_disposition")
    root_binding = amendment.get("archive_root_binding")
    original_root_digest = original_operation.get("archive_root_sha256")
    corrected_root_digest = original_operation.get(
        "corrected_archive_root_sha256"
    )
    if (
        not isinstance(root_binding, dict)
        or root_binding.get("original_sha256") != original_root_digest
        or root_binding.get("corrected_sha256") != corrected_root_digest
        or HEX_256.match(str(original_root_digest or "")) is None
        or HEX_256.match(str(corrected_root_digest or "")) is None
    ):
        findings.append({
            "code": "archive-amendment-root-binding-mismatch",
        })
    if original_root_digest != corrected_root_digest:
        material_fields.append("archive_root")
    for field in (
        "archive_visibility",
        "archive_root_class",
        "recovery_boundary",
        "approval_type",
    ):
        original_value = original_operation.get(field)
        if amendment.get(field) != original_value:
            material_fields.append(field)
    if material_fields:
        unverified.append("new-explicit-approval-required")
        findings.append({
            "code": "archive-amendment-material-scope-change",
            "fields": sorted(set(material_fields)),
        })

    config = adapter.get("controlled_archive", {})
    policies = (
        config.get("mapping_amendment_policies", [])
        if isinstance(config, dict)
        else []
    )
    policy_id = amendment.get("policy_id")
    matches = [
        item for item in policies
        if isinstance(item, dict) and item.get("id") == policy_id
    ]
    if len(matches) != 1:
        findings.append({
            "code": "archive-amendment-policy-unavailable",
            "policy_id": policy_id,
        })
    else:
        allowed = set(matches[0].get("allowed_changed_fields", []))
        supplemental_type = matches[0].get("supplemental_approval_type")
        changed = {
            field
            for field in set((original or {}).keys()) | set(corrected.keys())
            if (original or {}).get(field) != corrected.get(field)
        }
        if not changed or not changed.issubset(allowed):
            findings.append({
                "code": "archive-amendment-change-not-permitted",
                "changed_fields": sorted(changed),
                "allowed_changed_fields": sorted(allowed),
            })
    evidence = amendment.get("supplemental_evidence")
    if (
        not isinstance(evidence, dict)
        or not isinstance(evidence.get("path"), str)
        or not HEX_256.match(str(evidence.get("sha256", "")))
        or evidence.get("type") != (
            matches[0].get("supplemental_approval_type")
            if len(matches) == 1
            else None
        )
        or not isinstance(amendment.get("reason"), str)
        or not amendment.get("reason", "").strip()
    ):
        unverified.append("archive-amendment-supplemental-evidence-required")
    if findings or unverified:
        return None, findings, sorted(set(unverified))
    return json.loads(json.dumps(amendment)), [], []


def archive_authorization_lifecycle(
    adapter: dict,
    workspace: Path,
    *,
    authorization_id: str | None = None,
) -> dict:
    config = adapter.get("controlled_archive", {})
    scopes = (
        config.get("authorization_scopes", [])
        if isinstance(config, dict)
        else []
    )
    findings: list[dict] = []
    reports: list[dict] = []
    if not isinstance(scopes, list):
        findings.append({
            "code": "invalid-archive-authorization-scopes",
        })
        scopes = []
    for scope in scopes:
        if not isinstance(scope, dict):
            findings.append({"code": "invalid-archive-authorization-scope"})
            continue
        identifier = scope.get("id")
        if authorization_id is not None and identifier != authorization_id:
            continue
        roots = scope.get("source_roots")
        if (
            not isinstance(identifier, str)
            or not isinstance(roots, list)
            or not all(_is_relative_safe_path(root) for root in roots)
        ):
            findings.append({
                "code": "invalid-archive-authorization-scope",
                "authorization_id": identifier,
            })
            continue
        active_objects: list[str] = []
        for root in roots:
            candidate = workspace / root
            try:
                candidate.resolve(strict=False).relative_to(workspace.resolve())
            except ValueError:
                findings.append({
                    "code": "archive-authorization-scope-escape",
                    "authorization_id": identifier,
                    "path": root,
                })
                continue
            if candidate.is_symlink():
                findings.append({
                    "code": "archive-authorization-scope-symlink",
                    "authorization_id": identifier,
                    "path": root,
                })
                continue
            if candidate.is_file():
                active_objects.append(root)
            elif candidate.is_dir():
                for item in sorted(candidate.rglob("*")):
                    if item.is_file() and not item.is_symlink():
                        active_objects.append(
                            item.relative_to(workspace).as_posix()
                        )
        state = "active-use" if active_objects else "no-active-objects"
        reports.append({
            "authorization_id": identifier,
            "state": state,
            "active_objects": active_objects,
            "recommendation": "retain" if active_objects else "review-expiry-or-closure",
            "retention_impact": (
                "Retaining an unused authorization leaves future archive scope "
                "available; closure requires a separate protected change."
                if not active_objects
                else "The authorization still covers active objects."
            ),
        })
    if authorization_id is not None and not reports:
        findings.append({
            "code": "archive-authorization-scope-not-found",
            "authorization_id": authorization_id,
        })
    return {
        "result": "fail" if findings else "pass",
        "phase": "authorization-lifecycle",
        "analysis_only": True,
        "configuration_changed": False,
        "reports": reports,
        "mechanical_findings": findings,
        "recovery": (
            "Treat any closure or scope change as a new protected "
            "configuration event with explicit approval."
        ),
    }
