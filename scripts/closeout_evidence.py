"""Construction, parsing, and context binding for Closeout evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import re


CLOSEOUT_ATTESTATION_SCHEMA = "govern-ai-coding.closeout-attestation.v1"


def canonical_json_digest(payload: object) -> str:
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _result(status: str, path: Path, **fields: object) -> dict:
    return {"status": status, "path": str(path), **fields}


def _capabilities(payload: dict) -> list[str]:
    capabilities = ["closeout-envelope"]
    if isinstance(payload.get("final_content"), list):
        capabilities.append("final-content")
    if isinstance(payload.get("receipt_bindings"), dict):
        capabilities.append("receipt-bindings")
    if isinstance(payload.get("work_map_observation"), dict):
        capabilities.append("work-map-observation")
    if isinstance((payload.get("adapter") or {}).get("digest"), str):
        capabilities.append("adapter-digest")
    if isinstance((payload.get("event") or {}).get("final_git_commit"), str):
        capabilities.append("final-git-identity")
    if isinstance(payload.get("validation_inputs"), list):
        capabilities.append("validation-inputs")
    return capabilities


def parse_closeout_attestation(
    path: Path,
    *,
    current_schemas: list[str],
    historical_schemas: list[str],
) -> dict:
    """Parse a Closeout attestation without binding it to a consumer context."""
    if not path.is_file():
        return _result("missing", path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return _result("evidence-incomplete", path)
    if not isinstance(payload, dict):
        return _result("evidence-incomplete", path)

    schema = payload.get("schema")
    if schema in historical_schemas:
        return _result(
            "evidence-incomplete",
            path,
            schema=schema,
            historical_schema=True,
            capabilities=[],
        )
    if schema not in current_schemas:
        return _result("schema-mismatch", path, schema=schema)
    if payload.get("schema_version") is None or payload.get("kind") is None:
        return _result(
            "evidence-incomplete", path, schema=schema, payload=payload,
        )
    if (
        payload.get("schema_version") != "1"
        or payload.get("kind") != "closeout-attestation"
    ):
        return _result("schema-mismatch", path, schema=schema, payload=payload)
    if (
        payload.get("result") != "pass"
        or payload.get("immutable") is not True
        or payload.get("derived_evidence") is not True
        or payload.get("generated") is not True
        or payload.get("project_authority") is not False
    ):
        return _result(
            "evidence-incomplete", path, schema=schema, payload=payload,
        )
    required_structures = (
        isinstance(payload.get("adapter"), dict)
        and isinstance(payload.get("event"), dict)
        and isinstance(payload.get("actual_paths"), list)
        and isinstance(payload.get("final_content"), list)
        and isinstance(payload.get("approvals"), dict)
        and isinstance(payload.get("receipt_bindings"), dict)
        and isinstance(payload.get("result_reasons"), list)
        and isinstance(payload.get("recovery_actions"), list)
        and isinstance(payload.get("limitations"), list)
    )
    if not required_structures:
        return _result(
            "evidence-incomplete", path, schema=schema, payload=payload,
        )
    return _result(
        "parsed",
        path,
        schema=schema,
        capabilities=_capabilities(payload),
        payload=payload,
    )


def _file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _safe_relative_path(value: object) -> bool:
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    candidate = PurePosixPath(value)
    return (
        not candidate.is_absolute()
        and candidate.parts
        and all(part not in {"", ".", ".."} for part in candidate.parts)
        and candidate.as_posix() == value
    )


def _content_structure(entries: object) -> tuple[list[str] | None, str | None]:
    if not isinstance(entries, list) or not all(
        isinstance(entry, dict) for entry in entries
    ):
        return None, "evidence-incomplete"
    paths = [entry.get("path") for entry in entries]
    if (
        not all(_safe_relative_path(path) for path in paths)
        or len(paths) != len(set(paths))
    ):
        return None, "scope-mismatch"
    for entry in entries:
        existence = entry.get("existence")
        digest = entry.get("digest")
        if not isinstance(existence, bool):
            return None, "evidence-incomplete"
        if existence:
            if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                return None, "evidence-incomplete"
        elif digest is not None:
            return None, "evidence-incomplete"
    return paths, None


def load_receipt_binding(path: Path) -> dict | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict) or not isinstance(payload.get("schema"), str):
        return None
    return {
        "path": str(path),
        "digest": canonical_json_digest(payload),
        "schema": payload["schema"],
    }


def validation_input_projection(receipt: dict, path: Path) -> dict | None:
    if (
        receipt.get("schema") != "govern-ai-coding.validation-receipt.v1"
        or receipt.get("result") != "pass"
    ):
        return None
    lists = (
        receipt.get("input_classes"),
        receipt.get("frozen_paths"),
        receipt.get("commands"),
        receipt.get("supported_claims"),
        receipt.get("unsupported_claims"),
    )
    if not all(isinstance(value, list) for value in lists):
        return None
    if not lists[0] or not all(
        isinstance(value, str) and value for value in lists[0]
    ):
        return None
    if not lists[3] or not all(
        isinstance(value, str) and value for value in lists[3] + lists[4]
    ):
        return None
    environment = receipt.get("environment")
    if not isinstance(environment, dict):
        return None
    frozen_paths = []
    for entry in lists[1]:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            return None
        digest = entry.get("digest")
        if digest is not None and (
            not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        ):
            return None
        frozen_paths.append({
            "path": entry["path"],
            "existence": isinstance(digest, str),
            "digest": digest,
        })
    if not lists[2] or not all(
        isinstance(entry, dict)
        and isinstance(entry.get("command"), str)
        and bool(entry["command"])
        and entry.get("result") == "pass"
        for entry in lists[2]
    ):
        return None
    return {
        "binding": {
            "path": str(path),
            "digest": canonical_json_digest(receipt),
            "schema": receipt.get("schema"),
        },
        "input_classes": list(lists[0]),
        "frozen_paths": frozen_paths,
        "commands": list(lists[2]),
        "environment": environment,
        "supported_claims": list(lists[3]),
        "unsupported_claims": list(lists[4]),
    }


def _validate_modern_validation_structure(
    receipt: dict,
    receipt_path: Path,
) -> list[dict]:
    findings: list[dict] = []
    if receipt.get("schema") != "govern-ai-coding.validation-receipt.v1":
        findings.append({
            "code": "validation-receipt-schema-invalid",
            "path": str(receipt_path),
        })
    if receipt.get("result") != "pass":
        findings.append({
            "code": "validation-receipt-result-not-pass",
            "path": str(receipt_path),
        })
    frozen = receipt.get("frozen_paths")
    if not isinstance(frozen, list):
        findings.append({
            "code": "validation-receipt-frozen-paths-invalid",
            "path": str(receipt_path),
        })
        frozen = []
    elif any(
        not isinstance(entry, dict)
        or not _safe_relative_path(entry.get("path"))
        or (
            entry.get("digest") is not None
            and (
                not isinstance(entry.get("digest"), str)
                or re.fullmatch(r"[0-9a-f]{64}", entry["digest"]) is None
            )
        )
        for entry in frozen
    ):
        findings.append({
            "code": "validation-receipt-frozen-paths-invalid",
            "path": str(receipt_path),
        })
    commands = receipt.get("commands")
    if not isinstance(commands, list) or not commands or any(
        not isinstance(command, dict)
        or not isinstance(command.get("command"), str)
        or not command["command"]
        or command.get("result") != "pass"
        for command in commands
    ):
        findings.append({
            "code": "validation-receipt-commands-invalid",
            "path": str(receipt_path),
        })
    for field in ("environment", "supported_claims", "unsupported_claims"):
        value = receipt.get(field)
        valid = (
            isinstance(value, dict) and bool(value)
            if field == "environment"
            else isinstance(value, list)
            and bool(value)
            and all(isinstance(item, str) and item for item in value)
        )
        if not valid:
            findings.append({
                "code": "validation-receipt-field-invalid",
                "field": field,
            })
    if (
        receipt.get("result") == "pass"
        and "input_classes" in receipt
        and validation_input_projection(receipt, receipt_path) is None
    ):
        findings.append({
            "code": "validation-receipt-inputs-invalid",
            "path": str(receipt_path),
        })
    return findings


def _validate_freeze_bound_validation(
    receipt: dict,
    receipt_path: Path,
    workspace: Path,
    freeze_receipt: dict | None,
) -> list[dict]:
    findings = _validate_modern_validation_structure(receipt, receipt_path)
    if not isinstance(freeze_receipt, dict):
        findings.append({"code": "validation-receipt-freeze-missing"})
        return findings
    receipt_freeze = receipt.get("freeze")
    if not isinstance(receipt_freeze, dict) or receipt_freeze.get(
        "digest"
    ) != canonical_json_digest(freeze_receipt):
        findings.append({
            "code": "validation-receipt-freeze-mismatch",
            "path": str(receipt_path),
        })
    freeze_paths = freeze_receipt.get("paths")
    if not isinstance(freeze_paths, list):
        findings.append({
            "code": "validation-receipt-freeze-paths-invalid",
            "path": str(receipt_path),
        })
        freeze_paths = []
    valid_freeze_paths = [
        entry
        for entry in freeze_paths
        if isinstance(entry, dict)
        and _safe_relative_path(entry.get("path"))
        and isinstance(entry.get("existence"), bool)
        and (
            (
                entry["existence"]
                and isinstance(entry.get("digest"), str)
                and re.fullmatch(r"[0-9a-f]{64}", entry["digest"]) is not None
            )
            or (not entry["existence"] and entry.get("digest") is None)
        )
    ]
    if len(valid_freeze_paths) != len(freeze_paths):
        findings.append({
            "code": "validation-receipt-freeze-paths-invalid",
            "path": str(receipt_path),
        })
    expected_paths = {
        entry.get("path"): entry.get("digest")
        for entry in valid_freeze_paths
    }
    frozen = receipt.get("frozen_paths")
    if not isinstance(frozen, list):
        frozen = []
    actual_paths = {
        entry.get("path"): entry.get("digest")
        for entry in frozen
        if isinstance(entry, dict) and _safe_relative_path(entry.get("path"))
    }
    if actual_paths != expected_paths:
        findings.append({
            "code": "validation-receipt-frozen-paths-mismatch",
            "path": str(receipt_path),
        })
    for path, digest in expected_paths.items():
        if not isinstance(path, str):
            continue
        target = workspace / path
        if not target.is_file() or _file_digest(target) != digest:
            findings.append({
                "code": "validation-receipt-frozen-content-mismatch",
                "path": path,
            })
    return findings


def _validate_validation_input_content(
    receipt: dict,
    receipt_path: Path,
    workspace: Path,
) -> list[dict]:
    if validation_input_projection(receipt, receipt_path) is None:
        return []
    findings: list[dict] = []
    for entry in receipt["frozen_paths"]:
        path = entry["path"]
        expected_digest = entry.get("digest")
        target = workspace / path
        matches = (
            target.is_file()
            and isinstance(expected_digest, str)
            and _file_digest(target) == expected_digest
        ) or (
            not target.exists()
            and expected_digest is None
        )
        if not matches:
            findings.append({
                "code": "validation-receipt-frozen-content-mismatch",
                "path": path,
                "receipt": str(receipt_path),
            })
    return findings


def collect_validation_evidence(
    receipt_paths: list[str],
    workspace: Path,
    *,
    freeze_receipt: dict | None = None,
    require_freeze_binding: bool = False,
) -> tuple[list[dict], list[dict]]:
    """Load each selected validation receipt once into an immutable snapshot."""
    snapshots: list[dict] = []
    findings: list[dict] = []
    for raw_path in sorted(set(receipt_paths)):
        candidate = Path(raw_path)
        target = candidate if candidate.is_absolute() else workspace / candidate
        try:
            receipt = json.loads(target.read_text(encoding="utf-8"))
        except FileNotFoundError:
            findings.append({
                "code": "validation-receipt-missing",
                "path": raw_path,
            })
            continue
        except (OSError, UnicodeError, json.JSONDecodeError):
            findings.append({
                "code": "validation-receipt-malformed",
                "path": raw_path,
            })
            continue
        if not isinstance(receipt, dict) or not isinstance(
            receipt.get("schema"), str
        ):
            findings.append({
                "code": "validation-receipt-malformed",
                "path": raw_path,
            })
            continue

        projection = validation_input_projection(receipt, target)
        receipt_findings: list[dict] = []
        if require_freeze_binding:
            receipt_findings = _validate_freeze_bound_validation(
                receipt, target, workspace, freeze_receipt,
            )
        elif receipt.get("schema") == "govern-ai-coding.validation-receipt.v1":
            receipt_findings = _validate_modern_validation_structure(
                receipt, target,
            )
            if not receipt_findings:
                receipt_findings.extend(_validate_validation_input_content(
                    receipt, target, workspace,
                ))
        findings.extend(receipt_findings)
        if receipt_findings:
            continue
        binding = {
            "path": str(target),
            "digest": canonical_json_digest(receipt),
            "schema": receipt["schema"],
        }
        snapshots.append({
            "binding": binding,
            "projection": projection,
        })
    return snapshots, findings


def build_closeout_attestation(
    payload: dict,
    *,
    adapter: dict,
    workspace: Path,
    manifest: dict | None,
    impact_receipt: dict | None,
    freeze_receipt: dict | None,
    validation_evidence: list[dict],
) -> dict:
    """Build one immutable attestation from already selected evidence."""
    actual_paths = sorted(payload.get("closeout", {}).get("actual_paths", []))
    frozen_entries = (
        freeze_receipt.get("paths")
        if isinstance(freeze_receipt, dict)
        else None
    )
    if isinstance(frozen_entries, list):
        final_content = sorted(
            [
                {
                    "path": entry.get("path"),
                    "existence": entry.get("existence"),
                    "digest": entry.get("digest"),
                }
                for entry in frozen_entries
                if isinstance(entry, dict)
            ],
            key=lambda entry: str(entry.get("path")),
        )
    else:
        final_content = []
        for path in actual_paths:
            target = (workspace / path).resolve()
            exists = target.is_file()
            final_content.append({
                "path": path,
                "existence": exists,
                "digest": _file_digest(target) if exists else None,
            })

    semantic_review_binding = (payload.get("semantic_review") or {}).get(
        "binding"
    )
    if not (
        isinstance(semantic_review_binding, dict)
        and isinstance(semantic_review_binding.get("source"), str)
        and isinstance(semantic_review_binding.get("digest"), str)
    ):
        semantic_review_binding = None
    validation_bindings = [
        item["binding"]
        for item in validation_evidence
        if isinstance(item, dict) and isinstance(item.get("binding"), dict)
    ]
    validation_inputs = [
        item["projection"]
        for item in validation_evidence
        if isinstance(item, dict) and isinstance(item.get("projection"), dict)
    ]
    baseline_ref = (
        manifest.get("event", {}).get("baseline_ref")
        if manifest
        else (impact_receipt or {})
        .get("inventory_source", {})
        .get("metadata", {})
        .get("baseline_ref")
    )
    attestation = {
        "schema": CLOSEOUT_ATTESTATION_SCHEMA,
        "schema_version": "1",
        "kind": "closeout-attestation",
        "immutable": True,
        "adapter": {
            "project": adapter.get("project"),
            "schema_version": adapter.get("schema_version"),
            "digest": canonical_json_digest(adapter),
        },
        "event": {
            "id": manifest.get("event", {}).get("id") if manifest else None,
            "goal": manifest.get("event", {}).get("goal") if manifest else None,
            "baseline_ref": baseline_ref,
            "workspace": str(workspace.resolve()),
        },
        "result": "pass",
        "actual_paths": actual_paths,
        "final_content": final_content,
        "approvals": payload.get("approval_summary", {}),
        "receipt_bindings": {
            "impact": (
                canonical_json_digest(impact_receipt)
                if impact_receipt
                else None
            ),
            "semantic_review": semantic_review_binding,
            "freeze": (
                canonical_json_digest(freeze_receipt)
                if freeze_receipt
                else None
            ),
            "validation": validation_bindings,
        },
        "work_map_binding": (
            manifest.get("work_map_binding") if manifest is not None else None
        ),
        "result_reasons": list(payload.get("result_reasons", [])),
        "recovery_actions": list(payload.get("recovery_actions", [])),
        "limitations": list((payload.get("coverage") or {}).get("cannot_prove", [])),
        "derived_evidence": True,
        "generated": True,
        "project_authority": False,
    }
    final_git_commit = (
        freeze_receipt.get("git_commit")
        if isinstance(freeze_receipt, dict)
        else None
    )
    if final_git_commit is not None:
        attestation["event"]["final_git_commit"] = final_git_commit
    if validation_inputs:
        attestation["validation_inputs"] = validation_inputs
    if isinstance(payload.get("work_map_observation"), dict):
        attestation["work_map_observation"] = payload["work_map_observation"]
    return attestation


def _expected_receipt_bindings(
    manifest: dict,
    workspace: Path,
    impact_receipt: dict,
    freeze_receipt: dict,
    validation_bindings: list[dict],
) -> dict | None:
    receipts = manifest.get("receipts")
    if not isinstance(receipts, dict):
        return None

    semantic_review = manifest.get("semantic_review") or {}
    if not isinstance(semantic_review, dict):
        return None
    semantic_path = semantic_review.get("path")
    semantic_binding = None
    if isinstance(semantic_path, str) and semantic_path:
        candidate = Path(semantic_path)
        targets = [candidate]
        if not candidate.is_absolute():
            targets.insert(0, workspace / candidate)
        for target in targets:
            binding = load_receipt_binding(target)
            if binding is not None:
                semantic_binding = {
                    "source": binding["path"],
                    "digest": binding["digest"],
                }
                break
        if semantic_binding is None:
            return None

    return {
        "impact": canonical_json_digest(impact_receipt),
        "semantic_review": semantic_binding,
        "freeze": canonical_json_digest(freeze_receipt),
        "validation": validation_bindings,
    }


def bind_closeout_attestation(
    parsed: dict,
    *,
    path: Path,
    adapter: dict,
    workspace: Path,
    manifest: dict,
) -> dict:
    """Bind parsed evidence to one expected adapter, event, scope, and receipt set."""
    if parsed.get("status") != "parsed" or not isinstance(parsed.get("payload"), dict):
        return parsed
    payload = parsed["payload"]
    schema = parsed.get("schema")
    capabilities = list(parsed.get("capabilities", []))

    receipts = manifest.get("receipts")
    if not isinstance(receipts, dict):
        return _result("evidence-incomplete", path, schema=schema)
    pointer = receipts.get("closeout_attestation")
    if not isinstance(pointer, dict):
        return _result("evidence-incomplete", path, schema=schema)
    recorded_path = pointer.get("path")
    if not isinstance(recorded_path, str) or not recorded_path:
        return _result("evidence-incomplete", path, schema=schema)
    if Path(recorded_path).resolve() != path.resolve():
        return _result("scope-mismatch", path, schema=schema)
    if pointer.get("digest") != canonical_json_digest(payload):
        return _result("content-mismatch", path, schema=schema)

    attested_adapter = payload["adapter"]
    if any(
        attested_adapter.get(key) != adapter.get(key)
        for key in ("project", "schema_version")
    ):
        return _result("identity-mismatch", path, schema=schema)
    adapter_digest = attested_adapter.get("digest")
    if adapter_digest is not None:
        if not isinstance(adapter_digest, str):
            return _result("evidence-incomplete", path, schema=schema)
        if adapter_digest != canonical_json_digest(adapter):
            return _result("identity-mismatch", path, schema=schema)

    event = manifest.get("event") or {}
    if not isinstance(event, dict):
        return _result("evidence-incomplete", path, schema=schema)
    expected_event = {
        "id": event.get("id"),
        "goal": event.get("goal"),
        "baseline_ref": event.get("baseline_ref"),
        "workspace": str(workspace.resolve()),
    }
    if any(payload["event"].get(key) != value for key, value in expected_event.items()):
        return _result("identity-mismatch", path, schema=schema)

    scope = manifest.get("scope") or {}
    if not isinstance(scope, dict):
        return _result("evidence-incomplete", path, schema=schema)
    actual_paths = scope.get("actual_event_paths", [])
    if not isinstance(actual_paths, list) or not all(
        isinstance(item, str) for item in actual_paths
    ):
        return _result("evidence-incomplete", path, schema=schema)
    if (
        actual_paths != sorted(set(actual_paths))
        or not all(_safe_relative_path(item) for item in actual_paths)
    ):
        return _result("scope-mismatch", path, schema=schema)
    attested_actual_paths = payload["actual_paths"]
    if not all(isinstance(item, str) for item in attested_actual_paths):
        return _result("evidence-incomplete", path, schema=schema)
    if (
        attested_actual_paths != sorted(set(attested_actual_paths))
        or not all(_safe_relative_path(item) for item in attested_actual_paths)
    ):
        return _result("scope-mismatch", path, schema=schema)
    if attested_actual_paths != sorted(actual_paths):
        return _result("scope-mismatch", path, schema=schema)

    freeze_receipt = receipts.get("freeze")
    impact_receipt = receipts.get("impact")
    if not isinstance(freeze_receipt, dict) or not isinstance(impact_receipt, dict):
        return _result("evidence-incomplete", path, schema=schema)
    frozen_git_commit = freeze_receipt.get("git_commit")
    attested_git_commit = payload["event"].get("final_git_commit")
    if frozen_git_commit is not None or attested_git_commit is not None:
        if (
            not isinstance(frozen_git_commit, str)
            or not isinstance(attested_git_commit, str)
            or attested_git_commit != frozen_git_commit
        ):
            return _result("content-mismatch", path, schema=schema)
    frozen_entries = freeze_receipt.get("paths")
    frozen_paths, structure_status = _content_structure(frozen_entries)
    if structure_status is not None:
        return _result(structure_status, path, schema=schema)
    expected_final_content = sorted(
        (
            {
                "path": entry.get("path"),
                "existence": entry.get("existence"),
                "digest": entry.get("digest"),
            }
            for entry in frozen_entries
            if isinstance(entry, dict)
        ),
        key=lambda entry: str(entry.get("path")),
    )
    attested_final_content = payload["final_content"]
    attested_paths, structure_status = _content_structure(attested_final_content)
    if structure_status is not None:
        return _result(structure_status, path, schema=schema)
    if frozen_paths != actual_paths or attested_paths != actual_paths:
        return _result("scope-mismatch", path, schema=schema)
    if attested_final_content != expected_final_content:
        return _result("content-mismatch", path, schema=schema)

    workspace_root = workspace.resolve()
    for entry in expected_final_content:
        relative = entry.get("path")
        if not isinstance(relative, str):
            return _result("evidence-incomplete", path, schema=schema)
        target = (workspace / relative).resolve()
        try:
            target.relative_to(workspace_root)
        except ValueError:
            return _result("scope-mismatch", path, schema=schema)
        exists = target.is_file()
        digest = _file_digest(target) if exists else None
        if exists != entry.get("existence") or digest != entry.get("digest"):
            return _result("content-mismatch", path, schema=schema)

    validation_paths = receipts.get("validation", [])
    if not isinstance(validation_paths, list) or not all(
        isinstance(validation_path, str) for validation_path in validation_paths
    ):
        return _result("evidence-incomplete", path, schema=schema)
    validation_snapshots, validation_findings = collect_validation_evidence(
        validation_paths, workspace,
    )
    if validation_findings:
        status = (
            "content-mismatch"
            if any(
                finding.get("code") == "validation-receipt-result-not-pass"
                for finding in validation_findings
            )
            else "evidence-incomplete"
        )
        return _result(status, path, schema=schema)
    expected_bindings = _expected_receipt_bindings(
        manifest,
        workspace,
        impact_receipt,
        freeze_receipt,
        [snapshot["binding"] for snapshot in validation_snapshots],
    )
    if expected_bindings is None:
        return _result("evidence-incomplete", path, schema=schema)
    if payload["receipt_bindings"] != expected_bindings:
        return _result("content-mismatch", path, schema=schema)
    if "validation_inputs" in payload:
        expected_inputs = [
            snapshot["projection"]
            for snapshot in validation_snapshots
            if snapshot["projection"] is not None
        ]
        if not expected_inputs:
            return _result("evidence-incomplete", path, schema=schema)
        if payload["validation_inputs"] != expected_inputs:
            return _result("content-mismatch", path, schema=schema)
    return _result(
        "matching",
        path,
        schema=schema,
        capabilities=sorted(set(capabilities + ["context-bound"])),
        payload=payload,
    )
