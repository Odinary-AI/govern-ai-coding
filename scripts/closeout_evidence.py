"""Construction, parsing, and context binding for Closeout evidence."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re


CLOSEOUT_ATTESTATION_SCHEMA = "govern-ai-coding.closeout-attestation.v1"
VALIDATION_FACTS_SCHEMA = "govern-ai-coding.validation-facts.v1"
VALIDATION_RECEIPT_SCHEMA = "govern-ai-coding.validation-receipt.v1"
VALIDATION_PROFILE_REGISTRY_SCHEMA = (
    "govern-ai-coding.validation-consumer-profiles.v1"
)
VALIDATION_AXES = ("structure", "binding", "content", "freshness")
EVENT_MANIFEST_V1_SCHEMA = "govern-ai-coding.event-manifest.v1"
EVENT_MANIFEST_V2_SCHEMA = "govern-ai-coding.event-manifest.v2"
CLOSEOUT_RECEIPT_SCHEMA = "govern-ai-coding.closeout-receipt.v1"
_ATTEMPT_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
VALIDATION_PROFILE_POLICIES = {
    "standalone-freeze-bound-v1": {
        "structure": ("current-v1-complete-freeze", "always"),
        "binding": ("exact-freeze-digest", "always"),
        "content": ("exact-freeze-projection", "always"),
        "freshness": ("not-evaluated", "never"),
    },
    "closeout-compatible-v1": {
        "structure": ("current-or-legacy-identity", "current-v1"),
        "binding": ("not-required", "never"),
        "content": ("not-required", "never"),
        "freshness": (
            "projectable-receipt-workspace",
            "projectable-modern",
        ),
    },
    "work-map-closeout-v1": {
        "structure": ("current-v1-partial-freeze", "always"),
        "binding": ("exact-freeze-digest", "always"),
        "content": ("exact-freeze-projection", "always"),
        "freshness": ("supplied-freeze-workspace", "always"),
    },
}
VALIDATION_CONSUMER_PROFILES = {
    "standalone-freeze-bound-v1": {
        "schema": VALIDATION_PROFILE_REGISTRY_SCHEMA,
        "version": "1",
        "consumers": ["validate-validation-receipt CLI"],
        "purpose": (
            "Validate a current Validation Receipt against one complete "
            "canonical Freeze without reading workspace content."
        ),
        "axes": {
            "structure": {
                "mode": "current-v1-complete-freeze",
                "required_when": "always",
                "requirement": "current Validation Receipt v1 structure",
            },
            "binding": {
                "mode": "exact-freeze-digest",
                "required_when": "always",
                "requirement": "exact Evidence-v1 digest of the supplied Freeze",
            },
            "content": {
                "mode": "exact-freeze-projection",
                "required_when": "always",
                "requirement": "exact path/digest projection of the supplied Freeze",
            },
            "freshness": {
                "mode": "not-evaluated",
                "required_when": "never",
                "requirement": "not evaluated without a workspace consumer",
            },
        },
        "compatible_omissions": [
            "input_classes may be omitted, disabling inheritable input claims",
        ],
        "supported_conclusions": [
            "the current receipt structure is valid",
            "the receipt binds the exact supplied complete Freeze and path projection",
        ],
        "unsupported_conclusions": [
            "the recorded commands were executed",
            "workspace bytes are still fresh",
            "human approval, product acceptance, release, or readiness",
        ],
        "reopen_conditions": [
            "the supplied receipt or Freeze bytes change",
        ],
        "sunset_conditions": [
            "a later receipt schema replaces Validation Receipt v1 through an explicit migration contract",
        ],
    },
    "closeout-compatible-v1": {
        "schema": VALIDATION_PROFILE_REGISTRY_SCHEMA,
        "version": "1",
        "consumers": [
            "ordinary Closeout",
            "Closeout Attestation source-context rebinding",
            "Integration Verification attestation trust preflight",
        ],
        "purpose": (
            "Preserve legacy and capability-limited Closeout acceptance while "
            "checking current modern receipt inputs when they are projectable."
        ),
        "axes": {
            "structure": {
                "mode": "current-or-legacy-identity",
                "required_when": "current-v1",
                "requirement": "current V1 receipts only; legacy identity is retained",
            },
            "binding": {
                "mode": "not-required",
                "required_when": "never",
                "requirement": "not required by this compatibility consumer",
            },
            "content": {
                "mode": "not-required",
                "required_when": "never",
                "requirement": "no independent whole-Freeze comparison",
            },
            "freshness": {
                "mode": "projectable-receipt-workspace",
                "required_when": "projectable-modern",
                "requirement": "current bytes only for a complete modern input projection",
            },
        },
        "compatible_omissions": [
            "a non-current receipt with a string schema is retained as identity-only evidence",
            "input_classes may be omitted from a current receipt, disabling projection and freshness conclusions",
            "receipt-to-Freeze binding may be absent or unchecked",
        ],
        "supported_conclusions": [
            "the selected receipt identity is preserved for Closeout binding",
            "a complete modern projection still matches current listed workspace bytes",
        ],
        "unsupported_conclusions": [
            "identity-only or capability-limited evidence supports validation claims",
            "the receipt covers or binds the event's complete Freeze",
            "human approval, product acceptance, release, or readiness",
        ],
        "reopen_conditions": [
            "a projected frozen path changes or a selected receipt identity changes",
        ],
        "sunset_conditions": [
            "all supported Closeout and attestation inputs carry a migrated current receipt with explicit Freeze binding",
        ],
    },
    "work-map-closeout-v1": {
        "schema": VALIDATION_PROFILE_REGISTRY_SCHEMA,
        "version": "1",
        "consumers": ["Closeout for an Event Manifest with work_map_binding"],
        "purpose": (
            "Bind a current receipt to the supplied Work Map event Freeze and "
            "check every supplied frozen path against current workspace bytes."
        ),
        "axes": {
            "structure": {
                "mode": "current-v1-partial-freeze",
                "required_when": "always",
                "requirement": "current Validation Receipt v1 structure",
            },
            "binding": {
                "mode": "exact-freeze-digest",
                "required_when": "always",
                "requirement": "exact Evidence-v1 digest of the supplied Freeze",
            },
            "content": {
                "mode": "exact-freeze-projection",
                "required_when": "always",
                "requirement": "exact path/digest projection of the supplied Freeze",
            },
            "freshness": {
                "mode": "supplied-freeze-workspace",
                "required_when": "always",
                "requirement": "every supplied frozen path matches the workspace",
            },
        },
        "compatible_omissions": [
            "the supplied Freeze kind may be omitted on the retained partial-Freeze call path",
            "input_classes may be omitted without weakening the direct workspace freshness check",
        ],
        "supported_conclusions": [
            "the current receipt binds the supplied Freeze path projection",
            "every supplied frozen path matches current workspace bytes",
        ],
        "unsupported_conclusions": [
            "this profile alone proves the supplied Freeze is the event's complete valid Freeze",
            "the recorded commands were executed",
            "human approval, product acceptance, release, or readiness",
        ],
        "reopen_conditions": [
            "the supplied receipt, Freeze, or any supplied frozen workspace path changes",
        ],
        "sunset_conditions": [
            "the Work Map Closeout consumer migrates to a later explicit receipt and Freeze contract",
        ],
    },
}


def validate_validation_profile_registry(registry: object) -> list[dict]:
    if not isinstance(registry, dict) or not registry:
        return [{"code": "validation-profile-registry-invalid", "field": "root"}]
    findings: list[dict] = []
    if set(registry) != set(VALIDATION_PROFILE_POLICIES):
        findings.append({
            "code": "validation-profile-registry-invalid",
            "field": "profiles",
        })
    required_fields = (
        "consumers",
        "purpose",
        "compatible_omissions",
        "supported_conclusions",
        "unsupported_conclusions",
        "reopen_conditions",
        "sunset_conditions",
    )
    for name, profile in registry.items():
        if not isinstance(name, str) or not name.endswith("-v1"):
            findings.append({
                "code": "validation-profile-registry-invalid",
                "field": f"profiles.{name}.name",
            })
            continue
        if not isinstance(profile, dict):
            findings.append({
                "code": "validation-profile-registry-invalid",
                "field": f"profiles.{name}",
            })
            continue
        if (
            profile.get("schema") != VALIDATION_PROFILE_REGISTRY_SCHEMA
            or profile.get("version") != "1"
        ):
            findings.append({
                "code": "validation-profile-registry-invalid",
                "field": f"profiles.{name}.version",
            })
        axes = profile.get("axes")
        if not isinstance(axes, dict) or set(axes) != set(VALIDATION_AXES):
            findings.append({
                "code": "validation-profile-registry-invalid",
                "field": f"profiles.{name}.axes",
            })
        else:
            for axis in VALIDATION_AXES:
                axis_contract = axes[axis]
                expected = VALIDATION_PROFILE_POLICIES.get(name, {}).get(axis)
                valid_axis = (
                    isinstance(axis_contract, dict)
                    and isinstance(axis_contract.get("requirement"), str)
                    and bool(axis_contract["requirement"])
                    and expected is not None
                    and (
                        axis_contract.get("mode"),
                        axis_contract.get("required_when"),
                    ) == expected
                )
                if not valid_axis:
                    findings.append({
                        "code": "validation-profile-registry-invalid",
                        "field": f"profiles.{name}.axes.{axis}",
                    })
        for field in required_fields:
            value = profile.get(field)
            valid = (
                isinstance(value, str) and bool(value)
                if field == "purpose"
                else isinstance(value, list)
                and bool(value)
                and all(isinstance(item, str) and item for item in value)
            )
            if not valid:
                findings.append({
                    "code": "validation-profile-registry-invalid",
                    "field": f"profiles.{name}.{field}",
                })
    return findings


def canonical_evidence_v1_digest(payload: object) -> str:
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _manifest_path_matches(path: str, pattern: str) -> bool:
    normalized_path = path.rstrip("/")
    normalized_pattern = pattern.rstrip("/")
    return (
        normalized_path == normalized_pattern
        or normalized_path.startswith(normalized_pattern + "/")
    )


def _manifest_evidence_path(
    raw_path: object,
    *,
    manifest_path: Path | None,
    workspace: Path | None,
    adapter: dict | None,
) -> tuple[Path | None, str | None]:
    if not isinstance(raw_path, str) or not raw_path or "\\" in raw_path:
        return None, "event-manifest-attempt-path-unsafe"
    candidate = Path(raw_path)
    if candidate.is_absolute():
        resolved = candidate.resolve()
        if raw_path != str(resolved):
            return None, "event-manifest-attempt-path-unsafe"
    else:
        pure = PurePosixPath(raw_path)
        if (
            manifest_path is None
            or not pure.parts
            or any(part in {"", ".", ".."} for part in pure.parts)
            or pure.as_posix() != raw_path
        ):
            return None, "event-manifest-attempt-path-unsafe"
        base = manifest_path.parent.resolve()
        current = base
        for part in pure.parts:
            current = current / part
            if current.is_symlink():
                return None, "event-manifest-attempt-path-unsafe"
        lexical = base / Path(*pure.parts)
        resolved = lexical.resolve()
        try:
            resolved.relative_to(base)
        except ValueError:
            return None, "event-manifest-attempt-path-unsafe"
    if resolved.is_symlink() or not resolved.is_file():
        return resolved, "event-manifest-attempt-receipt-missing"
    try:
        if resolved.stat().st_nlink != 1:
            return resolved, "event-manifest-attempt-path-unsafe"
    except OSError:
        return resolved, "event-manifest-attempt-receipt-missing"
    if workspace is not None and adapter is not None:
        root = workspace.resolve()
        try:
            relative = resolved.relative_to(root).as_posix()
        except ValueError:
            relative = None
        if relative is not None:
            excluded = (
                (adapter.get("boundaries") or {}).get("excluded", [])
                if isinstance(adapter, dict)
                else []
            )
            if not isinstance(excluded, list) or not any(
                isinstance(pattern, str)
                and _manifest_path_matches(relative, pattern)
                for pattern in excluded
            ):
                return None, "event-manifest-attempt-path-unsafe"
    return resolved, None


def _load_bound_manifest_evidence(
    binding: object,
    *,
    manifest_path: Path | None,
    workspace: Path | None,
    adapter: dict | None,
    expected_schema: str,
    missing_code: str,
) -> tuple[dict | None, Path | None, list[dict]]:
    if not isinstance(binding, dict):
        return None, None, [{"code": "event-manifest-attempt-binding-invalid"}]
    raw_path = binding.get("path")
    path, path_error = _manifest_evidence_path(
        raw_path,
        manifest_path=manifest_path,
        workspace=workspace,
        adapter=adapter,
    )
    if path_error is not None:
        return None, path, [{
            "code": missing_code if path_error.endswith("receipt-missing") else path_error,
            "path": raw_path,
        }]
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None, path, [{
            "code": "event-manifest-attempt-binding-invalid",
            "path": raw_path,
        }]
    valid = (
        isinstance(payload, dict)
        and binding.get("schema") == expected_schema
        and payload.get("schema") == expected_schema
        and isinstance(binding.get("digest"), str)
        and re.fullmatch(r"[0-9a-f]{64}", binding["digest"]) is not None
        and binding["digest"] == canonical_evidence_v1_digest(payload)
    )
    if not valid:
        return payload if isinstance(payload, dict) else None, path, [{
            "code": "event-manifest-attempt-binding-invalid",
            "path": raw_path,
        }]
    return payload, path, []


def _closeout_receipt_structure_valid(
    receipt: object,
    *,
    result: object,
    freeze_digest: object,
    workspace: Path | None,
    adapter: dict | None,
) -> bool:
    if not isinstance(receipt, dict):
        return False
    receipt_adapter = receipt.get("adapter")
    receipt_workspace = receipt.get("workspace")
    final_content = receipt.get("final_content")
    freeze_binding = receipt.get("freeze")
    frozen_receipt = (
        freeze_binding.get("receipt")
        if isinstance(freeze_binding, dict)
        else None
    )
    impact_binding = receipt.get("impact")
    impact_receipt = (
        impact_binding.get("receipt")
        if isinstance(impact_binding, dict)
        else None
    )
    frozen_paths, freeze_findings = _validation_freeze_projection(
        frozen_receipt,
    )
    if not (
        receipt.get("schema") == CLOSEOUT_RECEIPT_SCHEMA
        and receipt.get("kind") == "live-closeout"
        and receipt.get("result") == result
        and isinstance(receipt_adapter, dict)
        and isinstance(receipt_adapter.get("project"), str)
        and isinstance(receipt_adapter.get("schema_version"), str)
        and isinstance(receipt_workspace, dict)
        and isinstance(receipt_workspace.get("path"), str)
        and bool(receipt_workspace["path"])
        and isinstance(final_content, dict)
        and isinstance(final_content.get("freeze_receipt"), str)
        and bool(final_content["freeze_receipt"])
        and isinstance(final_content.get("verified"), bool)
        and isinstance(final_content.get("paths"), list)
        and all(isinstance(path, str) for path in final_content["paths"])
        and len(final_content["paths"]) == len(set(final_content["paths"]))
        and isinstance(final_content.get("stale_paths"), list)
        and all(isinstance(path, str) for path in final_content["stale_paths"])
        and len(final_content["stale_paths"])
        == len(set(final_content["stale_paths"]))
        and receipt.get("derived_evidence") is True
        and receipt.get("generated") is True
        and receipt.get("project_authority") is False
        and isinstance(freeze_binding, dict)
        and freeze_binding.get("schema")
        == "govern-ai-coding.freeze-receipt.v1"
        and isinstance(frozen_receipt, dict)
        and frozen_receipt.get("schema")
        == "govern-ai-coding.freeze-receipt.v1"
        and freeze_binding.get("digest") == freeze_digest
        and freeze_digest == canonical_evidence_v1_digest(frozen_receipt)
        and not freeze_findings
        and frozen_receipt.get("adapter") == receipt_adapter
        and frozen_receipt.get("workspace") == receipt_workspace
        and frozen_receipt.get("derived_evidence") is True
        and frozen_receipt.get("generated") is True
        and frozen_receipt.get("project_authority") is False
        and [entry["path"] for entry in frozen_paths]
        == sorted(final_content["paths"])
        and isinstance(impact_binding, dict)
        and isinstance(impact_receipt, dict)
        and isinstance(impact_binding.get("digest"), str)
        and re.fullmatch(r"[0-9a-f]{64}", impact_binding["digest"])
        is not None
        and impact_binding["digest"]
        == canonical_evidence_v1_digest(impact_receipt)
    ):
        return False
    if result == "pass" and (
        final_content["verified"] is not True or final_content["stale_paths"]
    ):
        return False
    if adapter is not None and receipt_adapter != {
        "project": adapter.get("project"),
        "schema_version": adapter.get("schema_version"),
    }:
        return False
    if workspace is not None:
        try:
            recorded_workspace = Path(receipt_workspace["path"])
            if (
                not recorded_workspace.is_absolute()
                or recorded_workspace.resolve() != workspace.resolve()
            ):
                return False
        except (OSError, RuntimeError):
            return False
    return True


def validate_event_manifest_closeout_ledger(
    manifest: object,
    *,
    manifest_path: Path | None = None,
    workspace: Path | None = None,
    adapter: dict | None = None,
) -> list[dict]:
    """Validate every v2 attempt and the one explicit current pointer."""
    if not isinstance(manifest, dict):
        return [{"code": "event-manifest-attempt-binding-invalid", "field": "root"}]
    if manifest.get("schema") != EVENT_MANIFEST_V2_SCHEMA:
        return []
    closeout = manifest.get("closeout")
    receipts = manifest.get("receipts")
    if (
        manifest.get("schema_version") != "2"
        or not isinstance(closeout, dict)
        or not isinstance(receipts, dict)
    ):
        return [{"code": "event-manifest-attempt-binding-invalid", "field": "closeout"}]
    forbidden_closeout_fields = {
        "result", "result_reasons", "recovery_actions",
    }.intersection(closeout)
    if forbidden_closeout_fields or "closeout_attestation" in receipts:
        return [{
            "code": "event-manifest-attempt-binding-invalid",
            "field": (
                f"closeout.{sorted(forbidden_closeout_fields)[0]}"
                if forbidden_closeout_fields
                else "receipts.closeout_attestation"
            ),
        }]
    attempts = closeout.get("attempts")
    current = closeout.get("current")
    if (
        not isinstance(attempts, list)
        or "current" not in closeout
        or current is not None and not isinstance(current, str)
    ):
        return [{"code": "event-manifest-attempt-binding-invalid", "field": "closeout"}]
    findings: list[dict] = []
    ids: list[str] = []
    receipt_paths: list[tuple[str, tuple[int, int] | None]] = []
    attestation_paths: list[tuple[str, tuple[int, int] | None]] = []
    valid_passes: list[str] = []
    for index, attempt in enumerate(attempts):
        field = f"closeout.attempts.{index}"
        if not isinstance(attempt, dict):
            findings.append({
                "code": "event-manifest-attempt-binding-invalid", "field": field,
            })
            continue
        attempt_id = attempt.get("id")
        result = attempt.get("result")
        structurally_valid = (
            isinstance(attempt_id, str)
            and _ATTEMPT_ID_PATTERN.fullmatch(attempt_id) is not None
            and result in {"pass", "fail", "unproven"}
            and isinstance(attempt.get("result_reasons"), list)
            and all(isinstance(item, str) for item in attempt["result_reasons"])
            and isinstance(attempt.get("recovery_actions"), list)
            and all(isinstance(item, str) for item in attempt["recovery_actions"])
            and (
                attempt.get("attestation") is None
                or isinstance(attempt.get("attestation"), dict)
            )
        )
        if not structurally_valid:
            findings.append({
                "code": "event-manifest-attempt-binding-invalid", "field": field,
            })
        if isinstance(attempt_id, str):
            ids.append(attempt_id)
        receipt_binding = attempt.get("receipt")
        receipt, receipt_path, receipt_findings = _load_bound_manifest_evidence(
            receipt_binding,
            manifest_path=manifest_path,
            workspace=workspace,
            adapter=adapter,
            expected_schema=CLOSEOUT_RECEIPT_SCHEMA,
            missing_code="event-manifest-attempt-receipt-missing",
        )
        if receipt_path is not None:
            try:
                stat = receipt_path.stat()
                identity = (stat.st_dev, stat.st_ino)
            except OSError:
                identity = None
            receipt_paths.append((str(receipt_path), identity))
        findings.extend({**finding, "attempt_id": attempt_id} for finding in receipt_findings)
        binding_valid = (
            not receipt_findings
            and isinstance(attempt.get("freeze_digest"), str)
            and re.fullmatch(r"[0-9a-f]{64}", attempt["freeze_digest"])
            is not None
            and _closeout_receipt_structure_valid(
                receipt,
                result=result,
                freeze_digest=attempt.get("freeze_digest"),
                workspace=workspace,
                adapter=adapter,
            )
        )
        if not binding_valid:
            findings.append({
                "code": "event-manifest-attempt-binding-invalid",
                "attempt_id": attempt_id,
            })
        attestation_binding = attempt.get("attestation")
        if isinstance(attestation_binding, dict):
            attestation, attestation_path, attestation_findings = (
                _load_bound_manifest_evidence(
                    attestation_binding,
                    manifest_path=manifest_path,
                    workspace=workspace,
                    adapter=adapter,
                    expected_schema=CLOSEOUT_ATTESTATION_SCHEMA,
                    missing_code="event-manifest-attempt-attestation-missing",
                )
            )
            if attestation_path is not None:
                try:
                    stat = attestation_path.stat()
                    identity = (stat.st_dev, stat.st_ino)
                except OSError:
                    identity = None
                attestation_paths.append((str(attestation_path), identity))
            findings.extend(
                {**finding, "attempt_id": attempt_id}
                for finding in attestation_findings
            )
            if (
                result != "pass"
                or not isinstance(attestation, dict)
                or attestation.get("result") != "pass"
            ):
                findings.append({
                    "code": "event-manifest-attempt-binding-invalid",
                    "attempt_id": attempt_id,
                })
        if result == "pass" and binding_valid and not receipt_findings:
            valid_passes.append(attempt_id)
    for attempt_id in sorted(set(ids)):
        if ids.count(attempt_id) > 1:
            findings.append({
                "code": "event-manifest-attempt-id-duplicate",
                "attempt_id": attempt_id,
            })
    receipt_identities: dict[tuple[int, int] | tuple[str, str], list[str]] = {}
    for path, identity in receipt_paths:
        key = identity if identity is not None else ("path", path)
        receipt_identities.setdefault(key, []).append(path)
    for paths in receipt_identities.values():
        if len(paths) > 1:
            findings.append({
                "code": "event-manifest-attempt-receipt-duplicate",
                "paths": sorted(paths),
            })
    attestation_identities: dict[tuple[int, int] | tuple[str, str], list[str]] = {}
    for path, identity in attestation_paths:
        key = identity if identity is not None else ("path", path)
        attestation_identities.setdefault(key, []).append(path)
    for paths in attestation_identities.values():
        if len(paths) > 1:
            findings.append({
                "code": "event-manifest-attempt-attestation-duplicate",
                "paths": sorted(paths),
            })
    expected_current = valid_passes[-1] if valid_passes else None
    if current != expected_current:
        findings.append({
            "code": "event-manifest-current-invalid",
            "expected": expected_current,
            "actual": current,
        })
    unique = {
        json.dumps(finding, sort_keys=True, separators=(",", ":")): finding
        for finding in findings
    }
    return sorted(unique.values(), key=lambda item: json.dumps(item, sort_keys=True))


def current_closeout_attempt(
    manifest: object,
    *,
    manifest_path: Path | None = None,
    workspace: Path | None = None,
    adapter: dict | None = None,
) -> dict:
    """Resolve v2 Closeout evidence only through closeout.current."""
    findings = validate_event_manifest_closeout_ledger(
        manifest,
        manifest_path=manifest_path,
        workspace=workspace,
        adapter=adapter,
    )
    if findings:
        return {"status": "invalid", "findings": findings}
    if not isinstance(manifest, dict) or manifest.get("schema") != EVENT_MANIFEST_V2_SCHEMA:
        return {"status": "not-v2", "findings": []}
    current = manifest["closeout"]["current"]
    if current is None:
        return {"status": "missing", "findings": []}
    attempt = next(
        item for item in manifest["closeout"]["attempts"]
        if item["id"] == current
    )
    receipt, receipt_path, _findings = _load_bound_manifest_evidence(
        attempt["receipt"],
        manifest_path=manifest_path,
        workspace=workspace,
        adapter=adapter,
        expected_schema=CLOSEOUT_RECEIPT_SCHEMA,
        missing_code="event-manifest-attempt-receipt-missing",
    )
    attestation_path = None
    if isinstance(attempt.get("attestation"), dict):
        _attestation, attestation_path, _attestation_findings = (
            _load_bound_manifest_evidence(
                attempt["attestation"],
                manifest_path=manifest_path,
                workspace=workspace,
                adapter=adapter,
                expected_schema=CLOSEOUT_ATTESTATION_SCHEMA,
                missing_code="event-manifest-attempt-attestation-missing",
            )
        )
    return {
        "status": "matching",
        "attempt": copy.deepcopy(attempt),
        "receipt": receipt,
        "receipt_path": str(receipt_path),
        "receipt_binding": copy.deepcopy(attempt["receipt"]),
        "attestation_binding": copy.deepcopy(attempt.get("attestation")),
        "attestation_path": (
            str(attestation_path) if attestation_path is not None else None
        ),
        "findings": [],
    }


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
        "digest": canonical_evidence_v1_digest(payload),
        "schema": payload["schema"],
    }


def validate_validation_facts(facts: object) -> list[dict]:
    if not isinstance(facts, dict):
        return [{"code": "validation-facts-root-invalid", "field": "root"}]
    findings: list[dict] = []
    if facts.get("schema") != VALIDATION_FACTS_SCHEMA:
        findings.append({
            "code": "validation-facts-schema-invalid",
            "field": "schema",
        })
    if facts.get("result") != "pass":
        findings.append({
            "code": "validation-facts-result-not-pass",
            "field": "result",
        })
    input_classes = facts.get("input_classes")
    if (
        not isinstance(input_classes, list)
        or not input_classes
        or not all(isinstance(item, str) and item for item in input_classes)
        or len(input_classes) != len(set(input_classes))
    ):
        findings.append({
            "code": "validation-facts-input-classes-invalid",
            "field": "input_classes",
        })
    commands = facts.get("commands")
    if not isinstance(commands, list) or not commands:
        findings.append({
            "code": "validation-facts-commands-invalid",
            "field": "commands",
        })
        commands = []
    for index, command in enumerate(commands):
        if not isinstance(command, dict):
            findings.append({
                "code": "validation-facts-command-invalid",
                "field": f"commands[{index}]",
            })
            continue
        if not isinstance(command.get("command"), str) or not command["command"]:
            findings.append({
                "code": "validation-facts-command-invalid",
                "field": f"commands[{index}].command",
            })
        if command.get("result") != "pass":
            findings.append({
                "code": "validation-facts-command-result-invalid",
                "field": f"commands[{index}].result",
                "expected": "pass",
                "actual": command.get("result"),
            })
    if not isinstance(facts.get("environment"), dict) or not facts["environment"]:
        findings.append({
            "code": "validation-facts-environment-invalid",
            "field": "environment",
        })
    for field in ("supported_claims", "unsupported_claims"):
        value = facts.get(field)
        if (
            not isinstance(value, list)
            or not value
            or not all(isinstance(item, str) and item for item in value)
        ):
            findings.append({
                "code": "validation-facts-claims-invalid",
                "field": field,
            })
    return findings


def _validation_freeze_projection(
    freeze: object,
    *,
    require_kind: bool = True,
) -> tuple[list[dict], list[dict]]:
    findings: list[dict] = []
    if (
        not isinstance(freeze, dict)
        or freeze.get("schema") != "govern-ai-coding.freeze-receipt.v1"
        or (require_kind and freeze.get("kind") != "final-content-freeze")
    ):
        return [], [{
            "code": "validation-receipt-freeze-invalid",
            "field": "schema",
        }]
    paths = freeze.get("paths")
    if not isinstance(paths, list) or not paths:
        return [], [{
            "code": "validation-receipt-freeze-invalid",
            "field": "paths",
        }]
    projected: list[dict] = []
    seen: set[str] = set()
    for index, entry in enumerate(paths):
        valid = isinstance(entry, dict)
        path = entry.get("path") if valid else None
        existence = entry.get("existence") if valid else None
        digest = entry.get("digest") if valid else None
        valid = (
            valid
            and _safe_relative_path(path)
            and path not in seen
            and isinstance(existence, bool)
            and (
                existence
                and isinstance(digest, str)
                and re.fullmatch(r"[0-9a-f]{64}", digest) is not None
                or not existence and digest is None
            )
        )
        if not valid:
            findings.append({
                "code": "validation-receipt-freeze-invalid",
                "field": f"paths[{index}]",
            })
            continue
        seen.add(path)
        projected.append({"path": path, "digest": digest})
    return sorted(projected, key=lambda item: item["path"]), findings


def build_validation_receipt(
    freeze: object,
    facts: object,
) -> tuple[dict | None, list[dict]]:
    frozen_paths, findings = _validation_freeze_projection(freeze)
    findings.extend(validate_validation_facts(facts))
    if findings or not isinstance(freeze, dict) or not isinstance(facts, dict):
        return None, findings
    return {
        "schema": VALIDATION_RECEIPT_SCHEMA,
        "result": "pass",
        "freeze": {"digest": canonical_evidence_v1_digest(freeze)},
        "input_classes": copy.deepcopy(facts["input_classes"]),
        "frozen_paths": frozen_paths,
        "commands": copy.deepcopy(facts["commands"]),
        "environment": copy.deepcopy(facts["environment"]),
        "supported_claims": copy.deepcopy(facts["supported_claims"]),
        "unsupported_claims": copy.deepcopy(facts["unsupported_claims"]),
    }, []


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
            "digest": canonical_evidence_v1_digest(receipt),
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
    if not isinstance(commands, list) or not commands:
        findings.append({
            "code": "validation-receipt-commands-invalid",
            "path": str(receipt_path),
            "diagnostic": {
                "severity": "blocking",
                "category": "receipt_format",
                "message": "Validation receipt commands must be a non-empty list.",
                "recovery_actions": [
                    "Provide a non-empty commands list in this validation receipt; retain all still-valid event evidence."
                ],
            },
        })
        commands = []
    for index, command in enumerate(commands):
        if not isinstance(command, dict):
            field = f"commands[{index}]"
            findings.append({
                "code": "validation-receipt-command-invalid",
                "path": str(receipt_path),
                "index": index,
                "field": field,
                "expected": "object",
                "actual": type(command).__name__,
                "diagnostic": {
                    "severity": "blocking",
                    "category": "receipt_format",
                    "message": f"Validation receipt {field} must be an object.",
                    "recovery_actions": [
                        f"Correct only {field} in this validation receipt; retain all still-valid event evidence."
                    ],
                },
            })
            continue
        command_value = command.get("command")
        if not isinstance(command_value, str) or not command_value:
            field = f"commands[{index}].command"
            findings.append({
                "code": "validation-receipt-command-field-invalid",
                "path": str(receipt_path),
                "index": index,
                "field": field,
                "expected": "non-empty string",
                "actual": command_value,
                "diagnostic": {
                    "severity": "blocking",
                    "category": "receipt_format",
                    "message": f"Validation receipt {field} must be a non-empty string.",
                    "recovery_actions": [
                        f"Correct only {field} in this validation receipt; retain all still-valid event evidence."
                    ],
                },
            })
        result_value = command.get("result")
        if result_value != "pass":
            field = f"commands[{index}].result"
            findings.append({
                "code": "validation-receipt-command-result-invalid",
                "path": str(receipt_path),
                "index": index,
                "field": field,
                "expected": "pass",
                "actual": result_value,
                "diagnostic": {
                    "severity": "blocking",
                    "category": "receipt_format",
                    "message": (
                        f"Validation receipt {field} must be the exact value 'pass'."
                    ),
                    "recovery_actions": [
                        f"Set only {field} to the exact value 'pass' after confirming the recorded command passed; retain all still-valid event evidence."
                    ],
                },
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


def _validation_axis(
    *,
    required: bool,
    findings: list[dict] | None = None,
    proven: bool = False,
) -> dict:
    axis_findings = list(findings or [])
    return {
        "result": "fail" if axis_findings else "pass" if proven else "unproven",
        "required": required,
        "findings": axis_findings,
    }


def _freeze_bound_validation_axes(
    receipt: object,
    freeze: object,
    receipt_path: Path,
    *,
    require_kind: bool,
) -> tuple[dict, list[dict], list[dict]]:
    axes = {
        "structure": _validation_axis(required=True),
        "binding": _validation_axis(required=True),
        "content": _validation_axis(required=True),
        "freshness": _validation_axis(required=False),
    }
    if not isinstance(receipt, dict):
        findings = [{
            "code": "validation-receipt-malformed",
            "path": str(receipt_path),
            "field": "root",
        }]
        axes["structure"] = _validation_axis(
            required=True, findings=findings,
        )
        return axes, findings, []
    receipt_structure_findings = _validate_modern_validation_structure(
        receipt, receipt_path,
    )
    axes["structure"] = _validation_axis(
        required=True,
        findings=receipt_structure_findings,
        proven=not receipt_structure_findings,
    )
    findings = list(receipt_structure_findings)
    binding_findings: list[dict] = []
    if (
        not isinstance(receipt.get("freeze"), dict)
        or receipt["freeze"].get("digest") != canonical_evidence_v1_digest(freeze)
    ):
        binding_findings.append({
            "code": "validation-receipt-freeze-mismatch",
            "path": str(receipt_path),
        })
    expected_paths, freeze_findings = _validation_freeze_projection(
        freeze,
        require_kind=require_kind,
    )
    if freeze_findings:
        freeze_structure_findings = [
            finding for finding in freeze_findings
            if finding.get("field") == "schema"
        ]
        freeze_content_findings = [
            finding for finding in freeze_findings
            if finding.get("field") != "schema"
        ]
        summary_finding = {
            "code": "validation-receipt-freeze-paths-invalid",
            "path": str(receipt_path),
        }
        findings.extend(binding_findings)
        findings.extend(freeze_findings)
        findings.append(summary_finding)
        structure_findings = (
            list(receipt_structure_findings)
            + freeze_structure_findings
            + ([summary_finding] if freeze_structure_findings else [])
        )
        axes["structure"] = _validation_axis(
            required=True,
            findings=structure_findings,
            proven=not structure_findings,
        )
        axes["binding"] = _validation_axis(
            required=True,
            findings=binding_findings,
            proven=not binding_findings,
        )
        axes["content"] = _validation_axis(
            required=True,
            findings=(
                freeze_content_findings
                + ([summary_finding] if freeze_content_findings else [])
            ),
            proven=False,
        )
        return axes, findings, expected_paths
    axes["binding"] = _validation_axis(
        required=True,
        findings=binding_findings,
        proven=not binding_findings,
    )
    frozen = receipt.get("frozen_paths")
    actual_paths = []
    if isinstance(frozen, list):
        for entry in frozen:
            if isinstance(entry, dict):
                actual_paths.append({
                    "path": entry.get("path"),
                    "digest": entry.get("digest"),
                })
    content_findings = []
    if (
        len(actual_paths) != len({entry.get("path") for entry in actual_paths})
        or sorted(actual_paths, key=lambda item: str(item.get("path")))
        != expected_paths
    ):
        content_findings.append({
            "code": "validation-receipt-frozen-paths-mismatch",
            "path": str(receipt_path),
        })
    findings.extend(binding_findings)
    findings.extend(content_findings)
    axes["content"] = _validation_axis(
        required=True,
        findings=content_findings,
        proven=not content_findings,
    )
    return axes, findings, expected_paths


def validate_validation_receipt_for_profile(
    receipt: object,
    receipt_path: Path,
    *,
    profile: str,
    freeze: object = None,
    workspace: Path | None = None,
    content_observer=None,
) -> dict:
    registry_findings = validate_validation_profile_registry(
        VALIDATION_CONSUMER_PROFILES,
    )
    if registry_findings:
        raise RuntimeError(
            "invalid Validation Receipt consumer profile registry: "
            f"{registry_findings}"
        )
    if profile not in VALIDATION_CONSUMER_PROFILES:
        raise ValueError(f"unknown Validation Receipt consumer profile: {profile}")
    contract = VALIDATION_CONSUMER_PROFILES[profile]
    structure_mode = contract["axes"]["structure"]["mode"]
    freshness_mode = contract["axes"]["freshness"]["mode"]

    if structure_mode == "current-or-legacy-identity":
        axes = {
            axis: _validation_axis(required=False) for axis in VALIDATION_AXES
        }
        if not isinstance(receipt, dict):
            findings = [{
                "code": "validation-receipt-malformed",
                "path": str(receipt_path),
                "field": "root",
            }]
            axes["structure"] = _validation_axis(
                required=True, findings=findings,
            )
        elif receipt.get("schema") != VALIDATION_RECEIPT_SCHEMA:
            if isinstance(receipt.get("schema"), str):
                findings = []
            else:
                findings = [{
                    "code": "validation-receipt-malformed",
                    "path": str(receipt_path),
                    "field": "schema",
                }]
                axes["structure"] = _validation_axis(
                    required=True, findings=findings,
                )
        else:
            structure_findings = _validate_modern_validation_structure(
                receipt, receipt_path,
            )
            findings = list(structure_findings)
            axes["structure"] = _validation_axis(
                required=True,
                findings=structure_findings,
                proven=not structure_findings,
            )
            projection = validation_input_projection(receipt, receipt_path)
            if not structure_findings and projection is not None:
                freshness_findings = (
                    _validate_validation_input_content(
                        receipt,
                        receipt_path,
                        workspace,
                        content_observer=content_observer,
                    )
                    if workspace is not None or content_observer is not None
                    else [{
                        "code": "validation-receipt-workspace-missing",
                        "path": str(receipt_path),
                    }]
                )
                findings.extend(freshness_findings)
                axes["freshness"] = _validation_axis(
                    required=True,
                    findings=freshness_findings,
                    proven=not freshness_findings,
                )
    else:
        require_kind = structure_mode == "current-v1-complete-freeze"
        axes, findings, expected_entries = _freeze_bound_validation_axes(
            receipt,
            freeze,
            receipt_path,
            require_kind=require_kind,
        )
        if freshness_mode == "supplied-freeze-workspace":
            axes["freshness"]["required"] = True
            freshness_findings: list[dict] = []
            if workspace is None and content_observer is None:
                freshness_findings.append({
                    "code": "validation-receipt-workspace-missing",
                    "path": str(receipt_path),
                })
            else:
                for entry in expected_entries:
                    path = entry["path"]
                    digest = entry["digest"]
                    if content_observer is not None:
                        observed = content_observer(path)
                        matches = (
                            observed.get("result") == "pass"
                            and observed.get("existence") == (digest is not None)
                            and observed.get("digest") == digest
                        )
                    else:
                        target = workspace / path
                        matches = (
                            target.is_file()
                            and isinstance(digest, str)
                            and _file_digest(target) == digest
                        ) or (
                            not target.exists()
                            and digest is None
                        )
                    if not matches:
                        freshness_findings.append({
                            "code": "validation-receipt-frozen-content-mismatch",
                            "path": path,
                        })
            findings.extend(freshness_findings)
            axes["freshness"] = _validation_axis(
                required=True,
                findings=freshness_findings,
                proven=not freshness_findings and bool(expected_entries),
            )

    accepted = all(
        not axis["required"] or axis["result"] == "pass"
        for axis in axes.values()
    )
    return {
        "profile": profile,
        "accepted": accepted,
        "axes": axes,
        "findings": findings,
        "supported_conclusions": list(contract["supported_conclusions"]),
        "unsupported_conclusions": list(contract["unsupported_conclusions"]),
    }


def validate_validation_receipt(
    receipt: object,
    freeze: object,
    receipt_path: Path,
    *,
    require_full_freeze: bool = True,
) -> list[dict]:
    """Deprecated compatibility wrapper for the pre-profile Python API."""
    axes, findings, _expected_entries = _freeze_bound_validation_axes(
        receipt,
        freeze,
        receipt_path,
        require_kind=require_full_freeze,
    )
    del axes
    return findings


def _validate_freeze_bound_validation(
    receipt: dict,
    receipt_path: Path,
    workspace: Path,
    freeze_receipt: dict | None,
) -> list[dict]:
    """Deprecated compatibility helper for the pre-profile Work Map path."""
    if not isinstance(freeze_receipt, dict):
        return _validate_modern_validation_structure(receipt, receipt_path) + [{
            "code": "validation-receipt-freeze-missing",
        }]
    report = validate_validation_receipt_for_profile(
        receipt,
        receipt_path,
        profile="work-map-closeout-v1",
        freeze=freeze_receipt,
        workspace=workspace,
    )
    return report["findings"]


def _validate_validation_input_content(
    receipt: dict,
    receipt_path: Path,
    workspace: Path | None,
    *,
    content_observer=None,
) -> list[dict]:
    if validation_input_projection(receipt, receipt_path) is None:
        return []
    findings: list[dict] = []
    for entry in receipt["frozen_paths"]:
        path = entry["path"]
        expected_digest = entry.get("digest")
        if content_observer is not None:
            observed = content_observer(path)
            matches = (
                observed.get("result") == "pass"
                and observed.get("existence") == (expected_digest is not None)
                and observed.get("digest") == expected_digest
            )
        else:
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


def collect_validation_evidence_for_profile(
    receipt_paths: list[str],
    workspace: Path,
    *,
    profile: str,
    freeze_receipt: dict | None = None,
    content_observer=None,
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
        report = validate_validation_receipt_for_profile(
            receipt,
            target,
            profile=profile,
            freeze=freeze_receipt,
            workspace=workspace,
            content_observer=content_observer,
        )
        receipt_findings = report["findings"]
        findings.extend(receipt_findings)
        if receipt_findings:
            continue
        binding = {
            "path": str(target),
            "digest": canonical_evidence_v1_digest(receipt),
            "schema": receipt["schema"],
        }
        snapshots.append({
            "binding": binding,
            "projection": projection,
            "validation": report,
        })
    return snapshots, findings


def collect_validation_evidence(
    receipt_paths: list[str],
    workspace: Path,
    *,
    freeze_receipt: dict | None = None,
    require_freeze_binding: bool = False,
) -> tuple[list[dict], list[dict]]:
    """Deprecated compatibility wrapper for the pre-profile Python API."""
    snapshots, findings = collect_validation_evidence_for_profile(
        receipt_paths,
        workspace,
        profile=(
            "work-map-closeout-v1"
            if require_freeze_binding
            else "closeout-compatible-v1"
        ),
        freeze_receipt=freeze_receipt,
    )
    return [
        {
            "binding": snapshot["binding"],
            "projection": snapshot["projection"],
        }
        for snapshot in snapshots
    ], findings


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
            "digest": canonical_evidence_v1_digest(adapter),
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
                canonical_evidence_v1_digest(impact_receipt)
                if impact_receipt
                else None
            ),
            "semantic_review": semantic_review_binding,
            "freeze": (
                canonical_evidence_v1_digest(freeze_receipt)
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
        "impact": canonical_evidence_v1_digest(impact_receipt),
        "semantic_review": semantic_binding,
        "freeze": canonical_evidence_v1_digest(freeze_receipt),
        "validation": validation_bindings,
    }


def bind_closeout_attestation(
    parsed: dict,
    *,
    path: Path,
    adapter: dict,
    workspace: Path,
    manifest: dict,
    manifest_path: Path | None = None,
    content_observer=None,
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
    if manifest.get("schema") == EVENT_MANIFEST_V2_SCHEMA:
        current = current_closeout_attempt(
            manifest,
            manifest_path=manifest_path,
            workspace=workspace,
            adapter=adapter,
        )
        if current.get("status") != "matching":
            return _result("evidence-incomplete", path, schema=schema)
        pointer = current.get("attestation_binding")
        current_receipt = current.get("receipt")
        if not isinstance(current_receipt, dict):
            return _result("evidence-incomplete", path, schema=schema)
        impact_binding = current_receipt.get("impact")
        freeze_binding = current_receipt.get("freeze")
        receipt_bindings = payload.get("receipt_bindings")
        if not (
            isinstance(impact_binding, dict)
            and isinstance(impact_binding.get("receipt"), dict)
            and isinstance(freeze_binding, dict)
            and isinstance(freeze_binding.get("receipt"), dict)
            and isinstance(receipt_bindings, dict)
            and isinstance(receipt_bindings.get("validation"), list)
        ):
            return _result("evidence-incomplete", path, schema=schema)
        validation_paths = []
        for binding in receipt_bindings["validation"]:
            if not isinstance(binding, dict) or not isinstance(
                binding.get("path"), str
            ):
                return _result("evidence-incomplete", path, schema=schema)
            validation_paths.append(binding["path"])
        semantic_binding = receipt_bindings.get("semantic_review")
        if semantic_binding is not None and not (
            isinstance(semantic_binding, dict)
            and isinstance(semantic_binding.get("source"), str)
        ):
            return _result("evidence-incomplete", path, schema=schema)
        manifest = copy.deepcopy(manifest)
        manifest["receipts"]["impact"] = impact_binding["receipt"]
        manifest["receipts"]["freeze"] = freeze_binding["receipt"]
        manifest["receipts"]["validation"] = validation_paths
        manifest["semantic_review"] = (
            {"path": semantic_binding["source"]}
            if isinstance(semantic_binding, dict)
            else {}
        )
        manifest["scope"]["actual_event_paths"] = list(
            current_receipt["final_content"]["paths"]
        )
        receipts = manifest["receipts"]
    else:
        pointer = receipts.get("closeout_attestation")
    if not isinstance(pointer, dict):
        return _result("evidence-incomplete", path, schema=schema)
    recorded_path = pointer.get("path")
    if not isinstance(recorded_path, str) or not recorded_path:
        return _result("evidence-incomplete", path, schema=schema)
    recorded_candidate = Path(recorded_path)
    if (
        manifest.get("schema") == EVENT_MANIFEST_V2_SCHEMA
        and not recorded_candidate.is_absolute()
        and manifest_path is not None
    ):
        recorded_candidate = manifest_path.parent / recorded_candidate
    if recorded_candidate.resolve() != path.resolve():
        return _result("scope-mismatch", path, schema=schema)
    if pointer.get("digest") != canonical_evidence_v1_digest(payload):
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
        if adapter_digest != canonical_evidence_v1_digest(adapter):
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
        if content_observer is not None:
            observed = content_observer(relative)
            if observed.get("result") != "pass":
                return _result("content-mismatch", path, schema=schema)
            exists = observed.get("existence")
            digest = observed.get("digest")
        else:
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
    validation_snapshots, validation_findings = (
        collect_validation_evidence_for_profile(
            validation_paths,
            workspace,
            profile="closeout-compatible-v1",
            content_observer=content_observer,
        )
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
