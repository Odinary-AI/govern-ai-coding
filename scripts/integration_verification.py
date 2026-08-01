"""Bounded read-only verification of attested content after integration."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

try:
    from closeout_evidence import (
        bind_closeout_attestation,
        parse_closeout_attestation,
    )
except ModuleNotFoundError:
    _evidence_path = Path(__file__).with_name("closeout_evidence.py")
    _evidence_spec = importlib.util.spec_from_file_location(
        "govern_ai_coding_closeout_evidence_for_integration", _evidence_path,
    )
    if _evidence_spec is None or _evidence_spec.loader is None:
        raise
    _evidence_module = importlib.util.module_from_spec(_evidence_spec)
    _evidence_spec.loader.exec_module(_evidence_module)
    bind_closeout_attestation = _evidence_module.bind_closeout_attestation
    parse_closeout_attestation = _evidence_module.parse_closeout_attestation


CURRENT_SCHEMAS = ["govern-ai-coding.closeout-attestation.v1"]
HISTORICAL_SCHEMAS = ["govern-project-docs.closeout-attestation.v1"]
DIRECT_INPUT_CLASSES = {"paths", "adapter", "git-history"}


def _load_json(path: Path) -> dict | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _git(workspace: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        cwd=workspace,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _resolve_commit(workspace: Path, ref: str) -> str | None:
    completed = _git(workspace, "rev-parse", "--verify", f"{ref}^{{commit}}")
    if completed.returncode != 0:
        return None
    return completed.stdout.decode("utf-8", "replace").strip() or None


def _workspace_observation(workspace: Path, relative: str) -> dict:
    root = workspace.resolve()
    target = (workspace / relative).resolve()
    try:
        target.relative_to(root)
    except ValueError:
        return {"result": "fail", "reason": "attested-path-outside-target"}
    if not target.is_file():
        return {"result": "pass", "existence": False, "digest": None}
    return {
        "result": "pass",
        "existence": True,
        "digest": hashlib.sha256(target.read_bytes()).hexdigest(),
    }


def _ref_observation(workspace: Path, commit: str, relative: str) -> dict:
    object_name = f"{commit}:{relative}"
    exists = _git(workspace, "cat-file", "-e", object_name)
    if exists.returncode != 0:
        return {"result": "pass", "existence": False, "digest": None}
    blob = _git(workspace, "show", object_name)
    if blob.returncode != 0:
        return {"result": "fail", "reason": "target-blob-unreadable"}
    return {
        "result": "pass",
        "existence": True,
        "digest": hashlib.sha256(blob.stdout).hexdigest(),
    }


def _compare_content(payload: dict, observe) -> dict:
    paths = []
    for expected in payload["final_content"]:
        observed = observe(expected["path"])
        item = {"path": expected["path"], **observed}
        if observed.get("result") == "pass" and (
            observed.get("existence") != expected["existence"]
            or observed.get("digest") != expected["digest"]
        ):
            item.update({"result": "fail", "reason": "attested-content-changed"})
        paths.append(item)
    result = "pass" if all(item["result"] == "pass" for item in paths) else "fail"
    return {"result": result, "paths": paths}


def _target_adapter(
    workspace: Path,
    adapter_path: str,
    *,
    commit: str | None,
) -> tuple[dict | None, str | None]:
    candidate = Path(adapter_path)
    if candidate.is_absolute() or ".." in candidate.parts:
        return None, "target-adapter-outside-target"
    if commit is None:
        target = (workspace / candidate).resolve()
        try:
            target.relative_to(workspace.resolve())
        except ValueError:
            return None, "target-adapter-outside-target"
        value = _load_json(target)
        return (value, None) if value is not None else (None, "target-adapter-unreadable")
    blob = _git(workspace, "show", f"{commit}:{candidate.as_posix()}")
    if blob.returncode != 0:
        return None, "target-adapter-unreadable"
    try:
        value = json.loads(blob.stdout.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return None, "target-adapter-unreadable"
    return (value, None) if isinstance(value, dict) else (None, "target-adapter-unreadable")


def _adapter_result(payload: dict, target: dict | None, error: str | None) -> dict:
    if error is not None or target is None:
        return {"result": "fail", "reason": error or "target-adapter-unreadable"}
    expected = payload["adapter"].get("digest")
    if not isinstance(expected, str):
        return {"result": "unproven", "reason": "attested-adapter-digest-missing"}
    if _canonical_digest(target) != expected:
        return {"result": "fail", "reason": "target-adapter-changed"}
    return {"result": "pass"}


def _history_result(
    payload: dict,
    target_workspace: Path,
    target_commit: str | None,
    *,
    target_ref: str | None,
) -> dict:
    if target_ref is not None and target_commit is None:
        return {"result": "fail", "reason": "target-ref-unresolved"}
    attested_paths = payload["actual_paths"]
    if target_ref is None and attested_paths:
        unmerged = _git(target_workspace, "ls-files", "-u", "--", *attested_paths)
        if unmerged.returncode != 0:
            return {"result": "unproven", "reason": "target-index-unreadable"}
        if unmerged.stdout:
            return {"result": "fail", "reason": "attested-path-unmerged"}
    attested_commit = payload["event"].get("final_git_commit")
    if not isinstance(attested_commit, str) or not attested_commit:
        return {"result": "unproven", "reason": "attested-git-identity-missing"}
    if target_commit is None or _resolve_commit(target_workspace, attested_commit) is None:
        return {"result": "unproven", "reason": "git-history-unavailable"}
    ancestry = _git(
        target_workspace, "merge-base", "--is-ancestor",
        attested_commit, target_commit,
    )
    if ancestry.returncode == 0:
        return {
            "result": "pass",
            "relation": "attested-commit-is-target-or-ancestor",
        }
    return {
        "result": "unproven",
        "relation": "history-rewritten-or-unrelated",
    }


def _validation_result(
    payload: dict,
    *,
    content: dict,
    adapter: dict,
    history: dict,
) -> dict:
    inputs = payload.get("validation_inputs")
    if not isinstance(inputs, list) or not inputs:
        return {
            "result": "unproven",
            "claims": [],
            "unproven_inputs": ["validation-input-bindings"],
            "revalidate": [],
            "unsupported_claims": [],
        }
    component = {
        "paths": content["result"],
        "adapter": adapter["result"],
        "git-history": history["result"],
    }
    claims = []
    revalidate = []
    unproven_inputs = set()
    unsupported = set()
    for item in inputs:
        if not isinstance(item, dict):
            unproven_inputs.add("validation-input-bindings")
            continue
        classes = item.get("input_classes")
        supported = item.get("supported_claims")
        if not (
            isinstance(classes, list)
            and all(isinstance(value, str) for value in classes)
            and isinstance(supported, list)
            and all(isinstance(value, str) for value in supported)
        ):
            unproven_inputs.add("validation-input-bindings")
            continue
        for value in item.get("unsupported_claims", []):
            if isinstance(value, str):
                unsupported.add(value)
        results = []
        for input_class in classes:
            if input_class not in DIRECT_INPUT_CLASSES:
                results.append("unproven")
                unproven_inputs.add(input_class)
            else:
                results.append(component[input_class])
        if "fail" in results:
            claim_result = "revalidate"
            revalidate.extend(supported)
        elif "unproven" in results or not results:
            claim_result = "unproven"
        else:
            claim_result = "pass"
        claims.extend(
            {"claim": claim, "result": claim_result} for claim in supported
        )
    if any(item["result"] == "revalidate" for item in claims):
        result = "fail"
    elif not claims or any(item["result"] == "unproven" for item in claims):
        result = "unproven"
    else:
        result = "pass"
    return {
        "result": result,
        "claims": claims,
        "unproven_inputs": sorted(unproven_inputs),
        "revalidate": sorted(set(revalidate)),
        "unsupported_claims": sorted(unsupported),
    }


def _untrusted_result(status: str) -> dict:
    relation = "unproven" if status in {"missing", "evidence-incomplete"} else "fail"
    component = {"result": relation, "reason": status}
    return {
        "result": relation,
        "attestation": component,
        "adapter": {"result": "unproven"},
        "content": {"result": "unproven", "paths": []},
        "history": {"result": "unproven"},
        "validation": {
            "result": "unproven", "claims": [],
            "unproven_inputs": ["trusted-attestation"],
            "revalidate": [], "unsupported_claims": [],
        },
        "claim_boundary": {
            "proves": [],
            "does_not_prove": [
                "branch readiness", "release readiness", "product readiness",
            ],
        },
    }


def verify_integration(
    *,
    adapter_path: Path,
    source_workspace: Path,
    manifest_path: Path,
    attestation_path: Path,
    target_workspace: Path,
    target_adapter: str,
    target_ref: str | None = None,
) -> dict:
    """Verify only attested paths and explicitly declared validation inputs."""
    adapter = _load_json(Path(adapter_path))
    manifest = _load_json(Path(manifest_path))
    if adapter is None or manifest is None:
        return _untrusted_result("evidence-incomplete")
    parsed = parse_closeout_attestation(
        Path(attestation_path),
        current_schemas=CURRENT_SCHEMAS,
        historical_schemas=HISTORICAL_SCHEMAS,
    )
    bound = bind_closeout_attestation(
        parsed,
        path=Path(attestation_path),
        adapter=adapter,
        workspace=Path(source_workspace),
        manifest=manifest,
    )
    if bound.get("status") != "matching":
        return _untrusted_result(str(bound.get("status", "evidence-incomplete")))
    payload = bound["payload"]
    target_workspace = Path(target_workspace).resolve()
    target_commit = _resolve_commit(target_workspace, target_ref or "HEAD")
    if target_ref is not None:
        observe = (
            (lambda relative: _ref_observation(
                target_workspace, target_commit, relative,
            ))
            if target_commit is not None
            else (lambda relative: {
                "result": "fail", "reason": "target-ref-unresolved",
            })
        )
    else:
        observe = lambda relative: _workspace_observation(
            target_workspace, relative,
        )
    content = _compare_content(payload, observe)
    target_adapter_value, adapter_error = _target_adapter(
        target_workspace,
        target_adapter,
        commit=target_commit if target_ref is not None else None,
    )
    adapter_result = _adapter_result(
        payload, target_adapter_value, adapter_error,
    )
    history = _history_result(
        payload,
        target_workspace,
        target_commit,
        target_ref=target_ref,
    )
    validation = _validation_result(
        payload,
        content=content,
        adapter=adapter_result,
        history=history,
    )
    components = [
        content["result"], adapter_result["result"],
        history["result"], validation["result"],
    ]
    if "fail" in components:
        result = "fail"
    elif "unproven" in components:
        result = "unproven"
    else:
        result = "pass"
    return {
        "result": result,
        "attestation": {
            "result": "pass",
            "identity": _canonical_digest(payload),
        },
        "adapter": adapter_result,
        "content": content,
        "history": history,
        "validation": validation,
        "claim_boundary": {
            "proves": [
                "attested paths",
                "directly observed declared inputs",
            ],
            "does_not_prove": [
                "branch readiness", "release readiness", "product readiness",
            ],
        },
    }
