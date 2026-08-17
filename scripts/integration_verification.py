"""Bounded read-only verification of attested content after integration."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess

try:
    from closeout_evidence import (
        bind_closeout_attestation,
        canonical_evidence_v1_digest,
        current_closeout_attempt,
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
    canonical_evidence_v1_digest = (
        _evidence_module.canonical_evidence_v1_digest
    )
    current_closeout_attempt = _evidence_module.current_closeout_attempt
    parse_closeout_attestation = _evidence_module.parse_closeout_attestation


CURRENT_SCHEMAS = ["govern-ai-coding.closeout-attestation.v1"]
HISTORICAL_SCHEMAS = ["govern-project-docs.closeout-attestation.v1"]
DIRECT_INPUT_CLASSES = {"paths", "adapter", "git-history"}
FULL_OBJECT_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
GIT_ENVIRONMENT_OVERRIDES = {
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_DIR",
    "GIT_INDEX_FILE",
    "GIT_NAMESPACE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_REPLACE_REF_BASE",
    "GIT_SHALLOW_FILE",
    "GIT_WORK_TREE",
}


def _load_json(path: Path) -> dict | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _canonical_regular_file(
    raw_path: object,
    *,
    relative_base: Path | None = None,
) -> Path | None:
    if not isinstance(raw_path, (str, Path)):
        return None
    raw = str(raw_path)
    if not raw or "\\" in raw:
        return None
    candidate = Path(raw)
    if candidate.is_absolute():
        if raw != candidate.as_posix():
            return None
    else:
        if relative_base is None or not _safe_repository_path(raw):
            return None
        candidate = relative_base / Path(*PurePosixPath(raw).parts)
    try:
        absolute = candidate.absolute()
        current = Path(absolute.anchor)
        for part in absolute.parts[1:]:
            current = current / part
            metadata = os.lstat(current)
            if stat.S_ISLNK(metadata.st_mode):
                return None
        metadata = os.lstat(absolute)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            return None
        if absolute.resolve(strict=True) != absolute:
            return None
    except (OSError, RuntimeError):
        return None
    return absolute


def _safe_evidence_json(
    raw_path: object,
    *,
    relative_base: Path | None = None,
) -> tuple[dict | None, Path | None]:
    path = _canonical_regular_file(raw_path, relative_base=relative_base)
    if path is None:
        return None, None
    payload = _load_json(path)
    return payload, path


def _binding_matches(
    binding: object,
    *,
    relative_base: Path | None = None,
    path_field: str = "path",
    expected_path: Path | None = None,
) -> tuple[dict | None, Path | None]:
    if not isinstance(binding, dict):
        return None, None
    payload, path = _safe_evidence_json(
        binding.get(path_field),
        relative_base=relative_base,
    )
    if payload is None or path is None:
        return None, None
    if expected_path is not None and path != expected_path:
        return None, None
    schema = binding.get("schema")
    if schema is not None and schema != payload.get("schema"):
        return None, None
    if binding.get("digest") != canonical_evidence_v1_digest(payload):
        return None, None
    return payload, path


def _explicit_evidence_preflight(
    manifest: dict,
    manifest_path: Path,
    attestation: dict,
    attestation_path: Path,
) -> bool:
    receipts = manifest.get("receipts")
    bindings = attestation.get("receipt_bindings")
    if not isinstance(receipts, dict) or not isinstance(bindings, dict):
        return False
    if manifest.get("schema_version") == "2":
        current = current_closeout_attempt(
            manifest,
            manifest_path=manifest_path,
        )
        if current.get("status") != "matching":
            return False
        closeout_payload = current.get("receipt")
        attested_payload, _attested_path = _binding_matches(
            current.get("attestation_binding"),
            relative_base=manifest_path.parent,
            expected_path=attestation_path,
        )
        if not isinstance(closeout_payload, dict) or attested_payload != attestation:
            return False
    else:
        pointer = receipts.get("closeout_attestation")
        if not isinstance(pointer, dict):
            return False
        pointed, pointed_path = _safe_evidence_json(pointer.get("path"))
        if (
            pointed_path != attestation_path
            or pointed != attestation
            or pointer.get("digest") != canonical_evidence_v1_digest(attestation)
        ):
            return False

    validation_bindings = bindings.get("validation")
    if not isinstance(validation_bindings, list):
        return False
    observed_validation_paths = []
    for binding in validation_bindings:
        payload, path = _binding_matches(binding)
        if payload is None or path is None:
            return False
        observed_validation_paths.append(str(path))
    if manifest.get("schema_version") != "2" and receipts.get("validation") != observed_validation_paths:
        return False

    semantic_binding = bindings.get("semantic_review")
    if semantic_binding is not None:
        payload, semantic_path = _binding_matches(
            semantic_binding,
            path_field="source",
        )
        if payload is None or semantic_path is None:
            return False
        if manifest.get("schema_version") != "2":
            semantic = manifest.get("semantic_review")
            if (
                not isinstance(semantic, dict)
                or semantic.get("path") != str(semantic_path)
            ):
                return False
    return True


def _git(repository: Path, *args: str) -> subprocess.CompletedProcess:
    environment = os.environ.copy()
    for name in GIT_ENVIRONMENT_OVERRIDES:
        environment.pop(name, None)
    environment.update({
        "GIT_LITERAL_PATHSPECS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "LC_ALL": "C",
    })
    return subprocess.run(
        ["git", "--no-replace-objects", "-C", str(repository), *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
    )


def _resolve_commit(workspace: Path, ref: str) -> str | None:
    completed = _git(
        workspace,
        "rev-parse",
        "--verify",
        "--end-of-options",
        f"{ref}^{{commit}}",
    )
    if completed.returncode != 0:
        return None
    try:
        output = completed.stdout.decode("ascii").strip()
    except UnicodeError:
        return None
    return output if FULL_OBJECT_ID.fullmatch(output) is not None else None


def _git_directory(repository: Path, option: str) -> Path | None:
    observed = _git(repository, "rev-parse", option)
    if observed.returncode != 0:
        return None
    try:
        output = observed.stdout.decode("utf-8")
    except UnicodeError:
        return None
    if not output.endswith("\n") or "\0" in output or "\r" in output:
        return None
    value = output[:-1]
    if not value or "\n" in value:
        return None
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = repository / candidate
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    return resolved if resolved.is_dir() else None


def _repository(
    repository: Path,
    *,
    role: str,
) -> tuple[Path | None, str | None]:
    candidate = Path(repository)
    try:
        if candidate.is_symlink():
            return None, f"{role}-repository-symlink"
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        return None, f"{role}-repository-invalid"
    if not resolved.is_dir():
        return None, f"{role}-repository-invalid"
    git_directory = _git_directory(resolved, "--absolute-git-dir")
    common_directory = _git_directory(resolved, "--git-common-dir")
    if git_directory is None or common_directory is None:
        return None, f"{role}-repository-invalid"
    for directory in {git_directory, common_directory}:
        grafts = directory / "info" / "grafts"
        if grafts.exists() or grafts.is_symlink():
            try:
                active_grafts = any(
                    line.strip() and not line.lstrip().startswith(b"#")
                    for line in grafts.read_bytes().splitlines()
                )
            except OSError:
                active_grafts = True
            if active_grafts:
                return resolved, f"{role}-repository-graft-overlay"
    return resolved, None


def _raw_commit_parents(repository: Path, commit: str) -> list[str] | None:
    observed = _git(repository, "cat-file", "commit", commit)
    if observed.returncode != 0 or b"\0" in observed.stdout or b"\r" in observed.stdout:
        return None
    headers, separator, _message = observed.stdout.partition(b"\n\n")
    if not separator:
        return None
    lines = headers.split(b"\n")
    if not lines or not lines[0].startswith(b"tree "):
        return None
    tree_id = lines[0][len(b"tree "):]
    try:
        decoded_tree_id = tree_id.decode("ascii")
    except UnicodeError:
        return None
    if FULL_OBJECT_ID.fullmatch(decoded_tree_id) is None:
        return None
    parents: list[str] = []
    previous_header = b"tree"
    for line in lines[1:]:
        if line.startswith(b" "):
            if not previous_header:
                return None
            continue
        try:
            key, value = line.split(b" ", 1)
            key.decode("ascii")
        except (UnicodeError, ValueError):
            return None
        if re.fullmatch(rb"[A-Za-z][A-Za-z0-9-]*", key) is None:
            return None
        previous_header = key
        if key == b"tree":
            return None
        if key == b"parent":
            try:
                parent = value.decode("ascii")
            except UnicodeError:
                return None
            if FULL_OBJECT_ID.fullmatch(parent) is None:
                return None
            parents.append(parent)
    return parents


def _repository_is_shallow(repository: Path) -> bool | None:
    observed = _git(repository, "rev-parse", "--is-shallow-repository")
    if observed.returncode != 0:
        return None
    value = observed.stdout.decode("ascii", "ignore").strip()
    if value == "true":
        return True
    if value == "false":
        return False
    return None


def _safe_repository_path(value: object) -> bool:
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and bool(path.parts)
        and all(part not in {"", ".", ".."} for part in path.parts)
        and path.as_posix() == value
    )


def _valid_explicit_ref(repository: Path, ref: object) -> bool:
    if not isinstance(ref, str) or not ref:
        return False
    if FULL_OBJECT_ID.fullmatch(ref) is not None:
        return True
    if not ref.startswith("refs/"):
        return False
    return _git(repository, "check-ref-format", ref).returncode == 0


def _resolve_explicit_commit(repository: Path, ref: object) -> str | None:
    if not _valid_explicit_ref(repository, ref):
        return None
    return _resolve_commit(repository, str(ref))


def _decode_paths(value: bytes) -> list[str] | None:
    if not value:
        return []
    if not value.endswith(b"\0"):
        return None
    try:
        paths = [item.decode("utf-8") for item in value[:-1].split(b"\0")]
    except UnicodeError:
        return None
    if not all(_safe_repository_path(path) for path in paths):
        return None
    return paths


def _tree_observation(repository: Path, commit: str, relative: str) -> dict:
    if not _safe_repository_path(relative):
        return {"result": "fail", "reason": "source-path-unsafe"}
    listed = _git(
        repository,
        "ls-tree",
        "-z",
        "--full-tree",
        commit,
        "--",
        relative,
    )
    if listed.returncode != 0:
        return {"result": "fail", "reason": "git-tree-unreadable"}
    if not listed.stdout:
        return {"result": "pass", "existence": False, "digest": None}
    records = listed.stdout.split(b"\0")
    if records[-1] != b"" or len(records) != 2:
        return {"result": "fail", "reason": "git-tree-entry-invalid"}
    try:
        metadata, raw_path = records[0].split(b"\t", 1)
        mode, kind, object_id = metadata.decode("ascii").split(" ")
        observed_path = raw_path.decode("utf-8")
    except (UnicodeError, ValueError):
        return {"result": "fail", "reason": "git-tree-entry-invalid"}
    if observed_path != relative or not _safe_repository_path(observed_path):
        return {"result": "fail", "reason": "git-tree-entry-invalid"}
    if mode not in {"100644", "100755"} or kind != "blob":
        return {"result": "fail", "reason": "git-tree-entry-not-regular"}
    blob = _git(repository, "cat-file", "blob", object_id)
    if blob.returncode != 0:
        return {"result": "fail", "reason": "git-tree-blob-unreadable"}
    return {
        "result": "pass",
        "existence": True,
        "digest": hashlib.sha256(blob.stdout).hexdigest(),
        "bytes": blob.stdout,
    }


def _source_identity(
    repository: Path,
    source_ref: str,
    manifest: dict,
    attestation: dict,
    adapter_path: Path | str,
) -> tuple[dict, dict | None, object | None]:
    resolved_repository, repository_error = _repository(
        repository,
        role="source",
    )
    if resolved_repository is None or repository_error is not None:
        return ({"result": "fail", "reason": repository_error}, None, None)
    commit = _resolve_explicit_commit(resolved_repository, source_ref)
    if commit is None:
        return ({"result": "fail", "reason": "source-ref-unresolved"}, None, None)
    baseline_ref = (manifest.get("event") or {}).get("baseline_ref")
    baseline = _resolve_explicit_commit(resolved_repository, baseline_ref)
    if baseline is None:
        return ({"result": "fail", "reason": "source-baseline-unresolved"}, None, None)
    parent_ids = _raw_commit_parents(resolved_repository, commit)
    if parent_ids is None:
        return ({"result": "fail", "reason": "source-commit-object-invalid"}, None, None)
    if len(parent_ids) > 1:
        return ({"result": "fail", "reason": "source-merge-unsupported"}, None, None)
    if parent_ids != [baseline]:
        return ({"result": "fail", "reason": "source-parent-mismatch"}, None, None)
    changed = _git(
        resolved_repository,
        "diff-tree",
        "--no-commit-id",
        "--name-only",
        "--no-renames",
        "--no-ext-diff",
        "-r",
        "-z",
        baseline,
        commit,
        "--",
    )
    changed_paths = _decode_paths(changed.stdout) if changed.returncode == 0 else None
    actual_paths = attestation.get("actual_paths")
    if (
        not isinstance(actual_paths, list)
        or actual_paths != sorted(set(actual_paths))
        or not all(_safe_repository_path(path) for path in actual_paths)
    ):
        return ({"result": "fail", "reason": "source-paths-unsafe"}, None, None)
    if changed_paths is None or sorted(changed_paths) != actual_paths:
        return ({"result": "fail", "reason": "source-paths-mismatch"}, None, None)
    relative_adapter = str(adapter_path)
    if not _safe_repository_path(relative_adapter):
        return ({"result": "fail", "reason": "source-adapter-path-unsafe"}, None, None)
    adapter_observation = _tree_observation(
        resolved_repository, commit, relative_adapter,
    )
    raw_adapter = adapter_observation.get("bytes")
    if adapter_observation.get("result") != "pass" or not isinstance(raw_adapter, bytes):
        return ({"result": "fail", "reason": "source-adapter-unreadable"}, None, None)
    try:
        adapter = json.loads(raw_adapter.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        adapter = None
    attested_adapter = attestation.get("adapter")
    if not isinstance(adapter, dict) or not isinstance(attested_adapter, dict):
        return ({"result": "fail", "reason": "source-adapter-unreadable"}, None, None)
    if (
        any(
            adapter.get(key) != attested_adapter.get(key)
            for key in ("project", "schema_version")
        )
        or attested_adapter.get("digest") != canonical_evidence_v1_digest(adapter)
    ):
        return ({"result": "fail", "reason": "source-adapter-mismatch"}, None, None)
    observe = lambda relative: _tree_observation(
        resolved_repository, commit, relative,
    )
    for expected in attestation.get("final_content", []):
        if not isinstance(expected, dict) or not isinstance(expected.get("path"), str):
            return ({"result": "fail", "reason": "source-content-mismatch"}, None, None)
        observed = observe(expected["path"])
        if (
            observed.get("result") != "pass"
            or observed.get("existence") != expected.get("existence")
            or observed.get("digest") != expected.get("digest")
        ):
            return ({"result": "fail", "reason": "source-content-mismatch"}, None, None)
    recorded_commit = (attestation.get("event") or {}).get("final_git_commit")
    if recorded_commit is not None and recorded_commit != commit:
        return ({"result": "fail", "reason": "source-final-commit-mismatch"}, None, None)
    return ({
        "result": "pass",
        "repository": str(resolved_repository),
        "ref": source_ref,
        "commit": commit,
        "baseline": baseline,
        "relation": "source-sole-parent-is-manifest-baseline",
        "changed_paths": changed_paths,
    }, adapter, observe)


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
    strict_path: bool,
) -> tuple[dict | None, str | None]:
    candidate = Path(adapter_path)
    if strict_path:
        if not _safe_repository_path(adapter_path):
            return None, "target-adapter-path-unsafe"
        candidate = Path(*PurePosixPath(adapter_path).parts)
    elif candidate.is_absolute() or ".." in candidate.parts:
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
    if canonical_evidence_v1_digest(target) != expected:
        return {"result": "fail", "reason": "target-adapter-changed"}
    return {"result": "pass"}


def _history_result(
    payload: dict,
    target_workspace: Path,
    target_commit: str | None,
    *,
    target_ref: str | None,
    source_commit: str | None = None,
    explicit_source: bool = False,
    target_repository_error: str | None = None,
) -> dict:
    if explicit_source:
        if target_repository_error == "target-repository-graft-overlay":
            return {"result": "unproven", "reason": "target-history-graft"}
        if target_repository_error is not None:
            return {"result": "fail", "reason": target_repository_error}
        if target_ref is None:
            return {"result": "unproven", "reason": "target-ref-required"}
        if target_commit is None:
            return {"result": "unproven", "reason": "target-ref-unavailable"}
        if (
            source_commit is None
            or _resolve_explicit_commit(target_workspace, source_commit) is None
        ):
            return {"result": "unproven", "reason": "source-object-unavailable"}
        ancestry = _git(
            target_workspace,
            "merge-base",
            "--is-ancestor",
            source_commit,
            target_commit,
        )
        if ancestry.returncode == 0:
            return {
                "result": "pass",
                "relation": "source-commit-is-target-or-ancestor",
            }
        if ancestry.returncode == 1:
            shallow = _repository_is_shallow(target_workspace)
            if shallow is not False:
                return {"result": "unproven", "reason": "target-history-shallow"}
            return {
                "result": "fail",
                "reason": "source-commit-not-target-ancestor",
                "relation": "target-history-observably-unrelated",
            }
        return {"result": "unproven", "reason": "git-history-unavailable"}
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
        "diagnostics": [{
            "severity": "blocking" if relation == "fail" else "unproven",
            "category": "receipt_format",
            "code": "integration-attestation-untrusted",
            "message": f"Closeout attestation is not trusted: {status}.",
            "fields": {"status": status},
            "recovery_actions": [
                "Provide the original immutable Closeout attestation and matching source event context, then rerun only integration verification."
            ],
        }],
        "claim_boundary": {
            "proves": [],
            "does_not_prove": [
                "branch readiness", "release readiness", "product readiness",
            ],
        },
    }


def _source_failure(reason: str) -> dict:
    result = _untrusted_result("evidence-incomplete")
    result["result"] = "fail"
    result["source_identity"] = {"result": "fail", "reason": reason}
    result["diagnostics"] = [{
        "severity": "blocking",
        "category": "receipt_format",
        "code": "integration-source-identity-invalid",
        "message": "The explicit source Git identity could not be proven.",
        "fields": {"reason": reason},
        "recovery_actions": [
            "Provide one valid explicit source repository/ref pair bound to the manifest baseline and attested bytes."
        ],
    }]
    return result


def _integration_diagnostics(
    *,
    adapter: dict,
    content: dict,
    history: dict,
    validation: dict,
) -> list[dict]:
    diagnostics: list[dict] = []
    content_result = content.get("result")
    if content_result != "pass":
        affected_paths = sorted({
            item.get("path")
            for item in content.get("paths", [])
            if isinstance(item, dict)
            and item.get("result") != "pass"
            and isinstance(item.get("path"), str)
        })
        diagnostics.append({
            "severity": "blocking" if content_result == "fail" else "unproven",
            "category": "freeze_invalidation",
            "code": "integration-content-mismatch",
            "message": "Integrated content does not match every attested path.",
            "paths": affected_paths,
            "recovery_actions": [
                "Reconcile the listed target paths with the attested bytes or run affected validation and close a new governed event."
            ],
        })
    adapter_result = adapter.get("result")
    if adapter_result != "pass":
        diagnostics.append({
            "severity": "blocking" if adapter_result == "fail" else "unproven",
            "category": "adapter_configuration",
            "code": "integration-adapter-mismatch",
            "message": "The target adapter cannot inherit the attested adapter claim.",
            "fields": {"reason": adapter.get("reason")},
            "recovery_actions": [
                "Use the attested adapter identity or close a new governed event for the changed target adapter."
            ],
        })
    history_result = history.get("result")
    if history_result != "pass":
        diagnostics.append({
            "severity": "blocking" if history_result == "fail" else "unproven",
            "category": "validation_missing",
            "code": "integration-history-unproven",
            "message": "Target Git history does not prove the attested integration relation.",
            "fields": {"reason": history.get("reason")},
            "recovery_actions": [
                "Provide an observable target ref and ancestry relation, or retain the bounded history result as unproven."
            ],
        })
    validation_result = validation.get("result")
    if validation_result != "pass":
        revalidate = [
            value for value in validation.get("revalidate", [])
            if isinstance(value, str) and value
        ]
        diagnostics.append({
            "severity": "blocking" if validation_result == "fail" else "unproven",
            "category": "validation_missing",
            "code": (
                "integration-validation-revalidation-required"
                if revalidate
                else "integration-validation-unproven"
            ),
            "message": "Validation claims cannot be inherited for every declared input.",
            "fields": {
                "revalidate": revalidate,
                "unproven_inputs": validation.get("unproven_inputs", []),
            },
            "recovery_actions": [
                "Run only the listed affected validation obligations and close a new governed event for changed inputs."
                if revalidate
                else "Provide directly observable evidence for each declared validation input."
            ],
        })
    return sorted(
        diagnostics,
        key=lambda item: (item["severity"], item["category"], item["code"]),
    )


def verify_integration(
    *,
    adapter_path: Path | str,
    source_workspace: Path,
    source_repository: Path | None = None,
    source_ref: str | None = None,
    manifest_path: Path,
    attestation_path: Path,
    target_workspace: Path,
    target_adapter: str,
    target_ref: str | None = None,
) -> dict:
    """Verify only attested paths and explicitly declared validation inputs."""
    explicit_source = source_repository is not None or source_ref is not None
    if (source_repository is None) != (source_ref is None):
        return _source_failure("source-identity-pair-incomplete")
    if explicit_source:
        manifest, safe_manifest_path = _safe_evidence_json(Path(manifest_path))
        attestation, safe_attestation_path = _safe_evidence_json(
            Path(attestation_path),
        )
        if (
            manifest is None
            or safe_manifest_path is None
            or attestation is None
            or safe_attestation_path is None
        ):
            return _source_failure("evidence-file-unsafe")
    else:
        adapter = _load_json(Path(adapter_path))
        manifest = _load_json(Path(manifest_path))
        safe_manifest_path = Path(manifest_path)
        safe_attestation_path = Path(attestation_path)
        content_observer = None
        if adapter is None or manifest is None:
            return _untrusted_result("evidence-incomplete")
    parsed = parse_closeout_attestation(
        safe_attestation_path,
        current_schemas=CURRENT_SCHEMAS,
        historical_schemas=HISTORICAL_SCHEMAS,
    )
    if parsed.get("status") != "parsed" or not isinstance(parsed.get("payload"), dict):
        return _untrusted_result(str(parsed.get("status", "evidence-incomplete")))
    if explicit_source:
        if not _explicit_evidence_preflight(
            manifest,
            safe_manifest_path,
            parsed["payload"],
            safe_attestation_path,
        ):
            return _source_failure("evidence-file-unsafe")
        source_identity, adapter, content_observer = _source_identity(
            Path(source_repository),
            str(source_ref),
            manifest,
            parsed["payload"],
            adapter_path,
        )
        if source_identity.get("result") != "pass" or adapter is None:
            return _source_failure(
                str(source_identity.get("reason", "source-identity-invalid")),
            )
    if adapter is None:
        return _untrusted_result("evidence-incomplete")
    bound = bind_closeout_attestation(
        parsed,
        path=safe_attestation_path,
        adapter=adapter,
        workspace=Path(source_workspace),
        manifest=manifest,
        manifest_path=safe_manifest_path,
        content_observer=content_observer,
    )
    if bound.get("status") != "matching":
        result = _untrusted_result(
            str(bound.get("status", "evidence-incomplete")),
        )
        if explicit_source:
            result["source_identity"] = source_identity
        return result
    payload = bound["payload"]
    if explicit_source:
        resolved_target, target_repository_error = _repository(
            Path(target_workspace),
            role="target",
        )
        target_workspace = (
            resolved_target
            if resolved_target is not None
            else Path(target_workspace)
        )
    else:
        resolved_target = Path(target_workspace).resolve()
        target_workspace = resolved_target
        target_repository_error = None
    if explicit_source and target_ref is not None:
        target_commit = (
            _resolve_explicit_commit(target_workspace, target_ref)
            if resolved_target is not None
            else None
        )
    else:
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
        strict_path=explicit_source,
    )
    adapter_result = _adapter_result(
        payload, target_adapter_value, adapter_error,
    )
    history = _history_result(
        payload,
        target_workspace,
        target_commit,
        target_ref=target_ref,
        source_commit=(
            source_identity.get("commit")
            if explicit_source
            else None
        ),
        explicit_source=explicit_source,
        target_repository_error=target_repository_error,
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
    response = {
        "result": result,
        "attestation": {
            "result": "pass",
            "identity": canonical_evidence_v1_digest(payload),
        },
        "adapter": adapter_result,
        "content": content,
        "history": history,
        "validation": validation,
        "diagnostics": _integration_diagnostics(
            adapter=adapter_result,
            content=content,
            history=history,
            validation=validation,
        ),
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
    if explicit_source:
        response["source_identity"] = source_identity
    return response
