#!/usr/bin/env python3
"""
STD-DVA-001 v0.2.6

Purpose:
    Preserve every undeclared supported entry state exactly and apply only
    explicitly declared changes to a regular-file tar/tar.gz package.

Dependencies:
    Python standard library only.
"""

from __future__ import annotations

import argparse
import base64
import copy
from decimal import Decimal, InvalidOperation
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tarfile
import tempfile
from typing import Any, Dict, Iterable, List, Tuple


VERSION = "0.2.6"
FORMAT = "cleanroom-mutator-instruction/v1"
PLAN_FORMAT = "cleanroom-mutator-plan/v1"
AUDIT_FORMAT = "cleanroom-mutator-audit/v1"

PRG_SOURCE_BINDING = {
    "program_id": "PRG-DVA-001",
    "version": "0.2.6",
    "standard_id": "STD-DVA-001",
    "standard_file": "std/STD-DVA-001_v0.2.6.txt",
    "spl_file": "spl/SPL-DVA-001_v0.2.6.txt",
    "operator_entrypoint": "prg/PRG-DVA-001_v0.2.6.py",
    "command_surfaces": [
        "inspect", "plan", "apply", "verify", "rewind", "version", "help"
    ],
    "protocol_formats": {
        "instruction": "cleanroom-mutator-instruction/v1",
        "plan": "cleanroom-mutator-plan/v1",
        "audit": "cleanroom-mutator-audit/v1",
    },
}

INSTRUCTION_REQUIRED_FIELDS = frozenset({
    "format",
    "baseline_sha256",
    "operations",
})
CONTENT_FIELDS = frozenset({
    "content_utf8",
    "content_base64",
})
OPERATION_REQUIRED_FIELDS = {
    "create": frozenset({"op", "path"}),
    "replace": frozenset({"op", "path", "expected_sha256"}),
    "delete": frozenset({"op", "path", "expected_sha256"}),
    "rename": frozenset({
        "op", "from_path", "to_path", "expected_sha256",
    }),
}
OPERATION_OPTIONAL_FIELDS = {
    "create": CONTENT_FIELDS | frozenset({"mode"}),
    "replace": CONTENT_FIELDS | frozenset({"mode"}),
    "delete": frozenset(),
    "rename": frozenset(),
}

STRUCTURAL_PAX_KEYS = frozenset({
    "path", "linkpath", "size", "uid", "gid", "uname", "gname", "mtime"
})
SPARSE_PAX_PREFIXES = ("GNU.sparse.",)
SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


class CleanRoomError(RuntimeError):
    pass


class FileSnapshot:
    def __init__(self, *, path: Path, data: bytes, sha256: str) -> None:
        self.path = path
        self.data = data
        self.sha256 = sha256


class PackageSnapshot:
    def __init__(
        self, *, path: Path, data: bytes, sha256: str, root_name: str,
        state: Dict[str, Dict[str, Any]]
    ) -> None:
        self.path = path
        self.data = data
        self.sha256 = sha256
        self.root_name = root_name
        self.state = state


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_file_snapshot(path: Path) -> FileSnapshot:
    path = Path(path)
    try:
        with path.open("rb") as fh:
            before = os.fstat(fh.fileno())
            chunks: List[bytes] = []
            digest = hashlib.sha256()
            while True:
                chunk = fh.read(1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
                digest.update(chunk)
            after = os.fstat(fh.fileno())
    except OSError as exc:
        raise CleanRoomError(f"unable to read file: {path}: {exc}") from exc

    identity_before = (
        before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
        before.st_ctime_ns,
    )
    identity_after = (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if identity_before != identity_after:
        raise CleanRoomError(f"file changed while being read: {path}")

    data = b"".join(chunks)
    if len(data) != after.st_size:
        raise CleanRoomError(f"file size changed while being read: {path}")
    return FileSnapshot(path=path, data=data, sha256=digest.hexdigest())


def sha256_file(path: Path) -> str:
    return read_file_snapshot(Path(path)).sha256


def canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise CleanRoomError("value cannot be encoded as canonical UTF-8 JSON") from exc


def _require_utf8_text(value: Any, *, field: str, allow_empty: bool = True) -> str:
    if not isinstance(value, str):
        raise CleanRoomError(f"{field} must be a string")
    if not allow_empty and not value:
        raise CleanRoomError(f"{field} must be a non-empty string")
    if "\x00" in value:
        raise CleanRoomError(f"{field} contains a forbidden NUL character")
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise CleanRoomError(f"{field} must contain valid UTF-8 text") from exc
    return value


def safe_relpath(value: str) -> str:
    """Validate a literal POSIX relative path without rewriting it."""
    value = _require_utf8_text(value, field="path", allow_empty=False)
    if value.startswith("/"):
        raise CleanRoomError(f"absolute path is forbidden: {value}")
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise CleanRoomError(f"unsafe or non-canonical path is forbidden: {value}")
    return value


def _archive_member_path(member: tarfile.TarInfo) -> str:
    value = _require_utf8_text(member.name, field="archive member path", allow_empty=False)
    if member.isdir() and value.endswith("/"):
        value = value[:-1]
    if not value:
        raise CleanRoomError("archive member path is empty")
    return safe_relpath(value)


def _normalize_sha256(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise CleanRoomError(f"{field} must be exactly 64 hexadecimal characters")
    return value.lower()


def _validate_object_fields(
    value: Dict[str, Any],
    *,
    scope: str,
    required: frozenset[str],
    allowed: frozenset[str],
) -> None:
    actual = set(value)

    unknown = sorted(
        (key for key in actual if key not in allowed),
        key=lambda key: repr(key),
    )
    if unknown:
        raise CleanRoomError(
            f"{scope} contains unsupported fields: {unknown}"
        )

    missing = sorted(required - actual)
    if missing:
        raise CleanRoomError(
            f"{scope} is missing required fields: {missing}"
        )


def _canonical_decimal(value: Any, *, field: str = "mtime") -> str:
    if isinstance(value, bool):
        raise CleanRoomError(f"{field} must be an exact finite decimal number")
    if isinstance(value, float):
        value = str(value)
    elif isinstance(value, int):
        value = str(value)
    elif isinstance(value, Decimal):
        value = str(value)
    elif isinstance(value, str):
        if value != value.strip() or not value:
            raise CleanRoomError(f"{field} must be an exact finite decimal number")
    else:
        raise CleanRoomError(f"{field} must be an exact finite decimal number")

    try:
        number = Decimal(value)
    except (InvalidOperation, ValueError) as exc:
        raise CleanRoomError(f"{field} must be an exact finite decimal number") from exc
    if not number.is_finite():
        raise CleanRoomError(f"{field} must be finite")

    text = format(number, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    if text in {"-0", ""}:
        text = "0"
    return text


def _clean_pax_headers(value: Dict[str, str] | None, *, field: str) -> Dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise CleanRoomError(f"{field} must be an object")
    result: Dict[str, str] = {}
    for key, item in value.items():
        key = _require_utf8_text(key, field=f"{field} key", allow_empty=False)
        item = _require_utf8_text(item, field=f"{field}[{key}]")
        if "=" in key or "\n" in key or "\r" in key:
            raise CleanRoomError(f"{field} contains an invalid PAX key: {key!r}")
        result[key] = item
    return result


def _entry_record(
    *,
    kind: str,
    data: bytes = b"",
    mode: int,
    uid: int,
    gid: int,
    uname: str,
    gname: str,
    mtime: Any,
    typeflag: str | None = None,
    linkname: str = "",
    devmajor: int = 0,
    devminor: int = 0,
    pax_headers: Dict[str, str] | None = None,
    archive_pax_headers: Dict[str, str] | None = None,
) -> Dict[str, Any]:
    if kind not in {"file", "dir"}:
        raise CleanRoomError(f"unsupported state kind: {kind}")
    if not isinstance(data, bytes):
        raise CleanRoomError("entry data must be bytes")
    if kind == "dir" and data != b"":
        raise CleanRoomError("directory entry data must be empty")
    for field, value in (("mode", mode), ("uid", uid), ("gid", gid),
                         ("devmajor", devmajor), ("devminor", devminor)):
        if isinstance(value, bool) or not isinstance(value, int):
            raise CleanRoomError(f"{field} must be an integer")
    if not 0 <= mode <= 0o7777:
        raise CleanRoomError("mode must be an integer between 0 and 4095")

    uname = _require_utf8_text(uname, field="uname")
    gname = _require_utf8_text(gname, field="gname")
    linkname = _require_utf8_text(linkname, field="linkname")
    normalized_mtime = _canonical_decimal(mtime)

    default_type = tarfile.REGTYPE if kind == "file" else tarfile.DIRTYPE
    normalized_typeflag = default_type.hex() if typeflag is None else typeflag
    if not isinstance(normalized_typeflag, str):
        raise CleanRoomError("typeflag must be one byte encoded as hexadecimal")
    try:
        decoded_type = bytes.fromhex(normalized_typeflag)
    except ValueError as exc:
        raise CleanRoomError("typeflag must be one byte encoded as hexadecimal") from exc
    if len(decoded_type) != 1:
        raise CleanRoomError("typeflag must be one byte encoded as hexadecimal")

    return {
        "kind": kind,
        "data": data,
        "mode": mode,
        "uid": uid,
        "gid": gid,
        "uname": uname,
        "gname": gname,
        "mtime": normalized_mtime,
        "typeflag": normalized_typeflag.lower(),
        "linkname": linkname,
        "devmajor": devmajor,
        "devminor": devminor,
        "pax_headers": _clean_pax_headers(pax_headers, field="pax_headers"),
        "archive_pax_headers": _clean_pax_headers(
            archive_pax_headers, field="archive_pax_headers"
        ),
    }


def _member_pax_headers(
    member: tarfile.TarInfo, archive_pax_headers: Dict[str, str]
) -> Dict[str, str]:
    member_headers = _clean_pax_headers(dict(member.pax_headers), field="member pax_headers")
    supplemental: Dict[str, str] = {}
    for key, value in member_headers.items():
        if key in STRUCTURAL_PAX_KEYS:
            continue
        if key in archive_pax_headers and archive_pax_headers[key] == value:
            continue
        supplemental[key] = value
    return supplemental


def _assert_supported_member(member: tarfile.TarInfo, name: str) -> None:
    sparse_keys = [
        key for key in member.pax_headers
        if any(key.startswith(prefix) for prefix in SPARSE_PAX_PREFIXES)
    ]
    if member.sparse is not None or member.type == tarfile.GNUTYPE_SPARSE or sparse_keys:
        raise CleanRoomError(f"sparse archive entry is unsupported: {name}")
    if member.isdir() and member.size != 0:
        raise CleanRoomError(
            f"directory archive entry must have size 0: {name}: {member.size}"
        )


def validate_state_hierarchy(
    state: Dict[str, Dict[str, Any]], *, require_explicit_root: bool = False
) -> None:
    if "" in state and state[""]["kind"] != "dir":
        raise CleanRoomError("package root record must be a directory")
    if require_explicit_root and "" not in state:
        raise CleanRoomError("package root record is missing")

    for path, record in state.items():
        location = path or "<root>"
        if record.get("kind") not in {"file", "dir"}:
            raise CleanRoomError(
                f"unsupported state kind at {location}: {record.get('kind')}"
            )
        if record.get("kind") == "dir" and record.get("data", b"") != b"":
            raise CleanRoomError(
                f"directory entry data must be empty: {location}"
            )
        if path == "":
            continue
        safe_relpath(path)
        parts = path.split("/")
        for index in range(1, len(parts)):
            prefix = "/".join(parts[:index])
            if prefix in state and state[prefix]["kind"] != "dir":
                raise CleanRoomError(
                    f"invalid hierarchy: non-directory {prefix} is a parent of {path}"
                )


def load_archive_bytes(data: bytes, *, source: str = "<memory>") -> Dict[str, Dict[str, Any]]:
    state: Dict[str, Dict[str, Any]] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
            archive_pax_headers = _clean_pax_headers(
                dict(tf.pax_headers), field="archive_pax_headers"
            )
            structural_globals = sorted(
                set(archive_pax_headers).intersection(STRUCTURAL_PAX_KEYS)
            )
            if structural_globals:
                raise CleanRoomError(
                    "archive-global structural PAX keys are unsupported: "
                    f"{structural_globals}"
                )

            while True:
                member = tf.next()
                current_globals = _clean_pax_headers(
                    dict(tf.pax_headers), field="archive_pax_headers"
                )
                if current_globals != archive_pax_headers:
                    location = member.name if member is not None else "end of archive"
                    raise CleanRoomError(
                        "mid-archive global PAX header changes are unsupported "
                        f"before {location}"
                    )
                if member is None:
                    break

                name = _archive_member_path(member)
                if name in state:
                    raise CleanRoomError(f"duplicate archive entry: {name}")
                _assert_supported_member(member, name)

                member_headers = _clean_pax_headers(
                    dict(member.pax_headers), field=f"member pax_headers for {name}"
                )
                exact_mtime = member_headers.get("mtime", member.mtime)
                common = {
                    "mode": member.mode,
                    "uid": member.uid,
                    "gid": member.gid,
                    "uname": _require_utf8_text(member.uname or "", field=f"uname for {name}"),
                    "gname": _require_utf8_text(member.gname or "", field=f"gname for {name}"),
                    "mtime": exact_mtime,
                    "typeflag": member.type.hex(),
                    "linkname": _require_utf8_text(
                        member.linkname or "", field=f"linkname for {name}"
                    ),
                    "devmajor": member.devmajor,
                    "devminor": member.devminor,
                    "pax_headers": _member_pax_headers(member, archive_pax_headers),
                    "archive_pax_headers": {},
                }
                if member.isdir():
                    state[name] = _entry_record(kind="dir", **common)
                elif member.isfile():
                    fh = tf.extractfile(member)
                    if fh is None:
                        raise CleanRoomError(f"unable to read archive member: {name}")
                    state[name] = _entry_record(kind="file", data=fh.read(), **common)
                else:
                    raise CleanRoomError(
                        f"unsupported archive entry type for STD-DVA-001 v0.2.6: {name}"
                    )

            roots = sorted({name.split("/", 1)[0] for name in state})
            if len(roots) == 1 and roots[0] in state:
                state[roots[0]]["archive_pax_headers"] = archive_pax_headers
    except CleanRoomError:
        raise
    except (tarfile.TarError, OSError, UnicodeError, ValueError) as exc:
        raise CleanRoomError(f"invalid or unsupported archive: {source}: {exc}") from exc

    validate_state_hierarchy(state)
    return state


def load_archive(path: Path) -> Dict[str, Dict[str, Any]]:
    snapshot = read_file_snapshot(Path(path))
    return load_archive_bytes(snapshot.data, source=str(path))


def record_hash(record: Dict[str, Any]) -> str:
    metadata = {
        "kind": record["kind"],
        "mode": record["mode"],
        "uid": record["uid"],
        "gid": record["gid"],
        "uname": record["uname"],
        "gname": record["gname"],
        "mtime": record["mtime"],
        "typeflag": record.get(
            "typeflag",
            (tarfile.REGTYPE if record["kind"] == "file" else tarfile.DIRTYPE).hex(),
        ),
        "linkname": record.get("linkname", ""),
        "devmajor": record.get("devmajor", 0),
        "devminor": record.get("devminor", 0),
        "pax_headers": record.get("pax_headers", {}),
        "archive_pax_headers": record.get("archive_pax_headers", {}),
        "data_sha256": sha256_bytes(record.get("data", b"")),
    }
    return sha256_bytes(canonical_json_bytes(metadata))


def state_inventory(state: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    result = []
    for path in sorted(state):
        record = state[path]
        result.append(
            {
                "path": path,
                "kind": record["kind"],
                "record_sha256": record_hash(record),
                "data_sha256": sha256_bytes(record.get("data", b"")),
                "size": len(record.get("data", b"")),
                "mode": record["mode"],
                "uid": record["uid"],
                "gid": record["gid"],
                "uname": record["uname"],
                "gname": record["gname"],
                "mtime": record["mtime"],
                "typeflag": record.get("typeflag"),
                "linkname": record.get("linkname", ""),
                "devmajor": record.get("devmajor", 0),
                "devminor": record.get("devminor", 0),
                "pax_headers": record.get("pax_headers", {}),
                "archive_pax_headers": record.get("archive_pax_headers", {}),
            }
        )
    return result


def tree_root(state: Dict[str, Dict[str, Any]]) -> str:
    validate_state_hierarchy(state)
    pairs = [{"path": p, "record_sha256": record_hash(state[p])} for p in sorted(state)]
    return sha256_bytes(canonical_json_bytes(pairs))


def _reject_duplicate_json_fields(
    pairs: List[Tuple[str, Any]],
) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    duplicates = set()

    for key, value in pairs:
        if key in result:
            duplicates.add(key)
        else:
            result[key] = value

    if duplicates:
        raise CleanRoomError(
            f"duplicate JSON object fields are forbidden: {sorted(duplicates)}"
        )

    return result


def load_json(path: Path) -> Any:
    snapshot = read_file_snapshot(Path(path))
    try:
        return json.loads(
            snapshot.data.decode("utf-8", "strict"),
            object_pairs_hook=_reject_duplicate_json_fields,
        )
    except CleanRoomError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CleanRoomError(f"invalid UTF-8 JSON file: {path}") from exc


def assert_distinct_paths(**named_paths: Path) -> None:
    """Reject aliases among protected inputs and write destinations."""
    items = list(named_paths.items())
    for index, (left_name, left_path) in enumerate(items):
        left = Path(left_path).expanduser()
        left_resolved = left.resolve(strict=False)
        for right_name, right_path in items[index + 1:]:
            right = Path(right_path).expanduser()
            right_resolved = right.resolve(strict=False)
            collision = left_resolved == right_resolved
            if not collision and left.exists() and right.exists():
                try:
                    collision = os.path.samefile(left, right)
                except OSError:
                    collision = False
            if collision:
                raise CleanRoomError(
                    f"path collision: {left_name} and {right_name} refer to the same path"
                )


def decode_content(operation: Dict[str, Any]) -> bytes:
    has_utf8 = "content_utf8" in operation
    has_b64 = "content_base64" in operation
    if has_utf8 == has_b64:
        raise CleanRoomError(
            "exactly one of content_utf8 or content_base64 is required"
        )
    if has_utf8:
        value = _require_utf8_text(operation["content_utf8"], field="content_utf8")
        return value.encode("utf-8", "strict")
    value = operation["content_base64"]
    if not isinstance(value, str):
        raise CleanRoomError("content_base64 must be a string")
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise CleanRoomError("content_base64 is invalid") from exc


def validate_instruction(instruction: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(instruction, dict):
        raise CleanRoomError("instruction must be a JSON object")
    _validate_object_fields(
        instruction,
        scope="instruction",
        required=INSTRUCTION_REQUIRED_FIELDS,
        allowed=INSTRUCTION_REQUIRED_FIELDS,
    )
    if instruction.get("format") != FORMAT:
        raise CleanRoomError(f"instruction format must be {FORMAT}")
    baseline_sha256 = _normalize_sha256(
        instruction.get("baseline_sha256"), field="baseline_sha256"
    )
    operations = instruction.get("operations")
    if not isinstance(operations, list) or not operations:
        raise CleanRoomError("operations must be a non-empty array")

    normalized_ops: List[Dict[str, Any]] = []
    occupied_effect_paths = set()

    for index, raw in enumerate(operations):
        if not isinstance(raw, dict):
            raise CleanRoomError(f"operation {index} must be an object")
        if "op" not in raw:
            raise CleanRoomError(
                f"operation {index} is missing required fields: ['op']"
            )
        op = raw.get("op")
        if not isinstance(op, str) or op not in OPERATION_REQUIRED_FIELDS:
            raise CleanRoomError(f"operation {index} has unsupported op: {op}")

        required_fields = OPERATION_REQUIRED_FIELDS[op]
        allowed_fields = required_fields | OPERATION_OPTIONAL_FIELDS[op]
        _validate_object_fields(
            raw,
            scope=f"operation {index} ({op})",
            required=required_fields,
            allowed=allowed_fields,
        )

        item = {"op": op}
        if op in {"create", "replace", "delete"}:
            path = safe_relpath(raw.get("path", ""))
            item["path"] = path
            effect_paths = {path}
        else:
            source = safe_relpath(raw.get("from_path", ""))
            target = safe_relpath(raw.get("to_path", ""))
            if source == target:
                raise CleanRoomError("rename source and target must differ")
            item["from_path"] = source
            item["to_path"] = target
            effect_paths = {source, target}

        overlap = occupied_effect_paths.intersection(effect_paths)
        if overlap:
            raise CleanRoomError(
                f"multiple operations affect the same path: {sorted(overlap)}"
            )
        occupied_effect_paths.update(effect_paths)

        if op in {"replace", "delete", "rename"}:
            item["expected_sha256"] = _normalize_sha256(
                raw.get("expected_sha256"),
                field=f"operation {index} expected_sha256",
            )

        if op in {"create", "replace"}:
            data = decode_content(raw)
            item["content_base64"] = base64.b64encode(data).decode("ascii")
            if "mode" in raw:
                mode = raw["mode"]
                if isinstance(mode, bool) or not isinstance(mode, int) or not (0 <= mode <= 0o7777):
                    raise CleanRoomError("mode must be an integer between 0 and 4095")
                item["mode"] = mode
            elif op == "create":
                item["mode"] = 0o644

        normalized_ops.append(item)

    return {
        "format": FORMAT,
        "baseline_sha256": baseline_sha256,
        "operations": normalized_ops,
    }


def instruction_id(instruction: Dict[str, Any]) -> str:
    return sha256_bytes(canonical_json_bytes(instruction))


def strip_single_root(state: Dict[str, Dict[str, Any]]) -> Tuple[str, Dict[str, Dict[str, Any]]]:
    if not state:
        raise CleanRoomError("archive is empty")
    validate_state_hierarchy(state)
    roots = sorted({path.split("/", 1)[0] for path in state})
    if len(roots) != 1:
        raise CleanRoomError("archive must have exactly one top-level root")
    root = roots[0]
    root_record = state.get(root)
    if root_record is None or root_record["kind"] != "dir":
        raise CleanRoomError("top-level root must be an explicit directory entry")

    stripped: Dict[str, Dict[str, Any]] = {"": root_record}
    prefix = root + "/"
    for path, record in state.items():
        if path == root:
            continue
        if not path.startswith(prefix):
            raise CleanRoomError(f"archive member escapes the top-level root: {path}")
        new_path = path[len(prefix):]
        safe_relpath(new_path)
        if new_path in stripped:
            raise CleanRoomError(f"duplicate package path after root removal: {new_path}")
        stripped[new_path] = record
    validate_state_hierarchy(stripped, require_explicit_root=True)
    return root, stripped


def load_package_snapshot(path: Path) -> PackageSnapshot:
    file_snapshot = read_file_snapshot(Path(path))
    archive_state = load_archive_bytes(file_snapshot.data, source=str(path))
    root_name, state = strip_single_root(archive_state)
    return PackageSnapshot(
        path=Path(path),
        data=file_snapshot.data,
        sha256=file_snapshot.sha256,
        root_name=root_name,
        state=state,
    )


def load_package_state(path: Path) -> Tuple[str, Dict[str, Dict[str, Any]]]:
    snapshot = load_package_snapshot(Path(path))
    return snapshot.root_name, snapshot.state


def build_plan_from_snapshot(
    baseline: PackageSnapshot, instruction: Dict[str, Any]
) -> Dict[str, Any]:
    if baseline.sha256 != instruction["baseline_sha256"]:
        raise CleanRoomError(
            f"baseline hash mismatch: expected {instruction['baseline_sha256']}, "
            f"actual {baseline.sha256}"
        )
    declared_paths = []
    for op in instruction["operations"]:
        if op["op"] == "rename":
            declared_paths.extend([op["from_path"], op["to_path"]])
        else:
            declared_paths.append(op["path"])
    plan = {
        "format": PLAN_FORMAT,
        "program_version": VERSION,
        "baseline_sha256": baseline.sha256,
        "baseline_tree_root": tree_root(baseline.state),
        "instruction_sha256": instruction_id(instruction),
        "declared_paths": sorted(declared_paths),
        "operations": instruction["operations"],
    }
    plan["plan_sha256"] = sha256_bytes(canonical_json_bytes(plan))
    return plan


def build_plan(baseline: Path, instruction: Dict[str, Any]) -> Dict[str, Any]:
    return build_plan_from_snapshot(load_package_snapshot(Path(baseline)), instruction)


def _assert_file_hash(
    state: Dict[str, Dict[str, Any]], path: str, expected_sha256: str
) -> None:
    if path not in state:
        raise CleanRoomError(f"required path does not exist: {path}")
    record = state[path]
    if record["kind"] != "file":
        raise CleanRoomError(f"required path is not a regular file: {path}")
    actual = sha256_bytes(record["data"])
    if actual != expected_sha256:
        raise CleanRoomError(
            f"content hash mismatch for {path}: expected {expected_sha256}, actual {actual}"
        )


def apply_operations(
    baseline_state: Dict[str, Dict[str, Any]], operations: List[Dict[str, Any]]
) -> Dict[str, Dict[str, Any]]:
    state = copy.deepcopy(baseline_state)
    validate_state_hierarchy(state, require_explicit_root="" in state)

    for operation in operations:
        op = operation["op"]

        if op == "create":
            path = operation["path"]
            if path in state:
                raise CleanRoomError(f"create target already exists: {path}")
            state[path] = _entry_record(
                kind="file",
                data=base64.b64decode(operation["content_base64"]),
                mode=operation["mode"],
                uid=0,
                gid=0,
                uname="",
                gname="",
                mtime="0",
            )

        elif op == "replace":
            path = operation["path"]
            _assert_file_hash(state, path, operation["expected_sha256"])
            current = state[path]
            current["data"] = base64.b64decode(operation["content_base64"])
            if "mode" in operation:
                current["mode"] = operation["mode"]

        elif op == "delete":
            path = operation["path"]
            _assert_file_hash(state, path, operation["expected_sha256"])
            del state[path]

        elif op == "rename":
            source = operation["from_path"]
            target = operation["to_path"]
            _assert_file_hash(state, source, operation["expected_sha256"])
            if target in state:
                raise CleanRoomError(f"rename target already exists: {target}")
            state[target] = state.pop(source)

        else:  # pragma: no cover
            raise CleanRoomError(f"unsupported operation: {op}")

        validate_state_hierarchy(state, require_explicit_root="" in state)

    return state


def diff_paths(
    before: Dict[str, Dict[str, Any]], after: Dict[str, Dict[str, Any]]
) -> List[str]:
    changed = []
    for path in sorted(set(before) | set(after)):
        if path not in before or path not in after:
            changed.append(path)
        elif record_hash(before[path]) != record_hash(after[path]):
            changed.append(path)
    return changed


def validate_preservation(
    before: Dict[str, Dict[str, Any]],
    after: Dict[str, Dict[str, Any]],
    declared_paths: Iterable[str],
) -> Tuple[bool, List[str], List[str]]:
    validate_state_hierarchy(before, require_explicit_root="" in before)
    validate_state_hierarchy(after, require_explicit_root="" in after)
    declared = sorted(set(declared_paths))
    changed = diff_paths(before, after)
    unauthorized = sorted(set(changed) - set(declared))
    return not unauthorized, changed, unauthorized


def _apply_record_metadata(info: tarfile.TarInfo, record: Dict[str, Any]) -> None:
    info.type = bytes.fromhex(record.get(
        "typeflag",
        (tarfile.REGTYPE if record["kind"] == "file" else tarfile.DIRTYPE).hex(),
    ))
    info.mode = record["mode"]
    info.uid = record["uid"]
    info.gid = record["gid"]
    info.uname = record["uname"]
    info.gname = record["gname"]
    exact_mtime = _canonical_decimal(record["mtime"])
    info.mtime = int(Decimal(exact_mtime))
    info.linkname = record.get("linkname", "")
    info.devmajor = record.get("devmajor", 0)
    info.devminor = record.get("devminor", 0)
    info.pax_headers = dict(record.get("pax_headers", {}))
    if Decimal(exact_mtime) != Decimal(exact_mtime).to_integral_value():
        info.pax_headers["mtime"] = exact_mtime


def write_archive(
    state: Dict[str, Dict[str, Any]], output: Path, *, root_name: str
) -> None:
    root_name = safe_relpath(root_name)
    if "/" in root_name:
        raise CleanRoomError("root_name must be one top-level path component")
    validate_state_hierarchy(state, require_explicit_root="" in state)

    root_record = state.get(
        "",
        _entry_record(
            kind="dir", mode=0o755, uid=0, gid=0, uname="", gname="", mtime="0"
        ),
    )
    if root_record["kind"] != "dir":
        raise CleanRoomError("top-level root must be a directory")
    archive_pax_headers = _clean_pax_headers(
        root_record.get("archive_pax_headers", {}), field="archive_pax_headers"
    )
    structural_globals = sorted(
        set(archive_pax_headers).intersection(STRUCTURAL_PAX_KEYS)
    )
    if structural_globals:
        raise CleanRoomError(
            "archive-global structural PAX keys are unsupported: "
            f"{structural_globals}"
        )

    output = Path(output)
    if not output.parent.is_dir():
        raise CleanRoomError(f"output parent directory does not exist: {output.parent}")
    try:
        with output.open("wb") as raw:
            with gzip.GzipFile(
                filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9
            ) as gz:
                with tarfile.open(
                    fileobj=gz,
                    mode="w",
                    format=tarfile.PAX_FORMAT,
                    pax_headers=archive_pax_headers,
                ) as tf:
                    root_info = tarfile.TarInfo(root_name)
                    _apply_record_metadata(root_info, root_record)
                    root_info.size = 0
                    tf.addfile(root_info)

                    for path in sorted(state):
                        if path == "":
                            continue
                        safe_relpath(path)
                        record = state[path]
                        archive_name = f"{root_name}/{path}"
                        info = tarfile.TarInfo(archive_name)
                        _apply_record_metadata(info, record)
                        if record["kind"] == "dir":
                            info.size = 0
                            tf.addfile(info)
                        elif record["kind"] == "file":
                            data = record["data"]
                            info.size = len(data)
                            tf.addfile(info, io.BytesIO(data))
                        else:  # pragma: no cover
                            raise CleanRoomError(f"unsupported state kind: {record['kind']}")
            raw.flush()
            os.fsync(raw.fileno())
    except CleanRoomError:
        raise
    except (OSError, tarfile.TarError, UnicodeError, ValueError) as exc:
        raise CleanRoomError(f"unable to write archive {output}: {exc}") from exc


def _require_destination(path: Path, *, label: str) -> Path:
    path = Path(path)
    parent = path.parent
    if not parent.exists() or not parent.is_dir():
        raise CleanRoomError(f"{label} parent directory does not exist: {parent}")
    if path.is_symlink():
        raise CleanRoomError(f"{label} must not be a symbolic link: {path}")
    if path.exists() and not path.is_file():
        raise CleanRoomError(f"{label} must be a regular file path: {path}")
    return path


def _temporary_sibling(destination: Path, *, suffix: str) -> Path:
    fd, raw = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=suffix, dir=str(destination.parent)
    )
    os.close(fd)
    return Path(raw)


def _write_bytes_fsync(path: Path, data: bytes) -> None:
    try:
        with path.open("wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
    except OSError as exc:
        raise CleanRoomError(f"unable to write file {path}: {exc}") from exc


def _fsync_directory(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError as exc:
        raise CleanRoomError(f"unable to synchronize directory {path}: {exc}") from exc


def _atomic_write_bytes(destination: Path, data: bytes, *, label: str) -> None:
    destination = _require_destination(destination, label=label)
    temp = _temporary_sibling(destination, suffix=".tmp")
    try:
        _write_bytes_fsync(temp, data)
        os.replace(temp, destination)
        _fsync_directory(destination.parent)
    except CleanRoomError:
        raise
    except OSError as exc:
        raise CleanRoomError(f"unable to publish {label}: {exc}") from exc
    finally:
        if temp.exists():
            temp.unlink()


def _transactional_publish_pair(
    *,
    candidate_temp: Path,
    candidate_destination: Path,
    candidate_sha256: str,
    audit_temp: Path,
    audit_destination: Path,
    audit_sha256: str,
) -> None:
    candidate_destination = _require_destination(
        candidate_destination, label="candidate output"
    )
    audit_destination = _require_destination(audit_destination, label="audit output")

    destinations = [audit_destination, candidate_destination]
    sources = [audit_temp, candidate_temp]
    expected = [audit_sha256, candidate_sha256]
    backups: Dict[Path, Path] = {}
    published: List[Path] = []

    try:
        for destination in destinations:
            if destination.exists():
                backup = _temporary_sibling(destination, suffix=".backup")
                backups[destination] = backup
                shutil.copy2(destination, backup)
                with backup.open("rb") as fh:
                    os.fsync(fh.fileno())

        for source, destination, expected_sha in zip(sources, destinations, expected):
            os.replace(source, destination)
            published.append(destination)
            actual = sha256_file(destination)
            if actual != expected_sha:
                raise CleanRoomError(
                    f"published file hash mismatch for {destination}: "
                    f"expected {expected_sha}, actual {actual}"
                )

        for parent in sorted({p.parent for p in destinations}, key=str):
            _fsync_directory(parent)

    except Exception as exc:
        rollback_errors = []
        for destination in reversed(published):
            try:
                backup = backups.get(destination)
                if backup is not None and backup.exists():
                    os.replace(backup, destination)
                elif destination.exists():
                    destination.unlink()
            except OSError as rollback_exc:
                rollback_errors.append(f"{destination}: {rollback_exc}")
        for destination, backup in backups.items():
            if destination not in published and backup.exists():
                backup.unlink()
        if rollback_errors:
            raise CleanRoomError(
                "publication failed and rollback was incomplete: "
                + "; ".join(rollback_errors)
            ) from exc
        if isinstance(exc, CleanRoomError):
            raise
        raise CleanRoomError(f"transactional publication failed: {exc}") from exc
    finally:
        for path in sources:
            if path.exists():
                path.unlink()
        for backup in backups.values():
            if backup.exists():
                backup.unlink()


def candidate_audit(
    *,
    baseline: PackageSnapshot,
    instruction: Dict[str, Any],
    plan: Dict[str, Any],
    candidate: PackageSnapshot,
) -> Dict[str, Any]:
    preservation_pass, changed, unauthorized = validate_preservation(
        baseline.state, candidate.state, plan["declared_paths"]
    )
    binding_pass = (
        baseline.sha256 == instruction["baseline_sha256"] == plan["baseline_sha256"]
    )
    audit = {
        "format": AUDIT_FORMAT,
        "program_version": VERSION,
        "baseline_sha256": baseline.sha256,
        "instruction_baseline_sha256": instruction["baseline_sha256"],
        "baseline_snapshot_binding": "PASS" if binding_pass else "FAIL",
        "baseline_tree_root": tree_root(baseline.state),
        "instruction_sha256": instruction_id(instruction),
        "plan_sha256": plan["plan_sha256"],
        "declared_paths": plan["declared_paths"],
        "actual_changed_paths": changed,
        "unauthorized_changed_paths": unauthorized,
        "candidate_sha256": candidate.sha256,
        "candidate_tree_root": tree_root(candidate.state),
        "preservation_invariant": "PASS" if preservation_pass else "FAIL",
    }
    audit["audit_sha256"] = sha256_bytes(canonical_json_bytes(audit))
    return audit


def cmd_inspect(args: argparse.Namespace) -> int:
    snapshot = load_package_snapshot(Path(args.baseline))
    result = {
        "program_version": VERSION,
        "baseline": str(snapshot.path),
        "baseline_sha256": snapshot.sha256,
        "root_name": snapshot.root_name,
        "tree_root": tree_root(snapshot.state),
        "inventory": state_inventory(snapshot.state),
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def cmd_plan(args: argparse.Namespace) -> int:
    baseline_path = Path(args.baseline)
    instruction_path = Path(args.instruction)
    output = Path(args.output)
    assert_distinct_paths(
        baseline=baseline_path, instruction=instruction_path, output=output
    )
    _require_destination(output, label="plan output")
    instruction = validate_instruction(load_json(instruction_path))
    baseline = load_package_snapshot(baseline_path)
    plan = build_plan_from_snapshot(baseline, instruction)
    _atomic_write_bytes(
        output, canonical_json_bytes(plan) + b"\n", label="plan output"
    )
    return 0


def cmd_apply(args: argparse.Namespace) -> int:
    baseline_path = Path(args.baseline)
    instruction_path = Path(args.instruction)
    output = Path(args.output)
    audit_path = Path(args.audit)
    assert_distinct_paths(
        baseline=baseline_path,
        instruction=instruction_path,
        output=output,
        audit=audit_path,
    )
    _require_destination(output, label="candidate output")
    _require_destination(audit_path, label="audit output")

    instruction = validate_instruction(load_json(instruction_path))
    baseline = load_package_snapshot(baseline_path)
    plan = build_plan_from_snapshot(baseline, instruction)
    candidate_state = apply_operations(baseline.state, plan["operations"])

    preservation_pass, _, unauthorized = validate_preservation(
        baseline.state, candidate_state, plan["declared_paths"]
    )
    if not preservation_pass:
        raise CleanRoomError(f"undeclared paths changed: {unauthorized}")

    candidate_temp = _temporary_sibling(output, suffix=".candidate.tmp")
    audit_temp = _temporary_sibling(audit_path, suffix=".audit.tmp")
    try:
        write_archive(candidate_state, candidate_temp, root_name=baseline.root_name)
        candidate = load_package_snapshot(candidate_temp)
        if candidate.root_name != baseline.root_name:
            raise CleanRoomError("candidate root changed during serialization")
        if tree_root(candidate.state) != tree_root(candidate_state):
            raise CleanRoomError("candidate changed during serialization")

        audit = candidate_audit(
            baseline=baseline,
            instruction=instruction,
            plan=plan,
            candidate=candidate,
        )
        if audit["baseline_snapshot_binding"] != "PASS":
            raise CleanRoomError("baseline snapshot binding failed")
        if audit["preservation_invariant"] != "PASS":
            raise CleanRoomError("preservation invariant failed after reopen")

        audit_bytes = canonical_json_bytes(audit) + b"\n"
        _write_bytes_fsync(audit_temp, audit_bytes)
        _transactional_publish_pair(
            candidate_temp=candidate_temp,
            candidate_destination=output,
            candidate_sha256=candidate.sha256,
            audit_temp=audit_temp,
            audit_destination=audit_path,
            audit_sha256=sha256_bytes(audit_bytes),
        )
        print(candidate.sha256)
        return 0
    finally:
        if candidate_temp.exists():
            candidate_temp.unlink()
        if audit_temp.exists():
            audit_temp.unlink()


def cmd_verify(args: argparse.Namespace) -> int:
    baseline_path = Path(args.baseline)
    instruction_path = Path(args.instruction)
    candidate_path = Path(args.candidate)
    assert_distinct_paths(
        baseline=baseline_path,
        instruction=instruction_path,
        candidate=candidate_path,
    )
    instruction = validate_instruction(load_json(instruction_path))
    baseline = load_package_snapshot(baseline_path)
    plan = build_plan_from_snapshot(baseline, instruction)
    candidate = load_package_snapshot(candidate_path)
    if baseline.root_name != candidate.root_name:
        raise CleanRoomError("candidate root differs from baseline root")

    expected_state = apply_operations(baseline.state, plan["operations"])
    if tree_root(expected_state) != tree_root(candidate.state):
        raise CleanRoomError("candidate does not match the declared transformation")

    preservation_pass, changed, unauthorized = validate_preservation(
        baseline.state, candidate.state, plan["declared_paths"]
    )
    if not preservation_pass:
        raise CleanRoomError(f"undeclared paths changed: {unauthorized}")

    result = {
        "result": "PASS",
        "baseline_sha256": baseline.sha256,
        "candidate_sha256": candidate.sha256,
        "declared_paths": plan["declared_paths"],
        "actual_changed_paths": changed,
        "unauthorized_changed_paths": unauthorized,
        "baseline_tree_root": tree_root(baseline.state),
        "candidate_tree_root": tree_root(candidate.state),
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def cmd_rewind(args: argparse.Namespace) -> int:
    source_path = Path(args.baseline)
    destination = Path(args.output)
    assert_distinct_paths(baseline=source_path, output=destination)
    _require_destination(destination, label="rewind output")
    source = read_file_snapshot(source_path)
    temp = _temporary_sibling(destination, suffix=".rewind.tmp")
    try:
        _write_bytes_fsync(temp, source.data)
        if sha256_file(temp) != source.sha256:
            raise CleanRoomError("rewind copy verification failed")
        os.replace(temp, destination)
        _fsync_directory(destination.parent)
        if sha256_file(destination) != source.sha256:
            raise CleanRoomError("rewind publication verification failed")
        print(source.sha256)
        return 0
    except OSError as exc:
        raise CleanRoomError(f"unable to publish rewind output: {exc}") from exc
    finally:
        if temp.exists():
            temp.unlink()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Preserve the supported package state except for explicitly "
            "declared changes."
        )
    )
    parser.add_argument("--version", action="version", version=VERSION)
    sub = parser.add_subparsers(dest="command", required=True)

    inspect_p = sub.add_parser("inspect")
    inspect_p.add_argument("baseline")
    inspect_p.set_defaults(func=cmd_inspect)

    plan_p = sub.add_parser("plan")
    plan_p.add_argument("baseline")
    plan_p.add_argument("instruction")
    plan_p.add_argument("--output", required=True)
    plan_p.set_defaults(func=cmd_plan)

    apply_p = sub.add_parser("apply")
    apply_p.add_argument("baseline")
    apply_p.add_argument("instruction")
    apply_p.add_argument("--output", required=True)
    apply_p.add_argument("--audit", required=True)
    apply_p.set_defaults(func=cmd_apply)

    verify_p = sub.add_parser("verify")
    verify_p.add_argument("baseline")
    verify_p.add_argument("instruction")
    verify_p.add_argument("candidate")
    verify_p.set_defaults(func=cmd_verify)

    rewind_p = sub.add_parser("rewind")
    rewind_p.add_argument("baseline")
    rewind_p.add_argument("--output", required=True)
    rewind_p.set_defaults(func=cmd_rewind)

    return parser


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (CleanRoomError, OSError, UnicodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
