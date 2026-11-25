"""Offline Windows Gaming Services (WGS) container exporter over preserved raw atoms.

Generates a standard Windows Gaming Services directory layout:
    wgs/<XUID_16HEX>_<SCID_32HEX>/
        containers.index
        <CONTAINER_GUID_32HEX>/
            container.1
            <ATOM_GUID_32HEX>

Binary layout matches Windows Gaming Services (v14 containers.index, v4 container.1)
so third-party Game Pass save tools (e.g. XGP-save-extractor, XgpSaveTools) can read
cloud exports offline without modifying %LOCALAPPDATA%\\Packages.
"""

from __future__ import annotations

import json
import os
import re
import struct
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

WGS_INDEX_VERSION = 14
WGS_CONTAINER_VERSION = 4
WGS_CONTAINER_NUMBER = 1
WGS_INDEX_FLAGS = 3
WGS_CONTAINER_SYNC_FLAGS = 1
WGS_DEFAULT_QUOTA_BYTES = 0x40000000  # 1 GiB
WGS_ATOM_NAME_CHARS = 64  # 128 bytes UTF-16LE

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_WGS_UUID_NAMESPACE = uuid.UUID("7f3b5f8e-3c46-4b3a-9d60-6a98a0ef9b2d")

_ISO_TIMESTAMP_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})"
    r"(?:\.(\d+))?"
    r"(?:Z|([+-])(\d{2}):?(\d{2}))?$"
)


@dataclass(frozen=True)
class WgsContainerRecord:
    container_name: str
    container_guid: str
    atom_count: int
    size_bytes: int


@dataclass(frozen=True)
class WgsExportReport:
    title_dir: Path
    wgs_root: Path
    user_wgs_dir: Path
    containers_index_path: Path
    containers: tuple[WgsContainerRecord, ...]
    atom_count: int


def _atomic_write_bytes(target: Path, data: bytes) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = target.with_name(f".{target.name}.part")
    tmp_path.write_bytes(data)
    os.replace(tmp_path, target)


def _strip_savedgame_suffix(file_name: str) -> str:
    if file_name.lower().endswith(",savedgame"):
        return file_name[: -len(",savedgame")]
    return file_name


def _xuid_to_hex16(xuid: str | None) -> str:
    raw = (xuid or "").strip()
    if not raw:
        return "0" * 16
    try:
        return f"{int(raw, 10):016X}"
    except ValueError:
        try:
            return f"{int(raw, 16):016X}"
        except ValueError:
            return "0" * 16


def _scid_to_hex32(scid: str | None) -> str:
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", scid or "").upper()
    if not cleaned:
        return "0" * 32
    return cleaned.zfill(32)[:32]


def _iso_to_filetime(raw: str | None, *, fallback: int = 0) -> int:
    """Convert an ISO-8601 timestamp (including 7-digit 100ns ticks) to Windows FILETIME."""
    if not raw:
        return fallback
    match = _ISO_TIMESTAMP_RE.match(raw.strip())
    if not match:
        return fallback

    year, month, day, hour, minute, second = (int(match.group(i)) for i in range(1, 7))
    frac_str = match.group(7) or ""
    tz_sign, tz_h, tz_m = match.group(8), match.group(9), match.group(10)

    if tz_sign is not None:
        offset_minutes = int(tz_h) * 60 + int(tz_m)
        if tz_sign == "-":
            offset_minutes = -offset_minutes
        tz = timezone(timedelta(minutes=offset_minutes))
    else:
        tz = timezone.utc

    try:
        dt = datetime(year, month, day, hour, minute, second, tzinfo=tz).astimezone(timezone.utc)
    except ValueError:
        return fallback

    delta = dt - _FILETIME_EPOCH
    whole_seconds = delta.days * 86400 + delta.seconds
    if whole_seconds < 0:
        return fallback

    ticks_100ns = int((frac_str + "0000000")[:7])
    return whole_seconds * 10_000_000 + ticks_100ns


def _pack_utf16_str(value: str) -> bytes:
    encoded = value.encode("utf-16le")
    code_units = len(encoded) // 2
    return struct.pack("<I", code_units) + encoded


def _pack_fixed_utf16(value: str, num_chars: int = WGS_ATOM_NAME_CHARS) -> bytes:
    target_bytes = num_chars * 2
    encoded = value.encode("utf-16le")
    if len(encoded) > target_bytes:
        # Trim on a UTF-16 code unit boundary without leaving a lone high surrogate.
        trimmed = value
        while len(trimmed.encode("utf-16le")) > target_bytes:
            trimmed = trimmed[:-1]
        encoded = trimmed.encode("utf-16le")
    return encoded.ljust(target_bytes, b"\x00")


def _resolve_atom_uuid(atom_id: str, *, scid: str, container_name: str, atom_name: str) -> uuid.UUID:
    raw_guid = atom_id.split(",", maxsplit=1)[0].strip()
    try:
        return uuid.UUID(raw_guid)
    except ValueError:
        return uuid.uuid5(_WGS_UUID_NAMESPACE, f"atom:{scid}:{container_name}:{atom_name}:{atom_id}")


def export_wgs_from_raw(title_dir: Path) -> WgsExportReport:
    """Build a standard Windows Gaming Services (wgs/) directory offline from preserved raw exports.

    Never modifies or deletes anything in `raw_atoms/`, `manifests/`, `blobs.json`, or `reconstructed/`.
    """
    title_root = title_dir.resolve()
    manifest_path = title_root / "export_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    xuid = str(manifest.get("xuid") or "")
    scid = str(manifest.get("scid") or "")
    pfn = str(manifest.get("pfn") or "")
    exported_at = manifest.get("exported_at_utc")
    now_filetime = _iso_to_filetime(
        exported_at if isinstance(exported_at, str) else None,
        fallback=int((datetime.now(timezone.utc) - _FILETIME_EPOCH).total_seconds() * 10_000_000),
    )

    wgs_root = title_root / "wgs"
    user_folder_name = f"{_xuid_to_hex16(xuid)}_{_scid_to_hex32(scid)}"
    user_wgs_dir = wgs_root / user_folder_name
    user_wgs_dir.mkdir(parents=True, exist_ok=True)

    blobs = manifest.get("blobs") or []
    container_entries_bytes: list[bytes] = []
    container_records: list[WgsContainerRecord] = []
    total_atoms = 0
    latest_filetime = 0

    for blob in blobs:
        raw_file_name = str(blob.get("file_name") or "")
        container_name = _strip_savedgame_suffix(raw_file_name)
        raw_display_name = blob.get("display_name")
        display_name = str(raw_display_name) if raw_display_name is not None else container_name
        etag = str(blob.get("etag") or "")

        container_uuid = uuid.uuid5(_WGS_UUID_NAMESPACE, f"container:{scid}:{container_name}")
        container_guid_hex = container_uuid.hex.upper()
        container_dir = user_wgs_dir / container_guid_hex
        container_dir.mkdir(parents=True, exist_ok=True)

        atoms = blob.get("atoms") or []
        container_file_chunks = [struct.pack("<II", WGS_CONTAINER_VERSION, len(atoms))]
        container_size = 0

        for atom in atoms:
            atom_name = str(atom.get("atom_name") or "atom")
            atom_id = str(atom.get("atom_id") or "")
            raw_rel = str(atom.get("raw_relative_path") or "")
            raw_path = (title_root / raw_rel).resolve()
            try:
                raw_path.relative_to(title_root)
            except ValueError as exc:
                raise ValueError(f"Refusing to read outside title directory: {raw_rel!r}") from exc

            data = raw_path.read_bytes()
            container_size += len(data)
            total_atoms += 1

            atom_uuid = _resolve_atom_uuid(
                atom_id,
                scid=scid,
                container_name=container_name,
                atom_name=atom_name,
            )
            atom_out_path = container_dir / atom_uuid.hex.upper()
            _atomic_write_bytes(atom_out_path, data)

            container_file_chunks.append(_pack_fixed_utf16(atom_name))
            container_file_chunks.append(atom_uuid.bytes_le)
            container_file_chunks.append(atom_uuid.bytes_le)

        _atomic_write_bytes(
            container_dir / f"container.{WGS_CONTAINER_NUMBER}",
            b"".join(container_file_chunks),
        )

        modified_ft = _iso_to_filetime(
            blob.get("client_file_time") if isinstance(blob.get("client_file_time"), str) else None,
            fallback=now_filetime,
        )
        if modified_ft > latest_filetime:
            latest_filetime = modified_ft

        reported_size = blob.get("reported_size")
        entry_size = container_size if container_size > 0 else int(reported_size or 0)

        entry_bytes = b"".join(
            [
                _pack_utf16_str(container_name),
                _pack_utf16_str(display_name),
                _pack_utf16_str(etag),
                struct.pack("<BI", WGS_CONTAINER_NUMBER, WGS_CONTAINER_SYNC_FLAGS),
                container_uuid.bytes_le,
                struct.pack("<QQQ", modified_ft, 0, entry_size),
            ]
        )
        container_entries_bytes.append(entry_bytes)
        container_records.append(
            WgsContainerRecord(
                container_name=container_name,
                container_guid=container_guid_hex,
                atom_count=len(atoms),
                size_bytes=entry_size,
            )
        )

    store_pkg_name = f"{pfn}!Game" if pfn else ""
    store_id = str(uuid.uuid5(_WGS_UUID_NAMESPACE, f"store:{xuid}:{scid}"))
    index_creation_ft = latest_filetime or now_filetime

    index_header = b"".join(
        [
            struct.pack("<II", WGS_INDEX_VERSION, len(container_entries_bytes)),
            _pack_utf16_str(""),  # pkg_display_name (empty on Windows PC)
            _pack_utf16_str(store_pkg_name),
            struct.pack("<QI", index_creation_ft, WGS_INDEX_FLAGS),
            _pack_utf16_str(store_id),
            struct.pack("<Q", WGS_DEFAULT_QUOTA_BYTES),
        ]
    )

    containers_index_path = user_wgs_dir / "containers.index"
    _atomic_write_bytes(containers_index_path, index_header + b"".join(container_entries_bytes))

    return WgsExportReport(
        title_dir=title_root,
        wgs_root=wgs_root,
        user_wgs_dir=user_wgs_dir,
        containers_index_path=containers_index_path,
        containers=tuple(container_records),
        atom_count=total_atoms,
    )
