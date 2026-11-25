"""Raw-first read-only download and archival of Xbox Connected Storage saves."""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import httpx

from xbox_save_harvest.auth.xbox import XboxToken
from xbox_save_harvest.discovery.titlehub import TitleEntry
from xbox_save_harvest.storage.connected import (
    ConnectedStorageResponse,
    download_atom,
    get_blob_atoms,
    list_blobs,
)

INVALID_FS_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


class SaveExportError(RuntimeError):
    """Raised when a read-only Connected Storage export must fail fast."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True)
class ExportedAtomRecord:
    blob_file_name: str
    atom_name: str
    atom_id: str
    raw_relative_path: str
    size_bytes: int
    sha256: str
    content_type: str | None


@dataclass(frozen=True)
class TitleExportResult:
    title_name: str
    title_id: str
    scid: str
    pfn: str | None
    output_dir: Path
    status: str  # "exported" | "empty"
    blob_count: int
    atom_count: int
    total_bytes: int
    atoms: tuple[ExportedAtomRecord, ...]
    manifest_path: Path


def sanitize_segment(value: str, *, fallback: str = "item") -> str:
    """Make a single Windows-safe directory or file name segment without traversal."""
    cleaned = INVALID_FS_CHARS.sub("_", value.strip())
    cleaned = cleaned.strip(" .")
    if not cleaned or cleaned in {".", ".."}:
        return fallback
    return cleaned[:120]


def make_title_dirname(title: TitleEntry) -> str:
    label = sanitize_segment(title.name or title.pfn or title.title_id, fallback="title")
    suffix = sanitize_segment(title.title_id or (title.service_config_id or "")[-8:], fallback="id")
    return f"{label}__{suffix}"


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.part")
    tmp_path.write_bytes(data)
    os.replace(tmp_path, path)


def _atomic_write_json(path: Path, payload: Any) -> None:
    encoded = json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")
    _atomic_write_bytes(path, encoded)


def _fail_if_abort_status(stage: str, status_code: int, error_message: str | None, error_code: int | None) -> None:
    if status_code in {401, 403, 429}:
        detail = f" (code={error_code}: {error_message})" if error_code or error_message else ""
        raise SaveExportError(
            f"Aborting export at {stage}: HTTP {status_code}{detail}",
            status_code=status_code,
        )


def export_title_raw(
    client: httpx.Client,
    *,
    xuid: str,
    xsts_token: XboxToken,
    title: TitleEntry,
    output_root: Path,
    contract_version: str = "107",
    delay_seconds: float = 0.2,
    sleep_fn: Callable[[float], None] = time.sleep,
    on_progress: Callable[[str], None] | None = None,
) -> TitleExportResult:
    """Download all Connected Storage manifests and raw atom binaries for a title (strictly GET-only)."""
    if not title.service_config_id:
        raise SaveExportError(f"Title {title.name!r} has no serviceConfigId (SCID).")

    scid = title.service_config_id
    pfn = title.pfn
    title_dir = output_root / make_title_dirname(title)
    title_dir.mkdir(parents=True, exist_ok=True)

    def log(msg: str) -> None:
        if on_progress is not None:
            on_progress(msg)

    _atomic_write_json(
        title_dir / "title_metadata.json",
        {
            "exported_at_utc": datetime.now(timezone.utc).isoformat(),
            "xuid": xuid,
            "title_id": title.title_id,
            "name": title.name,
            "service_config_id": scid,
            "pfn": pfn,
            "devices": list(title.devices),
            "last_time_played": title.last_time_played,
            "raw_titlehub_entry": title.raw,
        },
    )

    log(f"Listing blobs for {title.name} (SCID={scid})...")
    blobs_resp: ConnectedStorageResponse = list_blobs(
        client,
        xuid=xuid,
        scid=scid,
        pfn=pfn,
        xsts_token=xsts_token,
        contract_version=contract_version,
    )

    _fail_if_abort_status("list_blobs", blobs_resp.status_code, blobs_resp.error_message, blobs_resp.error_code)

    if blobs_resp.is_empty_storage:
        manifest_path = title_dir / "export_manifest.json"
        _atomic_write_json(
            manifest_path,
            {
                "status": "empty",
                "scid": scid,
                "pfn": pfn,
                "http_status": blobs_resp.status_code,
                "error_code": blobs_resp.error_code,
                "blobs": [],
                "atoms": [],
            },
        )
        return TitleExportResult(
            title_name=title.name,
            title_id=title.title_id,
            scid=scid,
            pfn=pfn,
            output_dir=title_dir,
            status="empty",
            blob_count=0,
            atom_count=0,
            total_bytes=0,
            atoms=(),
            manifest_path=manifest_path,
        )

    if not blobs_resp.is_ok or blobs_resp.raw_json is None:
        raise SaveExportError(
            f"Unexpected response listing blobs for {title.name!r}: HTTP {blobs_resp.status_code}",
            status_code=blobs_resp.status_code,
        )

    _atomic_write_json(title_dir / "blobs.json", blobs_resp.raw_json)
    log(f"Found {len(blobs_resp.blobs)} blobs.")

    manifests_dir = title_dir / "manifests"
    raw_atoms_dir = title_dir / "raw_atoms"
    manifests_dir.mkdir(parents=True, exist_ok=True)
    raw_atoms_dir.mkdir(parents=True, exist_ok=True)

    blob_records: list[dict[str, Any]] = []
    exported_atoms: list[ExportedAtomRecord] = []
    downloaded_atom_cache: dict[str, tuple[str, int, str, str | None]] = {}
    total_bytes = 0

    for blob_idx, blob in enumerate(blobs_resp.blobs, start=1):
        if delay_seconds > 0 and blob_idx > 1:
            sleep_fn(delay_seconds)

        log(f"  [{blob_idx}/{len(blobs_resp.blobs)}] Fetching atom manifest for {blob.file_name!r}...")
        atom_map_resp = get_blob_atoms(
            client,
            xuid=xuid,
            scid=scid,
            file_name=blob.file_name,
            pfn=pfn,
            xsts_token=xsts_token,
            contract_version=contract_version,
        )
        _fail_if_abort_status(
            f"get_blob_atoms({blob.file_name})",
            atom_map_resp.status_code,
            atom_map_resp.error_message,
            atom_map_resp.error_code,
        )
        if not atom_map_resp.is_ok or atom_map_resp.atoms is None:
            raise SaveExportError(
                f"Failed to retrieve atom manifest for {blob.file_name!r}: HTTP {atom_map_resp.status_code}",
                status_code=atom_map_resp.status_code,
            )

        manifest_filename = f"{blob_idx:03d}_{sanitize_segment(blob.file_name)}.json"
        _atomic_write_json(
            manifests_dir / manifest_filename,
            {
                "blob_metadata": blob.raw,
                "response_headers": atom_map_resp.response_headers,
                "raw_manifest": atom_map_resp.raw_json,
            },
        )

        blob_atom_entries: list[dict[str, Any]] = []
        for atom_name, atom_id in atom_map_resp.atoms.items():
            if atom_id in downloaded_atom_cache:
                rel_path, size_bytes, digest, content_type = downloaded_atom_cache[atom_id]
            else:
                if delay_seconds > 0:
                    sleep_fn(delay_seconds)
                dl = download_atom(
                    client,
                    xuid=xuid,
                    scid=scid,
                    atom_id=atom_id,
                    pfn=pfn,
                    xsts_token=xsts_token,
                    contract_version=contract_version,
                )
                _fail_if_abort_status(
                    f"download_atom({atom_id})",
                    dl.status_code,
                    dl.error_message,
                    dl.error_code,
                )
                if not dl.is_ok:
                    raise SaveExportError(
                        f"Failed to download atom {atom_id!r} for blob {blob.file_name!r}: HTTP {dl.status_code}",
                        status_code=dl.status_code,
                    )

                atom_stem = sanitize_segment(atom_id.split(",")[0], fallback="atom")
                raw_path = raw_atoms_dir / f"{atom_stem}.bin"
                _atomic_write_bytes(raw_path, dl.data)

                rel_path = raw_path.relative_to(title_dir).as_posix()
                size_bytes = len(dl.data)
                digest = hashlib.sha256(dl.data).hexdigest()
                content_type = dl.response_headers.get("content-type")
                downloaded_atom_cache[atom_id] = (rel_path, size_bytes, digest, content_type)
                total_bytes += size_bytes
                log(f"      downloaded atom {atom_name!r} -> {atom_id} ({size_bytes:,} bytes)")

            record = ExportedAtomRecord(
                blob_file_name=blob.file_name,
                atom_name=atom_name,
                atom_id=atom_id,
                raw_relative_path=rel_path,
                size_bytes=size_bytes,
                sha256=digest,
                content_type=content_type,
            )
            exported_atoms.append(record)
            blob_atom_entries.append(
                {
                    "atom_name": atom_name,
                    "atom_id": atom_id,
                    "raw_relative_path": rel_path,
                    "size_bytes": size_bytes,
                    "sha256": digest,
                    "content_type": content_type,
                }
            )

        blob_records.append(
            {
                "file_name": blob.file_name,
                "display_name": blob.display_name,
                "reported_size": blob.size,
                "client_file_time": blob.client_file_time,
                "etag": blob.etag,
                "manifest_file": f"manifests/{manifest_filename}",
                "atoms": blob_atom_entries,
            }
        )

    manifest_path = title_dir / "export_manifest.json"
    _atomic_write_json(
        manifest_path,
        {
            "version": 1,
            "exported_at_utc": datetime.now(timezone.utc).isoformat(),
            "status": "exported",
            "xuid": xuid,
            "title_id": title.title_id,
            "title_name": title.name,
            "scid": scid,
            "pfn": pfn,
            "contract_version": contract_version,
            "blob_count": len(blob_records),
            "atom_count": len(exported_atoms),
            "unique_atom_bytes": total_bytes,
            "blobs": blob_records,
        },
    )

    return TitleExportResult(
        title_name=title.name,
        title_id=title.title_id,
        scid=scid,
        pfn=pfn,
        output_dir=title_dir,
        status="exported",
        blob_count=len(blob_records),
        atom_count=len(exported_atoms),
        total_bytes=total_bytes,
        atoms=tuple(exported_atoms),
        manifest_path=manifest_path,
    )
