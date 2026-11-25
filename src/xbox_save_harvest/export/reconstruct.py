"""Non-destructive post-download inspection and reconstruction over preserved raw atoms."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .archive import sanitize_segment


@dataclass(frozen=True)
class ReconstructedFile:
    blob_file_name: str
    atom_name: str
    source_raw_path: str
    output_relative_path: str
    size_bytes: int
    sha256: str
    detected_format: str
    hex_head: str
    ascii_preview: str


@dataclass(frozen=True)
class ReconstructionReport:
    title_dir: Path
    reconstructed_dir: Path
    report_path: Path
    files: tuple[ReconstructedFile, ...]


def detect_magic(data: bytes) -> tuple[str, str, str]:
    """Classify binary payload magic bytes without modifying data."""
    head = data[:16]
    hex_head = head.hex()
    ascii_preview = "".join(chr(b) if 32 <= b <= 126 else "." for b in data[:32])

    if not data:
        return "empty", hex_head, ascii_preview
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png", hex_head, ascii_preview
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg", hex_head, ascii_preview
    if data.startswith(b"DDS "):
        return "dds", hex_head, ascii_preview
    if data.startswith(b"\x1f\x8b"):
        return "gzip", hex_head, ascii_preview
    if data.startswith((b"\x78\x01", b"\x78\x9c", b"\x78\xda")):
        return "zlib", hex_head, ascii_preview
    if data.startswith(b"PK\x03\x04"):
        return "zip", hex_head, ascii_preview
    if data.startswith(b"SQLite format 3\x00"):
        return "sqlite3", hex_head, ascii_preview

    # Check if payload is UTF-8 JSON or plain text.
    try:
        text = data[:4096].decode("utf-8")
        stripped = text.lstrip()
        if stripped.startswith(("{", "[")):
            json.loads(data.decode("utf-8"))
            return "json", hex_head, ascii_preview
        if all(ch.isprintable() or ch in "\r\n\t" for ch in text):
            return "utf8_text", hex_head, ascii_preview
    except (UnicodeDecodeError, ValueError):
        pass

    return "binary", hex_head, ascii_preview


def _safe_blob_rel_parts(blob_file_name: str) -> list[str]:
    """Turn a Connected Storage blob fileName into safe relative path segments."""
    base = blob_file_name
    if base.lower().endswith(",savedgame"):
        base = base[: -len(",savedgame")]
    raw_parts = [p for p in base.replace("\\", "/").split("/") if p]
    safe_parts: list[str] = []
    for part in raw_parts:
        if part in {".", ".."}:
            continue
        safe_parts.append(sanitize_segment(part, fallback="blob"))
    return safe_parts or ["blob"]


def _atomic_copy_bytes(target: Path, data: bytes) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = target.with_name(f".{target.name}.part")
    tmp_path.write_bytes(data)
    os.replace(tmp_path, target)


def reconstruct_from_raw(title_dir: Path) -> ReconstructionReport:
    """Inspect preserved raw atoms and write a lossless reconstructed tree alongside inspection_report.json.

    Never modifies or deletes anything in `raw_atoms/`, `manifests/`, or `blobs.json`.
    """
    manifest_path = title_dir / "export_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    reconstructed_dir = title_dir / "reconstructed"
    reconstructed_dir.mkdir(parents=True, exist_ok=True)

    reconstructed_files: list[ReconstructedFile] = []
    report_blobs: list[dict[str, Any]] = []

    for blob in manifest.get("blobs", []):
        blob_name = str(blob.get("file_name") or "")
        blob_parts = _safe_blob_rel_parts(blob_name)
        atoms = blob.get("atoms", [])
        blob_out_entries: list[dict[str, Any]] = []

        # Preserve container path hierarchy cleanly:
        # - Multiple atoms: reconstructed/<blob_parts...>/<atom_name>
        # - Single atom:    reconstructed/<blob_parts...>/<atom_name>
        # Keeping the container directory avoids collisions when a container has both `data` and `icon`
        # or `param`, and preserves exact original atom names untouched.
        for atom in atoms:
            atom_name = str(atom.get("atom_name") or "atom")
            raw_rel = str(atom.get("raw_relative_path") or "")
            raw_path = (title_dir / raw_rel).resolve()
            if not str(raw_path).startswith(str(title_dir.resolve())):
                raise ValueError(f"Refusing to read outside title directory: {raw_rel!r}")

            data = raw_path.read_bytes()
            detected_format, hex_head, ascii_preview = detect_magic(data)

            safe_atom = sanitize_segment(atom_name, fallback="atom")
            out_path = reconstructed_dir.joinpath(*blob_parts, safe_atom)
            _atomic_copy_bytes(out_path, data)

            out_rel = out_path.relative_to(title_dir).as_posix()
            entry = ReconstructedFile(
                blob_file_name=blob_name,
                atom_name=atom_name,
                source_raw_path=raw_rel,
                output_relative_path=out_rel,
                size_bytes=len(data),
                sha256=str(atom.get("sha256") or ""),
                detected_format=detected_format,
                hex_head=hex_head,
                ascii_preview=ascii_preview,
            )
            reconstructed_files.append(entry)
            blob_out_entries.append(
                {
                    "atom_name": atom_name,
                    "source_raw_path": raw_rel,
                    "output_relative_path": out_rel,
                    "size_bytes": len(data),
                    "sha256": entry.sha256,
                    "detected_format": detected_format,
                    "hex_head": hex_head,
                    "ascii_preview": ascii_preview,
                }
            )

        report_blobs.append(
            {
                "blob_file_name": blob_name,
                "display_name": blob.get("display_name"),
                "reported_size": blob.get("reported_size"),
                "client_file_time": blob.get("client_file_time"),
                "sum_atom_bytes": sum(a["size_bytes"] for a in blob_out_entries),
                "atoms": blob_out_entries,
            }
        )

    report_path = title_dir / "inspection_report.json"
    report_payload = {
        "title_name": manifest.get("title_name"),
        "title_id": manifest.get("title_id"),
        "scid": manifest.get("scid"),
        "pfn": manifest.get("pfn"),
        "file_count": len(reconstructed_files),
        "blobs": report_blobs,
    }
    _atomic_copy_bytes(
        report_path,
        json.dumps(report_payload, indent=2, ensure_ascii=False).encode("utf-8"),
    )

    return ReconstructionReport(
        title_dir=title_dir,
        reconstructed_dir=reconstructed_dir,
        report_path=report_path,
        files=tuple(reconstructed_files),
    )
