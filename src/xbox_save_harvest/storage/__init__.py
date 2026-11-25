"""Strictly read-only Xbox Connected Storage package."""

from .connected import (
    TITLESTORAGE_BASE_URL,
    AtomDownloadResponse,
    BlobMetadata,
    ConnectedStorageResponse,
    download_atom,
    get_blob_atoms,
    list_blobs,
)

__all__ = [
    "AtomDownloadResponse",
    "BlobMetadata",
    "ConnectedStorageResponse",
    "TITLESTORAGE_BASE_URL",
    "download_atom",
    "get_blob_atoms",
    "list_blobs",
]
