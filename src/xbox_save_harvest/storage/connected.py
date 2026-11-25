"""Strictly read-only (GET-only) Xbox Connected Storage client."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import httpx

from xbox_save_harvest.auth.signing import XboxRequestSigner
from xbox_save_harvest.auth.xbox import XboxToken

TITLESTORAGE_BASE_URL = "https://titlestorage.xboxlive.com"

DIAGNOSTIC_HEADER_NAMES = (
    "content-type",
    "date",
    "ms-cv",
    "retry-after",
    "www-authenticate",
    "x-err",
    "x-xbl-correlation-id",
)


@dataclass(frozen=True)
class BlobMetadata:
    file_name: str
    display_name: str | None
    size: int | None
    client_file_time: str | None
    etag: str | None
    raw: dict[str, Any]

    @classmethod
    def from_api(cls, item: dict[str, Any]) -> "BlobMetadata":
        raw_size = item.get("size")
        size = int(raw_size) if isinstance(raw_size, (int, float)) else None
        return cls(
            file_name=str(item.get("fileName") or ""),
            display_name=str(item["displayName"]) if item.get("displayName") is not None else None,
            size=size,
            client_file_time=str(item["clientFileTime"]) if item.get("clientFileTime") is not None else None,
            etag=str(item["etag"]) if item.get("etag") is not None else None,
            raw=dict(item),
        )


@dataclass(frozen=True)
class ConnectedStorageResponse:
    url: str
    status_code: int
    contract_version: str
    response_headers: dict[str, str]
    blobs: tuple[BlobMetadata, ...] = ()
    atoms: dict[str, str] | None = None
    paging_info: dict[str, Any] | None = None
    error_code: int | None = None
    error_reason: str | None = None
    error_message: str | None = None
    raw_json: dict[str, Any] | None = None
    raw_body_preview: str = ""

    @property
    def is_ok(self) -> bool:
        return self.status_code == 200

    @property
    def is_empty_storage(self) -> bool:
        return self.status_code == 404 and self.error_code == 2005

    @property
    def is_forbidden(self) -> bool:
        return self.status_code == 403

    @property
    def is_unauthorized(self) -> bool:
        return self.status_code == 401

    @property
    def is_rate_limited(self) -> bool:
        return self.status_code == 429


def _build_headers(
    *,
    url: str,
    xsts_token: XboxToken,
    pfn: str | None,
    contract_version: str,
    accept_language: str,
    signer: XboxRequestSigner | None,
) -> dict[str, str]:
    auth_header = xsts_token.authorization_header()
    headers = {
        "Authorization": auth_header,
        "x-xbl-contract-version": contract_version,
        "Accept": "application/json, */*",
        "Accept-Language": accept_language,
    }
    if pfn:
        headers["x-xbl-pfn"] = pfn
    if signer is not None:
        headers["Signature"] = signer.sign_request(
            method="GET",
            url=url,
            body=b"",
            authorization=auth_header,
        )
    return headers


def _extract_diagnostic_headers(response: httpx.Response) -> dict[str, str]:
    found: dict[str, str] = {}
    for name in DIAGNOSTIC_HEADER_NAMES:
        value = response.headers.get(name)
        if value is not None:
            found[name] = value
    return found


def _parse_error_fields(payload: dict[str, Any] | None) -> tuple[int | None, str | None, str | None]:
    if not isinstance(payload, dict):
        return None, None, None

    raw_code = payload.get("code")
    code: int | None = None
    if raw_code is not None:
        try:
            code = int(raw_code)
        except (TypeError, ValueError):
            code = None

    reason = payload.get("reason") or payload.get("Reason")
    message = payload.get("description") or payload.get("message") or payload.get("Message")
    return (
        code,
        str(reason) if reason is not None else None,
        str(message) if message is not None else None,
    )


def _safe_json(response: httpx.Response) -> dict[str, Any] | None:
    try:
        data = response.json()
        return data if isinstance(data, dict) else None
    except ValueError:
        return None


def list_blobs(
    client: httpx.Client,
    *,
    xuid: str,
    scid: str,
    xsts_token: XboxToken,
    pfn: str | None = None,
    contract_version: str = "107",
    accept_language: str = "en-US",
    signer: XboxRequestSigner | None = None,
) -> ConnectedStorageResponse:
    """List Connected Storage save blobs for a user and SCID (strictly HTTP GET)."""
    url = f"{TITLESTORAGE_BASE_URL}/connectedstorage/users/xuid({xuid})/scids/{scid}"
    headers = _build_headers(
        url=url,
        xsts_token=xsts_token,
        pfn=pfn,
        contract_version=contract_version,
        accept_language=accept_language,
        signer=signer,
    )
    response = client.get(url, headers=headers)
    payload = _safe_json(response)
    diag_headers = _extract_diagnostic_headers(response)

    if response.status_code == 200 and isinstance(payload, dict):
        raw_blobs = payload.get("blobs") or []
        blobs = tuple(BlobMetadata.from_api(b) for b in raw_blobs if isinstance(b, dict))
        paging = payload.get("pagingInfo") if isinstance(payload.get("pagingInfo"), dict) else None
        return ConnectedStorageResponse(
            url=url,
            status_code=200,
            contract_version=contract_version,
            response_headers=diag_headers,
            blobs=blobs,
            paging_info=paging,
            raw_json=payload,
        )

    err_code, err_reason, err_msg = _parse_error_fields(payload)
    return ConnectedStorageResponse(
        url=url,
        status_code=response.status_code,
        contract_version=contract_version,
        response_headers=diag_headers,
        error_code=err_code,
        error_reason=err_reason,
        error_message=err_msg,
        raw_json=payload,
        raw_body_preview=response.text[:400],
    )


def get_blob_atoms(
    client: httpx.Client,
    *,
    xuid: str,
    scid: str,
    file_name: str,
    xsts_token: XboxToken,
    pfn: str | None = None,
    contract_version: str = "107",
    accept_language: str = "en-US",
    signer: XboxRequestSigner | None = None,
) -> ConnectedStorageResponse:
    """Retrieve the atom manifest map for a single Connected Storage blob (strictly HTTP GET)."""
    encoded_name = quote(file_name, safe=",._-")
    url = f"{TITLESTORAGE_BASE_URL}/connectedstorage/users/xuid({xuid})/scids/{scid}/{encoded_name}"
    headers = _build_headers(
        url=url,
        xsts_token=xsts_token,
        pfn=pfn,
        contract_version=contract_version,
        accept_language=accept_language,
        signer=signer,
    )
    response = client.get(url, headers=headers)
    payload = _safe_json(response)
    diag_headers = _extract_diagnostic_headers(response)

    if response.status_code == 200 and isinstance(payload, dict):
        raw_atoms = payload.get("atoms")
        atoms = {str(k): str(v) for k, v in raw_atoms.items()} if isinstance(raw_atoms, dict) else {}
        return ConnectedStorageResponse(
            url=url,
            status_code=200,
            contract_version=contract_version,
            response_headers=diag_headers,
            atoms=atoms,
            raw_json=payload,
        )

    err_code, err_reason, err_msg = _parse_error_fields(payload)
    return ConnectedStorageResponse(
        url=url,
        status_code=response.status_code,
        contract_version=contract_version,
        response_headers=diag_headers,
        error_code=err_code,
        error_reason=err_reason,
        error_message=err_msg,
        raw_json=payload,
        raw_body_preview=response.text[:400],
    )


@dataclass(frozen=True)
class AtomDownloadResponse:
    url: str
    atom_id: str
    status_code: int
    contract_version: str
    response_headers: dict[str, str]
    data: bytes = b""
    error_code: int | None = None
    error_reason: str | None = None
    error_message: str | None = None
    raw_body_preview: str = ""

    @property
    def is_ok(self) -> bool:
        return self.status_code == 200

    @property
    def is_forbidden(self) -> bool:
        return self.status_code == 403

    @property
    def is_unauthorized(self) -> bool:
        return self.status_code == 401

    @property
    def is_rate_limited(self) -> bool:
        return self.status_code == 429


def download_atom(
    client: httpx.Client,
    *,
    xuid: str,
    scid: str,
    atom_id: str,
    xsts_token: XboxToken,
    pfn: str | None = None,
    contract_version: str = "107",
    accept_language: str = "en-US",
    signer: XboxRequestSigner | None = None,
) -> AtomDownloadResponse:
    """Download raw binary bytes for a single Connected Storage atom (strictly HTTP GET)."""
    encoded_atom = quote(atom_id, safe=",._-")
    url = f"{TITLESTORAGE_BASE_URL}/connectedstorage/users/xuid({xuid})/scids/{scid}/{encoded_atom}"
    headers = _build_headers(
        url=url,
        xsts_token=xsts_token,
        pfn=pfn,
        contract_version=contract_version,
        accept_language=accept_language,
        signer=signer,
    )
    response = client.get(url, headers=headers)
    diag_headers = _extract_diagnostic_headers(response)

    if response.status_code == 200:
        return AtomDownloadResponse(
            url=url,
            atom_id=atom_id,
            status_code=200,
            contract_version=contract_version,
            response_headers=diag_headers,
            data=response.content,
        )

    payload = _safe_json(response)
    err_code, err_reason, err_msg = _parse_error_fields(payload)
    return AtomDownloadResponse(
        url=url,
        atom_id=atom_id,
        status_code=response.status_code,
        contract_version=contract_version,
        response_headers=diag_headers,
        error_code=err_code,
        error_reason=err_reason,
        error_message=err_msg,
        raw_body_preview=response.text[:400],
    )
