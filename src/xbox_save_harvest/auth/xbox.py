"""Xbox Live Device, User, and XSTS token exchange."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from .oauth import redact_token
from .signing import XboxRequestSigner

DEVICE_AUTH_URL = "https://device.auth.xboxlive.com/device/authenticate"
USER_AUTH_URL = "https://user.auth.xboxlive.com/user/authenticate"
XSTS_AUTH_URL = "https://xsts.auth.xboxlive.com/xsts/authorize"

XBOX_AUTH_RELYING_PARTY = "http://auth.xboxlive.com"
XBOX_LIVE_RELYING_PARTY = "http://xboxlive.com"

KNOWN_XERR_MESSAGES: dict[int, str] = {
    2148916233: "This Microsoft account does not have an Xbox Live profile.",
    2148916235: "Xbox Live is unavailable in this account's region or the account is banned.",
    2148916236: "Account requires adult verification on the Xbox website.",
    2148916237: "Account requires adult verification on the Xbox website.",
    2148916238: "Child account requires parental consent / Family Safety approval.",
}


class XboxAuthError(RuntimeError):
    """Raised when an Xbox Live authentication or authorization call fails."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        xerr: int | None = None,
        endpoint: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.xerr = xerr
        self.endpoint = endpoint


def _parse_iso_utc(raw: str | None) -> datetime:
    if not raw:
        return datetime.now(timezone.utc)
    normalized = raw.replace("Z", "+00:00")
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


@dataclass(frozen=True)
class XboxToken:
    token: str
    issue_instant: datetime
    not_after: datetime
    display_claims: dict[str, Any]

    def is_expired(self, leeway_seconds: int = 120) -> bool:
        return datetime.now(timezone.utc) >= (self.not_after - timedelta(seconds=leeway_seconds))

    @property
    def xui_claims(self) -> dict[str, Any]:
        xui = self.display_claims.get("xui")
        if isinstance(xui, list) and xui and isinstance(xui[0], dict):
            return xui[0]
        return {}

    @property
    def user_hash(self) -> str | None:
        uhs = self.xui_claims.get("uhs")
        return str(uhs) if uhs is not None else None

    @property
    def xuid(self) -> str | None:
        xid = self.xui_claims.get("xid")
        return str(xid) if xid is not None else None

    @property
    def gamertag(self) -> str | None:
        gtg = self.xui_claims.get("gtg") or self.xui_claims.get("mgt")
        return str(gtg) if gtg is not None else None

    def authorization_header(self) -> str:
        if not self.user_hash:
            raise ValueError("Cannot build XBL3.0 header without user_hash (uhs) claim.")
        return f"XBL3.0 x={self.user_hash};{self.token}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "token": self.token,
            "issue_instant": self.issue_instant.isoformat(),
            "not_after": self.not_after.isoformat(),
            "display_claims": self.display_claims,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "XboxToken":
        return cls(
            token=str(data["token"]),
            issue_instant=_parse_iso_utc(data.get("issue_instant")),
            not_after=_parse_iso_utc(data.get("not_after")),
            display_claims=dict(data.get("display_claims") or {}),
        )

    @classmethod
    def from_api_response(cls, payload: dict[str, Any]) -> "XboxToken":
        return cls(
            token=str(payload["Token"]),
            issue_instant=_parse_iso_utc(payload.get("IssueInstant")),
            not_after=_parse_iso_utc(payload.get("NotAfter")),
            display_claims=dict(payload.get("DisplayClaims") or {}),
        )

    def __repr__(self) -> str:
        return (
            f"XboxToken(token={redact_token(self.token)}, "
            f"not_after={self.not_after.isoformat()!r}, "
            f"uhs={self.user_hash!r}, xuid={self.xuid!r}, gamertag={self.gamertag!r})"
        )


def _post_json(
    client: httpx.Client,
    url: str,
    body_obj: dict[str, Any],
    *,
    signer: XboxRequestSigner | None = None,
    contract_version: str = "1",
) -> dict[str, Any]:
    body_bytes = json.dumps(body_obj, separators=(",", ":")).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "x-xbl-contract-version": contract_version,
    }
    if signer is not None:
        headers["Signature"] = signer.sign_request(method="POST", url=url, body=body_bytes)

    response = client.post(url, content=body_bytes, headers=headers)
    payload = _safe_json(response)

    if response.status_code != 200:
        raise _build_xbox_error(url, response, payload)

    return payload


def authenticate_device(
    client: httpx.Client,
    signer: XboxRequestSigner,
    *,
    device_type: str = "Win32",
    device_version: str = "0.0.0",
    device_id: str | None = None,
    serial_number: str | None = None,
) -> XboxToken:
    """Obtain an Xbox Live DeviceToken bound to the signer's ECDSA P-256 ProofKey."""
    did = device_id or str(uuid.uuid4())
    sn = serial_number or str(uuid.uuid4())
    body = {
        "RelyingParty": XBOX_AUTH_RELYING_PARTY,
        "TokenType": "JWT",
        "Properties": {
            "AuthMethod": "ProofOfPossession",
            "Id": f"{{{did}}}",
            "DeviceType": device_type,
            "SerialNumber": f"{{{sn}}}",
            "Version": device_version,
            "ProofKey": signer.proof_key,
        },
    }
    payload = _post_json(client, DEVICE_AUTH_URL, body, signer=signer, contract_version="1")
    return XboxToken.from_api_response(payload)


def authenticate_user(
    client: httpx.Client,
    msa_access_token: str,
    *,
    signer: XboxRequestSigner | None = None,
    token_prefix: str = "t=",
) -> XboxToken:
    """Exchange an MSA OAuth access token for an Xbox Live UserToken."""
    body = {
        "RelyingParty": XBOX_AUTH_RELYING_PARTY,
        "TokenType": "JWT",
        "Properties": {
            "AuthMethod": "RPS",
            "SiteName": "user.auth.xboxlive.com",
            "RpsTicket": f"{token_prefix}{msa_access_token}",
        },
    }
    payload = _post_json(client, USER_AUTH_URL, body, signer=signer, contract_version="1")
    return XboxToken.from_api_response(payload)


def authorize_xsts(
    client: httpx.Client,
    user_token: str,
    *,
    device_token: str | None = None,
    title_token: str | None = None,
    relying_party: str = XBOX_LIVE_RELYING_PARTY,
    sandbox_id: str = "RETAIL",
    optional_display_claims: list[str] | None = None,
    signer: XboxRequestSigner | None = None,
) -> XboxToken:
    """Exchange Xbox tokens for an XSTS authorization token (`http://xboxlive.com`)."""
    properties: dict[str, Any] = {
        "SandboxId": sandbox_id,
        "UserTokens": [user_token],
    }
    if device_token:
        properties["DeviceToken"] = device_token
    if title_token:
        properties["TitleToken"] = title_token
    if optional_display_claims:
        properties["OptionalDisplayClaims"] = optional_display_claims

    body = {
        "RelyingParty": relying_party,
        "TokenType": "JWT",
        "Properties": properties,
    }
    payload = _post_json(client, XSTS_AUTH_URL, body, signer=signer, contract_version="1")
    return XboxToken.from_api_response(payload)


def _safe_json(response: httpx.Response) -> dict[str, Any]:
    try:
        data = response.json()
        return data if isinstance(data, dict) else {}
    except ValueError:
        return {}


def _build_xbox_error(url: str, response: httpx.Response, payload: dict[str, Any]) -> XboxAuthError:
    xerr_raw = payload.get("XErr") or response.headers.get("X-Err")
    xerr: int | None = None
    if xerr_raw is not None:
        try:
            xerr = int(xerr_raw)
        except (TypeError, ValueError):
            xerr = None

    known_hint = KNOWN_XERR_MESSAGES.get(xerr) if xerr is not None else None
    server_msg = payload.get("Message") or response.reason_phrase or "Request failed"
    parts = [f"Xbox auth request to {url} failed with HTTP {response.status_code}"]
    if xerr is not None:
        parts.append(f"XErr={xerr}")
    if known_hint:
        parts.append(known_hint)
    elif server_msg:
        parts.append(str(server_msg))
    return XboxAuthError(" - ".join(parts), status_code=response.status_code, xerr=xerr, endpoint=url)
