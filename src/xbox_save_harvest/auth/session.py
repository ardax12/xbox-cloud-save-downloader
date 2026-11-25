"""Local-only authentication session management and token caching."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import httpx

from .oauth import (
    DeviceCodePrompt,
    MsaToken,
    OAuthError,
    poll_for_token,
    redact_token,
    refresh_access_token,
    request_device_code,
    resolve_client_id,
)
from .signing import XboxRequestSigner
from .xbox import (
    XboxToken,
    authenticate_device,
    authenticate_user,
    authorize_xsts,
)


def default_session_path() -> Path:
    """Store cached auth session under LocalAppData (outside the git repo)."""
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / "PcGamepassSaveHarvest" / "session.json"
    return Path.home() / ".pc_gamepass_save_harvest" / "session.json"


@dataclass(frozen=True)
class AuthSession:
    client_id: str
    device_key_pem: str
    msa_token: MsaToken
    device_token: XboxToken
    user_token: XboxToken
    xsts_token: XboxToken

    @property
    def xuid(self) -> str | None:
        return self.xsts_token.xuid

    @property
    def user_hash(self) -> str | None:
        return self.xsts_token.user_hash or self.user_token.user_hash

    @property
    def gamertag(self) -> str | None:
        return self.xsts_token.gamertag

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": 1,
            "client_id": self.client_id,
            "device_key_pem": self.device_key_pem,
            "msa_token": self.msa_token.to_dict(),
            "device_token": self.device_token.to_dict(),
            "user_token": self.user_token.to_dict(),
            "xsts_token": self.xsts_token.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuthSession":
        return cls(
            client_id=str(data["client_id"]),
            device_key_pem=str(data["device_key_pem"]),
            msa_token=MsaToken.from_dict(data["msa_token"]),
            device_token=XboxToken.from_dict(data["device_token"]),
            user_token=XboxToken.from_dict(data["user_token"]),
            xsts_token=XboxToken.from_dict(data["xsts_token"]),
        )

    def __repr__(self) -> str:
        return (
            f"AuthSession(client_id={self.client_id!r}, "
            f"xuid={self.xuid!r}, uhs={self.user_hash!r}, gamertag={self.gamertag!r}, "
            f"msa={redact_token(self.msa_token.access_token)}, "
            f"xsts={redact_token(self.xsts_token.token)})"
        )


def load_session(path: Path | None = None) -> AuthSession | None:
    target = path or default_session_path()
    if not target.exists():
        return None
    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
        return AuthSession.from_dict(raw)
    except (OSError, ValueError, KeyError):
        return None


def save_session(session: AuthSession, path: Path | None = None) -> Path:
    target = path or default_session_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = target.with_suffix(".tmp")
    tmp_path.write_text(json.dumps(session.to_dict(), indent=2), encoding="utf-8")
    os.replace(tmp_path, target)
    return target


def authenticate_session(
    *,
    client: httpx.Client | None = None,
    session_path: Path | None = None,
    client_id: str | None = None,
    device_type: str = "Win32",
    device_version: str = "0.0.0",
    force_fresh: bool = False,
    on_device_code: Callable[[DeviceCodePrompt], None] | None = None,
) -> AuthSession:
    """Authenticate locally using cached tokens if valid, refreshing or prompting via Device Code."""
    cid = resolve_client_id(client_id)
    target_path = session_path or default_session_path()

    own_client = client is None
    http = client or httpx.Client(timeout=30.0)
    try:
        cached = None if force_fresh else load_session(target_path)

        if cached and cached.client_id == cid and not cached.xsts_token.is_expired():
            return cached

        signer = XboxRequestSigner.from_pem(cached.device_key_pem) if cached else XboxRequestSigner()

        msa_token: MsaToken | None = None
        if cached and cached.client_id == cid:
            if not cached.msa_token.is_expired():
                msa_token = cached.msa_token
            elif cached.msa_token.refresh_token:
                try:
                    msa_token = refresh_access_token(http, cached.msa_token.refresh_token, client_id=cid)
                except OAuthError:
                    msa_token = None

        if msa_token is None:
            prompt = request_device_code(http, client_id=cid)
            if on_device_code is not None:
                on_device_code(prompt)
            msa_token = poll_for_token(http, prompt, client_id=cid)

        device_token = authenticate_device(
            http,
            signer,
            device_type=device_type,
            device_version=device_version,
        )
        user_token = authenticate_user(http, msa_token.access_token, signer=signer)
        xsts_token = authorize_xsts(
            http,
            user_token.token,
            device_token=device_token.token,
            signer=signer,
        )

        session = AuthSession(
            client_id=cid,
            device_key_pem=signer.to_pem(),
            msa_token=msa_token,
            device_token=device_token,
            user_token=user_token,
            xsts_token=xsts_token,
        )
        save_session(session, target_path)
        return session
    finally:
        if own_client:
            http.close()
