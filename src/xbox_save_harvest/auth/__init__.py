"""Authentication package for Microsoft Account and Xbox Live tokens."""

from .oauth import (
    DEFAULT_CLIENT_ID,
    XBOX_LIVE_SCOPE,
    DeviceCodePrompt,
    MsaToken,
    OAuthError,
    poll_for_token,
    redact_token,
    refresh_access_token,
    request_device_code,
    resolve_client_id,
)
from .session import (
    AuthSession,
    authenticate_session,
    default_session_path,
    load_session,
    save_session,
)
from .signing import XboxRequestSigner, windows_filetime
from .xbox import (
    XboxAuthError,
    XboxToken,
    authenticate_device,
    authenticate_user,
    authorize_xsts,
)

__all__ = [
    "AuthSession",
    "DEFAULT_CLIENT_ID",
    "DeviceCodePrompt",
    "MsaToken",
    "OAuthError",
    "XBOX_LIVE_SCOPE",
    "XboxAuthError",
    "XboxRequestSigner",
    "XboxToken",
    "authenticate_device",
    "authenticate_session",
    "authenticate_user",
    "authorize_xsts",
    "default_session_path",
    "load_session",
    "poll_for_token",
    "redact_token",
    "refresh_access_token",
    "request_device_code",
    "resolve_client_id",
    "save_session",
    "windows_filetime",
]
