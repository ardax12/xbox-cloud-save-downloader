"""Read-only Xbox Title Hub client for dynamic game discovery."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

import httpx

from xbox_save_harvest.auth.xbox import XboxToken

TITLEHUB_URL_TEMPLATE = (
    "https://titlehub.xboxlive.com/users/xuid({xuid})/titles/titlehistory/"
    "decoration/scid,image,detail"
)


class TitleHubError(RuntimeError):
    """Raised when a Title Hub query fails."""

    def __init__(self, message: str, *, status_code: int | None = None, body_preview: str = "") -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body_preview = body_preview


@dataclass(frozen=True)
class TitleEntry:
    title_id: str
    name: str
    service_config_id: str | None
    pfn: str | None
    devices: tuple[str, ...]
    title_type: str | None
    last_time_played: str | None
    raw: dict[str, Any]

    @property
    def has_cloud_ids(self) -> bool:
        return bool(self.service_config_id and self.pfn)

    @classmethod
    def from_api(cls, item: dict[str, Any]) -> "TitleEntry":
        raw_devices = item.get("devices") or []
        devices = tuple(str(d) for d in raw_devices if d is not None)
        history = item.get("titleHistory")
        last_played = history.get("lastTimePlayed") if isinstance(history, dict) else None
        scid = item.get("serviceConfigId")
        pfn = item.get("pfn")
        return cls(
            title_id=str(item.get("titleId") or ""),
            name=str(item.get("name") or ""),
            service_config_id=str(scid) if scid else None,
            pfn=str(pfn) if pfn else None,
            devices=devices,
            title_type=str(item.get("type")) if item.get("type") else None,
            last_time_played=str(last_played) if last_played else None,
            raw=dict(item),
        )


@dataclass(frozen=True)
class TitleHistoryResult:
    status_code: int
    titles: tuple[TitleEntry, ...]
    raw_json: dict[str, Any]


def fetch_title_history(
    client: httpx.Client,
    *,
    xuid: str,
    xsts_token: XboxToken,
    accept_language: str = "en-US",
    contract_version: str = "2",
) -> TitleHistoryResult:
    """Fetch the authenticated user's Xbox title history via read-only GET."""
    url = TITLEHUB_URL_TEMPLATE.format(xuid=xuid)
    response = client.get(
        url,
        headers={
            "Authorization": xsts_token.authorization_header(),
            "x-xbl-contract-version": contract_version,
            "Accept": "application/json",
            "Accept-Language": accept_language,
        },
    )
    if response.status_code != 200:
        preview = response.text[:400]
        raise TitleHubError(
            f"Title Hub request failed with HTTP {response.status_code} ({response.reason_phrase}).",
            status_code=response.status_code,
            body_preview=preview,
        )

    payload = response.json()
    raw_titles = payload.get("titles") if isinstance(payload, dict) else None
    if not isinstance(raw_titles, list):
        raise TitleHubError(
            "Title Hub returned HTTP 200 but payload did not contain a 'titles' list.",
            status_code=200,
            body_preview=response.text[:400],
        )

    entries = tuple(TitleEntry.from_api(item) for item in raw_titles if isinstance(item, dict))
    return TitleHistoryResult(
        status_code=response.status_code,
        titles=entries,
        raw_json=payload,
    )


def find_matching_titles(
    titles: Sequence[TitleEntry],
    terms: Sequence[str],
) -> list[TitleEntry]:
    """Case-insensitively match titles by name, PFN, SCID, or TitleId without device exclusions."""
    lowered = [t.strip().lower() for t in terms if t.strip()]
    if not lowered:
        return list(titles)

    matches: list[TitleEntry] = []
    for entry in titles:
        haystack = " ".join(
            part.lower()
            for part in (entry.name, entry.pfn or "", entry.service_config_id or "", entry.title_id)
        )
        if any(term in haystack for term in lowered):
            matches.append(entry)
    return matches
