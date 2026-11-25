"""Game discovery package (Title Hub)."""

from .titlehub import (
    TITLEHUB_URL_TEMPLATE,
    TitleEntry,
    TitleHistoryResult,
    TitleHubError,
    fetch_title_history,
    find_matching_titles,
)

__all__ = [
    "TITLEHUB_URL_TEMPLATE",
    "TitleEntry",
    "TitleHistoryResult",
    "TitleHubError",
    "fetch_title_history",
    "find_matching_titles",
]
