"""Phase 5 user-facing CLI for read-only Xbox PC cloud save harvesting."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Callable, Sequence

import httpx

from .auth import (
    AuthSession,
    DeviceCodePrompt,
    OAuthError,
    XboxAuthError,
    authenticate_session,
    default_session_path,
    redact_token,
)
from .discovery import TitleEntry, TitleHubError, fetch_title_history, find_matching_titles
from .export import SaveExportError, export_title_raw, export_wgs_from_raw, reconstruct_from_raw
from .storage import ConnectedStorageResponse, list_blobs

logger = logging.getLogger("xbox_save_harvest")


def configure_logging(*, verbose: bool = False, log_file: Path | None = None) -> None:
    """Configure non-secret application logging (keeping HTTP wire logs quiet by default)."""
    level = logging.DEBUG if verbose else logging.INFO
    handlers: list[logging.Handler] = []

    if verbose:
        stream_handler = logging.StreamHandler(sys.stderr)
        stream_handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        handlers.append(stream_handler)

    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        )
        handlers.append(file_handler)

    root = logging.getLogger("xbox_save_harvest")
    root.handlers.clear()
    root.setLevel(level)
    for h in handlers:
        root.addHandler(h)
    root.propagate = False

    # Never leak raw Authorization headers through httpx/httpcore debug logs.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


def format_bytes(size: int) -> str:
    """Format byte count into a human-readable string."""
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    if size < 1024 * 1024 * 1024:
        return f"{size / (1024 * 1024):.2f} MB"
    return f"{size / (1024 * 1024 * 1024):.2f} GB"


def sort_titles_for_display(titles: Sequence[TitleEntry]) -> list[TitleEntry]:
    """Sort titles with most recently played first, then alphabetically by name."""
    return sorted(
        titles,
        key=lambda t: (
            bool(t.last_time_played),
            t.last_time_played or "",
            t.name.lower(),
        ),
        reverse=True,
    )


def parse_selection(raw: str, max_index: int) -> list[int]:
    """Parse 1-based user selection like '1', '1,3,5', '2-4', or 'all' into sorted unique 0-based indices.

    Returns an empty list for 'q'/'quit'/'cancel'. Raises ValueError on invalid input.
    """
    text = raw.strip().lower()
    if not text or text in {"q", "quit", "exit", "cancel"}:
        return []
    if text == "all":
        return list(range(max_index))

    selected: set[int] = set()
    for part in text.split(","):
        token = part.strip()
        if not token:
            continue
        if "-" in token:
            bounds = token.split("-", maxsplit=1)
            if len(bounds) != 2 or not bounds[0].strip().isdigit() or not bounds[1].strip().isdigit():
                raise ValueError(f"Invalid range {token!r}. Expected format like '1-3'.")
            start = int(bounds[0].strip())
            end = int(bounds[1].strip())
            if start < 1 or end < start or end > max_index:
                raise ValueError(f"Range {token!r} is out of bounds (valid: 1..{max_index}).")
            for idx in range(start, end + 1):
                selected.add(idx - 1)
        else:
            if not token.isdigit():
                raise ValueError(f"Invalid selection {token!r}. Enter numbers, ranges (1-3), 'all', or 'q'.")
            num = int(token)
            if num < 1 or num > max_index:
                raise ValueError(f"Selection {num} is out of bounds (valid: 1..{max_index}).")
            selected.add(num - 1)

    if not selected:
        raise ValueError("No valid indices selected.")
    return sorted(selected)


def _print_device_code_prompt(prompt: DeviceCodePrompt) -> None:
    print()
    print("=== Microsoft Account Sign-In Required ===")
    print(f"1. Open : {prompt.verification_uri}")
    print(f"2. Code : {prompt.user_code}")
    print(f"   (Expires in {prompt.expires_in}s; waiting for browser sign-in...)")
    print()
    sys.stdout.flush()


def _cloud_id_label(entry: TitleEntry) -> str:
    if entry.service_config_id and entry.pfn:
        return "SCID+PFN"
    if entry.service_config_id:
        return "SCID-only"
    return "no-SCID"


def _storage_probe_label(resp: ConnectedStorageResponse) -> str:
    if resp.is_ok:
        total_bytes = sum(b.size or 0 for b in resp.blobs)
        return f"SAVES ({len(resp.blobs)} blobs, {format_bytes(total_bytes)})"
    if resp.is_empty_storage:
        return "empty (no cloud saves)"
    if resp.is_rate_limited:
        return "rate-limited (HTTP 429)"
    if resp.status_code == 403:
        code_part = f" code={resp.error_code}" if resp.error_code else ""
        return f"denied (HTTP 403{code_part})"
    return f"HTTP {resp.status_code}"


def _ensure_session(
    *,
    client: httpx.Client,
    session_path: Path,
    force_fresh: bool = False,
) -> AuthSession:
    logger.info("Authenticating Xbox Live session (cache=%s, fresh=%s)", session_path, force_fresh)
    session = authenticate_session(
        client=client,
        session_path=session_path,
        force_fresh=force_fresh,
        on_device_code=_print_device_code_prompt,
    )
    if not session.xuid or not session.user_hash:
        raise XboxAuthError(
            "Authenticated XSTS token did not include XUID or User Hash claims. Try `xbox-save-harvest login --fresh`."
        )
    logger.info(
        "Authenticated as gamertag=%s xuid=%s xsts=%s",
        session.gamertag or "<unknown>",
        session.xuid,
        redact_token(session.xsts_token.token),
    )
    return session


def _format_title_row(index: int, entry: TitleEntry, *, storage_status: str | None = None) -> str:
    last_played = (entry.last_time_played or "")[:10] or "unknown"
    devices = ",".join(entry.devices) if entry.devices else "-"
    row = (
        f"  [{index:>3}] {entry.name:<46} | id={entry.title_id:<11} | "
        f"last={last_played} | {devices:<22} | {_cloud_id_label(entry)}"
    )
    if storage_status is not None:
        row += f" | {storage_status}"
    return row


def _cmd_login(args: argparse.Namespace, *, client: httpx.Client) -> int:
    session_path = args.session_path or default_session_path()
    session = _ensure_session(
        client=client,
        session_path=session_path,
        force_fresh=args.fresh,
    )
    print("=== Xbox Live Account Authenticated ===")
    print(f"Gamertag      : {session.gamertag or '<unknown>'}")
    print(f"XUID          : {session.xuid}")
    print(f"User Hash     : {session.user_hash}")
    print(f"Session Cache : {session_path}")
    print(f"MSA Access    : {redact_token(session.msa_token.access_token)} (expires {session.msa_token.expires_at.isoformat()})")
    print(f"XSTS Token    : {redact_token(session.xsts_token.token)} (expires {session.xsts_token.not_after.isoformat()})")
    return 0


def _cmd_list(args: argparse.Namespace, *, client: httpx.Client) -> int:
    import time

    session_path = args.session_path or default_session_path()
    session = _ensure_session(client=client, session_path=session_path)
    history = fetch_title_history(client, xuid=session.xuid or "", xsts_token=session.xsts_token)

    titles = find_matching_titles(history.titles, args.filters or ())
    if args.only_with_scid:
        titles = [t for t in titles if t.service_config_id]
    titles = sort_titles_for_display(titles)

    print(
        f"Account: {session.gamertag or '<unknown>'} (XUID {session.xuid}) - "
        f"showing {len(titles)} of {len(history.titles)} Title Hub game(s)"
    )
    if not titles:
        print("No matching titles found.")
        return 0

    for idx, entry in enumerate(titles, start=1):
        storage_status: str | None = None
        if args.probe_storage:
            if not entry.service_config_id:
                storage_status = "skipped (no SCID)"
            else:
                if idx > 1 and args.delay > 0:
                    time.sleep(args.delay)
                resp = list_blobs(
                    client,
                    xuid=session.xuid or "",
                    scid=entry.service_config_id,
                    pfn=entry.pfn,
                    xsts_token=session.xsts_token,
                )
                storage_status = _storage_probe_label(resp)
                print(_format_title_row(idx, entry, storage_status=storage_status))
                if resp.is_rate_limited:
                    print("Stopped probing immediately due to HTTP 429 rate limit.", file=sys.stderr)
                    return 1
                continue
        print(_format_title_row(idx, entry, storage_status=storage_status))

    return 0


def _select_titles_interactive(
    titles: Sequence[TitleEntry],
    *,
    input_fn: Callable[[str], str],
) -> list[TitleEntry]:
    print("\nSelect game(s) to export (read-only):")
    for idx, entry in enumerate(titles, start=1):
        print(_format_title_row(idx, entry))
    print()

    while True:
        try:
            raw = input_fn("Enter number(s) (e.g. 1, 1,3, 1-3, all, or q to cancel): ")
        except EOFError:
            return []
        try:
            indices = parse_selection(raw, len(titles))
        except ValueError as exc:
            print(f"  {exc}")
            continue
        return [titles[i] for i in indices]


def _default_output_dir() -> Path:
    """Default export folder next to the standalone .exe when frozen, or ./saves_output otherwise."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / "saves_output"
    return Path("saves_output")


def _export_selected_titles(
    *,
    client: httpx.Client,
    session: AuthSession,
    selected: Sequence[TitleEntry],
    out_dir: Path,
    delay: float = 0.2,
    no_reconstruct: bool = False,
) -> int:
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"\nExport destination: {out_dir.resolve()}")
    print(f"Selected {len(selected)} title(s) (strictly read-only GET).\n")

    exported_count = 0
    empty_count = 0
    skipped_count = 0
    total_atoms = 0
    total_bytes = 0

    for title in selected:
        if not title.service_config_id:
            print(f"Skipping {title.name!r} (titleId={title.title_id}): no SCID in Title Hub metadata.")
            skipped_count += 1
            continue

        print(f"=== Exporting: {title.name} (titleId={title.title_id}) ===")
        logger.info("Exporting title=%s title_id=%s scid=%s", title.name, title.title_id, title.service_config_id)
        export_res = export_title_raw(
            client,
            xuid=session.xuid or "",
            xsts_token=session.xsts_token,
            title=title,
            output_root=out_dir,
            delay_seconds=max(0.0, delay),
            on_progress=print,
        )

        if export_res.status == "empty":
            print(
                f"  No synchronized cloud saves found (HTTP 404 / code 2005). "
                f"Metadata saved to {export_res.output_dir.resolve()}\n"
            )
            empty_count += 1
            continue

        exported_count += 1
        total_atoms += export_res.atom_count
        total_bytes += export_res.total_bytes

        print(
            f"  Raw archive : {export_res.blob_count} blob(s), {export_res.atom_count} atom(s), "
            f"{format_bytes(export_res.total_bytes)} ({export_res.total_bytes:,} B)"
        )
        print(f"  Output dir  : {export_res.output_dir.resolve()}")

        if not no_reconstruct:
            recon = reconstruct_from_raw(export_res.output_dir)
            wgs = export_wgs_from_raw(export_res.output_dir)
            exact, total_blobs = _count_byte_exact_blobs(recon.report_path)
            print(
                f"  Reconstructed: {len(recon.files)} file(s) "
                f"(byte-exact: {exact}/{total_blobs} blobs) -> {recon.reconstructed_dir.resolve()}"
            )
            print(
                f"  WGS layout  : {len(wgs.containers)} container(s), {wgs.atom_count} atom(s) "
                f"-> {wgs.user_wgs_dir.resolve()}"
            )
            print(f"  Report      : {recon.report_path.resolve()}")
        print()

    print("=== Export Summary ===")
    print(
        f"Exported: {exported_count} | Empty: {empty_count} | Skipped (no SCID): {skipped_count} | "
        f"Atoms: {total_atoms} | Total size: {format_bytes(total_bytes)} ({total_bytes:,} B)"
    )
    return 0


def _cmd_export(
    args: argparse.Namespace,
    *,
    client: httpx.Client,
    input_fn: Callable[[str], str],
) -> int:
    session_path = args.session_path or default_session_path()
    session = _ensure_session(client=client, session_path=session_path)
    history = fetch_title_history(client, xuid=session.xuid or "", xsts_token=session.xsts_token)

    candidates = sort_titles_for_display(history.titles)
    selected: list[TitleEntry]

    if args.title_ids:
        wanted_ids = {tid.strip() for tid in args.title_ids if tid.strip()}
        selected = [t for t in candidates if t.title_id in wanted_ids]
        missing = wanted_ids - {t.title_id for t in selected}
        if missing:
            print(f"Warning: TitleId(s) not found in Title Hub history: {sorted(missing)}", file=sys.stderr)
    elif args.filters:
        selected = find_matching_titles(candidates, args.filters)
    else:
        pool = [t for t in candidates if t.service_config_id]
        if not pool:
            print("No titles with cloud storage identifiers (SCID) were found in Title Hub.", file=sys.stderr)
            return 1
        selected = _select_titles_interactive(pool, input_fn=input_fn)

    if not selected:
        print("No titles selected; nothing exported.")
        return 0

    return _export_selected_titles(
        client=client,
        session=session,
        selected=selected,
        out_dir=args.out_dir,
        delay=args.delay,
        no_reconstruct=args.no_reconstruct,
    )


def _run_wizard(
    *,
    client: httpx.Client,
    input_fn: Callable[[str], str],
    session_path: Path,
    delay: float = 0.2,
) -> int:
    print("============================================================")
    print("  PcGamepassSaveHarvest - Read-Only Xbox Cloud Save Export  ")
    print("============================================================")
    print("Safety: Strictly read-only (GET only). Never modifies or")
    print("        deletes your Xbox cloud saves. All tokens stay local.")
    print()

    session = _ensure_session(client=client, session_path=session_path)
    print(f"Signed in as: {session.gamertag or '<unknown>'} (XUID {session.xuid})")
    print("Loading your Xbox game history from Title Hub...")

    history = fetch_title_history(client, xuid=session.xuid or "", xsts_token=session.xsts_token)
    all_titles = sort_titles_for_display(history.titles)
    pool = [t for t in all_titles if t.service_config_id]
    if not pool:
        print("No titles with cloud storage identifiers (SCID) were found in your Title Hub history.")
        return 1

    print(f"Found {len(pool)} game(s) with cloud storage IDs (out of {len(all_titles)} total titles).\n")

    filtered = pool
    while True:
        try:
            query = input_fn(
                f"Optional search filter (e.g. 'yakuza', or press Enter to show all {len(pool)} games): "
            ).strip()
        except EOFError:
            print("Cancelled.")
            return 0
        if not query:
            filtered = pool
            break
        matches = find_matching_titles(pool, [query])
        if matches:
            filtered = matches
            break
        print(f"  No games matched {query!r}. Try another keyword or press Enter to list all.")

    selected = _select_titles_interactive(filtered, input_fn=input_fn)
    if not selected:
        print("No games selected; nothing exported.")
        return 0

    default_out = _default_output_dir()
    try:
        raw_out = input_fn(f"Export folder [{default_out.resolve()}]: ").strip()
    except EOFError:
        raw_out = ""
    cleaned_out = raw_out.strip().strip('"').strip("'")
    out_dir = Path(cleaned_out) if cleaned_out else default_out

    return _export_selected_titles(
        client=client,
        session=session,
        selected=selected,
        out_dir=out_dir,
        delay=delay,
        no_reconstruct=False,
    )


def _count_byte_exact_blobs(report_path: Path) -> tuple[int, int]:
    import json

    payload = json.loads(report_path.read_text(encoding="utf-8"))
    blobs = payload.get("blobs", [])
    exact = sum(
        1
        for b in blobs
        if b.get("reported_size") is not None and b.get("sum_atom_bytes") == b.get("reported_size")
    )
    return exact, len(blobs)


def _cmd_reconstruct(args: argparse.Namespace) -> int:
    target_dir: Path = args.title_dir
    manifest = target_dir / "export_manifest.json"
    if not manifest.exists():
        print(f"No export_manifest.json found in {target_dir}.", file=sys.stderr)
        return 1
    recon = reconstruct_from_raw(target_dir)
    wgs = export_wgs_from_raw(target_dir)
    exact, total_blobs = _count_byte_exact_blobs(recon.report_path)
    print(
        f"Reconstructed {len(recon.files)} file(s) (byte-exact: {exact}/{total_blobs} blobs) "
        f"into {recon.reconstructed_dir.resolve()}"
    )
    print(
        f"WGS layout written ({len(wgs.containers)} container(s), {wgs.atom_count} atom(s)) "
        f"into {wgs.user_wgs_dir.resolve()}"
    )
    print(f"Inspection report written to {recon.report_path.resolve()}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--session-path",
        type=Path,
        default=None,
        help=f"Path to local auth session cache (default: {default_session_path()}).",
    )
    common.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable diagnostic stderr logging (never logs raw tokens).",
    )
    common.add_argument(
        "--log-file",
        type=Path,
        default=None,
        help="Optional path to write non-secret application logs.",
    )

    parser = argparse.ArgumentParser(
        prog="xbox-save-harvest",
        description=(
            "Read-only Xbox Connected Storage cloud save downloader for Windows. "
            "Run with no arguments (or double-click the .exe) to launch the guided interactive mode."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # login
    p_login = subparsers.add_parser(
        "login",
        parents=[common],
        help="Authenticate with Microsoft/Xbox locally via Device Code (or verify cached session).",
    )
    p_login.add_argument(
        "--fresh",
        action="store_true",
        help="Ignore cached tokens and start a fresh browser Device Code sign-in.",
    )

    # list
    p_list = subparsers.add_parser(
        "list",
        parents=[common],
        help="List games discovered in your Xbox Title Hub history.",
    )
    p_list.add_argument(
        "--filter",
        dest="filters",
        action="append",
        default=None,
        help="Case-insensitive substring match against title name, PFN, SCID, or TitleId (repeatable).",
    )
    p_list.add_argument(
        "--only-with-scid",
        action="store_true",
        help="Only show titles that have a Connected Storage SCID.",
    )
    p_list.add_argument(
        "--probe-storage",
        action="store_true",
        help="Perform a read-only GET against Connected Storage for each listed title to check for saves.",
    )
    p_list.add_argument(
        "--delay",
        type=float,
        default=0.2,
        help="Polite delay in seconds between probe requests (default: 0.2).",
    )

    # export
    p_export = subparsers.add_parser(
        "export",
        parents=[common],
        help="Download raw cloud saves and reconstruct them into a local directory (strictly GET-only).",
    )
    p_export.add_argument(
        "--filter",
        dest="filters",
        action="append",
        default=None,
        help="Case-insensitive substring match for titles to export (repeatable).",
    )
    p_export.add_argument(
        "--title-id",
        dest="title_ids",
        action="append",
        default=None,
        help="Exact Xbox TitleId to export (repeatable).",
    )
    p_export.add_argument(
        "--out-dir",
        type=Path,
        default=Path("saves_output"),
        help="Destination root directory for exported saves (default: ./saves_output).",
    )
    p_export.add_argument(
        "--delay",
        type=float,
        default=0.2,
        help="Polite delay in seconds between Connected Storage GET requests (default: 0.2).",
    )
    p_export.add_argument(
        "--no-reconstruct",
        action="store_true",
        help="Only archive raw manifests and untouched binary atoms without building reconstructed/ or wgs/.",
    )

    # reconstruct
    p_recon = subparsers.add_parser(
        "reconstruct",
        parents=[common],
        help="Offline: rebuild reconstructed/, wgs/, and inspection_report.json from an existing raw export.",
    )
    p_recon.add_argument(
        "title_dir",
        type=Path,
        help="Path to an exported title folder containing export_manifest.json.",
    )

    return parser


def _pause_before_exit(input_fn: Callable[[str], str]) -> None:
    try:
        input_fn("\nPress Enter to close...")
    except (EOFError, KeyboardInterrupt):
        pass


def main(
    argv: Sequence[str] | None = None,
    *,
    client: httpx.Client | None = None,
    input_fn: Callable[[str], str] = input,
) -> int:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(errors="replace")
            except (OSError, ValueError):
                pass

    effective_argv = list(argv) if argv is not None else sys.argv[1:]
    launched_bare = len(effective_argv) == 0

    args: argparse.Namespace | None = None
    if not launched_bare:
        parser = build_parser()
        args = parser.parse_args(effective_argv)
        configure_logging(verbose=bool(args.verbose), log_file=args.log_file)
        if args.command == "reconstruct":
            try:
                return _cmd_reconstruct(args)
            except (OSError, ValueError) as exc:
                print(f"Reconstruction failed: {exc}", file=sys.stderr)
                return 1
    else:
        configure_logging(verbose=False, log_file=None)

    own_client = client is None
    http = client or httpx.Client(timeout=60.0)
    exit_code = 1
    try:
        if launched_bare:
            exit_code = _run_wizard(
                client=http,
                input_fn=input_fn,
                session_path=default_session_path(),
            )
        elif args is not None and args.command == "login":
            exit_code = _cmd_login(args, client=http)
        elif args is not None and args.command == "list":
            exit_code = _cmd_list(args, client=http)
        elif args is not None and args.command == "export":
            exit_code = _cmd_export(args, client=http, input_fn=input_fn)
        else:
            exit_code = 2
    except KeyboardInterrupt:
        print("\nCancelled by user.", file=sys.stderr)
        exit_code = 130
    except (OAuthError, XboxAuthError) as exc:
        logger.error("Authentication error: %s", exc)
        print(f"Authentication failed: {exc}", file=sys.stderr)
        exit_code = 1
    except TitleHubError as exc:
        logger.error("Title Hub error: %s", exc)
        print(f"Title Hub discovery failed: {exc}", file=sys.stderr)
        exit_code = 1
    except SaveExportError as exc:
        logger.error("Export aborted: %s", exc)
        print(f"Save export failed: {exc}", file=sys.stderr)
        exit_code = 1
    except httpx.HTTPError as exc:
        logger.error("Network error: %s", exc)
        print(f"Network error: {exc}", file=sys.stderr)
        exit_code = 1
    finally:
        if own_client:
            http.close()
        if launched_bare:
            _pause_before_exit(input_fn)

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
