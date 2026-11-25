# xbox-cloud-save-downloader

A standalone, strictly **read-only** Windows tool that downloads **your own** Xbox PC / PC Game Pass cloud saves directly from Xbox Connected Storage (`titlestorage.xboxlive.com`) — even if the game is no longer installed or your Game Pass subscription has ended.

---

## How to Use

### Option 1: Double-Click the `.exe` (No Python Required)

1. Download **`xbox-save-harvest.exe`** from the latest **GitHub Release**.
2. **Double-click `xbox-save-harvest.exe`** to open the guided interactive exporter.
3. Follow the prompts:
   - **Sign in:** Open `https://www.microsoft.com/link` in your browser and enter the short code shown in the window. Your password is **never** entered into this app.
   - **Find your game(s):** Type part of a game name (for example `yakuza`) or press Enter to list your Xbox history, then enter one or more numbers (e.g. `1`, `1,2`, `1-3`, or `all`).
   - **Choose where to save:** Press Enter to export into `saves_output\` next to the `.exe`, or type a custom folder path.
4. When finished, your raw cloud backup and organized save files will be inside `<out-dir>\<Game Name>__<TitleId>\`.

### Option 2: CLI Commands (PowerShell / Terminal)

You can also run `xbox-save-harvest.exe` with subcommands instead of the guided wizard:

```powershell
# Sign in or verify your cached session
xbox-save-harvest.exe login

# List games in your Xbox history (--probe-storage checks which ones have cloud saves)
xbox-save-harvest.exe list --filter "yakuza" --probe-storage

# Export saves interactively, by title filter, or by TitleId
xbox-save-harvest.exe export --out-dir .\saves_output
xbox-save-harvest.exe export --filter "Yakuza: Like a Dragon" --filter "Yakuza 6" --out-dir .\saves_output
xbox-save-harvest.exe export --title-id 1791400679 --out-dir .\saves_output

# Offline re-inspection / reconstruction from an existing raw export folder
xbox-save-harvest.exe reconstruct ".\saves_output\Yakuza_ Like a Dragon__1791400679"
```

### Export Folder Layout

Each exported game gets its own folder:

```text
<TitleName>__<TitleId>/
├── title_metadata.json     # Title Hub metadata (TitleId, SCID, PFN, devices, lastPlayed)
├── blobs.json              # Raw Connected Storage blob list
├── manifests/              # Raw per-blob atom manifests + response headers
├── raw_atoms/              # Untouched raw binary save atoms (<GUID>.bin)
├── export_manifest.json    # Export index with SHA-256 digests and sizes
├── reconstructed/          # Human-readable lossless copy organized by save path + atom name
├── inspection_report.json  # Magic-byte classification, SHA-256, and byte-exact size checks
└── wgs/                    # Standard Windows Gaming Services layout (containers.index + container.1 + atoms)
```

### Using Exported Saves

Always keep `raw_atoms/` and `manifests/` as your untouched backup, and work from **copies** of either `reconstructed/` or `wgs/`:

- **Human-browsable files (`reconstructed/`):** Mirrors Microsoft's exact container → atom structure (each save container becomes a folder holding its named payload atom(s), such as a single file, a save + thumbnail, or numbered chunks for large saves). For games whose save format is identical across stores, copy the save payload out of `reconstructed/` and rename it to match your target game's save filename.
- **Game Pass save tool compatibility (`wgs/`):** Mirrors the exact binary format Windows Gaming Services writes under `SystemAppData\wgs\` (`<XUID>_<SCID>\containers.index`, `container.1`, and hex-named atom files). You can feed `wgs/` into third-party Game Pass → Steam converters (such as `XGP-save-extractor`, `XgpSaveTools`, or game-specific tools) for titles that split saves into chunks or add Xbox-specific headers/footers.

---

## How It Works

Normally, the Xbox PC app only syncs cloud saves when you install and launch a game — and it blocks you from installing or launching games once your Game Pass subscription expires or a title leaves the catalog. However, Microsoft still keeps **your own** cloud save data stored on Xbox Connected Storage tied to your Xbox Live account.

This tool talks directly to the same official Xbox Live HTTPS endpoints in four read-only steps:

1. **Authenticate locally (OAuth Device Code + Proof-of-Possession Device Token)**
   - Uses Microsoft's standard OAuth 2.0 Device Code flow (`login.live.com`) so you sign in on Microsoft's own website.
   - Generates a local ECDSA P-256 keypair and signs requests to `device.auth.xboxlive.com`, `user.auth.xboxlive.com`, and `xsts.auth.xboxlive.com` to obtain an `XSTS` token bound to a `DeviceToken`. *(Standard user-only XSTS tokens are rejected by Connected Storage with `HTTP 403`; a Proof-of-Possession `DeviceToken` is what makes read access work without scraping Windows Credential Manager.)*
2. **Discover your games dynamically (Title Hub)**
   - Calls `GET https://titlehub.xboxlive.com/users/xuid({xuid})/titles/titlehistory/...` to fetch your play history and resolve each game's `TitleId`, Service Configuration ID (`SCID`), and `PackageFamilyName` (`PFN`) — no hardcoded game lists required.
3. **Read cloud save containers and atoms (Connected Storage — `GET` only)**
   - Lists your save containers: `GET https://titlestorage.xboxlive.com/connectedstorage/users/xuid({xuid})/scids/{scid}`
   - Fetches each container's atom map: `GET .../scids/{scid}/{encoded_fileName}`
   - Downloads each raw binary save atom: `GET .../scids/{scid}/{atom_id}` (e.g. `<GUID>,binary`)
   - Sends `x-xbl-contract-version: 107` and `x-xbl-pfn: <PFN>` with your `XBL3.0` authorization header.
4. **Preserve raw data first, then emit `reconstructed/` and `wgs/` losslessly**
   - Writes the untouched cloud JSON manifests and exact binary atom bytes to disk first, records SHA-256 hashes, checks `sum(atom_sizes) == blob.size` in the report, and builds both a human-readable `reconstructed/` tree and a standard Windows Gaming Services `wgs/` folder offline.

---

## Safety & Scope

- **Strictly read-only on Xbox Connected Storage:** Only HTTP `GET` requests exist in the storage client. No uploads, deletions, overwrites, or lock mutations (`PUT`/`POST`/`PATCH`/`DELETE`, `AssignLock`, `ReleaseLock`, `DeleteAtomAsync`) are implemented.
- **Local-only credentials:** Tokens stay on your PC at `%LOCALAPPDATA%\PcGamepassSaveHarvest\session.json` and are redacted in all CLI output and logs.
- **Fail-fast protection:** Batch downloads immediately stop on `HTTP 401`, `HTTP 403`, or `HTTP 429` rather than retrying aggressively.
- **Out of scope:** Save format conversion, game-specific decryption/re-encryption, cloud uploads, launching games, registry modifications, or accessing anyone else's account.

---

## FAQ

**Can I download PC Game Pass saves after my subscription expires or a game leaves Game Pass?**  
Yes. Microsoft continues storing your cloud saves on Xbox Connected Storage even when you no longer have an active Game Pass subscription or store entitlement to install the game.

**Do I need the game installed to extract my Xbox cloud saves?**  
No. Saves are downloaded directly from Microsoft's cloud (`titlestorage.xboxlive.com`), so you never have to re-download 50–100+ GB just to trigger a local Xbox app sync.

**How do I transfer downloaded Game Pass saves to Steam?**  
Every export writes both a human-readable `reconstructed/` folder and a standard Windows Gaming Services `wgs/` folder (`containers.index` + `container.1` + raw atom files). For games with identical PC save formats, copy and rename the payload from `reconstructed/`; for games that split saves into chunks or embed Xbox headers/footers (such as Starfield or Yakuza/Like a Dragon), pass the exported `wgs/` folder into a community Game Pass → Steam converter like `XGP-save-extractor` or `XgpSaveTools`.

**Does this work for Xbox Play Anywhere / console saves?**  
Any game in your Xbox Title Hub history that stores saves in Xbox Connected Storage (PC Game Pass, Microsoft Store, and Play Anywhere titles) can be discovered and downloaded. Games that use a publisher's own cloud servers instead of Xbox Connected Storage will show no Connected Storage blobs.

**Is this safe for my Xbox account?**  
The storage client is strictly read-only (`GET` only — no write, delete, or lock-breaking requests exist in the codebase). You sign in directly on `https://www.microsoft.com/link` (never typing your password into this app), tokens remain local on your PC, and GitHub Releases are compiled automatically by GitHub Actions from the exact source in this repository.

---

## Building From Source

Requires Windows 10/11 and Python 3.12+:

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install -e ".[build]"

# Run directly from source
.venv\Scripts\xbox-save-harvest.exe --help

# Build standalone dist\release\xbox-save-harvest.exe + SHA256SUMS.txt
.\scripts\build_exe.ps1
```

Pushing a version tag (e.g. `git tag v0.1.0 && git push origin v0.1.0`) triggers [`.github/workflows/release.yml`](.github/workflows/release.yml) to build `xbox-save-harvest.exe` + `SHA256SUMS.txt` on `windows-latest` and publish a GitHub Release automatically.

---

## References

This project was written from scratch in Python using protocol findings and prior research from the following open-source repositories:

- **[billynothingelse/xbcsmgr](https://github.com/billynothingelse/xbcsmgr)** *(archived .NET 7 project)* — Key reference for Xbox Connected Storage (`titlestorage.xboxlive.com`) endpoints, `x-xbl-contract-version: 107`, `x-xbl-pfn` headers, and Title Hub (`titlehub.xboxlive.com`) discovery. Unlike `xbcsmgr`, this tool uses pure interactive OAuth instead of scraping Windows Credential Manager, preserves `Win32` titles during discovery, and strictly omits all lock/write/delete operations.
- **[AlphaBs/XboxAuthNet](https://github.com/AlphaBs/XboxAuthNet)** *(MIT .NET library)* — Reference for Microsoft OAuth Device Code authentication, ECDSA P-256 Proof-of-Possession request signing (`Signature` header with Windows FILETIME + raw 64-byte IEEE P1363 `r || s`), and the Xbox Device Token → User Token → XSTS authorization flow.
- **[vinifreitaspaulino/mc-xbox-dl](https://github.com/vinifreitaspaulino/mc-xbox-dl)** *(Python Connected Storage tool)* — Reference for Python Connected Storage API behavior, error-code semantics (`HTTP 403 code 2011` vs `HTTP 404 code 2005`), and raw atom downloads.
