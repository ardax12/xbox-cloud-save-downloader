<#
.SYNOPSIS
    Build the standalone Windows executable for PcGamepassSaveHarvest (no Python required).

.DESCRIPTION
    Produces two release files in dist\release\:
      1. xbox-save-harvest.exe   (single-file double-clickable Windows executable)
      2. SHA256SUMS.txt          (SHA-256 verification checksum)
#>
[CmdletBinding()]
param(
    [string]$PythonExe = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $RepoRoot

try {
    if (-not $PythonExe) {
        $VenvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"
        $PythonExe = if (Test-Path $VenvPython) { $VenvPython } else { "python" }
    }

    Write-Host "Using Python: $PythonExe"
    & $PythonExe --version

    foreach ($dir in @("build", "dist")) {
        $full = Join-Path $RepoRoot $dir
        if (Test-Path $full) {
            Remove-Item -Recurse -Force $full
        }
    }

    $ReleaseDir = Join-Path $RepoRoot "dist\release"
    New-Item -ItemType Directory -Force -Path $ReleaseDir | Out-Null

    Write-Host "`n=== Building standalone xbox-save-harvest.exe ==="
    & $PythonExe -m PyInstaller `
        --noconfirm `
        --clean `
        --onefile `
        --console `
        --name "xbox-save-harvest" `
        --paths "src" `
        --collect-data "certifi" `
        --collect-submodules "cryptography" `
        --hidden-import "xbox_save_harvest.cli" `
        --distpath $ReleaseDir `
        --workpath "build\pyinstaller" `
        --specpath "build\spec" `
        "src\xbox_save_harvest\__main__.py"
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller build failed with exit code $LASTEXITCODE" }

    $ExePath = Join-Path $ReleaseDir "xbox-save-harvest.exe"
    Write-Host "`n=== Smoke testing xbox-save-harvest.exe ==="
    & $ExePath --help
    if ($LASTEXITCODE -ne 0) { throw "Smoke test failed for $ExePath" }

    $Hash = (Get-FileHash -Path $ExePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $ChecksumPath = Join-Path $ReleaseDir "SHA256SUMS.txt"
    Set-Content -Path $ChecksumPath -Value "$Hash  xbox-save-harvest.exe" -Encoding ascii

    Write-Host "`n=== Release Artifacts Ready ==="
    Get-ChildItem -Path $ReleaseDir -File | Format-Table Name, Length -AutoSize
    Get-Content $ChecksumPath
}
finally {
    Pop-Location
}
