# heist installer for Windows — https://github.com/iamdainwi/heist
#
# Usage (run in PowerShell):
#   irm https://raw.githubusercontent.com/iamdainwi/heist/master/install.ps1 | iex
#
# Options (set before running):
#   $env:HEIST_VERSION     — specific version to install, e.g. "v0.2.0" (default: latest)
#   $env:HEIST_INSTALL_DIR — destination directory (default: $env:LOCALAPPDATA\heist\bin)
#
# The script will:
#   1. Detect your architecture.
#   2. Download the right pre-built binary from GitHub Releases.
#   3. Verify the SHA-256 checksum.
#   4. Install the binary and add the install directory to your user PATH.

#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Helpers ───────────────────────────────────────────────────────────────────

function Write-Step  { param($msg) Write-Host "  heist: $msg" -ForegroundColor Cyan }
function Write-Ok    { param($msg) Write-Host "  [OK]   $msg" -ForegroundColor Green }
function Write-Fatal { param($msg) Write-Host "  [ERR]  $msg" -ForegroundColor Red; exit 1 }

# ── Detect architecture ───────────────────────────────────────────────────────

$Arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { 'x86_64' }
    'ARM64' { 'x86_64' }   # No ARM64 Windows build yet; fall back to x86_64 via emulation
    default { Write-Fatal "Unsupported architecture: $env:PROCESSOR_ARCHITECTURE" }
}

$OS = 'windows'

# ── Resolve version ───────────────────────────────────────────────────────────

$Repo    = 'iamdainwi/heist'
$BaseUrl = "https://github.com/$Repo/releases"

if (-not $env:HEIST_VERSION) {
    Write-Step 'Fetching latest release version...'
    try {
        $Response = Invoke-WebRequest -Uri "$BaseUrl/latest" -MaximumRedirection 0 -ErrorAction SilentlyContinue
        $Location = $Response.Headers['Location']
    } catch {
        $Location = $_.Exception.Response.Headers.Location.ToString()
    }
    if (-not $Location) { Write-Fatal 'Could not determine latest release. Set $env:HEIST_VERSION manually.' }
    $Version = $Location -replace '.*/tag/', ''
} else {
    $Version = $env:HEIST_VERSION
}

Write-Step "Installing heist $Version ($OS/$Arch)..."

# ── Build download URLs ───────────────────────────────────────────────────────

$Archive     = "heist-$OS-$Arch.zip"
$DownloadUrl = "$BaseUrl/download/$Version/$Archive"
$ChecksumUrl = "$DownloadUrl.sha256"

# ── Download ──────────────────────────────────────────────────────────────────

$Tmp = Join-Path $env:TEMP "heist-install-$([System.IO.Path]::GetRandomFileName())"
New-Item -ItemType Directory -Path $Tmp | Out-Null

$ArchivePath  = Join-Path $Tmp $Archive
$ChecksumPath = "$ArchivePath.sha256"

Write-Step "Downloading $Archive..."
try {
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $ArchivePath -UseBasicParsing
    Invoke-WebRequest -Uri $ChecksumUrl -OutFile $ChecksumPath -UseBasicParsing
} catch {
    Write-Fatal "Download failed: $_`nCheck your internet connection or try a specific HEIST_VERSION."
}

# ── Verify checksum ───────────────────────────────────────────────────────────

Write-Step 'Verifying checksum...'

$Expected = (Get-Content $ChecksumPath -Raw).Trim().Split()[0].ToLower()
$Actual   = (Get-FileHash $ArchivePath -Algorithm SHA256).Hash.ToLower()

if ($Actual -ne $Expected) {
    Write-Fatal "Checksum mismatch!`n  expected: $Expected`n  got:      $Actual`nAborting for safety."
}
Write-Ok 'Checksum verified.'

# ── Extract ───────────────────────────────────────────────────────────────────

Expand-Archive -Path $ArchivePath -DestinationPath $Tmp -Force

# ── Choose install directory ──────────────────────────────────────────────────

if ($env:HEIST_INSTALL_DIR) {
    $InstallDir = $env:HEIST_INSTALL_DIR
} else {
    $InstallDir = Join-Path $env:LOCALAPPDATA 'heist\bin'
}

if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir | Out-Null
}

# ── Install ───────────────────────────────────────────────────────────────────

$Binary = Join-Path $Tmp 'heist.exe'
if (-not (Test-Path $Binary)) {
    Write-Fatal 'Binary not found in archive. The release may be malformed.'
}

Copy-Item $Binary (Join-Path $InstallDir 'heist.exe') -Force

# ── Add to user PATH (persistent) ────────────────────────────────────────────

$CurrentPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($CurrentPath -notlike "*$InstallDir*") {
    Write-Step 'Adding install directory to user PATH...'
    [Environment]::SetEnvironmentVariable('Path', "$CurrentPath;$InstallDir", 'User')
    $env:Path += ";$InstallDir"
    Write-Ok "$InstallDir added to user PATH."
    Write-Step 'Restart your terminal for the PATH change to take effect in new sessions.'
}

# ── Verify ────────────────────────────────────────────────────────────────────

$InstalledVer = & (Join-Path $InstallDir 'heist.exe') --version 2>&1
Write-Ok "heist $InstalledVer installed to $InstallDir\heist.exe"

# ── Cleanup ───────────────────────────────────────────────────────────────────

Remove-Item -Recurse -Force $Tmp

# ── Next steps ────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "Get started:" -ForegroundColor White
Write-Host "  heist init"
Write-Host "  heist set github/token"
Write-Host "  heist get github/token"
Write-Host "  heist --help"
Write-Host ""
