#!/usr/bin/env sh
# heist installer — https://github.com/iamdainwi/heist
#
# Usage (pick one):
#   curl  -fsSL https://raw.githubusercontent.com/iamdainwi/heist/master/install.sh | sh
#   wget  -qO-  https://raw.githubusercontent.com/iamdainwi/heist/master/install.sh | sh
#
# Options (set as env vars before piping):
#   HEIST_VERSION   — install a specific version, e.g. v0.2.0 (default: latest)
#   HEIST_INSTALL_DIR — destination directory (default: /usr/local/bin, falls back to ~/.local/bin)
#
# The script will:
#   1. Detect your OS and architecture.
#   2. Download the right pre-built binary from GitHub Releases.
#   3. Verify the SHA-256 checksum.
#   4. Install the binary to your PATH.

set -eu

# ── Helpers ───────────────────────────────────────────────────────────────────

say()  { printf '\033[1m  heist:\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m  ✓\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31m  ✗\033[0m %s\n' "$*" >&2; exit 1; }
need() {
    command -v "$1" >/dev/null 2>&1 || err "Required tool not found: $1. Please install it and retry."
}

# ── Dependency check ──────────────────────────────────────────────────────────

need curl
need tar

# ── Detect OS ─────────────────────────────────────────────────────────────────

OS="$(uname -s)"
case "$OS" in
    Linux)  OS=linux  ;;
    Darwin) OS=macos  ;;
    *)      err "Unsupported operating system: $OS. Please build from source." ;;
esac

# ── Detect architecture ───────────────────────────────────────────────────────

ARCH="$(uname -m)"
case "$ARCH" in
    x86_64 | amd64)         ARCH=x86_64  ;;
    aarch64 | arm64)        ARCH=aarch64 ;;
    *)  err "Unsupported architecture: $ARCH. Please build from source." ;;
esac

# ── Resolve version ───────────────────────────────────────────────────────────

REPO="iamdainwi/heist"
BASE_URL="https://github.com/${REPO}/releases"

if [ -z "${HEIST_VERSION:-}" ]; then
    say "Fetching latest release version..."
    # Follow redirects on the /latest page and extract the version tag from the final URL.
    HEIST_VERSION="$(
        curl -fsSL --head "${BASE_URL}/latest" \
            | grep -i '^location:' \
            | sed 's|.*/tag/||' \
            | tr -d '[:space:]'
    )"
    [ -n "$HEIST_VERSION" ] || err "Could not determine the latest release version. Try setting HEIST_VERSION manually."
fi

say "Installing heist ${HEIST_VERSION} (${OS}/${ARCH})..."

# ── Build download URLs ───────────────────────────────────────────────────────

ARCHIVE="heist-${OS}-${ARCH}.tar.gz"
DOWNLOAD_URL="${BASE_URL}/download/${HEIST_VERSION}/${ARCHIVE}"
CHECKSUM_URL="${DOWNLOAD_URL}.sha256"

# ── Download ──────────────────────────────────────────────────────────────────

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

say "Downloading ${ARCHIVE}..."
curl -fsSL --progress-bar -o "${TMP}/${ARCHIVE}"        "$DOWNLOAD_URL" \
    || err "Download failed. Check your internet connection or try a specific HEIST_VERSION."
curl -fsSL                  -o "${TMP}/${ARCHIVE}.sha256" "$CHECKSUM_URL" \
    || err "Checksum download failed."

# ── Verify checksum ───────────────────────────────────────────────────────────

say "Verifying checksum..."
EXPECTED="$(awk '{print $1}' "${TMP}/${ARCHIVE}.sha256")"

if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL="$(sha256sum "${TMP}/${ARCHIVE}" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
    ACTUAL="$(shasum -a 256 "${TMP}/${ARCHIVE}" | awk '{print $1}')"
else
    err "No SHA-256 tool found (sha256sum or shasum). Cannot verify download integrity."
fi

[ "$ACTUAL" = "$EXPECTED" ] \
    || err "Checksum mismatch!\n  expected: $EXPECTED\n  got:      $ACTUAL\nAborting for safety."

ok "Checksum verified."

# ── Extract ───────────────────────────────────────────────────────────────────

tar -xzf "${TMP}/${ARCHIVE}" -C "$TMP"

# ── Choose install directory ──────────────────────────────────────────────────

if [ -n "${HEIST_INSTALL_DIR:-}" ]; then
    INSTALL_DIR="$HEIST_INSTALL_DIR"
elif [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
    INSTALL_DIR=/usr/local/bin
elif [ "$(id -u)" -eq 0 ]; then
    # Running as root but /usr/local/bin doesn't exist — create it.
    mkdir -p /usr/local/bin
    INSTALL_DIR=/usr/local/bin
else
    # Fallback: user-local bin (no sudo required).
    INSTALL_DIR="${HOME}/.local/bin"
    mkdir -p "$INSTALL_DIR"
fi

# ── Install ───────────────────────────────────────────────────────────────────

BINARY="${TMP}/heist"
[ -f "$BINARY" ] || err "Binary not found in archive. The release may be malformed."

chmod +x "$BINARY"

# If we can't write to the install dir directly, try sudo.
if [ -w "$INSTALL_DIR" ]; then
    mv "$BINARY" "${INSTALL_DIR}/heist"
else
    say "Writing to ${INSTALL_DIR} requires elevated privileges..."
    sudo mv "$BINARY" "${INSTALL_DIR}/heist"
fi

# ── Verify the installed binary ───────────────────────────────────────────────

INSTALLED_VERSION="$("${INSTALL_DIR}/heist" --version 2>&1 | awk '{print $2}')"

ok "heist ${INSTALLED_VERSION} installed to ${INSTALL_DIR}/heist"

# ── PATH check ────────────────────────────────────────────────────────────────

case ":${PATH}:" in
    *":${INSTALL_DIR}:"*) : ;;   # already on PATH — nothing to do
    *)
        echo ""
        say "NOTE: ${INSTALL_DIR} is not in your PATH."
        say "Add the following line to your shell profile (~/.bashrc, ~/.zshrc, etc.):"
        echo ""
        printf '    export PATH="%s:$PATH"\n' "${INSTALL_DIR}"
        echo ""
        say "Then restart your shell or run:  source ~/.bashrc"
        ;;
esac

echo ""
printf '\033[1mGet started:\033[0m\n'
printf '  heist init\n'
printf '  heist set github/token\n'
printf '  heist get github/token\n'
printf '  heist --help\n'
echo ""
