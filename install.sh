#!/bin/sh
# onyx installer — detects platform, downloads the right binary from the
# latest GitHub release, and installs to /usr/local/bin.
set -e
umask 077

REPO="shervin9/onyx"
INSTALL_DIR="/usr/local/bin"
BIN="onyx"

# ── Detect platform ──────────────────────────────────────────────────────────
OS=$(uname -s)
ARCH=$(uname -m)

case "$OS-$ARCH" in
  Linux-x86_64)   ARTIFACT="onyx-linux-x86_64" ;;
  Linux-aarch64)  ARTIFACT="onyx-linux-arm64"  ;;
  Darwin-arm64)   ARTIFACT="onyx-macos-arm64"  ;;
  *)
    echo "onyx: unsupported platform $OS-$ARCH" >&2
    echo "Please build from source: https://github.com/$REPO" >&2
    exit 1 ;;
esac

# ── Fetch latest release tag ──────────────────────────────────────────────────
LATEST=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
  | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')

if [ -z "$LATEST" ]; then
  echo "onyx: could not determine latest release" >&2
  exit 1
fi

URL="https://github.com/$REPO/releases/download/$LATEST/$ARTIFACT"
SUMS_URL="https://github.com/$REPO/releases/download/$LATEST/onyx-sha256sums.txt"
TMP_BIN=$(mktemp "/tmp/${BIN}.XXXXXX")
TMP_SUMS=$(mktemp "/tmp/${BIN}-sha256sums.XXXXXX")

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

echo "Installing onyx $LATEST ($ARTIFACT)..."
curl -fsSL "$URL" -o "$TMP_BIN"
curl -fsSL "$SUMS_URL" -o "$TMP_SUMS"

EXPECTED=$(grep " $ARTIFACT\$" "$TMP_SUMS" | awk '{print $1}')
if [ -z "$EXPECTED" ]; then
  echo "onyx: checksum for $ARTIFACT not found in release" >&2
  rm -f "$TMP_BIN" "$TMP_SUMS"
  exit 1
fi

ACTUAL=$(sha256_file "$TMP_BIN")
if [ "$EXPECTED" != "$ACTUAL" ]; then
  echo "onyx: checksum verification failed for $ARTIFACT" >&2
  rm -f "$TMP_BIN" "$TMP_SUMS"
  exit 1
fi

chmod +x "$TMP_BIN"
rm -f "$TMP_SUMS"

# Install — try sudo if the target directory isn't writable directly.
if [ -w "$INSTALL_DIR" ]; then
  mv "$TMP_BIN" "$INSTALL_DIR/$BIN"
else
  sudo mv "$TMP_BIN" "$INSTALL_DIR/$BIN"
fi

echo "onyx installed to $INSTALL_DIR/$BIN"
echo "Run: onyx user@host"
