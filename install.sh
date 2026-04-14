#!/bin/sh
# onyx installer — detects platform, downloads the right binary from the
# latest GitHub release, and installs to /usr/local/bin.
set -e

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

echo "Installing onyx $LATEST ($ARTIFACT)..."
curl -fsSL "$URL" -o "/tmp/$BIN"
chmod +x "/tmp/$BIN"

# Install — try sudo if the target directory isn't writable directly.
if [ -w "$INSTALL_DIR" ]; then
  mv "/tmp/$BIN" "$INSTALL_DIR/$BIN"
else
  sudo mv "/tmp/$BIN" "$INSTALL_DIR/$BIN"
fi

echo "onyx installed to $INSTALL_DIR/$BIN"
echo "Run: onyx user@host"
