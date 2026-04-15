#!/bin/sh
# onyx installer — detects platform, downloads the right binary from the
# latest GitHub release, and installs to /usr/local/bin.
set -e
umask 077

REPO="shervin9/onyx"
INSTALL_DIR="/usr/local/bin"
BIN="onyx"
SERVER_X86_ARTIFACT="onyx-server-linux-x86_64"
SERVER_ARM_ARTIFACT="onyx-server-linux-arm64"

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
TMP_SERVER_X86=$(mktemp "/tmp/${SERVER_X86_ARTIFACT}.XXXXXX")
TMP_SERVER_ARM=$(mktemp "/tmp/${SERVER_ARM_ARTIFACT}.XXXXXX")
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
curl -fsSL "https://github.com/$REPO/releases/download/$LATEST/$SERVER_X86_ARTIFACT" -o "$TMP_SERVER_X86"
curl -fsSL "https://github.com/$REPO/releases/download/$LATEST/$SERVER_ARM_ARTIFACT" -o "$TMP_SERVER_ARM"
curl -fsSL "$SUMS_URL" -o "$TMP_SUMS"

EXPECTED=$(grep " $ARTIFACT\$" "$TMP_SUMS" | awk '{print $1}')
if [ -z "$EXPECTED" ]; then
  echo "onyx: checksum for $ARTIFACT not found in release" >&2
  rm -f "$TMP_BIN" "$TMP_SERVER_X86" "$TMP_SERVER_ARM" "$TMP_SUMS"
  exit 1
fi

ACTUAL=$(sha256_file "$TMP_BIN")
if [ "$EXPECTED" != "$ACTUAL" ]; then
  echo "onyx: checksum verification failed for $ARTIFACT" >&2
  rm -f "$TMP_BIN" "$TMP_SERVER_X86" "$TMP_SERVER_ARM" "$TMP_SUMS"
  exit 1
fi

EXPECTED_SERVER_X86=$(grep " $SERVER_X86_ARTIFACT\$" "$TMP_SUMS" | awk '{print $1}')
EXPECTED_SERVER_ARM=$(grep " $SERVER_ARM_ARTIFACT\$" "$TMP_SUMS" | awk '{print $1}')
if [ -z "$EXPECTED_SERVER_X86" ] || [ -z "$EXPECTED_SERVER_ARM" ]; then
  echo "onyx: checksum for companion onyx-server binaries not found in release" >&2
  rm -f "$TMP_BIN" "$TMP_SERVER_X86" "$TMP_SERVER_ARM" "$TMP_SUMS"
  exit 1
fi

ACTUAL_SERVER_X86=$(sha256_file "$TMP_SERVER_X86")
ACTUAL_SERVER_ARM=$(sha256_file "$TMP_SERVER_ARM")
if [ "$EXPECTED_SERVER_X86" != "$ACTUAL_SERVER_X86" ] || [ "$EXPECTED_SERVER_ARM" != "$ACTUAL_SERVER_ARM" ]; then
  echo "onyx: checksum verification failed for companion onyx-server binaries" >&2
  rm -f "$TMP_BIN" "$TMP_SERVER_X86" "$TMP_SERVER_ARM" "$TMP_SUMS"
  exit 1
fi

chmod +x "$TMP_BIN"
chmod +x "$TMP_SERVER_X86" "$TMP_SERVER_ARM"
rm -f "$TMP_SUMS"

# Install — try sudo if the target directory isn't writable directly.
if [ -w "$INSTALL_DIR" ]; then
  mv "$TMP_BIN" "$INSTALL_DIR/$BIN"
  mv "$TMP_SERVER_X86" "$INSTALL_DIR/$SERVER_X86_ARTIFACT"
  mv "$TMP_SERVER_ARM" "$INSTALL_DIR/$SERVER_ARM_ARTIFACT"
else
  sudo mv "$TMP_BIN" "$INSTALL_DIR/$BIN"
  sudo mv "$TMP_SERVER_X86" "$INSTALL_DIR/$SERVER_X86_ARTIFACT"
  sudo mv "$TMP_SERVER_ARM" "$INSTALL_DIR/$SERVER_ARM_ARTIFACT"
fi

echo "onyx installed to $INSTALL_DIR/$BIN"
echo "Run: onyx user@host"
