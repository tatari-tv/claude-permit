#!/usr/bin/env bash
set -euo pipefail

REPO="tatari-tv/claude-permit"
BIN_NAME="claude-permit"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$OS" in
  linux)
    case "$ARCH" in
      x86_64)  SUFFIX="linux-amd64" ;;
      aarch64) SUFFIX="linux-arm64" ;;
      *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
    esac
    ;;
  darwin)
    case "$ARCH" in
      x86_64) SUFFIX="macos-x86_64" ;;
      arm64)  SUFFIX="macos-arm64" ;;
      *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
    esac
    ;;
  *) echo "Unsupported OS: $OS" >&2; exit 1 ;;
esac

LATEST=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
  | grep '"tag_name"' \
  | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')

if [ -z "$LATEST" ]; then
  echo "Failed to determine latest release" >&2
  exit 1
fi

TARBALL="${BIN_NAME}-${LATEST}-${SUFFIX}.tar.gz"
URL="https://github.com/$REPO/releases/download/$LATEST/$TARBALL"

echo "Installing $BIN_NAME $LATEST ($SUFFIX) to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

curl -fsSL "$URL" -o "$TMP/$TARBALL"
tar -xzf "$TMP/$TARBALL" -C "$TMP"
install -m 755 "$TMP/$BIN_NAME" "$INSTALL_DIR/$BIN_NAME"

echo "Installed: $INSTALL_DIR/$BIN_NAME"

if ! echo ":$PATH:" | grep -q ":$INSTALL_DIR:"; then
  echo "Note: add $INSTALL_DIR to your PATH"
  echo "  export PATH=\"\$PATH:$INSTALL_DIR\""
fi
