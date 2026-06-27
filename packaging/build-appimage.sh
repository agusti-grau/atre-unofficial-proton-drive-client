#!/bin/bash
set -euo pipefail
# Build AppImage for Proton Drive
# Requires: linuxdeploy, GTK3, and libappindicator3/ayatana-appindicator3 for tray support

APP=proton-drive
VERSION=${1:-$(git describe --tags --always 2>/dev/null || echo "0.1.0")}
ARCH=x86_64

echo "Building Proton Drive AppImage version $VERSION"

# Build release binaries (tray enabled for GUI)
cargo build --release --workspace --exclude proton-gui
cargo build --release -p proton-gui --features tray

# Create AppDir structure
APPDIR="build/ProtonDrive-$VERSION-$ARCH.AppDir"
mkdir -p "$APPDIR/usr/bin"
mkdir -p "$APPDIR/usr/share/applications"
mkdir -p "$APPDIR/usr/share/icons/hicolor/scalable/apps"

# Copy binaries
cp target/release/protond "$APPDIR/usr/bin/"
cp target/release/proton-drive "$APPDIR/usr/bin/"
cp target/release/proton-gui "$APPDIR/usr/bin/"

# Copy desktop file and icon
cp packaging/proton-drive.desktop "$APPDIR/usr/share/applications/com.proton.drive.desktop"
cp packaging/icons/proton-drive.svg "$APPDIR/usr/share/icons/hicolor/scalable/apps/"

# Create symlinks for AppImage
ln -sf usr/bin/proton-gui "$APPDIR/AppRun"
ln -sf usr/share/applications/com.proton.drive.desktop "$APPDIR/com.proton.drive.desktop"
ln -sf usr/share/icons/hicolor/scalable/apps/proton-drive.svg "$APPDIR/proton-drive.svg"

# Fetch and verify linuxdeploy
LINUXDEPLOY_URL="https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage"
LINUXDEPLOY_FILE="linuxdeploy-x86_64.AppImage"
LINUXDEPLOY_SHA256="${LINUXDEPLOY_SHA256:-}"

if [[ ! -x "$LINUXDEPLOY_FILE" ]]; then
    wget -q -c "$LINUXDEPLOY_URL" -O "$LINUXDEPLOY_FILE"
fi

if [[ -n "$LINUXDEPLOY_SHA256" ]]; then
    echo "$LINUXDEPLOY_SHA256  $LINUXDEPLOY_FILE" | sha256sum -c -
fi

chmod +x "$LINUXDEPLOY_FILE"
./"$LINUXDEPLOY_FILE" --appdir "$APPDIR" --output appimage

echo "Done: ProtonDrive-$VERSION-$ARCH.AppImage"
