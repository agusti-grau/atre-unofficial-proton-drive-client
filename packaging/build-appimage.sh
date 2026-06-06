#!/bin/bash
set -euo pipefail
# Build AppImage for Proton Drive
# Requires: linuxdeploy and linuxdeploy-plugin-qt

APP=proton-drive
VERSION=${1:-$(git describe --tags --always 2>/dev/null || echo "0.1.0")}
ARCH=x86_64

echo "Building Proton Drive AppImage version $VERSION"

# Build release binaries
cargo build --release --workspace --exclude proton-gui
cargo build --release -p proton-gui

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
cp packaging/proton-drive.desktop "$APPDIR/usr/share/applications/"
# Rename desktop file for AppImage conventions
cp packaging/proton-drive.desktop "$APPDIR/com.proton.drive.desktop"
cp packaging/icons/proton-drive.svg "$APPDIR/usr/share/icons/hicolor/scalable/apps/"

# Create symlinks for AppImage
ln -sf usr/bin/proton-gui "$APPDIR/AppRun"
ln -sf usr/share/applications/com.proton.drive.desktop "$APPDIR/com.proton.drive.desktop"
ln -sf usr/share/icons/hicolor/scalable/apps/proton-drive.svg "$APPDIR/proton-drive.svg"

# Run linuxdeploy
wget -q -c "https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage"
chmod +x linuxdeploy-x86_64.AppImage
./linuxdeploy-x86_64.AppImage --appdir "$APPDIR" --output appimage

echo "Done: ProtonDrive-$VERSION-$ARCH.AppImage"
