#!/bin/zsh
set -euo pipefail
cd "${0:A:h:h}"
CONFIGURATION="${OUTSIDE_IN_BUILD:-release}"
swift build -c "$CONFIGURATION" "$@"
APP="$PWD/dist/Outside In.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
BIN_DIR="$(swift build -c "$CONFIGURATION" --show-bin-path "$@")"
cp "$BIN_DIR/OutsideIn" "$APP/Contents/MacOS/OutsideIn"
cp Assets/OutsideIn.icns "$APP/Contents/Resources/OutsideIn.icns"
cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleName</key><string>Outside In</string>
<key>CFBundleDisplayName</key><string>Outside In</string>
<key>CFBundleIdentifier</key><string>local.outsidein.app</string>
<key>CFBundleExecutable</key><string>OutsideIn</string>
<key>CFBundleIconFile</key><string>OutsideIn</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.2.0</string>
<key>CFBundleVersion</key><string>3</string>
<key>LSMinimumSystemVersion</key><string>14.0</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
codesign --force --sign - "$APP"
print "Built: $APP"
