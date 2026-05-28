#!/bin/zsh
set -euo pipefail

TEAM_ID="${TEAM_ID:-6JYK2B5HZ3}"
SIGNING_IDENTITY_NAME="${SIGNING_IDENTITY_NAME:-Developer ID Application: RUXU WU ($TEAM_ID)}"
SCHEME="${SCHEME:-WireGuardmacOS}"
PROJECT="${PROJECT:-WireGuard.xcodeproj}"
CONFIGURATION="${CONFIGURATION:-Release}"
APP_NAME="${APP_NAME:-WireGuard}"
VOLUME_NAME="${VOLUME_NAME:-wgx}"
NOTARY_PROFILE="${NOTARY_PROFILE:-}"

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$ROOT_DIR/build/release"
VERSION_CONFIG="$ROOT_DIR/Sources/WireGuardApp/Config/Version.xcconfig"
ARCHIVE_PATH="$BUILD_DIR/$APP_NAME.xcarchive"
EXPORT_PATH="$BUILD_DIR/export"
DMG_STAGE="$BUILD_DIR/dmg-stage"
DMG_UNSIGNED_PATH="$BUILD_DIR/$VOLUME_NAME-unsigned.dmg"
DMG_RW_PATH="$BUILD_DIR/$VOLUME_NAME-rw.dmg"
DMG_PATH="$BUILD_DIR/$VOLUME_NAME.dmg"
EXPORT_OPTIONS="$BUILD_DIR/exportOptions-developer-id.plist"
DMG_WINDOW_WIDTH=720
DMG_WINDOW_HEIGHT=440
DMG_ICON_SIZE=128
DMG_APP_ICON_X=205
DMG_APP_ICON_Y=215
DMG_APPLICATIONS_ICON_X=515
DMG_APPLICATIONS_ICON_Y=215

mkdir -p "$BUILD_DIR"

require_signing_identity() {
  if ! security find-identity -v -p codesigning | grep -F "$SIGNING_IDENTITY_NAME" >/dev/null; then
    echo "Unable to find a valid code-signing identity: $SIGNING_IDENTITY_NAME" >&2
    echo "Install the Developer ID Application certificate with its private key in the keychain used by xcodebuild." >&2
    exit 1
  fi
}

verify_signed_bundle() {
  local bundle_path="$1"
  local system_extension_path="$bundle_path/Contents/Library/SystemExtensions/com.github.wuruxu.wgx.network-extension.systemextension"
  local login_item_path="$bundle_path/Contents/Library/LoginItems/WireGuardLoginItemHelper.app"

  codesign --verify --deep --strict --verbose=4 "$bundle_path"
  codesign --verify --strict --verbose=4 "$system_extension_path"
  codesign --verify --strict --verbose=4 "$login_item_path"
}

require_signing_identity

if [[ -d "/Volumes/$VOLUME_NAME" ]]; then
  hdiutil detach "/Volumes/$VOLUME_NAME" -quiet || true
fi

if [[ ! -f "$VERSION_CONFIG" ]]; then
  echo "Unable to find version config at $VERSION_CONFIG" >&2
  exit 1
fi

CURRENT_VERSION_ID="$(awk -F= '/^[[:space:]]*VERSION_ID[[:space:]]*=/ { gsub(/[[:space:]]/, "", $2); print $2; exit }' "$VERSION_CONFIG")"
if [[ -z "$CURRENT_VERSION_ID" || ! "$CURRENT_VERSION_ID" =~ '^[0-9]+$' ]]; then
  echo "Unable to read numeric VERSION_ID from $VERSION_CONFIG" >&2
  exit 1
fi

NEXT_VERSION_ID="$((CURRENT_VERSION_ID + 1))"
NEXT_VERSION_ID="$NEXT_VERSION_ID" perl -0pi -e 's/(^VERSION_ID[[:space:]]*=[[:space:]]*)\d+/$1$ENV{NEXT_VERSION_ID}/m' "$VERSION_CONFIG"
echo "Bumped VERSION_ID: $CURRENT_VERSION_ID -> $NEXT_VERSION_ID"

cat > "$EXPORT_OPTIONS" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>method</key>
	<string>developer-id</string>
	<key>teamID</key>
	<string>$TEAM_ID</string>
	<key>signingStyle</key>
	<string>manual</string>
	<key>signingCertificate</key>
	<string>$SIGNING_IDENTITY_NAME</string>
	<key>stripSwiftSymbols</key>
	<true/>
	<key>provisioningProfiles</key>
	<dict>
		<key>com.github.wuruxu.wgx</key>
		<string>com.github.wuruxu.wgx</string>
		<key>com.github.wuruxu.wgx.network-extension</key>
		<string>com.github.wuruxu.wgx.network-extension</string>
	</dict>
</dict>
</plist>
PLIST

xcodebuild \
  -project "$PROJECT" \
  -scheme "$SCHEME" \
  -configuration "$CONFIGURATION" \
  -destination "generic/platform=macOS" \
  -archivePath "$ARCHIVE_PATH" \
  -derivedDataPath "$BUILD_DIR/DerivedData" \
  -allowProvisioningUpdates \
  clean archive

rm -rf "$EXPORT_PATH" "$DMG_STAGE" "$DMG_UNSIGNED_PATH" "$DMG_RW_PATH" "$DMG_PATH"
mkdir -p "$EXPORT_PATH" "$DMG_STAGE"

xcodebuild \
  -exportArchive \
  -archivePath "$ARCHIVE_PATH" \
  -exportPath "$EXPORT_PATH" \
  -exportOptionsPlist "$EXPORT_OPTIONS" \
  -allowProvisioningUpdates

APP_PATH="$EXPORT_PATH/$APP_NAME.app"
if [[ ! -d "$APP_PATH" ]]; then
  echo "Unable to find exported app at $APP_PATH" >&2
  exit 1
fi

verify_signed_bundle "$APP_PATH"

ditto "$APP_PATH" "$DMG_STAGE/$APP_NAME.app"
ln -s /Applications "$DMG_STAGE/Applications"

hdiutil create \
  -volname "$VOLUME_NAME" \
  -srcfolder "$DMG_STAGE" \
  -ov \
  -format UDRW \
  "$DMG_RW_PATH"

MOUNT_OUTPUT="$(hdiutil attach "$DMG_RW_PATH" -readwrite -noverify -noautoopen)"
DEVICE="$(printf "%s\n" "$MOUNT_OUTPUT" | awk '/\/Volumes\// { print $1; exit }')"
VOLUME_PATH="$(printf "%s\n" "$MOUNT_OUTPUT" | sed -n 's#^.*\(/Volumes/.*\)$#\1#p' | head -n 1)"

if [[ -z "$DEVICE" || -z "$VOLUME_PATH" || ! -d "$VOLUME_PATH" ]]; then
  echo "Unable to mount writable DMG" >&2
  printf "%s\n" "$MOUNT_OUTPUT" >&2
  exit 1
fi

cleanup_dmg_mount() {
  if [[ -n "${VOLUME_PATH:-}" && -d "$VOLUME_PATH" ]]; then
    hdiutil detach "$VOLUME_PATH" -quiet || true
  elif [[ -n "${DEVICE:-}" ]]; then
    hdiutil detach "$DEVICE" -quiet || true
  fi
}
trap cleanup_dmg_mount EXIT

mkdir -p "$VOLUME_PATH/.background"
mkdir -p "$BUILD_DIR/SwiftModuleCache"
BACKGROUND_PATH="$VOLUME_PATH/.background/background.png" \
DMG_WINDOW_WIDTH="$DMG_WINDOW_WIDTH" \
DMG_WINDOW_HEIGHT="$DMG_WINDOW_HEIGHT" \
swift -module-cache-path "$BUILD_DIR/SwiftModuleCache" - <<'SWIFT'
import AppKit
import Foundation

let environment = ProcessInfo.processInfo.environment
guard let backgroundPath = environment["BACKGROUND_PATH"],
      let widthText = environment["DMG_WINDOW_WIDTH"], let width = Int(widthText),
      let heightText = environment["DMG_WINDOW_HEIGHT"], let height = Int(heightText) else {
    fputs("Missing DMG background environment\n", stderr)
    exit(1)
}

let size = NSSize(width: width, height: height)
let image = NSImage(size: size)
image.lockFocus()

NSColor(calibratedRed: 0.965, green: 0.970, blue: 0.976, alpha: 1).setFill()
NSBezierPath(rect: NSRect(origin: .zero, size: size)).fill()

NSColor(calibratedRed: 0.52, green: 0.56, blue: 0.60, alpha: 1).setStroke()
let arc = NSBezierPath()
arc.lineWidth = 5
arc.lineCapStyle = .round
arc.lineJoinStyle = .round
let startPoint = NSPoint(x: 282, y: 226)
let endPoint = NSPoint(x: 438, y: 226)
let controlPoint1 = NSPoint(x: 318, y: 286)
let controlPoint2 = NSPoint(x: 402, y: 286)
arc.move(to: startPoint)
arc.curve(to: endPoint, controlPoint1: controlPoint1, controlPoint2: controlPoint2)
arc.stroke()

let tangent = NSPoint(x: endPoint.x - controlPoint2.x, y: endPoint.y - controlPoint2.y)
let arrowAngle = atan2(tangent.y, tangent.x)
let arrowTip = endPoint
let arrowHead = NSBezierPath()
arrowHead.lineWidth = 5
arrowHead.lineCapStyle = .round
arrowHead.lineJoinStyle = .round
arrowHead.move(to: arrowTip)
arrowHead.line(to: NSPoint(x: arrowTip.x - cos(arrowAngle - 0.65) * 20, y: arrowTip.y - sin(arrowAngle - 0.65) * 20))
arrowHead.move(to: arrowTip)
arrowHead.line(to: NSPoint(x: arrowTip.x - cos(arrowAngle + 0.65) * 20, y: arrowTip.y - sin(arrowAngle + 0.65) * 20))
arrowHead.stroke()

image.unlockFocus()

guard let tiffData = image.tiffRepresentation,
      let bitmap = NSBitmapImageRep(data: tiffData),
      let pngData = bitmap.representation(using: .png, properties: [:]) else {
    fputs("Unable to render DMG background\n", stderr)
    exit(1)
}

try pngData.write(to: URL(fileURLWithPath: backgroundPath))
SWIFT

osascript <<APPLESCRIPT
set volumeFolder to POSIX file "$VOLUME_PATH" as alias
set backgroundFile to POSIX file "$VOLUME_PATH/.background/background.png" as alias

tell application "Finder"
  tell folder volumeFolder
    open
    set current view of container window to icon view
    set toolbar visible of container window to false
    set statusbar visible of container window to false
    set bounds of container window to {100, 100, 100 + $DMG_WINDOW_WIDTH, 100 + $DMG_WINDOW_HEIGHT}
    set viewOptions to the icon view options of container window
    set arrangement of viewOptions to not arranged
    set icon size of viewOptions to $DMG_ICON_SIZE
    set background picture of viewOptions to backgroundFile
    set position of item "$APP_NAME.app" of container window to {$DMG_APP_ICON_X, $DMG_APP_ICON_Y}
    set position of item "Applications" of container window to {$DMG_APPLICATIONS_ICON_X, $DMG_APPLICATIONS_ICON_Y}
    update without registering applications
    delay 1
    close
  end tell
end tell
APPLESCRIPT

sync
hdiutil detach "$VOLUME_PATH" -quiet
DEVICE=""
VOLUME_PATH=""

hdiutil convert "$DMG_RW_PATH" \
  -format UDZO \
  -imagekey zlib-level=9 \
  -o "$DMG_UNSIGNED_PATH"
rm -f "$DMG_RW_PATH"

codesign --force --timestamp --sign "$SIGNING_IDENTITY_NAME" "$DMG_UNSIGNED_PATH"
mv "$DMG_UNSIGNED_PATH" "$DMG_PATH"

if [[ -n "$NOTARY_PROFILE" ]]; then
  xcrun notarytool submit "$DMG_PATH" --keychain-profile "$NOTARY_PROFILE" --wait
  xcrun stapler staple "$DMG_PATH"
fi

echo "Developer ID DMG created: $DMG_PATH"
if [[ -z "$NOTARY_PROFILE" ]]; then
  echo "Notarization skipped. Set NOTARY_PROFILE=<keychain-profile> to submit and staple."
fi
