all:
	xcodebuild -project WireGuard.xcodeproj -scheme WireGuardmacOS -configuration Debug -destination 'platform=macOS' build
rel:
	xcodebuild  -project WireGuard.xcodeproj  -scheme WireGuardmacOS  -configuration Release  -destination 'platform=macOS'  -derivedDataPath build/DerivedData  -allowProvisioningUpdates  -allowProvisioningDeviceRegistration  clean build
sign:
	NOTARY_PROFILE=wgx-notary ./scripts/release-macos-dmg.sh
