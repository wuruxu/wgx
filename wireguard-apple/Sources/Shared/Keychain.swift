// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation
import Security

class Keychain {
    static func openReference(called ref: Data) -> String? {
        var result: CFTypeRef?
        let ret = SecItemCopyMatching([kSecValuePersistentRef: ref,
                                        kSecReturnData: true] as CFDictionary,
                                       &result)
        if ret != errSecSuccess || result == nil {
            wg_log(.error, message: "Unable to open config from keychain: \(ret)")
            return nil
        }
        guard let data = result as? Data else { return nil }
        return String(data: data, encoding: String.Encoding.utf8)
    }

    static func makeReference(containing value: String, called name: String, previouslyReferencedBy oldRef: Data? = nil) -> Data? {
        var ret: OSStatus
        guard var bundleIdentifier = Bundle.main.bundleIdentifier else {
            wg_log(.error, staticMessage: "Unable to determine bundle identifier")
            return nil
        }
        if bundleIdentifier.hasSuffix(".network-extension") {
            bundleIdentifier.removeLast(".network-extension".count)
        }
        let itemLabel = "WireGuard Tunnel: \(name)"
        var items: [CFString: Any] = [kSecClass: kSecClassGenericPassword,
                                    kSecAttrLabel: itemLabel,
                                    kSecAttrAccount: name + ": " + UUID().uuidString,
                                    kSecAttrDescription: "wg-quick(8) config",
                                    kSecAttrService: bundleIdentifier,
                                    kSecValueData: value.data(using: .utf8) as Any,
                                    kSecReturnPersistentRef: true]

        #if os(iOS)
        items[kSecAttrAccessGroup] = FileManager.appGroupId
        items[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlock
        #elseif os(macOS)
        items[kSecAttrSynchronizable] = false
        items[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly

        let providerBundleIdentifier = "\(bundleIdentifier).network-extension"
        let embeddedExtensionPath = Bundle.main.bundleURL
            .appendingPathComponent("Contents", isDirectory: true)
            .appendingPathComponent("Library", isDirectory: true)
            .appendingPathComponent("SystemExtensions", isDirectory: true)
            .appendingPathComponent("\(providerBundleIdentifier).systemextension", isDirectory: true)
            .path

        var trustedApplications = [SecTrustedApplication]()
        for extensionPath in [embeddedExtensionPath] + installedSystemExtensionPaths(providerBundleIdentifier: providerBundleIdentifier) {
            if let trustedApplication = makeTrustedApplication(path: extensionPath) {
                trustedApplications.append(trustedApplication)
            }
        }
        guard !trustedApplications.isEmpty else {
            wg_log(.error, staticMessage: "Unable to create any keychain extension trusted application objects")
            return nil
        }
        if let mainApp = makeTrustedApplication(path: nil) {
            trustedApplications.append(mainApp)
        }

        var access: SecAccess?
        ret = SecAccessCreate(itemLabel as CFString, trustedApplications as CFArray, &access)
        if ret != errSecSuccess || access == nil {
            wg_log(.error, message: "Unable to create keychain ACL object: \(ret)")
            return nil
        }
        items[kSecAttrAccess] = access!
        #else
        #error("Unimplemented")
        #endif

        var ref: CFTypeRef?
        ret = SecItemAdd(items as CFDictionary, &ref)
        if ret != errSecSuccess || ref == nil {
            wg_log(.error, message: "Unable to add config to keychain: \(ret)")
            return nil
        }
        if let oldRef = oldRef {
            deleteReference(called: oldRef)
        }
        return ref as? Data
    }

    static func deleteReference(called ref: Data) {
        let ret = SecItemDelete([kSecValuePersistentRef: ref] as CFDictionary)
        if ret != errSecSuccess {
            wg_log(.error, message: "Unable to delete config from keychain: \(ret)")
        }
    }

    static func deleteReferences(except whitelist: Set<Data>) {
        var result: CFTypeRef?
        let ret = SecItemCopyMatching([kSecClass: kSecClassGenericPassword,
                                       kSecAttrService: Bundle.main.bundleIdentifier as Any,
                                       kSecMatchLimit: kSecMatchLimitAll,
                                       kSecReturnPersistentRef: true] as CFDictionary,
                                      &result)
        if ret != errSecSuccess || result == nil {
            return
        }
        guard let items = result as? [Data] else { return }
        for item in items {
            if !whitelist.contains(item) {
                deleteReference(called: item)
            }
        }
    }

    static func verifyReference(called ref: Data) -> Bool {
        return SecItemCopyMatching([kSecValuePersistentRef: ref] as CFDictionary,
                                   nil) != errSecItemNotFound
    }

    #if os(macOS)
    private static func makeTrustedApplication(path: String?) -> SecTrustedApplication? {
        var trustedApplication: SecTrustedApplication?
        let ret = SecTrustedApplicationCreateFromPath(path, &trustedApplication)
        if ret != errSecSuccess || trustedApplication == nil {
            wg_log(.error, message: "Unable to create keychain trusted application object for \(path ?? "<current app>"): \(ret)")
            return nil
        }
        return trustedApplication
    }

    private static func installedSystemExtensionPaths(providerBundleIdentifier: String) -> [String] {
        let systemExtensionsURL = URL(fileURLWithPath: "/Library/SystemExtensions", isDirectory: true)
        guard let extensionContainers = try? FileManager.default.contentsOfDirectory(
            at: systemExtensionsURL,
            includingPropertiesForKeys: nil
        ) else {
            return []
        }

        return extensionContainers
            .map {
                $0.appendingPathComponent("\(providerBundleIdentifier).systemextension", isDirectory: true)
                    .path
            }
            .filter { FileManager.default.fileExists(atPath: $0) }
    }
    #endif
}
