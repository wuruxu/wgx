// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Cocoa
import Vision

class QRCodeImportPanelPresenter {
    static func presentQRCodeImportPanel(tunnelsManager: TunnelsManager, sourceVC: NSViewController?) {
        guard let sourceVC = sourceVC else { return }

        let temporaryURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("wireguard-qr-import-\(UUID().uuidString)")
            .appendingPathExtension("png")

        captureScreenSelection(to: temporaryURL) { result in
            switch result {
            case .failure(.screenCaptureCancelled):
                return
            case .failure(let error):
                ErrorPresenter.showErrorAlert(error: error, from: sourceVC)
            case .success:
                decodeQRCode(from: temporaryURL) { result in
                    try? FileManager.default.removeItem(at: temporaryURL)

                    switch result {
                    case .failure(let error):
                        ErrorPresenter.showErrorAlert(error: error, from: sourceVC)
                    case .success(let code):
                        importQRCode(code, into: tunnelsManager, sourceVC: sourceVC)
                    }
                }
            }
        }
    }

    private static func captureScreenSelection(to url: URL, completion: @escaping (Result<Void, QRCodeImportError>) -> Void) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture")
        process.arguments = ["-i", "-x", url.path]
        process.terminationHandler = { process in
            DispatchQueue.main.async {
                guard FileManager.default.fileExists(atPath: url.path) else {
                    completion(.failure(.screenCaptureCancelled))
                    return
                }
                guard process.terminationStatus == 0 else {
                    completion(.failure(.screenCaptureFailed))
                    return
                }
                completion(.success(()))
            }
        }

        do {
            try process.run()
        } catch {
            completion(.failure(.screenCaptureFailed))
        }
    }

    private static func decodeQRCode(from url: URL, completion: @escaping (Result<String, QRCodeImportError>) -> Void) {
        guard let image = NSImage(contentsOf: url),
              let cgImage = image.cgImage(forProposedRect: nil, context: nil, hints: nil) else {
            completion(.failure(.unreadableQRCode))
            return
        }

        let request = VNDetectBarcodesRequest { request, error in
            DispatchQueue.main.async {
                if error != nil {
                    completion(.failure(.unreadableQRCode))
                    return
                }

                let qrCode = (request.results as? [VNBarcodeObservation])?
                    .first { $0.symbology == .qr && $0.payloadStringValue != nil }?
                    .payloadStringValue

                if let qrCode = qrCode {
                    completion(.success(qrCode))
                } else {
                    completion(.failure(.unreadableQRCode))
                }
            }
        }
        request.symbologies = [.qr]

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                try VNImageRequestHandler(cgImage: cgImage, options: [:]).perform([request])
            } catch {
                DispatchQueue.main.async {
                    completion(.failure(.unreadableQRCode))
                }
            }
        }
    }

    private static func importQRCode(_ code: String, into tunnelsManager: TunnelsManager, sourceVC: NSViewController) {
        let tunnelConfiguration: TunnelConfiguration
        do {
            tunnelConfiguration = try TunnelConfiguration(fromWgQuickConfig: code, called: "Scanned")
        } catch let error as WireGuardAppError {
            ErrorPresenter.showErrorAlert(error: error, from: sourceVC)
            return
        } catch {
            ErrorPresenter.showErrorAlert(error: QRCodeImportError.invalidQRCode, from: sourceVC)
            return
        }

        promptForTunnelName(for: tunnelConfiguration, sourceVC: sourceVC) { name in
            guard let name = name else { return }
            tunnelConfiguration.name = name
            tunnelsManager.add(tunnelConfiguration: tunnelConfiguration) { result in
                switch result {
                case .failure(let error):
                    ErrorPresenter.showErrorAlert(error: error, from: sourceVC)
                case .success:
                    break
                }
            }
        }
    }

    private static func promptForTunnelName(for tunnelConfiguration: TunnelConfiguration, sourceVC: NSViewController, completion: @escaping (String?) -> Void) {
        guard let window = sourceVC.view.window else {
            completion(nil)
            return
        }

        let alert = NSAlert()
        alert.messageText = tr("alertScanQRCodeNamePromptTitle")
        alert.addButton(withTitle: tr("actionSave"))
        alert.addButton(withTitle: tr("actionCancel"))

        let textField = NSTextField(frame: NSRect(x: 0, y: 0, width: 240, height: 24))
        textField.stringValue = tunnelConfiguration.name ?? "Scanned"
        alert.accessoryView = textField

        alert.beginSheetModal(for: window) { response in
            guard response == .alertFirstButtonReturn else {
                completion(nil)
                return
            }

            let tunnelName = textField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !tunnelName.isEmpty else {
                ErrorPresenter.showErrorAlert(error: TunnelsManagerError.tunnelNameEmpty, from: sourceVC)
                completion(nil)
                return
            }
            completion(tunnelName)
        }
    }
}

private enum QRCodeImportError: WireGuardAppError {
    case screenCaptureCancelled
    case screenCaptureFailed
    case unreadableQRCode
    case invalidQRCode

    var alertText: AlertText {
        switch self {
        case .screenCaptureCancelled:
            return (tr("alertScanQRCodeScreenCaptureCancelledTitle"), tr("alertScanQRCodeScreenCaptureCancelledMessage"))
        case .screenCaptureFailed:
            return (tr("alertScanQRCodeScreenCaptureFailedTitle"), tr("alertScanQRCodeScreenCaptureFailedMessage"))
        case .unreadableQRCode:
            return (tr("alertScanQRCodeUnreadableQRCodeTitle"), tr("alertScanQRCodeUnreadableQRCodeMessage"))
        case .invalidQRCode:
            return (tr("alertScanQRCodeInvalidQRCodeTitle"), tr("alertScanQRCodeInvalidQRCodeMessage"))
        }
    }
}
