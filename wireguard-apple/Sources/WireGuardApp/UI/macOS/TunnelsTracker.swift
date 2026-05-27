// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Cocoa

// Keeps track of tunnels and informs the following objects of changes in tunnels:
//   - Status menu
//   - Status item controller
//   - Tunnels list view controller in the Manage Tunnels window

class TunnelsTracker {

    weak var statusMenu: StatusMenu? {
        didSet {
            statusMenu?.currentTunnel = currentTunnel
        }
    }
    weak var statusItemController: StatusItemController? {
        didSet {
            statusItemController?.currentTunnel = currentTunnel
        }
    }
    weak var manageTunnelsRootVC: ManageTunnelsRootViewController?

    private var tunnelsManager: TunnelsManager
    private let dockIconBadgeController = DockIconBadgeController()
    private var tunnelStatusObservers = [AnyObject]()
    private(set) var currentTunnel: TunnelContainer? {
        didSet {
            statusMenu?.currentTunnel = currentTunnel
            statusItemController?.currentTunnel = currentTunnel
            dockIconBadgeController.currentTunnel = currentTunnel
        }
    }

    var shouldKeepDockIconVisible: Bool {
        guard let currentTunnel = currentTunnel else { return false }
        switch currentTunnel.status {
        case .active, .activating, .waiting, .reasserting, .restarting:
            return true
        case .inactive, .deactivating:
            return false
        }
    }

    init(tunnelsManager: TunnelsManager) {
        self.tunnelsManager = tunnelsManager
        currentTunnel = tunnelsManager.tunnelInOperation()
        dockIconBadgeController.currentTunnel = currentTunnel

        for index in 0 ..< tunnelsManager.numberOfTunnels() {
            let tunnel = tunnelsManager.tunnel(at: index)
            let statusObservationToken = observeStatus(of: tunnel)
            tunnelStatusObservers.insert(statusObservationToken, at: index)
        }

        tunnelsManager.tunnelsListDelegate = self
        tunnelsManager.activationDelegate = self
    }

    func observeStatus(of tunnel: TunnelContainer) -> AnyObject {
        return tunnel.observe(\.status) { [weak self] tunnel, _ in
            guard let self = self else { return }
            if tunnel.status == .deactivating || tunnel.status == .inactive {
                if self.currentTunnel == tunnel {
                    self.currentTunnel = self.tunnelsManager.tunnelInOperation()
                }
            } else {
                self.currentTunnel = tunnel
            }
        }
    }

    func refreshDockIconBadge() {
        dockIconBadgeController.refresh()
    }
}

private final class DockIconBadgeController {
    var currentTunnel: TunnelContainer? {
        didSet {
            updateDockIconBadge()
        }
    }

    private let baseApplicationIcon = NSApp.applicationIconImage.copy() as? NSImage
    private var animationTimer: Timer?
    private var animationProgress: CGFloat = 0

    private enum BadgeState {
        case hidden
        case connecting
        case connected
    }

    private var badgeState: BadgeState {
        guard let currentTunnel = currentTunnel else { return .hidden }
        switch currentTunnel.status {
        case .active:
            return .connected
        case .activating, .waiting, .reasserting, .restarting:
            return .connecting
        case .inactive, .deactivating:
            return .hidden
        }
    }

    func refresh() {
        updateDockIconBadge()
    }

    private func updateDockIconBadge() {
        switch badgeState {
        case .hidden:
            stopConnectingAnimation()
            restoreBaseApplicationIcon()
        case .connected:
            stopConnectingAnimation()
            setDockIconBorder(color: .systemGreen)
        case .connecting:
            startConnectingAnimation()
        }
    }

    private func startConnectingAnimation() {
        guard animationTimer == nil else { return }
        let timer = Timer(timeInterval: 0.05, repeats: true) { [weak self] _ in
            self?.updateConnectingAnimationFrame()
        }
        RunLoop.main.add(timer, forMode: .common)
        animationTimer = timer
        updateConnectingAnimationFrame()
    }

    private func stopConnectingAnimation() {
        animationTimer?.invalidate()
        animationTimer = nil
        animationProgress = 0
    }

    private func updateConnectingAnimationFrame() {
        animationProgress += 0.05
        let breath = CGFloat((sin(Double(animationProgress * .pi)) + 1) / 2)
        let color = NSColor.interpolate(from: .systemYellow, to: .systemGreen, progress: breath)
        setDockIconBorder(color: color)
    }

    private func restoreBaseApplicationIcon() {
        if let baseApplicationIcon = baseApplicationIcon {
            NSApp.applicationIconImage = baseApplicationIcon
        }
    }

    private func setDockIconBorder(color: NSColor) {
        guard let baseApplicationIcon = baseApplicationIcon else { return }

        let iconSize = baseApplicationIcon.size
        let lineWidth: CGFloat = 3.6
        let borderInset = lineWidth * 1.2
        let borderRect = NSRect(origin: .zero, size: iconSize).insetBy(dx: borderInset, dy: borderInset)
        let cornerRadius = min(iconSize.width, iconSize.height) * 0.28

        let image = NSImage(size: iconSize)
        image.lockFocus()
        baseApplicationIcon.draw(in: NSRect(origin: .zero, size: iconSize))

        let shadowPath = NSBezierPath(
            roundedRect: borderRect.insetBy(dx: -lineWidth * 0.5, dy: -lineWidth * 0.5),
            xRadius: cornerRadius,
            yRadius: cornerRadius
        )
        shadowPath.lineWidth = lineWidth + 1
        NSColor.black.withAlphaComponent(0.25).setStroke()
        shadowPath.stroke()

        let highlightPath = NSBezierPath(
            roundedRect: borderRect.insetBy(dx: lineWidth * 0.25, dy: lineWidth * 0.25),
            xRadius: cornerRadius,
            yRadius: cornerRadius
        )
        highlightPath.lineWidth = lineWidth + 0.4
        NSColor.white.withAlphaComponent(0.85).setStroke()
        highlightPath.stroke()

        let borderPath = NSBezierPath(
            roundedRect: borderRect.insetBy(dx: lineWidth * 0.5, dy: lineWidth * 0.5),
            xRadius: cornerRadius,
            yRadius: cornerRadius
        )
        borderPath.lineWidth = lineWidth
        color.setStroke()
        borderPath.stroke()
        image.unlockFocus()

        NSApp.applicationIconImage = image
    }
}

private extension NSColor {
    static func interpolate(from startColor: NSColor, to endColor: NSColor, progress: CGFloat) -> NSColor {
        guard let startColor = startColor.usingColorSpace(.deviceRGB),
              let endColor = endColor.usingColorSpace(.deviceRGB) else {
            return progress < 0.5 ? startColor : endColor
        }
        return NSColor(
            red: startColor.redComponent + (endColor.redComponent - startColor.redComponent) * progress,
            green: startColor.greenComponent + (endColor.greenComponent - startColor.greenComponent) * progress,
            blue: startColor.blueComponent + (endColor.blueComponent - startColor.blueComponent) * progress,
            alpha: startColor.alphaComponent + (endColor.alphaComponent - startColor.alphaComponent) * progress
        )
    }
}

extension TunnelsTracker: TunnelsManagerListDelegate {
    func tunnelAdded(at index: Int) {
        let tunnel = tunnelsManager.tunnel(at: index)
        if tunnel.status != .deactivating && tunnel.status != .inactive {
            self.currentTunnel = tunnel
        }
        let statusObservationToken = observeStatus(of: tunnel)
        tunnelStatusObservers.insert(statusObservationToken, at: index)

        statusMenu?.insertTunnelMenuItem(for: tunnel, at: index)
        manageTunnelsRootVC?.tunnelsListVC?.tunnelAdded(at: index)
    }

    func tunnelModified(at index: Int) {
        manageTunnelsRootVC?.tunnelsListVC?.tunnelModified(at: index)
    }

    func tunnelMoved(from oldIndex: Int, to newIndex: Int) {
        let statusObserver = tunnelStatusObservers.remove(at: oldIndex)
        tunnelStatusObservers.insert(statusObserver, at: newIndex)

        statusMenu?.moveTunnelMenuItem(from: oldIndex, to: newIndex)
        manageTunnelsRootVC?.tunnelsListVC?.tunnelMoved(from: oldIndex, to: newIndex)
    }

    func tunnelRemoved(at index: Int, tunnel: TunnelContainer) {
        tunnelStatusObservers.remove(at: index)

        statusMenu?.removeTunnelMenuItem(at: index)
        manageTunnelsRootVC?.tunnelsListVC?.tunnelRemoved(at: index)
    }
}

extension TunnelsTracker: TunnelsManagerActivationDelegate {
    func tunnelActivationAttemptFailed(tunnel: TunnelContainer, error: TunnelsManagerActivationAttemptError) {
        if let manageTunnelsRootVC = manageTunnelsRootVC, manageTunnelsRootVC.view.window?.isVisible ?? false {
            ErrorPresenter.showErrorAlert(error: error, from: manageTunnelsRootVC)
        } else {
            ErrorPresenter.showErrorAlert(error: error, from: nil)
        }
    }

    func tunnelActivationAttemptSucceeded(tunnel: TunnelContainer) {
        // Nothing to do
    }

    func tunnelActivationFailed(tunnel: TunnelContainer, error: TunnelsManagerActivationError) {
        if let manageTunnelsRootVC = manageTunnelsRootVC, manageTunnelsRootVC.view.window?.isVisible ?? false {
            ErrorPresenter.showErrorAlert(error: error, from: manageTunnelsRootVC)
        } else {
            ErrorPresenter.showErrorAlert(error: error, from: nil)
        }
    }

    func tunnelActivationSucceeded(tunnel: TunnelContainer) {
        // Nothing to do
    }
}
