// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Cocoa

protocol StatusMenuWindowDelegate: AnyObject {
    func showManageTunnelsWindow(completion: ((NSWindow?) -> Void)?)
}

private enum TransferDirection {
    case rx
    case tx
}

class StatusMenu: NSMenu {

    let tunnelsManager: TunnelsManager

    var statusMenuItem: NSMenuItem?
    var networksMenuItem: NSMenuItem?
    var deactivateMenuItem: NSMenuItem?
    private var runtimeTransferRefreshTimer: Timer?
    private var runtimeTransferHighlightResetTimer: Timer?
    private var lastRuntimeRxBytes: UInt64?
    private var lastRuntimeTxBytes: UInt64?
    private var highlightedTransferDirections = Set<TransferDirection>()
    private let transferMenuTextField = NSTextField(labelWithString: "")

    private let tunnelsBreakdownMenu = NSMenu()
    private let tunnelsMenuItem = NSMenuItem(title: tr("macTunnelsMenuTitle"), action: nil, keyEquivalent: "")
    private let tunnelsMenuSeparatorItem = NSMenuItem.separator()

    private var firstTunnelMenuItemIndex = 0
    private var numberOfTunnelMenuItems = 0
    private var tunnelsPresentationStyle = StatusMenuTunnelsPresentationStyle.inline

    var currentTunnel: TunnelContainer? {
        didSet {
            updateStatusMenuItems(with: currentTunnel)
        }
    }
    weak var windowDelegate: StatusMenuWindowDelegate?

    init(tunnelsManager: TunnelsManager) {
        self.tunnelsManager = tunnelsManager

        super.init(title: tr("macMenuTitle"))

        delegate = self

        addStatusMenuItems()
        addItem(NSMenuItem.separator())

        tunnelsMenuItem.submenu = tunnelsBreakdownMenu
        addItem(tunnelsMenuItem)

        firstTunnelMenuItemIndex = numberOfItems
        populateInitialTunnelMenuItems()

        addItem(tunnelsMenuSeparatorItem)

        addTunnelManagementItems()
        addItem(NSMenuItem.separator())
        addApplicationItems()
    }

    required init(coder decoder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func addStatusMenuItems() {
        let statusTitle = tr(format: "macStatus (%@)", tr("tunnelStatusInactive"))
        let statusMenuItem = NSMenuItem(title: statusTitle, action: nil, keyEquivalent: "")
        statusMenuItem.isEnabled = false
        addItem(statusMenuItem)
        let networksMenuItem = NSMenuItem(title: "", action: nil, keyEquivalent: "")
        networksMenuItem.isEnabled = true
        networksMenuItem.isHidden = true

        let transferMenuView = NSView(frame: NSRect(x: 0, y: 0, width: 260, height: 22))
        transferMenuTextField.frame = NSRect(x: 18, y: 2, width: 230, height: 18)
        transferMenuTextField.font = NSFont.menuFont(ofSize: 0)
        transferMenuTextField.lineBreakMode = .byTruncatingTail
        transferMenuTextField.maximumNumberOfLines = 1
        transferMenuView.addSubview(transferMenuTextField)
        networksMenuItem.view = transferMenuView

        addItem(networksMenuItem)
        let deactivateMenuItem = NSMenuItem(title: tr("macToggleStatusButtonDeactivate"), action: #selector(deactivateClicked), keyEquivalent: "")
        deactivateMenuItem.target = self
        deactivateMenuItem.isHidden = true
        addItem(deactivateMenuItem)
        self.statusMenuItem = statusMenuItem
        self.networksMenuItem = networksMenuItem
        self.deactivateMenuItem = deactivateMenuItem
    }

    func updateStatusMenuItems(with tunnel: TunnelContainer?) {
        guard let statusMenuItem = statusMenuItem, let networksMenuItem = networksMenuItem, let deactivateMenuItem = deactivateMenuItem else { return }
        guard let tunnel = tunnel else {
            statusMenuItem.title = tr(format: "macStatus (%@)", tr("tunnelStatusInactive"))
            resetRuntimeTransferState()
            networksMenuItem.isHidden = true
            deactivateMenuItem.isHidden = true
            return
        }
        var statusText: String

        switch tunnel.status {
        case .waiting:
            statusText = tr("tunnelStatusWaiting")
        case .inactive:
            statusText = tr("tunnelStatusInactive")
        case .activating:
            statusText = tr("tunnelStatusActivating")
        case .active:
            statusText = tr("tunnelStatusActive")
        case .deactivating:
            statusText = tr("tunnelStatusDeactivating")
        case .reasserting:
            statusText = tr("tunnelStatusReasserting")
        case .restarting:
            statusText = tr("tunnelStatusRestarting")
        }

        statusMenuItem.title = tr(format: "macStatus (%@)", statusText)

        if tunnel.status == .active {
            updateTransferMenuItem(rxBytes: lastRuntimeRxBytes ?? 0, txBytes: lastRuntimeTxBytes ?? 0)
            networksMenuItem.isHidden = false
        } else {
            resetRuntimeTransferState()
            networksMenuItem.isHidden = true
        }
        deactivateMenuItem.isHidden = tunnel.status != .active
    }

    private func startRuntimeTransferRefresh() {
        runtimeTransferRefreshTimer?.invalidate()
        runtimeTransferRefreshTimer = nil
        reloadRuntimeTransfer()

        guard currentTunnel?.status == .active else { return }
        let timer = Timer(timeInterval: 1, repeats: true) { [weak self] _ in
            self?.reloadRuntimeTransfer()
        }
        runtimeTransferRefreshTimer = timer
        RunLoop.main.add(timer, forMode: .common)
    }

    private func stopRuntimeTransferRefresh() {
        runtimeTransferRefreshTimer?.invalidate()
        runtimeTransferRefreshTimer = nil
    }

    private func reloadRuntimeTransfer() {
        guard let tunnel = currentTunnel, tunnel.status == .active else {
            updateStatusMenuItems(with: currentTunnel)
            return
        }

        tunnel.getRuntimeTunnelConfiguration { [weak self, weak tunnel] tunnelConfiguration in
            DispatchQueue.main.async {
                guard let self = self, let tunnel = tunnel, self.currentTunnel === tunnel else { return }
                guard tunnel.status == .active else {
                    self.updateStatusMenuItems(with: tunnel)
                    return
                }

                let peers = tunnelConfiguration?.peers ?? []
                let rxBytes = peers.reduce(UInt64(0)) { total, peer in total + (peer.rxBytes ?? 0) }
                let txBytes = peers.reduce(UInt64(0)) { total, peer in total + (peer.txBytes ?? 0) }
                self.updateTransferMenuItem(rxBytes: rxBytes, txBytes: txBytes)
                self.networksMenuItem?.isHidden = false
            }
        }
    }

    private func updateTransferMenuItem(rxBytes: UInt64, txBytes: UInt64) {
        var changedDirections = Set<TransferDirection>()
        if let lastRuntimeRxBytes = lastRuntimeRxBytes, rxBytes != lastRuntimeRxBytes {
            changedDirections.insert(.rx)
        }
        if let lastRuntimeTxBytes = lastRuntimeTxBytes, txBytes != lastRuntimeTxBytes {
            changedDirections.insert(.tx)
        }

        lastRuntimeRxBytes = rxBytes
        lastRuntimeTxBytes = txBytes

        if !changedDirections.isEmpty {
            highlightedTransferDirections.formUnion(changedDirections)
            runtimeTransferHighlightResetTimer?.invalidate()
            let timer = Timer(timeInterval: 0.5, repeats: false) { [weak self] _ in
                guard let self = self else { return }
                self.highlightedTransferDirections.removeAll()
                self.applyTransferMenuTitle(rxBytes: rxBytes, txBytes: txBytes)
            }
            runtimeTransferHighlightResetTimer = timer
            RunLoop.main.add(timer, forMode: .common)
        }

        applyTransferMenuTitle(rxBytes: rxBytes, txBytes: txBytes)
    }

    private func applyTransferMenuTitle(rxBytes: UInt64, txBytes: UInt64) {
        let title = Self.prettyBytes(rxBytes: rxBytes, txBytes: txBytes)
        let attributedTitle = NSMutableAttributedString(
            string: title,
            attributes: [
                .font: NSFont.menuFont(ofSize: 0),
                .foregroundColor: NSColor.labelColor
            ]
        )

        if highlightedTransferDirections.contains(.rx), let range = title.range(of: "↓") {
            attributedTitle.addAttribute(.foregroundColor, value: NSColor(calibratedRed: 0.0, green: 0.45, blue: 0.12, alpha: 1.0), range: NSRange(range, in: title))
        }
        if highlightedTransferDirections.contains(.tx), let range = title.range(of: "↑") {
            attributedTitle.addAttribute(.foregroundColor, value: NSColor(calibratedRed: 0.0, green: 0.45, blue: 0.12, alpha: 1.0), range: NSRange(range, in: title))
        }

        transferMenuTextField.attributedStringValue = attributedTitle
    }

    private func resetRuntimeTransferState() {
        runtimeTransferHighlightResetTimer?.invalidate()
        runtimeTransferHighlightResetTimer = nil
        lastRuntimeRxBytes = nil
        lastRuntimeTxBytes = nil
        highlightedTransferDirections.removeAll()
        applyTransferMenuTitle(rxBytes: 0, txBytes: 0)
    }

    private static func prettyBytes(rxBytes: UInt64, txBytes: UInt64) -> String {
        return "↓ \(prettyBytes(rxBytes))   ↑ \(prettyBytes(txBytes))"
    }

    private static func prettyBytes(_ bytes: UInt64) -> String {
        switch bytes {
        case 0..<1024:
            return "\(bytes) B"
        case 1024..<(1024 * 1024):
            return String(format: "%.2f KiB", Double(bytes) / 1024)
        case 1024..<(1024 * 1024 * 1024):
            return String(format: "%.2f MiB", Double(bytes) / (1024 * 1024))
        case 1024..<(1024 * 1024 * 1024 * 1024):
            return String(format: "%.2f GiB", Double(bytes) / (1024 * 1024 * 1024))
        default:
            return String(format: "%.2f TiB", Double(bytes) / (1024 * 1024 * 1024 * 1024))
        }
    }

    func addTunnelManagementItems() {
        let manageItem = NSMenuItem(title: tr("macMenuManageTunnels"), action: #selector(manageTunnelsClicked), keyEquivalent: "")
        manageItem.target = self
        addItem(manageItem)
        let importItem = NSMenuItem(title: tr("macMenuImportTunnels"), action: #selector(importTunnelsClicked), keyEquivalent: "")
        importItem.target = self
        addItem(importItem)
    }

    func addApplicationItems() {
        let aboutItem = NSMenuItem(title: tr("macMenuAbout"), action: #selector(AppDelegate.aboutClicked), keyEquivalent: "")
        aboutItem.target = NSApp.delegate
        addItem(aboutItem)
        let quitItem = NSMenuItem(title: tr("macMenuQuit"), action: #selector(AppDelegate.quit), keyEquivalent: "")
        quitItem.target = NSApp.delegate
        addItem(quitItem)
    }

    @objc func deactivateClicked() {
        if let currentTunnel = currentTunnel {
            tunnelsManager.startDeactivation(of: currentTunnel)
        }
    }

    @objc func tunnelClicked(sender: AnyObject) {
        guard let tunnelMenuItem = sender as? TunnelMenuItem else { return }
        let tunnel = tunnelMenuItem.tunnel
        if tunnel.hasOnDemandRules {
            let turnOn = !tunnel.isActivateOnDemandEnabled
            tunnelsManager.setOnDemandEnabled(turnOn, on: tunnel) { error in
                if error == nil && !turnOn {
                    self.tunnelsManager.startDeactivation(of: tunnel)
                }
            }
        } else {
            if tunnel.status == .inactive {
                tunnelsManager.startActivation(of: tunnel)
            } else if tunnel.status == .active {
                tunnelsManager.startDeactivation(of: tunnel)
            }
        }
    }

    @objc func manageTunnelsClicked() {
        windowDelegate?.showManageTunnelsWindow(completion: nil)
    }

    @objc func importTunnelsClicked() {
        windowDelegate?.showManageTunnelsWindow { [weak self] manageTunnelsWindow in
            guard let self = self else { return }
            guard let manageTunnelsWindow = manageTunnelsWindow else { return }
            ImportPanelPresenter.presentImportPanel(tunnelsManager: self.tunnelsManager,
                                                    sourceVC: manageTunnelsWindow.contentViewController)
        }
    }
}

extension StatusMenu: NSMenuDelegate {
    func menuWillOpen(_ menu: NSMenu) {
        startRuntimeTransferRefresh()
    }

    func menuDidClose(_ menu: NSMenu) {
        stopRuntimeTransferRefresh()
    }
}

extension StatusMenu {
    func insertTunnelMenuItem(for tunnel: TunnelContainer, at tunnelIndex: Int) {
        let nextNumberOfTunnels = numberOfTunnelMenuItems + 1

        guard !reparentTunnelMenuItems(nextNumberOfTunnels: nextNumberOfTunnels) else {
            return
        }

        let menuItem = makeTunnelItem(tunnel: tunnel)
        switch tunnelsPresentationStyle {
        case .submenu:
            tunnelsBreakdownMenu.insertItem(menuItem, at: tunnelIndex)
        case .inline:
            insertItem(menuItem, at: firstTunnelMenuItemIndex + tunnelIndex)
        }

        numberOfTunnelMenuItems = nextNumberOfTunnels
        updateTunnelsMenuItemVisibility()
    }

    func removeTunnelMenuItem(at tunnelIndex: Int) {
        let nextNumberOfTunnels = numberOfTunnelMenuItems - 1

        guard !reparentTunnelMenuItems(nextNumberOfTunnels: nextNumberOfTunnels) else {
            return
        }

        switch tunnelsPresentationStyle {
        case .submenu:
            tunnelsBreakdownMenu.removeItem(at: tunnelIndex)
        case .inline:
            removeItem(at: firstTunnelMenuItemIndex + tunnelIndex)
        }

        numberOfTunnelMenuItems = nextNumberOfTunnels
        updateTunnelsMenuItemVisibility()
    }

    func moveTunnelMenuItem(from oldTunnelIndex: Int, to newTunnelIndex: Int) {
        let tunnel = tunnelsManager.tunnel(at: newTunnelIndex)
        let menuItem = makeTunnelItem(tunnel: tunnel)

        switch tunnelsPresentationStyle {
        case .submenu:
            tunnelsBreakdownMenu.removeItem(at: oldTunnelIndex)
            tunnelsBreakdownMenu.insertItem(menuItem, at: newTunnelIndex)
        case .inline:
            removeItem(at: firstTunnelMenuItemIndex + oldTunnelIndex)
            insertItem(menuItem, at: firstTunnelMenuItemIndex + newTunnelIndex)
        }
    }

    private func makeTunnelItem(tunnel: TunnelContainer) -> TunnelMenuItem {
        let menuItem = TunnelMenuItem(tunnel: tunnel, action: #selector(tunnelClicked(sender:)))
        menuItem.target = self
        menuItem.isHidden = !tunnel.isTunnelAvailableToUser
        return menuItem
    }

    private func populateInitialTunnelMenuItems() {
        let numberOfTunnels = tunnelsManager.numberOfTunnels()
        let initialStyle = tunnelsPresentationStyle.preferredPresentationStyle(numberOfTunnels: numberOfTunnels)

        tunnelsPresentationStyle = initialStyle
        switch initialStyle {
        case .inline:
            numberOfTunnelMenuItems = addTunnelMenuItems(into: self, at: firstTunnelMenuItemIndex)
        case .submenu:
            numberOfTunnelMenuItems = addTunnelMenuItems(into: tunnelsBreakdownMenu, at: 0)
        }

        updateTunnelsMenuItemVisibility()
    }

    private func reparentTunnelMenuItems(nextNumberOfTunnels: Int) -> Bool {
        let nextStyle = tunnelsPresentationStyle.preferredPresentationStyle(numberOfTunnels: nextNumberOfTunnels)

        switch (tunnelsPresentationStyle, nextStyle) {
        case (.inline, .submenu):
            tunnelsPresentationStyle = nextStyle
            for index in (0..<numberOfTunnelMenuItems).reversed() {
                removeItem(at: firstTunnelMenuItemIndex + index)
            }
            numberOfTunnelMenuItems = addTunnelMenuItems(into: tunnelsBreakdownMenu, at: 0)
            updateTunnelsMenuItemVisibility()
            return true

        case (.submenu, .inline):
            tunnelsPresentationStyle = nextStyle
            tunnelsBreakdownMenu.removeAllItems()
            numberOfTunnelMenuItems = addTunnelMenuItems(into: self, at: firstTunnelMenuItemIndex)
            updateTunnelsMenuItemVisibility()
            return true

        case (.submenu, .submenu), (.inline, .inline):
            return false
        }
    }

    private func addTunnelMenuItems(into menu: NSMenu, at startIndex: Int) -> Int {
        let numberOfTunnels = tunnelsManager.numberOfTunnels()
        for tunnelIndex in 0..<numberOfTunnels {
            let tunnel = tunnelsManager.tunnel(at: tunnelIndex)
            let menuItem = makeTunnelItem(tunnel: tunnel)
            menu.insertItem(menuItem, at: startIndex + tunnelIndex)
        }
        return numberOfTunnels
    }

    private func updateTunnelsMenuItemVisibility() {
        switch tunnelsPresentationStyle {
        case .inline:
            tunnelsMenuItem.isHidden = true
        case .submenu:
            tunnelsMenuItem.isHidden = false
        }
        tunnelsMenuSeparatorItem.isHidden = numberOfTunnelMenuItems == 0
    }
}

class TunnelMenuItem: NSMenuItem {

    var tunnel: TunnelContainer

    private var statusObservationToken: AnyObject?
    private var nameObservationToken: AnyObject?
    private var isOnDemandEnabledObservationToken: AnyObject?

    init(tunnel: TunnelContainer, action selector: Selector?) {
        self.tunnel = tunnel
        super.init(title: tunnel.name, action: selector, keyEquivalent: "")
        updateStatus()
        let statusObservationToken = tunnel.observe(\.status) { [weak self] _, _ in
            self?.updateStatus()
        }
        updateTitle()
        let nameObservationToken = tunnel.observe(\TunnelContainer.name) { [weak self] _, _ in
            self?.updateTitle()
        }
        let isOnDemandEnabledObservationToken = tunnel.observe(\.isActivateOnDemandEnabled) { [weak self] _, _ in
            self?.updateTitle()
            self?.updateStatus()
        }
        self.statusObservationToken = statusObservationToken
        self.isOnDemandEnabledObservationToken = isOnDemandEnabledObservationToken
        self.nameObservationToken = nameObservationToken
    }

    required init(coder decoder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func updateTitle() {
        if tunnel.isActivateOnDemandEnabled {
            title = tunnel.name + " (On-Demand)"
        } else {
            title = tunnel.name
        }
    }

    func updateStatus() {
        if tunnel.isActivateOnDemandEnabled {
            state = (tunnel.status == .inactive || tunnel.status == .deactivating) ? .mixed : .on
        } else {
            state = (tunnel.status == .inactive || tunnel.status == .deactivating) ? .off : .on
        }
    }
}

private enum StatusMenuTunnelsPresentationStyle {
    case inline
    case submenu

    func preferredPresentationStyle(numberOfTunnels: Int) -> StatusMenuTunnelsPresentationStyle {
        let maxInlineTunnels = 10

        if case .inline = self, numberOfTunnels > maxInlineTunnels {
            return .submenu
        } else if case .submenu = self, numberOfTunnels <= maxInlineTunnels {
            return .inline
        } else {
            return self
        }
    }
}
