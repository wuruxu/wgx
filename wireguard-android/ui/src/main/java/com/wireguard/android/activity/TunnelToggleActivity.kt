/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.github.wuruxu.wgx.activity

import android.Manifest
import android.content.ComponentName
import android.os.Build
import android.os.Bundle
import android.service.quicksettings.TileService
import android.util.Log
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.github.wuruxu.wgx.Application
import com.github.wuruxu.wgx.QuickTileService
import com.github.wuruxu.wgx.R
import com.github.wuruxu.wgx.backend.WgxBackend
import com.github.wuruxu.wgx.backend.Tunnel
import com.github.wuruxu.wgx.util.ErrorMessages
import com.github.wuruxu.wgx.util.WgxVpnNotification
import kotlinx.coroutines.launch

class TunnelToggleActivity : AppCompatActivity() {
    private val permissionActivityResultLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { toggleTunnelWithPermissionsResult() }
    private val notificationPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) {
            val tunnel = Application.getTunnelManager().lastUsedTunnel
            if (it && tunnel != null && tunnel.state == Tunnel.State.UP)
                WgxVpnNotification.start(this, tunnel)
            TileService.requestListeningState(this, ComponentName(this, QuickTileService::class.java))
            finishAffinity()
        }

    private fun toggleTunnelWithPermissionsResult() {
        val tunnel = Application.getTunnelManager().lastUsedTunnel ?: return
        lifecycleScope.launch {
            try {
                val state = tunnel.setStateAsync(Tunnel.State.TOGGLE)
                if (state == Tunnel.State.UP && !WgxVpnNotification.canPostNotifications(this@TunnelToggleActivity) && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                    return@launch
                }
            } catch (e: Throwable) {
                TileService.requestListeningState(this@TunnelToggleActivity, ComponentName(this@TunnelToggleActivity, QuickTileService::class.java))
                val error = ErrorMessages[e]
                val message = getString(R.string.toggle_error, error)
                Log.e(TAG, message, e)
                Toast.makeText(this@TunnelToggleActivity, message, Toast.LENGTH_LONG).show()
                finishAffinity()
                return@launch
            }
            TileService.requestListeningState(this@TunnelToggleActivity, ComponentName(this@TunnelToggleActivity, QuickTileService::class.java))
            finishAffinity()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        lifecycleScope.launch {
            if (Application.getBackend() is WgxBackend) {
                try {
                    val intent = WgxBackend.VpnService.prepare(this@TunnelToggleActivity)
                    if (intent != null) {
                        permissionActivityResultLauncher.launch(intent)
                        return@launch
                    }
                } catch (e: Exception) {
                    Toast.makeText(this@TunnelToggleActivity, ErrorMessages[e], Toast.LENGTH_LONG).show()
                }
            }
            toggleTunnelWithPermissionsResult()
        }
    }

    companion object {
        private const val TAG = "WireGuard/TunnelToggleActivity"
    }
}
