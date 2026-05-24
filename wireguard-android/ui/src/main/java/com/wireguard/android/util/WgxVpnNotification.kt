/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.github.wuruxu.wgx.util

import android.Manifest
import android.annotation.SuppressLint
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.widget.Toast
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.github.wuruxu.wgx.Application.Companion.getTunnelManager
import com.github.wuruxu.wgx.R
import com.github.wuruxu.wgx.activity.MainActivity
import com.github.wuruxu.wgx.backend.Tunnel
import com.github.wuruxu.wgx.model.ObservableTunnel
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

object WgxVpnNotification {
    const val ACTION_DISCONNECT = "com.github.wuruxu.wgx.action.DISCONNECT_FROM_NOTIFICATION"
    private const val CHANNEL_ID = "wgx_vpn_status"
    private const val NOTIFICATION_ID = 1001
    private var updaterJob: Job? = null

    fun start(context: Context, tunnel: ObservableTunnel) {
        if (!canPostNotifications(context))
            return
        createChannel(context)
        updaterJob?.cancel()
        updaterJob = applicationScope.launch {
            while (isActive && tunnel.state == Tunnel.State.UP) {
                show(context, tunnel)
                delay(1000)
            }
        }
    }

    fun stop(context: Context) {
        updaterJob?.cancel()
        updaterJob = null
        NotificationManagerCompat.from(context).cancel(NOTIFICATION_ID)
    }

    @SuppressLint("MissingPermission")
    private fun show(context: Context, tunnel: ObservableTunnel) {
        val statistics = tunnel.statistics
        val transfer = context.getString(
            R.string.transfer_rx_tx_arrows,
            QuantityFormatter.formatBytes(statistics?.totalRx() ?: 0L),
            QuantityFormatter.formatBytes(statistics?.totalTx() ?: 0L)
        )
        val content = context.getString(R.string.wgx_vpn_notification_content, transfer)
        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_tile)
            .setContentTitle(context.getString(R.string.wgx_vpn_notification_title, tunnel.name))
            .setContentText(content)
            .setStyle(NotificationCompat.BigTextStyle().bigText(content))
            .setContentIntent(mainActivityIntent(context))
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_STATUS)
            .addAction(
                R.drawable.ic_action_delete,
                context.getString(R.string.wgx_vpn_notification_disconnect),
                disconnectIntent(context, tunnel.name)
            )
            .build()
        NotificationManagerCompat.from(context).notify(NOTIFICATION_ID, notification)
    }

    fun canPostNotifications(context: Context): Boolean {
        return Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
    }

    private fun createChannel(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O)
            return
        val channel = NotificationChannel(
            CHANNEL_ID,
            context.getString(R.string.wgx_vpn_notification_channel),
            NotificationManager.IMPORTANCE_LOW
        )
        context.getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    private fun disconnectIntent(context: Context, tunnelName: String): PendingIntent {
        val intent = Intent(context, DisconnectReceiver::class.java).apply {
            action = ACTION_DISCONNECT
            putExtra("tunnel", tunnelName)
        }
        return PendingIntent.getBroadcast(
            context,
            NOTIFICATION_ID,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
    }

    class DisconnectReceiver : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent?) {
            applicationScope.launch {
                if (intent?.action != ACTION_DISCONNECT)
                    return@launch
                val tunnelName = intent.getStringExtra("tunnel") ?: return@launch
                val manager = getTunnelManager()
                val tunnel = manager.getTunnels()[tunnelName] ?: return@launch
                try {
                    manager.setTunnelState(tunnel, Tunnel.State.DOWN)
                } catch (e: Throwable) {
                    Toast.makeText(context, ErrorMessages[e], Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    private fun mainActivityIntent(context: Context): PendingIntent {
        val intent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        return PendingIntent.getActivity(
            context,
            NOTIFICATION_ID,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
    }
}
