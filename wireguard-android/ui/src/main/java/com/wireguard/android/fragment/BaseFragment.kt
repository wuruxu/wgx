/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.github.wuruxu.wgx.fragment

import android.Manifest
import android.content.Context
import android.os.Build
import android.util.Log
import android.view.View
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.databinding.DataBindingUtil
import androidx.databinding.ViewDataBinding
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.google.android.material.snackbar.Snackbar
import com.github.wuruxu.wgx.Application
import com.github.wuruxu.wgx.R
import com.github.wuruxu.wgx.activity.BaseActivity
import com.github.wuruxu.wgx.activity.BaseActivity.OnSelectedTunnelChangedListener
import com.github.wuruxu.wgx.backend.WgxBackend
import com.github.wuruxu.wgx.backend.Tunnel
import com.github.wuruxu.wgx.databinding.TunnelDetailFragmentBinding
import com.github.wuruxu.wgx.databinding.TunnelListItemBinding
import com.github.wuruxu.wgx.model.ObservableTunnel
import com.github.wuruxu.wgx.util.ErrorMessages
import com.github.wuruxu.wgx.util.WgxVpnNotification
import kotlinx.coroutines.launch

/**
 * Base class for fragments that need to know the currently-selected tunnel. Only does anything when
 * attached to a `BaseActivity`.
 */
abstract class BaseFragment : Fragment(), OnSelectedTunnelChangedListener {
    private var pendingTunnel: ObservableTunnel? = null
    private var pendingTunnelUp: Boolean? = null
    private var pendingNotificationTunnel: ObservableTunnel? = null
    private val permissionActivityResultLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        val tunnel = pendingTunnel
        val checked = pendingTunnelUp
        if (tunnel != null && checked != null)
            setTunnelStateWithPermissionsResult(tunnel, checked)
        pendingTunnel = null
        pendingTunnelUp = null
    }
    private val notificationPermissionLauncher = registerForActivityResult(ActivityResultContracts.RequestPermission()) {
        val tunnel = pendingNotificationTunnel
        val context = context
        if (it && tunnel != null && context != null)
            WgxVpnNotification.start(context, tunnel)
        pendingNotificationTunnel = null
    }

    protected var selectedTunnel: ObservableTunnel?
        get() = (activity as? BaseActivity)?.selectedTunnel
        protected set(tunnel) {
            (activity as? BaseActivity)?.selectedTunnel = tunnel
        }

    override fun onAttach(context: Context) {
        super.onAttach(context)
        (activity as? BaseActivity)?.addOnSelectedTunnelChangedListener(this)
    }

    override fun onDetach() {
        (activity as? BaseActivity)?.removeOnSelectedTunnelChangedListener(this)
        super.onDetach()
    }

    fun setTunnelState(view: View, checked: Boolean) {
        val tunnel = when (val binding = DataBindingUtil.findBinding<ViewDataBinding>(view)) {
            is TunnelDetailFragmentBinding -> binding.tunnel
            is TunnelListItemBinding -> binding.item
            else -> return
        } ?: return
        val activity = activity ?: return
        activity.lifecycleScope.launch {
            if (Application.getBackend() is WgxBackend) {
                try {
                    val intent = WgxBackend.VpnService.prepare(activity)
                    if (intent != null) {
                        pendingTunnel = tunnel
                        pendingTunnelUp = checked
                        permissionActivityResultLauncher.launch(intent)
                        return@launch
                    }
                } catch (e: Throwable) {
                    val message = activity.getString(R.string.error_prepare, ErrorMessages[e])
                    Snackbar.make(view, message, Snackbar.LENGTH_LONG)
                        .setAnchorView(view.findViewById(R.id.create_fab))
                        .show()
                    Log.e(TAG, message, e)
                }
            }
            setTunnelStateWithPermissionsResult(tunnel, checked)
        }
    }

    private fun setTunnelStateWithPermissionsResult(tunnel: ObservableTunnel, checked: Boolean) {
        val activity = activity ?: return
        activity.lifecycleScope.launch {
            try {
                val state = tunnel.setStateAsync(Tunnel.State.of(checked))
                if (state == Tunnel.State.UP)
                    showNotificationWithPermission(tunnel)
            } catch (e: Throwable) {
                val error = ErrorMessages[e]
                val messageResId = if (checked) R.string.error_up else R.string.error_down
                val message = activity.getString(messageResId, error)
                val view = view
                if (view != null)
                    Snackbar.make(view, message, Snackbar.LENGTH_LONG)
                        .setAnchorView(view.findViewById(R.id.create_fab))
                        .show()
                else
                    Toast.makeText(activity, message, Toast.LENGTH_LONG).show()
                Log.e(TAG, message, e)
            }
        }
    }

    private fun showNotificationWithPermission(tunnel: ObservableTunnel) {
        val context = context ?: return
        if (WgxVpnNotification.canPostNotifications(context)) {
            WgxVpnNotification.start(context, tunnel)
            return
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pendingNotificationTunnel = tunnel
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    companion object {
        private const val TAG = "WireGuard/BaseFragment"
    }
}
