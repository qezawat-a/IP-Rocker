package com.qezawat.iprocker.data

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities

/** Checks the network a scan would run on. */
object NetworkGuard {

    /**
     * True when a VPN is the active network. A scan through a VPN measures the
     * VPN's route to Cloudflare rather than the route from the user's own
     * connection, and DNS answers come from the VPN's resolver, so the results
     * would not describe the user's network.
     */
    fun vpnActive(context: Context): Boolean {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return false
        val network = cm.activeNetwork ?: return false
        val caps = cm.getNetworkCapabilities(network) ?: return false
        return caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
    }
}
