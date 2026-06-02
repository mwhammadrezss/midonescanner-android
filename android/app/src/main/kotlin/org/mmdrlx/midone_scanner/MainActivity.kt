package org.mmdrlx.midone_scanner

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Build
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterActivity() {

    companion object {
        const val CHANNEL = "org.mmdrlx.midone_scanner/dns_vpn"
        const val VPN_REQUEST_CODE = 100
    }

    private var pendingVpnResult: MethodChannel.Result? = null
    private var pendingDns1: String? = null
    private var pendingDns2: String? = null
    private var methodChannel: MethodChannel? = null

    private val vpnStatusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action != DnsVpnService.ACTION_STATUS) return
            val running = intent.getBooleanExtra(DnsVpnService.EXTRA_RUNNING, false)
            val dns1    = intent.getStringExtra(DnsVpnService.EXTRA_DNS1_STATUS)
            val dns2    = intent.getStringExtra(DnsVpnService.EXTRA_DNS2_STATUS)
            methodChannel?.invokeMethod("onVpnStatus", mapOf(
                "running" to running,
                "dns1"    to (dns1 ?: ""),
                "dns2"    to (dns2 ?: "")
            ))
        }
    }

    // ── Flutter Engine ─────────────────────────────────────────────────────

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        methodChannel = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL)
        methodChannel!!.setMethodCallHandler { call, result ->
            when (call.method) {
                "startVpn" -> {
                    val dns1 = call.argument<String>("dns1") ?: "1.1.1.1"
                    val dns2 = call.argument<String>("dns2")
                    handleStartVpn(dns1, dns2, result)
                }
                "stopVpn" -> {
                    stopVpnService()
                    result.success(true)
                }
                "getVpnStatus" -> {
                    result.success(mapOf(
                        "running" to DnsVpnService.isRunning,
                        "dns1"    to (DnsVpnService.activeDns1 ?: ""),
                        "dns2"    to (DnsVpnService.activeDns2 ?: "")
                    ))
                }
                else -> result.notImplemented()
            }
        }
    }

    // ── VPN Start Flow ─────────────────────────────────────────────────────

    private fun handleStartVpn(dns1: String, dns2: String?, result: MethodChannel.Result) {
        // Check if VPN permission is needed
        val vpnIntent = VpnService.prepare(this)
        if (vpnIntent != null) {
            // Need permission dialog
            pendingVpnResult = result
            pendingDns1 = dns1
            pendingDns2 = dns2
            startActivityForResult(vpnIntent, VPN_REQUEST_CODE)
        } else {
            // Permission already granted
            startVpnService(dns1, dns2)
            result.success(true)
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST_CODE) {
            if (resultCode == Activity.RESULT_OK) {
                val dns1 = pendingDns1 ?: "1.1.1.1"
                val dns2 = pendingDns2
                startVpnService(dns1, dns2)
                pendingVpnResult?.success(true)
            } else {
                pendingVpnResult?.error("VPN_DENIED", "User denied VPN permission", null)
            }
            pendingVpnResult = null
            pendingDns1 = null
            pendingDns2 = null
        }
    }

    private fun startVpnService(dns1: String, dns2: String?) {
        val intent = Intent(this, DnsVpnService::class.java).apply {
            action = DnsVpnService.ACTION_START
            putExtra(DnsVpnService.EXTRA_DNS1, dns1)
            if (dns2 != null) putExtra(DnsVpnService.EXTRA_DNS2, dns2)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
    }

    private fun stopVpnService() {
        val intent = Intent(this, DnsVpnService::class.java).apply {
            action = DnsVpnService.ACTION_STOP
        }
        startService(intent)
    }

    // ── Activity Lifecycle ─────────────────────────────────────────────────

    override fun onResume() {
        super.onResume()
        val filter = IntentFilter(DnsVpnService.ACTION_STATUS)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(vpnStatusReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(vpnStatusReceiver, filter)
        }
    }

    override fun onPause() {
        super.onPause()
        try { unregisterReceiver(vpnStatusReceiver) } catch (_: Exception) {}
    }
}
