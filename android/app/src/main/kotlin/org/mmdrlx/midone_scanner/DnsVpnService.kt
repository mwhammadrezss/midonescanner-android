package org.mmdrlx.midone_scanner

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicBoolean

class DnsVpnService : VpnService() {

    companion object {
        const val TAG = "DnsVpnService"
        const val CHANNEL_ID = "dns_vpn_channel"
        const val NOTIF_ID = 9001
        const val ACTION_START  = "ACTION_START_DNS_VPN"
        const val ACTION_STOP   = "ACTION_STOP_DNS_VPN"
        const val EXTRA_DNS1    = "dns1"
        const val EXTRA_DNS2    = "dns2"
        const val ACTION_STATUS = "org.mmdrlx.midone_scanner.DNS_VPN_STATUS"
        const val EXTRA_RUNNING      = "running"
        const val EXTRA_DNS1_STATUS  = "dns1_status"
        const val EXTRA_DNS2_STATUS  = "dns2_status"

        @Volatile var isRunning:   Boolean = false
        @Volatile var activeDns1:  String? = null
        @Volatile var activeDns2:  String? = null
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private val running = AtomicBoolean(false)
    private var tunnelThread: Thread? = null

    // ── Lifecycle ──────────────────────────────────────────────────────────

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopVpn()
                return START_NOT_STICKY
            }
            ACTION_START -> {
                val dns1 = intent.getStringExtra(EXTRA_DNS1) ?: "1.1.1.1"
                val dns2 = intent.getStringExtra(EXTRA_DNS2)
                startVpn(dns1, dns2)
            }
        }
        return START_STICKY
    }

    override fun onRevoke() {
        stopVpn()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    // ── Start / Stop ───────────────────────────────────────────────────────

    private fun startVpn(dns1: String, dns2: String?) {
        if (running.get()) stopVpn()

        activeDns1 = dns1
        activeDns2 = dns2

        val builder = Builder()
            .setSession("MidONe DNS")
            .addAddress("10.111.222.1", 30)
            .addRoute("0.0.0.0", 0)
            .setMtu(1500)
            .addDnsServer(dns1)
            .addDisallowedApplication(packageName)

        if (dns2 != null) {
            try { builder.addDnsServer(dns2) } catch (_: Exception) {}
        }

        vpnInterface = builder.establish() ?: run {
            Log.e(TAG, "VPN establish() returned null")
            broadcastStatus(false)
            return
        }

        running.set(true)
        isRunning = true
        broadcastStatus(true)
        startForegroundNotif()

        tunnelThread = Thread({ runTunnel(dns1, dns2) }, "dns-vpn-tunnel").also { it.start() }
        Log.i(TAG, "VPN started — DNS1=$dns1 DNS2=$dns2")
    }

    private fun stopVpn() {
        running.set(false)
        isRunning  = false
        activeDns1 = null
        activeDns2 = null
        tunnelThread?.interrupt()
        tunnelThread = null
        try { vpnInterface?.close() } catch (_: Exception) {}
        vpnInterface = null
        broadcastStatus(false)
        stopForeground(true)
        stopSelf()
        Log.i(TAG, "VPN stopped")
    }

    // ── Tunnel Loop ────────────────────────────────────────────────────────

    private fun runTunnel(dns1: String, dns2: String?) {
        val pfd  = vpnInterface ?: return
        val ins  = FileInputStream(pfd.fileDescriptor)
        val outs = FileOutputStream(pfd.fileDescriptor)
        val buf  = ByteArray(32767)

        while (running.get()) {
            try {
                val len = ins.read(buf)
                if (len <= 0) { Thread.sleep(10); continue }

                if (len < 28) continue // min IPv4(20)+UDP(8)

                val ipVersion    = (buf[0].toInt() shr 4) and 0xF
                if (ipVersion != 4) continue

                val ipHeaderLen  = (buf[0].toInt() and 0xF) * 4
                val protocol     = buf[9].toInt() and 0xFF
                if (protocol != 17) continue // UDP only

                val dstPort = ((buf[ipHeaderLen + 2].toInt() and 0xFF) shl 8) or
                               (buf[ipHeaderLen + 3].toInt() and 0xFF)
                if (dstPort != 53) continue

                val srcPort = ((buf[ipHeaderLen].toInt() and 0xFF) shl 8) or
                               (buf[ipHeaderLen + 1].toInt() and 0xFF)

                val payloadOffset = ipHeaderLen + 8
                val payloadLen    = len - payloadOffset
                if (payloadLen <= 0) continue

                val dnsQuery = buf.copyOfRange(payloadOffset, payloadOffset + payloadLen)
                val srcIpBytes = buf.copyOfRange(12, 16)  // original source IP

                val response = forwardDns(dnsQuery, dns1, dns2) ?: continue

                val resp = buildUdpPacket(
                    srcIp   = byteArrayOf(10, 111.toByte(), 222.toByte(), 1),
                    dstIp   = srcIpBytes,
                    srcPort = 53,
                    dstPort = srcPort,
                    payload = response
                )
                outs.write(resp)
            } catch (_: InterruptedException) {
                break
            } catch (e: Exception) {
                if (!running.get()) break
                Log.w(TAG, "Tunnel error: ${e.message}")
            }
        }
    }

    // ── DNS Forwarding ─────────────────────────────────────────────────────

    private fun forwardDns(query: ByteArray, dns1: String, dns2: String?): ByteArray? {
        for (upstream in listOfNotNull(dns1, dns2)) {
            try {
                val sock = DatagramSocket()
                protect(sock)
                sock.soTimeout = 3000
                val addr = InetAddress.getByName(upstream)
                sock.send(DatagramPacket(query, query.size, addr, 53))
                val respBuf = ByteArray(4096)
                val respPkt = DatagramPacket(respBuf, respBuf.size)
                sock.receive(respPkt)
                sock.close()
                return respBuf.copyOf(respPkt.length)
            } catch (_: Exception) {
                // try fallback
            }
        }
        return null
    }

    // ── Packet Builder ─────────────────────────────────────────────────────

    private fun buildUdpPacket(
        srcIp: ByteArray, dstIp: ByteArray,
        srcPort: Int, dstPort: Int,
        payload: ByteArray
    ): ByteArray {
        val udpLen   = 8 + payload.size
        val totalLen = 20 + udpLen
        val buf = ByteBuffer.allocate(totalLen)

        // IPv4 header
        buf.put(0x45.toByte())               // version=4, IHL=5
        buf.put(0.toByte())                  // DSCP/ECN
        buf.putShort(totalLen.toShort())     // total length
        buf.putShort(0.toShort())            // identification
        buf.putShort(0x4000.toShort())       // flags: Don't Fragment
        buf.put(64.toByte())                 // TTL
        buf.put(17.toByte())                 // protocol: UDP
        buf.putShort(0.toShort())            // checksum placeholder
        buf.put(srcIp)
        buf.put(dstIp)

        // IP checksum
        val ipChecksum = checksum(buf.array(), 0, 20)
        buf.putShort(10, ipChecksum)

        // UDP header
        buf.putShort(srcPort.toShort())
        buf.putShort(dstPort.toShort())
        buf.putShort(udpLen.toShort())
        buf.putShort(0.toShort())            // UDP checksum optional

        // Payload
        buf.put(payload)
        return buf.array()
    }

    private fun checksum(data: ByteArray, offset: Int, length: Int): Short {
        var sum = 0L
        var i = offset
        while (i < offset + length - 1) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if ((offset + length) % 2 != 0) {
            sum += (data[offset + length - 1].toInt() and 0xFF) shl 8
        }
        while (sum shr 16 != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        return (sum.inv() and 0xFFFF).toShort()
    }

    // ── Foreground Notification ────────────────────────────────────────────

    private fun startForegroundNotif() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID, "DNS VPN",
                NotificationManager.IMPORTANCE_LOW
            ).apply { description = "MidONe active DNS tunnel" }
            getSystemService(NotificationManager::class.java)
                .createNotificationChannel(channel)
        }

        val stopIntent = PendingIntent.getService(
            this, 0,
            Intent(this, DnsVpnService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notif = (if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
            Notification.Builder(this, CHANNEL_ID)
        else
            @Suppress("DEPRECATION") Notification.Builder(this))
            .setSmallIcon(android.R.drawable.ic_menu_compass)
            .setContentTitle("MidONe DNS Active")
            .setContentText("DNS → ${activeDns1}")
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Stop", stopIntent)
            .setOngoing(true)
            .build()

        startForeground(NOTIF_ID, notif)
    }

    // ── Broadcast ─────────────────────────────────────────────────────────

    private fun broadcastStatus(isRunning: Boolean) {
        val intent = Intent(ACTION_STATUS).apply {
            putExtra(EXTRA_RUNNING,     isRunning)
            putExtra(EXTRA_DNS1_STATUS, activeDns1)
            putExtra(EXTRA_DNS2_STATUS, activeDns2)
        }
        sendBroadcast(intent)
    }
}
