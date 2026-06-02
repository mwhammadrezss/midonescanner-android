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
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.nio.ByteBuffer
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

class DnsVpnService : VpnService() {

    companion object {
        const val TAG               = "DnsVpnService"
        const val CHANNEL_ID        = "dns_vpn_channel"
        const val NOTIF_ID          = 9001
        const val ACTION_START      = "ACTION_START_DNS_VPN"
        const val ACTION_STOP       = "ACTION_STOP_DNS_VPN"
        const val EXTRA_DNS1        = "dns1"
        const val EXTRA_DNS2        = "dns2"
        const val ACTION_STATUS     = "org.mmdrlx.midone_scanner.DNS_VPN_STATUS"
        const val EXTRA_RUNNING     = "running"
        const val EXTRA_DNS1_STATUS = "dns1_status"
        const val EXTRA_DNS2_STATUS = "dns2_status"

        @Volatile var isRunning:  Boolean = false
        @Volatile var activeDns1: String? = null
        @Volatile var activeDns2: String? = null
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private val running      = AtomicBoolean(false)
    private var tunnelThread: Thread? = null
    // Thread pool: هر DNS query موازی handle می‌شه
    private val dnsPool = Executors.newFixedThreadPool(8)

    // ── Lifecycle ──────────────────────────────────────────────────────────

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> { stopVpn(); return START_NOT_STICKY }
            ACTION_START -> {
                val dns1 = intent.getStringExtra(EXTRA_DNS1) ?: "1.1.1.1"
                val dns2 = intent.getStringExtra(EXTRA_DNS2)
                startVpn(dns1, dns2)
            }
        }
        return START_STICKY
    }

    override fun onRevoke() { stopVpn(); super.onRevoke() }
    override fun onDestroy() { stopVpn(); super.onDestroy() }

    // ── Start / Stop ───────────────────────────────────────────────────────

    private fun startVpn(dns1: String, dns2: String?) {
        if (running.get()) stopVpn()

        activeDns1 = dns1
        activeDns2 = dns2

        // ════════════════════════════════════════════════════════════════════
        // KEY FIX: addRoute فقط برای IP های DNS server، نه 0.0.0.0/0
        // یعنی فقط DNS traffic از tunnel رد می‌شه.
        // همه ترافیک دیگه (بازی، مرورگر، ...) مستقیم از شبکه واقعی میره.
        // ════════════════════════════════════════════════════════════════════
        val builder = Builder()
            .setSession("MidONe DNS")
            .addAddress("10.111.222.1", 32)
            .setMtu(1500)
            .addDnsServer(dns1)
            .addRoute(dns1, 32)           // فقط dns1 IP از TUN رد بشه
            .addDisallowedApplication(packageName)

        if (dns2 != null) {
            try {
                builder.addDnsServer(dns2)
                builder.addRoute(dns2, 32)  // فقط dns2 IP هم از TUN
            } catch (_: Exception) {}
        }

        vpnInterface = builder.establish() ?: run {
            Log.e(TAG, "establish() failed")
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
        dnsPool.shutdownNow()
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
            // FIX: handle non-blocking TUN read (EAGAIN → IOException)
            val len = try {
                ins.read(buf)
            } catch (e: IOException) {
                if (!running.get()) break
                Thread.sleep(5)
                continue
            }

            if (len <= 0) { Thread.sleep(5); continue }

            // Bounds check قبل از هر parse
            if (len < 20) continue                                    // min IPv4 header
            val ipVersion   = (buf[0].toInt() shr 4) and 0xF
            if (ipVersion != 4) continue
            val ipHeaderLen = (buf[0].toInt() and 0xF) * 4
            if (ipHeaderLen < 20 || len < ipHeaderLen + 8) continue   // malformed
            val protocol = buf[9].toInt() and 0xFF
            if (protocol != 17) continue                               // UDP only

            val dstPort = ((buf[ipHeaderLen + 2].toInt() and 0xFF) shl 8) or
                           (buf[ipHeaderLen + 3].toInt() and 0xFF)
            if (dstPort != 53) continue                                // DNS only

            val srcPort       = ((buf[ipHeaderLen].toInt() and 0xFF) shl 8) or
                                 (buf[ipHeaderLen + 1].toInt() and 0xFF)
            val payloadOffset = ipHeaderLen + 8
            val payloadLen    = len - payloadOffset
            if (payloadLen <= 0) continue

            // snapshot قبل از넘ردن به thread
            val dnsQuery   = buf.copyOfRange(payloadOffset, payloadOffset + payloadLen)
            val srcIpBytes = buf.copyOfRange(12, 16)

            // FIX: هر query موازی forward می‌شه — tunnel block نمی‌شه
            dnsPool.execute {
                try {
                    val response = forwardDns(dnsQuery, dns1, dns2) ?: return@execute
                    val parts = dns1.split(".")
                    val srcIpArr = try {
                        byteArrayOf(parts[0].toInt().toByte(), parts[1].toInt().toByte(),
                                    parts[2].toInt().toByte(), parts[3].toInt().toByte())
                    } catch (_: Exception) { byteArrayOf(10, 111.toByte(), 222.toByte(), 1) }
                    val resp = buildUdpPacket(
                        srcIp   = srcIpArr,
                        dstIp   = srcIpBytes,
                        srcPort = 53,
                        dstPort = srcPort,
                        payload = response
                    )
                    synchronized(outs) { outs.write(resp) }
                } catch (e: Exception) {
                    Log.w(TAG, "DNS dispatch error: ${e.message}")
                }
            }
        }
    }

    // ── DNS Forwarding — با socket leak fix ───────────────────────────────

    private fun forwardDns(query: ByteArray, dns1: String, dns2: String?): ByteArray? {
        for (upstream in listOfNotNull(dns1, dns2)) {
            // FIX: try-finally تضمین می‌کنه socket همیشه بسته می‌شه
            val sock = DatagramSocket()
            try {
                protect(sock)
                sock.soTimeout = 3000
                val addr = InetAddress.getByName(upstream)
                sock.send(DatagramPacket(query, query.size, addr, 53))
                val respBuf = ByteArray(4096)
                val respPkt = DatagramPacket(respBuf, respBuf.size)
                sock.receive(respPkt)
                return respBuf.copyOf(respPkt.length)
            } catch (_: Exception) {
                // fallback به dns2
            } finally {
                try { sock.close() } catch (_: Exception) {}
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

        buf.put(0x45.toByte())
        buf.put(0.toByte())
        buf.putShort((totalLen and 0xFFFF).toShort())
        buf.putShort(0.toShort())
        buf.putShort(0x4000.toShort())
        buf.put(64.toByte())
        buf.put(17.toByte())
        buf.putShort(0.toShort())   // checksum placeholder
        buf.put(srcIp)
        buf.put(dstIp)

        // IP checksum
        buf.putShort(10, checksum(buf.array(), 0, 20))

        buf.putShort(srcPort.toShort())
        buf.putShort(dstPort.toShort())
        buf.putShort((udpLen and 0xFFFF).toShort())
        buf.putShort(0.toShort())   // UDP checksum — 0 = valid در IPv4

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
        if ((offset + length) % 2 != 0)
            sum += (data[offset + length - 1].toInt() and 0xFF) shl 8
        while (sum shr 16 != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        return (sum.inv() and 0xFFFF).toShort()
    }

    // ── Notification ───────────────────────────────────────────────────────

    private fun startForegroundNotif() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val ch = NotificationChannel(CHANNEL_ID, "DNS VPN", NotificationManager.IMPORTANCE_LOW)
                .apply { description = "MidONe DNS tunnel active" }
            getSystemService(NotificationManager::class.java).createNotificationChannel(ch)
        }

        val stopPi = PendingIntent.getService(
            this, 0,
            Intent(this, DnsVpnService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        @Suppress("DEPRECATION")
        val notif = (if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
            Notification.Builder(this, CHANNEL_ID)
        else
            Notification.Builder(this))
            .setSmallIcon(android.R.drawable.ic_menu_compass)
            .setContentTitle("MidONe DNS Active")
            .setContentText("→ ${activeDns1}")
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Stop", stopPi)
            .setOngoing(true)
            .build()

        startForeground(NOTIF_ID, notif)
    }

    // ── Broadcast ─────────────────────────────────────────────────────────

    private fun broadcastStatus(isRunning: Boolean) {
        sendBroadcast(Intent(ACTION_STATUS).apply {
            putExtra(EXTRA_RUNNING,     isRunning)
            putExtra(EXTRA_DNS1_STATUS, activeDns1)
            putExtra(EXTRA_DNS2_STATUS, activeDns2)
        })
    }
}
