// lib/engine/probe_engine.dart
// Android-like TLS fingerprint probe
export '../models/probe_result.dart';
import 'dart:async';
import 'dart:io';

const kShiroSni  = 'www.google.com';
const kShiroAlpn = 'http/1.1';

// ── SNI presets for ShirKhorshid CDN ────────────────────────────────────────
// Sources:
//   1. Wireshark pcap analysis of ShirKhorshid (confirmed SNI=www.google.com)
//   2. Python scanner (MidONeScanner.py) CDN_MAP
//   3. Domain fronting research (2025): Fastly/Akamai still partially viable
//
// For ShirKhorshid (uses Google CDN mode): www.google.com is primary.
// Other SNIs are tested in Deep mode to find best-performing CDN edge IP.
//
// Domain fronting status (2026):
//   Google: disabled 2018 — but Google CDN IPs still reachable via TLS probe
//   Cloudflare: disabled 2015 — IPs still scannable
//   Akamai (a248.e.akamai.net): still valid cert/SNI, partial fronting
//   Fastly (global.fastly.net): varies by customer config, may still work
//   Microsoft/Azure: disabled 2022
const kDeepSniPresets = [
  'www.google.com',        // ★ PRIMARY — confirmed by ShirKhorshid Wireshark
  'google.com',            // Google CDN fallback
  'speed.cloudflare.com',  // Cloudflare — best for bandwidth test (/__down)
  'cloudflare.com',        // Cloudflare fallback
  'a248.e.akamai.net',     // Akamai — valid cert, partial fronting
  'fonts.googleapis.com',  // Google APIs CDN
  'global.fastly.net',     // Fastly — fronting may still work
  'github.com',            // GitHub (Fastly-backed)
  'ajax.aspnetcdn.com',    // Microsoft CDN
];

Future<({double latencyMs, int retransmits})?> androidTlsProbe(
  String ip, {
  String sni           = kShiroSni,
  int timeoutMs        = 5000,
  int serverHelloMs    = 6000,
}) async {
  Socket?       rawSock;
  SecureSocket? tls;
  try {
    final sw = Stopwatch()..start();

    rawSock = await Socket.connect(
      ip, 443,
      timeout: Duration(milliseconds: timeoutMs),
    );

    tls = await SecureSocket.secure(
      rawSock,
      host: sni,
      onBadCertificate: (_) => true,
      supportedProtocols: [kShiroAlpn],
    ).timeout(Duration(milliseconds: serverHelloMs));

    sw.stop();

    // Drain a tiny bit to confirm ApplicationData (Phase 4)
    final completer = Completer<void>();
    StreamSubscription? sub;
    sub = tls.listen(
      (_) { if (!completer.isCompleted) completer.complete(); },
      onError: (_) { if (!completer.isCompleted) completer.complete(); },
      onDone:  () { if (!completer.isCompleted) completer.complete(); },
    );
    await completer.future
        .timeout(const Duration(seconds: 2))
        .catchError((_) {});
    await sub.cancel();

    try { await tls.close(); } catch (_) {}
    tls.destroy();

    return (latencyMs: sw.elapsedMicroseconds / 1000.0, retransmits: 0);
  } catch (_) {
    return null;
  } finally {
    try { tls?.destroy();     } catch (_) {}
    try { rawSock?.destroy(); } catch (_) {}
  }
}

Future<({double latencyMs, int retransmits})?> probeWithRetry(
  String ip, {
  String sni   = kShiroSni,
  int retries  = 5,
}) async {
  for (int i = 0; i < retries; i++) {
    final r = await androidTlsProbe(ip, sni: sni);
    if (r != null) return r;
    if (i < retries - 1) {
      await Future.delayed(const Duration(milliseconds: 300));
    }
  }
  return null;
}

// ── Quick TCP pre-filter — detect dead/fake IPs fast ────────────────────────
// Run with high concurrency before full scan to skip clearly dead IPs.
Future<bool> quickTcpCheck(String ip, {int timeoutMs = 3000}) async {
  Socket? sock;
  try {
    sock = await Socket.connect(
      ip, 443,
      timeout: Duration(milliseconds: timeoutMs),
    );
    return true;
  } catch (_) {
    return false;
  } finally {
    try { sock?.destroy(); } catch (_) {}
  }
}

// ── Bandwidth measurement (Normal mode) ─────────────────────────────────────
// Matches the Python scanner (MidONeScanner.py) method.
// Sends HTTP GET and measures download speed in KB/s.
Future<double?> measureBandwidthKBs(
  String ip, {
  String sni        = kShiroSni,
  int testDurationMs = 5000,
}) async {
  Socket?       rawSock;
  SecureSocket? tls;
  StreamSubscription? sub;
  try {
    rawSock = await Socket.connect(
      ip, 443,
      timeout: const Duration(seconds: 4),
    );

    tls = await SecureSocket.secure(
      rawSock,
      host: sni,
      onBadCertificate: (_) => true,
      supportedProtocols: [kShiroAlpn],
    ).timeout(const Duration(seconds: 6));

    // Use Cloudflare speed endpoint if SNI matches, else GET /
    final path = sni == 'speed.cloudflare.com'
        ? '/__down?bytes=8000000'
        : '/';

    tls.write(
      'GET $path HTTP/1.1\r\n'
      'Host: $sni\r\n'
      'User-Agent: Android\r\n'
      'Accept: */*\r\n'
      'Connection: close\r\n\r\n',
    );

    int   total     = 0;
    final sw        = Stopwatch()..start();
    final completer = Completer<void>();

    sub = tls.listen(
      (chunk) {
        total += chunk.length;
        if (sw.elapsed.inMilliseconds >= testDurationMs) {
          if (!completer.isCompleted) completer.complete();
        }
      },
      onError: (_) { if (!completer.isCompleted) completer.complete(); },
      onDone:  () { if (!completer.isCompleted) completer.complete(); },
      cancelOnError: true,
    );

    await completer.future
        .timeout(Duration(milliseconds: testDurationMs + 2000))
        .catchError((_) {});

    sw.stop();
    await sub.cancel();
    try { await tls.close(); } catch (_) {}
    tls.destroy();

    final elapsedSec = sw.elapsedMilliseconds / 1000.0;
    if (total >= 4096 && elapsedSec > 0) {
      final speedKBs = (total / 1024.0) / elapsedSec;
      return double.parse(speedKBs.toStringAsFixed(1));
    }
    return null;
  } catch (_) {
    return null;
  } finally {
    try { sub?.cancel();      } catch (_) {}
    try { tls?.destroy();     } catch (_) {}
    try { rawSock?.destroy(); } catch (_) {}
  }
}

// ProbeResult is defined in models/probe_result.dart (re-exported above)
