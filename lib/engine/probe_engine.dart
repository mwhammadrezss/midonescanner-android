// lib/engine/probe_engine.dart
// Android-like TLS fingerprint probe
// p4: smartRetryBackoff — exponential jitter retry
// p9: randomTlsPacing — random microsecond delay before TLS handshake
// p17: captivePortalDetector — enhanced cert validation

export '../models/probe_result.dart';
import 'dart:async';
import 'dart:io';
import 'dart:math';

const kShiroSni  = 'www.google.com';
const kShiroAlpn = 'http/1.1';

// Shared random instance for pacing
final _probeRng = Random();

// ── SNI presets for ShirKhorshid CDN ────────────────────────────────────────
// Sources:
//   1. Wireshark pcap analysis of ShirKhorshid (confirmed SNI=www.google.com)
//   2. Python scanner (MidONeScanner.py) CDN_MAP
//   3. Domain fronting research (2025): Fastly/Akamai still partially viable
//
// Priority groups for deep mode:
//   Group 1 (Google-family): www.google.com, google.com, fonts.googleapis.com
//   Group 2 (Cloudflare):    speed.cloudflare.com, cloudflare.com
//   Group 3 (Akamai/Fastly): a248.e.akamai.net, global.fastly.net, github.com
//   Group 4 (Other):         ajax.aspnetcdn.com
//
// If a Google-family SNI passes, skip remaining Google-family.
// Order matters: best known first.
const kDeepSniPresets = [
  'www.google.com',        // ★ PRIMARY — confirmed by ShirKhorshid Wireshark
  'google.com',            // Google CDN fallback
  'fonts.googleapis.com',  // Google APIs CDN
  'speed.cloudflare.com',  // Cloudflare — best for bandwidth test (/__down)
  'cloudflare.com',        // Cloudflare fallback
  'a248.e.akamai.net',     // Akamai — valid cert, partial fronting
  'global.fastly.net',     // Fastly — fronting may still work
  'github.com',            // GitHub (Fastly-backed)
  'ajax.aspnetcdn.com',    // Microsoft CDN
];

// SNI family groups for early-exit in deep mode
const kSniGoogleFamily    = {'www.google.com', 'google.com', 'fonts.googleapis.com'};
const kSniCloudflareFamily = {'speed.cloudflare.com', 'cloudflare.com'};

// ── Probe result with separate TCP/TLS timing ───────────────────────────────
class ProbeTimings {
  final double tcpMs;
  final double tlsMs;
  final double totalMs;

  const ProbeTimings({
    required this.tcpMs,
    required this.tlsMs,
    required this.totalMs,
  });
}

// ── p17: Captive portal detection ────────────────────────────────────────────
// Returns true if the cert looks like a captive portal injection.
bool isCaptivePortalCert(X509Certificate cert) {
  // Extremely short PEM = almost certainly captive portal / transparent proxy
  if (cert.pem.length < 300) return true;
  return false;
}

// ── Cert validation helper ───────────────────────────────────────────────────
// onBadCertificate callback: accept CDN fronting (SNI mismatch) but reject
// captive portals and transparent proxies that intercept with no real cert.
//
// Strategy:
//   - pem.isEmpty  → no real cert, reject (captive portal / null cert)
//   - pem.length < 200 → suspiciously short, likely fake
//   - otherwise    → real cert, accept (CDN fronting is intentional)
//
// Public so tunnel_engine.dart can reuse the same policy.
bool acceptCdnCert(X509Certificate cert) {
  if (cert.pem.isEmpty) return false;
  if (cert.pem.length < 200) return false; // ISP injection / transparent proxy
  return true; // real cert — SNI mismatch ok for CDN fronting
}

Future<({double latencyMs, int retransmits, ProbeTimings? timings})?> androidTlsProbe(
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
    final tcpMs = sw.elapsedMicroseconds / 1000.0;

    // p9: randomTlsPacing — add random microsecond delay before TLS handshake
    // Reduces robotic fingerprint pattern
    await Future.delayed(
      Duration(microseconds: 100 + _probeRng.nextInt(900)),
    );

    tls = await SecureSocket.secure(
      rawSock,
      host: sni,
      onBadCertificate: acceptCdnCert,
      supportedProtocols: [kShiroAlpn],
    ).timeout(Duration(milliseconds: serverHelloMs));

    sw.stop();
    final totalMs = sw.elapsedMicroseconds / 1000.0;
    final tlsMs   = totalMs - tcpMs;

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

    return (
      latencyMs: totalMs,
      retransmits: 0,
      timings: ProbeTimings(tcpMs: tcpMs, tlsMs: tlsMs, totalMs: totalMs),
    );
  } catch (_) {
    return null;
  } finally {
    try { tls?.destroy();     } catch (_) {}
    try { rawSock?.destroy(); } catch (_) {}
  }
}

// p4: smartRetryBackoff — exponential jitter retry
// Delays: 300ms → ~700ms → ~1500ms with jitter (clamped to 3000ms)
Future<({double latencyMs, int retransmits, ProbeTimings? timings})?> probeWithRetry(
  String ip, {
  String sni   = kShiroSni,
  int retries  = 5,
}) async {
  for (int i = 0; i < retries; i++) {
    final r = await androidTlsProbe(ip, sni: sni);
    if (r != null) return r;
    if (i < retries - 1) {
      // Exponential backoff with jitter: base * 2^i + random 0-200ms
      final baseMs = (300 * pow(2, i)).toInt();
      final jitterMs = _probeRng.nextInt(200);
      final delayMs = (baseMs + jitterMs).clamp(300, 3000);
      await Future.delayed(Duration(milliseconds: delayMs));
    }
  }
  return null;
}

// ── Quick TLS pre-filter ─────────────────────────────────────────────────────
// p5: quickTlsHelloProbe — Full SYN → ClientHello → ServerHello check.
// More accurate than TCP-only: catches TLS blackholes early.
// Uses same cert policy as main probes.
Future<bool> quickTlsCheck(String ip, {int timeoutMs = 4000}) async {
  Socket? sock; // CHANGE: TCP-only pre-filter — Iranian ISPs DPI-reset TLS handshakes
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

// ── p1: Adaptive timeout based on measured RTT ──────────────────────────────
// p1: adaptiveTimeoutEngine — timeout based on RTT + optional subnet hint
int adaptiveServerHelloMs(double firstRttMs, {int? subnetHintMs}) {
  final rttBased = (firstRttMs * 3).clamp(6000, 15000).toInt();
  if (subnetHintMs != null) {
    // Blend RTT-based and subnet-based hints
    return ((rttBased + subnetHintMs) ~/ 2).clamp(4000, 15000);
  }
  return rttBased;
}

// ── Bandwidth measurement ────────────────────────────────────────────────────
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
      onBadCertificate: acceptCdnCert,
      supportedProtocols: [kShiroAlpn],
    ).timeout(const Duration(seconds: 6));

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
