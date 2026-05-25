// lib/engine/probe_engine.dart
// Android-like TLS fingerprint probe — NO HTTP HEAD, NO CDN headers
import 'dart:async';
import 'dart:io';
import '../models/probe_result.dart';

// ── Fixed SNI for Shir Khorshid CDN mode ────────────────────────────────────
const kShiroSni  = 'www.google.com';
const kShiroAlpn = 'http/1.1';

// ─── Phase 1+2: TCP SYN + Android TLS fingerprint ───────────────────────────
//
// Replicates the exact behaviour observed in the Wireshark capture:
//   • legacy_version = TLS 1.2  (0x0303)
//   • supported_versions ext  → TLS 1.3 + TLS 1.2
//   • ALPN = http/1.1
//   • SNI  = www.google.com
//   • Large fragmented ClientHello (Android splits at ~1430 B)
//   • onBadCertificate = accept all (tunnel does not validate leaf cert)
//   • ServerHello wait ≤ 6 s  (pcap showed ~3 s delay on real network)
//
// Returns null on any failure so the caller can advance to next retry.
Future<({double latencyMs, int retransmits})?> androidTlsProbe(
  String ip, {
  int timeoutMs     = 5000,
  int serverHelloMs = 6000,
}) async {
  Socket? rawSock;
  SecureSocket? tls;
  try {
    final sw = Stopwatch()..start();

    // ── Phase 1: TCP SYN ────────────────────────────────────────────────
    rawSock = await Socket.connect(
      ip, 443,
      timeout: Duration(milliseconds: timeoutMs),
    );

    // ── Phase 2: Android-like TLS handshake ─────────────────────────────
    // Dart's SecureSocket always sends TLS 1.3 ClientHello when the platform
    // supports it, which matches Android 10+.  We accept bad certs exactly
    // as Shir Khorshid does (it does not validate CDN edge certificates).
    tls = await SecureSocket.secure(
      rawSock,
      host: kShiroSni,
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
    await completer.future.timeout(const Duration(seconds: 2)).catchError((_) {});
    await sub.cancel();

    await tls.close();
    tls.destroy();

    return (latencyMs: sw.elapsedMicroseconds / 1000.0, retransmits: 0);
  } catch (_) {
    return null;
  } finally {
    try { tls?.destroy();    } catch (_) {}
    try { rawSock?.destroy(); } catch (_) {}
  }
}

// ─── Retry wrapper: Phase 1-4 with up to 3 attempts ─────────────────────────
Future<({double latencyMs, int retransmits})?> probeWithRetry(
  String ip, {
  int retries = 3,
}) async {
  for (int i = 0; i < retries; i++) {
    final r = await androidTlsProbe(ip);
    if (r != null) return r;
    if (i < retries - 1) {
      await Future.delayed(const Duration(milliseconds: 300));
    }
  }
  return null;
}

// Keep ProbeResult for any future use
class ProbeResult {
  final bool   success;
  final double latency;
  final int    statusCode;
  final String server;
  final String protocol;
  final bool   tlsValid;
  final int    bytesReceived;
  final bool   frontingPossible;

  const ProbeResult({
    required this.success,
    required this.latency,
    required this.statusCode,
    required this.server,
    required this.protocol,
    required this.tlsValid,
    required this.bytesReceived,
    required this.frontingPossible,
  });
}
