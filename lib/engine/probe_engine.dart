// lib/engine/probe_engine.dart
// Android-like TLS fingerprint probe
// p4: smartRetryBackoff — exponential jitter retry
// p9: randomTlsPacing — random microsecond delay before TLS handshake
// p17: captivePortalDetector — enhanced cert validation
// cf1: cfHttpProbe — HTTP GET /cdn-cgi/trace + colo detection (Cloudflare SNIs)
// UPGRADED: throttle detection, randomized WS key, watchdog integration

export '../models/probe_result.dart';
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'watchdog_engine.dart';

const kShiroSni  = 'www.google.com';
const kShiroAlpn = 'http/1.1';

// Shared random instance for pacing
final _probeRng = Random();

// ── SNI presets for ShirKhorshid CDN ────────────────────────────────────────
const kDeepSniPresets = [
  'www.google.com',
  'google.com',
  'fonts.googleapis.com',
  'speed.cloudflare.com',
  'cloudflare.com',
  'a248.e.akamai.net',
  'global.fastly.net',
  'github.com',
  'ajax.aspnetcdn.com',
];

// SNI family groups for early-exit in deep mode
const kSniGoogleFamily     = {'www.google.com', 'google.com', 'fonts.googleapis.com'};
const kSniCloudflareFamily = {'speed.cloudflare.com', 'cloudflare.com'};

// ── cf2: Cloudflare SNI rotation list ────────────────────────────────────────
// When no explicit SNI is given for a Cloudflare HTTP probe, rotate through
// these hostnames to reduce DPI fingerprint (mirrors SenPai sniHostnames).
const kCfSniHostnames = [
  'speed.cloudflare.com',
  'www.cloudflare.com',
  'cloudflare.com',
  '1.1.1.1.cdn.cloudflare.net',
  'blog.cloudflare.com',
];

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
bool isCaptivePortalCert(X509Certificate cert) {
  if (cert.pem.length < 300) return true;
  return false;
}

// ── Cert validation helper ───────────────────────────────────────────────────
bool acceptCdnCert(X509Certificate cert) {
  if (cert.pem.isEmpty) return false;
  if (cert.pem.length < 200) return false;
  return true;
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
// cf-sni-rotation: if sniRotation=true, each retry cycles through kCfSniHostnames
// UPGRADED: watchdog wraps each androidTlsProbe call to kill hung sockets
Future<({double latencyMs, int retransmits, ProbeTimings? timings, String sniUsed})?> probeWithRetry(
  String ip, {
  String sni         = kShiroSni,
  int    retries     = 5,
  bool   sniRotation = false,
}) async {
  for (int i = 0; i < retries; i++) {
    final effectiveSni = (sniRotation && kCfSniHostnames.isNotEmpty)
        ? kCfSniHostnames[i % kCfSniHostnames.length]
        : sni;
    // UPGRADED: watchdog ensures hung sockets are killed within 16s
    final r = await withWatchdog(
      fn: () => androidTlsProbe(ip, sni: effectiveSni),
      timeout: const Duration(seconds: 10),
      fallback: null,
    );
    if (r != null) {
      return (
        latencyMs:   r.latencyMs,
        retransmits: r.retransmits,
        timings:     r.timings,
        sniUsed:     effectiveSni,
      );
    }
    if (i < retries - 1) {
      final baseMs   = (300 * pow(2, i)).toInt();
      final jitterMs = _probeRng.nextInt(200);
      final delayMs  = (baseMs + jitterMs).clamp(200, 2000);
      await Future.delayed(Duration(milliseconds: delayMs));
    }
  }
  return null;
}

// p5: quickTlsHelloProbe
Future<bool> quickTlsCheck(String ip, {int timeoutMs = 3000}) async {
  Socket?       rawSock;
  SecureSocket? tls;
  try {
    rawSock = await Socket.connect(
      ip, 443,
      timeout: Duration(milliseconds: timeoutMs),
    );

    await Future.delayed(
      Duration(microseconds: 50 + _probeRng.nextInt(450)),
    );

    tls = await SecureSocket.secure(
      rawSock,
      host: kShiroSni,
      onBadCertificate: acceptCdnCert,
      supportedProtocols: [kShiroAlpn],
    ).timeout(Duration(milliseconds: timeoutMs));
    return true;
  } catch (_) {
    return false;
  } finally {
    try { tls?.destroy();     } catch (_) {}
    try { rawSock?.destroy(); } catch (_) {}
  }
}

// p1: adaptiveTimeoutEngine
int adaptiveServerHelloMs(double firstRttMs, {int? subnetHintMs}) {
  final rttBased = (firstRttMs * 3).clamp(6000, 15000).toInt();
  if (subnetHintMs != null) {
    return ((rttBased + subnetHintMs) ~/ 2).clamp(4000, 15000);
  }
  return rttBased;
}

// ── Bandwidth measurement with Throttle Detection ────────────────────────────
// UPGRADED: tracks 1-second speed samples and detects >40% throttling
Future<({double? speedKBs, bool throttled, int throttlePct})> measureBandwidthKBsDetailed(
  String ip, {
  String sni         = kShiroSni,
  int testDurationMs = 5000,
}) async {
  Socket?             rawSock;
  SecureSocket?       tls;
  StreamSubscription? sub;
  try {
    rawSock = await Socket.connect(ip, 443, timeout: const Duration(seconds: 4));
    tls = await SecureSocket.secure(
      rawSock,
      host: sni,
      onBadCertificate: acceptCdnCert,
      supportedProtocols: [kShiroAlpn],
    ).timeout(const Duration(seconds: 6));

    final path = sni == 'speed.cloudflare.com' ? '/__down?bytes=8000000' : '/';
    tls.write(
      'GET $path HTTP/1.1\r\n'
      'Host: $sni\r\n'
      'User-Agent: Android\r\n'
      'Accept: */*\r\n'
      'Connection: close\r\n\r\n',
    );

    int   total      = 0;
    final sw         = Stopwatch()..start();
    final completer  = Completer<void>();
    final samples    = <double>[]; // KB/s per second
    int   lastSampleMs = 0;
    int   lastTotal    = 0;

    sub = tls.listen(
      (chunk) {
        total += chunk.length;
        final elapsed = sw.elapsedMilliseconds;
        if (elapsed - lastSampleMs >= 1000) {
          final intervalBytes = total - lastTotal;
          final intervalSec   = (elapsed - lastSampleMs) / 1000.0;
          if (intervalSec > 0) {
            samples.add((intervalBytes / 1024.0) / intervalSec);
          }
          lastSampleMs = elapsed;
          lastTotal    = total;
        }
        if (elapsed >= testDurationMs) {
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
      bool throttled   = false;
      int  throttlePct = 0;
      if (samples.length >= 4) {
        final mid  = samples.length ~/ 2;
        final fAvg = samples.sublist(0, mid).reduce((a, b) => a + b) / mid;
        final sAvg = samples.sublist(mid).reduce((a, b) => a + b) / (samples.length - mid);
        if (fAvg > 0) {
          final drop  = (fAvg - sAvg) / fAvg;
          throttlePct = (drop * 100).round().clamp(0, 100);
          throttled   = drop > 0.40;
        }
      }
      return (
        speedKBs:    double.parse(speedKBs.toStringAsFixed(1)),
        throttled:   throttled,
        throttlePct: throttlePct,
      );
    }
    return (speedKBs: null, throttled: false, throttlePct: 0);
  } catch (_) {
    return (speedKBs: null, throttled: false, throttlePct: 0);
  } finally {
    try { sub?.cancel();      } catch (_) {}
    try { tls?.destroy();     } catch (_) {}
    try { rawSock?.destroy(); } catch (_) {}
  }
}

/// Legacy wrapper — returns speed only (used by scanner_engine.dart & deep_scan_engine.dart)
Future<double?> measureBandwidthKBs(
  String ip, {
  String sni         = kShiroSni,
  int testDurationMs = 5000,
}) async {
  final r = await measureBandwidthKBsDetailed(
    ip, sni: sni, testDurationMs: testDurationMs);
  return r.speedKBs;
}

// ── cf1: Cloudflare HTTP probe ───────────────────────────────────────────────
class CfHttpResult {
  final bool   tlsOk;
  final int    httpStatus;
  final String colo;

  const CfHttpResult({
    required this.tlsOk,
    required this.httpStatus,
    required this.colo,
  });

  bool get isCloudflareEdge =>
      tlsOk && httpStatus >= 200 && httpStatus < 400 && colo.isNotEmpty;
}

Future<CfHttpResult> cfHttpProbe(
  String ip, {
  String sni        = '',
  int totalBudgetMs = 8000,
}) async {
  final effectiveSni = sni.isNotEmpty ? sni : 'speed.cloudflare.com';

  const tries = 3; // 3 tries like SenPai default
  for (int attempt = 0; attempt < tries; attempt++) {
    Socket?             raw;
    SecureSocket?       tls;
    StreamSubscription? sub;
    try {
      raw = await Socket.connect(
        ip, 443,
        timeout: Duration(milliseconds: totalBudgetMs ~/ 4),
      );

      await Future.delayed(Duration(microseconds: 100 + _probeRng.nextInt(900)));

      tls = await SecureSocket.secure(
        raw,
        host: effectiveSni,
        onBadCertificate: acceptCdnCert,
      ).timeout(Duration(milliseconds: totalBudgetMs ~/ 2));

      tls.write(
        'GET /cdn-cgi/trace HTTP/1.1\r\n'
        'Host: $effectiveSni\r\n'
        'User-Agent: MidONe/1.0\r\n'
        'Connection: close\r\n\r\n',
      );

      final buf       = StringBuffer();
      final completer = Completer<void>();
      sub = tls.listen(
        (chunk) {
          buf.write(utf8.decode(chunk, allowMalformed: true));
          if (buf.length > 2048 && !completer.isCompleted) completer.complete();
        },
        onDone:        () { if (!completer.isCompleted) completer.complete(); },
        onError:       (_) { if (!completer.isCompleted) completer.complete(); },
        cancelOnError: true,
      );

      await completer.future
          .timeout(Duration(milliseconds: totalBudgetMs ~/ 4))
          .catchError((_) {});

      await sub.cancel();

      final response   = buf.toString();
      final httpStatus = _cfParseHttpStatus(response);
      final colo       = _cfParseColo(response);

      if (colo.isNotEmpty || httpStatus > 0) {
        return CfHttpResult(tlsOk: true, httpStatus: httpStatus, colo: colo);
      }
    } catch (_) {
      // fall through to retry
    } finally {
      try { await sub?.cancel(); } catch (_) {}
      try { tls?.destroy();      } catch (_) {}
      try { raw?.destroy();      } catch (_) {}
    }

    if (attempt < tries - 1) {
      await Future.delayed(Duration(milliseconds: 10 + _probeRng.nextInt(50)));
    }
  }

  return const CfHttpResult(tlsOk: false, httpStatus: -1, colo: '');
}

int _cfParseHttpStatus(String response) {
  final match = RegExp(r'HTTP/1\.\d (\d{3})').firstMatch(response);
  return int.tryParse(match?.group(1) ?? '') ?? -1;
}

String _cfParseColo(String response) {
  final sepIdx = response.indexOf('\r\n\r\n');
  final headers = sepIdx >= 0 ? response.substring(0, sepIdx) : '';
  final body    = sepIdx >= 0 ? response.substring(sepIdx + 4) : response;

  for (final raw in body.split('\n')) {
    final line = raw.trimRight();
    if (line.startsWith('colo=')) {
      final val = line.substring('colo='.length).trim();
      if (val.isNotEmpty) return val;
    }
  }

  for (final raw in headers.split('\n')) {
    final line = raw.trimRight();
    if (line.toLowerCase().startsWith('cf-ray:')) {
      final value = line.substring('cf-ray:'.length).trim();
      final parts = value.split('-');
      if (parts.length >= 2) {
        final colo = parts.last.trim();
        if (colo.length >= 3) return colo.toUpperCase().substring(0, 3);
      }
    }
  }

  return '';
}

// ── ws2: WebSocket DPI probe ──────────────────────────────────────────────────
// UPGRADED: WS key is now random per-call (not a fixed fingerprint)
Future<bool> cfWsProbe(
  String ip, {
  String sni           = 'speed.cloudflare.com',
  String wsHost        = '',
  String wsPath        = '/',
  int    totalBudgetMs = 8000,
}) async {
  final host = wsHost.isNotEmpty ? wsHost : sni;
  final path = _normalizeWsPath(wsPath);

  // UPGRADED: random 16-byte WS key — not a fixed fingerprint
  final wsKeyBytes = List<int>.generate(16, (_) => _probeRng.nextInt(256));
  final wsKey      = base64.encode(wsKeyBytes);

  Socket?             raw;
  SecureSocket?       tls;
  StreamSubscription? sub;

  try {
    raw = await Socket.connect(
      ip, 443,
      timeout: Duration(milliseconds: totalBudgetMs ~/ 3),
    );
    tls = await SecureSocket.secure(
      raw,
      host: sni,
      onBadCertificate: (_) => true,
    ).timeout(Duration(milliseconds: totalBudgetMs ~/ 3));

    tls.setOption(SocketOption.tcpNoDelay, true);

    final dataBuf       = StringBuffer();
    final dataCompleter = Completer<String?>();
    bool connDead       = false;

    sub = tls.listen(
      (chunk) {
        dataBuf.write(utf8.decode(chunk, allowMalformed: true));
        if (!dataCompleter.isCompleted) {
          dataCompleter.complete(dataBuf.toString());
        }
      },
      onError: (_) {
        connDead = true;
        if (!dataCompleter.isCompleted) dataCompleter.complete(null);
      },
      onDone: () {
        connDead = true;
        if (!dataCompleter.isCompleted) dataCompleter.complete(null);
      },
      cancelOnError: true,
    );

    // Phase 1: idle hold 2s
    final phase1 = await dataCompleter.future
        .timeout(const Duration(seconds: 2), onTimeout: () => 'timeout');

    if (connDead || phase1 == null) return false;

    // Phase 2: WebSocket upgrade with random key
    final wsRequest =
        'GET $path HTTP/1.1\r\n'
        'Host: $host\r\n'
        'Upgrade: websocket\r\n'
        'Connection: Upgrade\r\n'
        'Sec-WebSocket-Key: $wsKey\r\n'
        'Sec-WebSocket-Version: 13\r\n'
        '\r\n';

    try {
      await Future(() => tls!.write(wsRequest))
          .timeout(Duration(milliseconds: totalBudgetMs ~/ 2));
    } catch (_) {
      return false;
    }

    final phase2Completer = Completer<bool>();
    sub.onData((chunk) {
      dataBuf.write(utf8.decode(chunk, allowMalformed: true));
      if (dataBuf.toString().contains('HTTP/') && !phase2Completer.isCompleted) {
        phase2Completer.complete(true);
      }
    });
    sub.onError((_) {
      if (!phase2Completer.isCompleted) phase2Completer.complete(false);
    });
    sub.onDone(() {
      if (!phase2Completer.isCompleted) phase2Completer.complete(false);
    });

    if (dataBuf.toString().contains('HTTP/') && !phase2Completer.isCompleted) {
      phase2Completer.complete(true);
    }

    final ok = await phase2Completer.future.timeout(
      Duration(milliseconds: totalBudgetMs ~/ 3),
      onTimeout: () => false,
    );

    await sub.cancel();
    return ok;

  } catch (_) {
    return false;
  } finally {
    try { await sub?.cancel(); } catch (_) {}
    try { tls?.destroy();      } catch (_) {}
    try { raw?.destroy();      } catch (_) {}
  }
}

String _normalizeWsPath(String path) {
  if (path.isEmpty) return '/';
  if (!path.startsWith('/')) return '/$path';
  return path;
}

// ProbeResult is defined in models/probe_result.dart (re-exported above)
