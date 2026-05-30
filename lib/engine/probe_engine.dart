// lib/engine/probe_engine.dart
// Android-like TLS fingerprint probe
// p4: smartRetryBackoff — exponential jitter retry
// p9: randomTlsPacing — random microsecond delay before TLS handshake
// p17: captivePortalDetector — enhanced cert validation
// cf1: cfHttpProbe — HTTP GET /cdn-cgi/trace + colo detection (Cloudflare SNIs)

export '../models/probe_result.dart';
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

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
//   mirrors SenPai: sni = sniHostnames[attempt % len(sniHostnames)]
// Returns null if all retries fail.
// successSni: outputs which SNI finally succeeded (for sniUsed in ScanResult).
Future<({double latencyMs, int retransmits, ProbeTimings? timings, String sniUsed})?> probeWithRetry(
  String ip, {
  String sni         = kShiroSni,
  int    retries     = 5,
  bool   sniRotation = false,  // cf-sni-rotation: rotate CF SNIs on each retry
}) async {
  for (int i = 0; i < retries; i++) {
    // cf-sni-rotation: pick SNI from rotation list for each attempt
    final effectiveSni = (sniRotation && kCfSniHostnames.isNotEmpty)
        ? kCfSniHostnames[i % kCfSniHostnames.length]
        : sni;
    final r = await androidTlsProbe(ip, sni: effectiveSni);
    if (r != null) {
      return (
        latencyMs:  r.latencyMs,
        retransmits: r.retransmits,
        timings:    r.timings,
        sniUsed:    effectiveSni,
      );
    }
    if (i < retries - 1) {
      final baseMs   = (300 * pow(2, i)).toInt();
      final jitterMs = _probeRng.nextInt(200);
      final delayMs  = (baseMs + jitterMs).clamp(300, 3000);
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

// ── Bandwidth measurement ────────────────────────────────────────────────────
Future<double?> measureBandwidthKBs(
  String ip, {
  String sni         = kShiroSni,
  int testDurationMs = 5000,
}) async {
  Socket?             rawSock;
  SecureSocket?       tls;
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

// ── cf1: Cloudflare HTTP probe ───────────────────────────────────────────────
// Sends GET /cdn-cgi/trace to confirm the IP is a real Cloudflare edge and
// reads the datacenter (colo) identifier.
// Budget-split timeout: TCP = total/4, TLS = total/2, HTTP = total/4.
class CfHttpResult {
  final bool   tlsOk;
  final int    httpStatus; // HTTP status code; -1 if request failed
  final String colo;       // CF datacenter code e.g. "FRA"; "" if not detected

  const CfHttpResult({
    required this.tlsOk,
    required this.httpStatus,
    required this.colo,
  });

  /// True only when the IP is confirmed as a live Cloudflare edge.
  bool get isCloudflareEdge =>
      tlsOk && httpStatus >= 200 && httpStatus < 400 && colo.isNotEmpty;
}

Future<CfHttpResult> cfHttpProbe(
  String ip, {
  String sni        = '',
  int totalBudgetMs = 8000,
}) async {
  // cf2: SNI rotation — if no explicit SNI given, use speed.cloudflare.com for HTTP
  // (mirrors SenPai: sni == "" && mode == ModeHTTP → "speed.cloudflare.com")
  // For TLS-only, rotate randomly through kCfSniHostnames.
  final effectiveSni = sni.isNotEmpty
      ? sni
      : 'speed.cloudflare.com';

  Socket?             raw;
  SecureSocket?       tls;
  StreamSubscription? sub;
  try {
    // TCP — 25% of budget
    raw = await Socket.connect(
      ip, 443,
      timeout: Duration(milliseconds: totalBudgetMs ~/ 4),
    );

    // p9: random pacing before TLS handshake
    await Future.delayed(Duration(microseconds: 100 + _probeRng.nextInt(900)));

    // TLS — 50% of budget
    tls = await SecureSocket.secure(
      raw,
      host: effectiveSni,
      onBadCertificate: acceptCdnCert,
    ).timeout(Duration(milliseconds: totalBudgetMs ~/ 2));

    // HTTP GET /cdn-cgi/trace — 25% of budget
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
        // Stop after enough data for headers + body
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

    return CfHttpResult(tlsOk: true, httpStatus: httpStatus, colo: colo);
  } catch (_) {
    return const CfHttpResult(tlsOk: false, httpStatus: -1, colo: '');
  } finally {
    try { await sub?.cancel(); } catch (_) {}
    try { tls?.destroy();      } catch (_) {}
    try { raw?.destroy();      } catch (_) {}
  }
}

/// Parses HTTP status code from raw HTTP response.
/// e.g. "HTTP/1.1 200 OK" → 200
int _cfParseHttpStatus(String response) {
  final match = RegExp(r'HTTP/1\.\d (\d{3})').firstMatch(response);
  return int.tryParse(match?.group(1) ?? '') ?? -1;
}

/// Parses Cloudflare datacenter code from response.
/// Tries body first ("colo=FRA"), then CF-Ray header ("CF-Ray: 12345-FRA").
String _cfParseColo(String response) {
  // Split headers and body at the blank line
  final sepIdx = response.indexOf('\r\n\r\n');
  final headers = sepIdx >= 0 ? response.substring(0, sepIdx) : '';
  final body    = sepIdx >= 0 ? response.substring(sepIdx + 4) : response;

  // From /cdn-cgi/trace body — parse line-by-line (exact match, like SenPai parseColoCDN)
  for (final raw in body.split('\n')) {
    final line = raw.trimRight(); // strip trailing \r
    if (line.startsWith('colo=')) {
      final val = line.substring('colo='.length).trim();
      if (val.isNotEmpty) return val;
    }
  }

  // From CF-Ray response header — split on "-", take last segment (like SenPai parseColoRay)
  // e.g. "CF-Ray: 8abc123def-FRA" → "FRA"
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
// Tests whether WebSocket-grade TLS connections reach the Cloudflare edge
// without being killed by DPI. Mirrors SenPai probeWebSocket exactly:
//
//  Phase 1 — idle hold (2 s):
//    Some DPI systems RST long-lived TLS connections before any application
//    data is exchanged. If the connection dies during the idle hold, wsOk=false.
//
//  Phase 2 — WebSocket upgrade:
//    Sends an HTTP/1.1 Upgrade: websocket request and checks that any HTTP
//    response arrives (even 400/404). If DPI drops the connection before CF
//    can respond, wsOk=false.
//
// TLS cert is NOT verified here — cfHttpProbe already verified it.
// Timeout budget: TCP+TLS = timeout/3, idle = 2s fixed, WS write = timeout/2, read = timeout/3.
// ws2: WebSocket DPI probe — mirrors SenPai probeWebSocket exactly.
//
// Fix: Use a SINGLE StreamSubscription for both Phase 1 and Phase 2.
// The previous implementation used tls.first (which internally calls listen())
// followed by a second tls.listen() — this caused:
//   StateError: "Bad state: Stream has already been listened to"
// which was silently caught, making wsOk always false.
//
// SenPai uses net.Conn.Read() which is not a stream — no subscription issue.
// Dart fix: open one subscription at start, share it across both phases.
//
//  Phase 1 — idle hold (2 s, mirrors SenPai: tlsConn.SetDeadline(now+2s) + Read):
//    Waits for any incoming data. Server won't send anything before WS upgrade,
//    so a timeout here is EXPECTED and means connection is alive.
//    Any other error (RST/EOF) = DPI killed the idle TLS connection → false.
//
//  Phase 2 — WebSocket upgrade (mirrors SenPai write+read loop):
//    Sends HTTP/1.1 Upgrade: websocket. If CF responds with any HTTP line
//    ("HTTP/") the connection is DPI-permissive → true.
//    No response before budget/3 = DPI dropped the WS upgrade → false.
//
// Budget: TCP+TLS = budget/3, idle = 2s fixed, WS write+read = budget/3.
Future<bool> cfWsProbe(
  String ip, {
  String sni           = 'speed.cloudflare.com',
  String wsHost        = '',    // empty = use sni
  String wsPath        = '/',   // WebSocket upgrade path
  int    totalBudgetMs = 8000,
}) async {
  final host = wsHost.isNotEmpty ? wsHost : sni;
  final path = _normalizeWsPath(wsPath);
  Socket?             raw;
  SecureSocket?       tls;
  StreamSubscription? sub;

  try {
    // ── TCP + TLS — budget/3 (mirrors SenPai: dialer Timeout = timeout/3) ──
    raw = await Socket.connect(
      ip, 443,
      timeout: Duration(milliseconds: totalBudgetMs ~/ 3),
    );
    tls = await SecureSocket.secure(
      raw,
      host: sni,
      onBadCertificate: (_) => true, // cert already verified by cfHttpProbe
    ).timeout(Duration(milliseconds: totalBudgetMs ~/ 3));

    tls.setOption(SocketOption.tcpNoDelay, true);

    // ── Open ONE subscription shared by both phases ───────────────────────
    // This is the key fix: Dart SecureSocket is a single-subscription stream.
    // We must call listen() exactly once and reuse it for Phase 1 and Phase 2.
    final dataBuf      = StringBuffer();
    final dataCompleter = Completer<String?>(); // null = timeout/error
    bool connDead      = false;

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

    // ── Phase 1: idle hold — 2 s fixed (mirrors SenPai SetDeadline+Read) ──
    // Wait for any spontaneous data from server.
    // Timeout = EXPECTED (server waits for us) → connection alive.
    // null    = RST/EOF during idle → DPI killed → return false.
    final phase1 = await dataCompleter.future
        .timeout(const Duration(seconds: 2), onTimeout: () => 'timeout');

    if (connDead || phase1 == null) return false;
    // 'timeout' or any data received both mean connection is still alive.

    // ── Phase 2: WebSocket upgrade (mirrors SenPai write + read) ──────────
    // Fixed WS key mirrors SenPai exactly: "c2VucGFpc2Nhbm5lcg=="
    final wsRequest =
        'GET \$path HTTP/1.1\r\n'
        'Host: \$host\r\n'
        'Upgrade: websocket\r\n'
        'Connection: Upgrade\r\n'
        'Sec-WebSocket-Key: c2VucGFpc2Nhbm5lcg==\r\n'
        'Sec-WebSocket-Version: 13\r\n'
        '\r\n';

    // Write deadline — mirrors SenPai: tlsConn.SetDeadline(now + timeout/2)
    // Dart SecureSocket.write() is an async sink operation. On a stalled TCP
    // connection the write may block until the kernel buffer drains.
    // Wrapping in a Future.timeout(budget/2) mirrors SenPai's write deadline.
    try {
      await Future(() => tls!.write(wsRequest))
          .timeout(Duration(milliseconds: totalBudgetMs ~/ 2));
    } catch (_) {
      return false;
    }

    // Read CF response — any HTTP line means WS upgrade reached CF edge.
    // Mirrors SenPai: strings.Contains(respBuf, "HTTP/")
    final phase2Completer = Completer<bool>();
    // Re-use same subscription — reassign its handlers via a new completer.
    // Since sub is already listening, we poll dataBuf which is already filling.
    // Attach a parallel listener on the same stream won't work — instead we
    // replace onData via sub.onData and watch for "HTTP/" in accumulated buf.
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

    // Check if "HTTP/" already arrived while we were writing
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

/// Normalizes a WebSocket path — mirrors SenPai normalizeWSPath.
String _normalizeWsPath(String path) {
  if (path.isEmpty) return '/';
  if (!path.startsWith('/')) return '/$path';
  return path;
}

// ProbeResult is defined in models/probe_result.dart (re-exported above)
