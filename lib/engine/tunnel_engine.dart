// lib/engine/tunnel_engine.dart
// Phase 5-7: Tunnel Survival + DPI Resistance
//
// KEEPALIVE STRATEGY:
// OPTIONS is sent as a lightweight keepalive to prevent CDN edge idle-timeout
// RST (typically 15-30s on Cloudflare/Akamai). This is NOT meant to bypass
// Iranian DPI — DPI acts on the TLS ClientHello SNI, not on application-layer
// HTTP methods. The survival test verifies the CDN edge keeps the connection
// alive long enough for ShirKhorshid's tunnel to be useful.
import 'dart:async';
import 'dart:io';
import 'probe_engine.dart';

class SurvivalResult {
  final bool survived;
  final int  survivalMs;
  final bool dpiKilled;
  final bool blackhole;

  const SurvivalResult({
    required this.survived,
    required this.survivalMs,
    required this.dpiKilled,
    required this.blackhole,
  });
}

// Phase 5: Tunnel Survival (20-30 s) + Phase 7: DPI Resistance
//
// Sends HTTP OPTIONS keepalive every 5s to prevent CDN idle timeout RST.
// A connection that survives 10+ seconds is usable for ShirKhorshid tunnel.
// A connection that survives 20-30s is ideal (full mark).
Future<SurvivalResult> tunnelSurvivalTest(
  String ip, {
  String sni                  = kShiroSni,
  int    survivalTargetMs     = 25000,
  int    keepaliveIntervalMs  = 5000,
}) async {
  Socket?       rawSock;
  SecureSocket? tls;
  final         sw        = Stopwatch()..start();
  bool          dpiKilled = false;
  bool          blackhole = false;

  try {
    rawSock = await Socket.connect(
      ip, 443,
      timeout: const Duration(seconds: 5),
    );

    tls = await SecureSocket.secure(
      rawSock,
      host: sni,
      onBadCertificate: (_) => true,
      supportedProtocols: [kShiroAlpn],
    ).timeout(const Duration(seconds: 6));

    bool connectionDead = false;
    final deathCompleter = Completer<void>();

    final sub = tls.listen(
      (_) {}, // Drain incoming data (CDN responses to OPTIONS)
      onError: (_) {
        dpiKilled = true;
        connectionDead = true;
        if (!deathCompleter.isCompleted) deathCompleter.complete();
      },
      onDone: () {
        dpiKilled = true;
        connectionDead = true;
        if (!deathCompleter.isCompleted) deathCompleter.complete();
      },
      cancelOnError: true,
    );

    final endTime = DateTime.now().add(Duration(milliseconds: survivalTargetMs));

    while (DateTime.now().isBefore(endTime) && !connectionDead) {
      try {
        // OPTIONS: minimal HTTP request — prevents CDN idle-timeout RST.
        // CDN edges (Cloudflare, Akamai) typically close idle connections
        // after 15-30s. This ping keeps the connection alive.
        tls.write(
          'OPTIONS / HTTP/1.1\r\n'
          'Host: $sni\r\n'
          'User-Agent: Android\r\n'
          'Connection: keep-alive\r\n\r\n',
        );
      } catch (_) {
        dpiKilled = true;
        break;
      }
      await Future.any([
        Future.delayed(Duration(milliseconds: keepaliveIntervalMs)),
        deathCompleter.future,
      ]);
    }

    sw.stop();
    await sub.cancel();
    try { await tls.close(); } catch (_) {}
    tls.destroy();

    // Survived = connection was NOT killed AND lasted at least half the target.
    // Half-target (10s for normal, 15s for deep) is the minimum useful duration.
    final survived = !dpiKilled &&
        sw.elapsedMilliseconds >= survivalTargetMs ~/ 2;

    return SurvivalResult(
      survived:   survived,
      survivalMs: sw.elapsedMilliseconds,
      dpiKilled:  dpiKilled,
      blackhole:  blackhole,
    );
  } catch (e) {
    sw.stop();
    blackhole  = e is TimeoutException;
    dpiKilled  = !blackhole;
    return SurvivalResult(
      survived:   false,
      survivalMs: sw.elapsedMilliseconds,
      dpiKilled:  dpiKilled,
      blackhole:  blackhole,
    );
  } finally {
    try { tls?.destroy();     } catch (_) {}
    try { rawSock?.destroy(); } catch (_) {}
  }
}
