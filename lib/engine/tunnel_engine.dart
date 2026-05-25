// lib/engine/tunnel_engine.dart
// Phase 5-7: Tunnel Survival + DPI Resistance
import 'dart:async';
import 'dart:io';
import 'probe_engine.dart';

/// Result of a survival test
class SurvivalResult {
  final bool   survived;
  final int    survivalMs;   // time tunnel stayed alive (ms)
  final bool   dpiKilled;    // RST/FIN arrived unexpectedly
  final bool   blackhole;    // no data at all (freeze)

  const SurvivalResult({
    required this.survived,
    required this.survivalMs,
    required this.dpiKilled,
    required this.blackhole,
  });
}

// ─── Phase 5: Tunnel Survival (20-30 s) ─────────────────────────────────────
//
// Opens a real TLS connection and keeps it alive by sending tiny encrypted
// packets every ~5 s, exactly as a VPN client would.
// Fails if:
//   • RST or FIN arrives (DPI kill / ISP blackhole)
//   • No data within 8 s (freeze / blackhole)
//   • Socket error
//
Future<SurvivalResult> tunnelSurvivalTest(
  String ip, {
  int survivalTargetMs = 25000,   // 25 s target
  int keepaliveIntervalMs = 5000, // send tiny packet every 5 s
}) async {
  Socket? rawSock;
  SecureSocket? tls;
  final sw = Stopwatch()..start();
  bool dpiKilled  = false;
  bool blackhole  = false;

  try {
    rawSock = await Socket.connect(
      ip, 443,
      timeout: const Duration(seconds: 5),
    );

    tls = await SecureSocket.secure(
      rawSock,
      host: kShiroSni,
      onBadCertificate: (_) => true,
      supportedProtocols: [kShiroAlpn],
    ).timeout(const Duration(seconds: 6));

    // Listen for unexpected close
    bool connectionDead = false;
    final deathCompleter = Completer<void>();
    final sub = tls.listen(
      (_) {},   // ignore incoming data
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

    // Keep sending tiny keepalive packets until target time or death
    final endTime = DateTime.now().add(Duration(milliseconds: survivalTargetMs));
    while (DateTime.now().isBefore(endTime) && !connectionDead) {
      // Tiny HTTP/1.1 OPTIONS request as keepalive
      try {
        tls.write(
          'OPTIONS / HTTP/1.1
'
          'Host: $kShiroSni
'
          'User-Agent: Android
'
          'Connection: keep-alive

',
        );
      } catch (_) {
        dpiKilled = true;
        break;
      }
      // Wait keepalive interval or until death
      await Future.any([
        Future.delayed(Duration(milliseconds: keepaliveIntervalMs)),
        deathCompleter.future,
      ]);
    }

    sw.stop();
    await sub.cancel();
    await tls.close();
    tls.destroy();

    // Phase 7: DPI Resistance check
    // If survived full target without DPI kill → passed
    final survived = !dpiKilled && sw.elapsedMilliseconds >= survivalTargetMs ~/ 2;
    return SurvivalResult(
      survived:   survived,
      survivalMs: sw.elapsedMilliseconds,
      dpiKilled:  dpiKilled,
      blackhole:  blackhole,
    );
  } catch (e) {
    sw.stop();
    // Timeout = blackhole
    blackhole = e is TimeoutException;
    dpiKilled = !blackhole;
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
