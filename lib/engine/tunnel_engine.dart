// lib/engine/tunnel_engine.dart
// Phase 5-7: Tunnel Survival + DPI Resistance
//
// STRATEGY: Hold the TLS connection open silently and measure how long
// the CDN edge keeps it alive before sending RST/FIN.
//
// WHY NO HTTP KEEPALIVE:
// Sending HTTP requests (OPTIONS etc.) causes the CDN to close the connection
// gracefully after responding — this is normal HTTP behavior, NOT a scan fail.
// ShirKhorshid sends its own VPN protocol data through the tunnel, not HTTP.
// The correct test is: does the raw TLS connection stay alive long enough?
//
// SURVIVAL TIERS (from Wireshark: ShirKhorshid RSTs at ~32s):
//   ≥ 20s = Excellent
//   ≥ 10s = Good
//   ≥  5s = Usable
//   <  5s = Weak
//
// We run a progressive test: bail early if connection dies fast.
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

Future<SurvivalResult> tunnelSurvivalTest(
  String ip, {
  String sni               = kShiroSni,
  int    survivalTargetMs  = 25000,
}) async {
  Socket?       rawSock;
  SecureSocket? tls;
  final         sw        = Stopwatch()..start();
  bool          errorKilled = false;
  bool          blackhole   = false;

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

    // Hold connection open silently.
    // onError = RST / network error → truly killed
    // onDone  = graceful FIN → CDN idle timeout (normal, measure elapsed)
    bool  connectionDead = false;
    final deathCompleter = Completer<void>();

    final sub = tls.listen(
      (_) {},
      onError: (_) {
        errorKilled    = true;
        connectionDead = true;
        if (!deathCompleter.isCompleted) deathCompleter.complete();
      },
      onDone: () {
        connectionDead = true;
        if (!deathCompleter.isCompleted) deathCompleter.complete();
      },
      cancelOnError: true,
    );

    // Wait: either target time or connection dies
    await Future.any([
      Future.delayed(Duration(milliseconds: survivalTargetMs)),
      deathCompleter.future,
    ]);

    sw.stop();
    await sub.cancel();
    try { await tls.close(); } catch (_) {}
    tls.destroy();

    // Survived = no error AND lasted at least 5 seconds (minimum usable)
    final survived = !errorKilled && sw.elapsedMilliseconds >= 5000;

    return SurvivalResult(
      survived:   survived,
      survivalMs: sw.elapsedMilliseconds,
      dpiKilled:  errorKilled,
      blackhole:  blackhole,
    );
  } catch (e) {
    sw.stop();
    blackhole   = e is TimeoutException;
    errorKilled = !blackhole;
    return SurvivalResult(
      survived:   false,
      survivalMs: sw.elapsedMilliseconds,
      dpiKilled:  errorKilled,
      blackhole:  blackhole,
    );
  } finally {
    try { tls?.destroy();     } catch (_) {}
    try { rawSock?.destroy(); } catch (_) {}
  }
}
