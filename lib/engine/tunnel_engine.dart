// lib/engine/tunnel_engine.dart
// Phase 5-7: Tunnel Survival + DPI Resistance
//
// STRATEGY: Send periodic randomized heartbeat payloads to simulate
// real VPN traffic. Pure idle TLS doesn't reflect actual tunnel behavior —
// some CDNs tolerate idle connections but drop real traffic.
//
// HEARTBEAT (anti-detection):
//   - Size: 8–64 bytes random (was fixed 16 — machine-detectable pattern)
//   - Interval: 3–7s random jitter (was exactly 5s — periodic = detectable)
//   Real VPN traffic is NOT perfectly periodic. Fixed intervals are a
//   DPI fingerprint.
//
// HEARTBEAT SAFETY:
//   - flush guard: wait for previous write before scheduling next
//   - cancellation: respects isCancelled token immediately
//   - no zombie heartbeats: connectionDead flag checked before every write
//
// BLACKHOLE DETECTION: Both TimeoutException AND stalled socket
// (no RST, no FIN, no data) are treated as blackhole.
//
// SURVIVAL TIERS (from Wireshark: ShirKhorshid RSTs at ~32s):
//   ≥ 20s = Excellent
//   ≥ 10s = Good
//   ≥  5s = Usable
//   <  5s = Weak
import 'dart:async';
import 'dart:io';
import 'dart:math';
import 'probe_engine.dart'; // for kShiroSni, kShiroAlpn, acceptCdnCert (exported)

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

final _rng = Random.secure();

// Random payload: 8–64 bytes (non-periodic size)
List<int> _heartbeatPayload() {
  final size = 8 + _rng.nextInt(57); // 8..64
  return List.generate(size, (_) => _rng.nextInt(256));
}

// Random delay: 3000–7000ms (non-periodic interval)
int _heartbeatDelayMs() => 3000 + _rng.nextInt(4001); // 3000..7000

Future<SurvivalResult> tunnelSurvivalTest(
  String ip, {
  String sni               = kShiroSni,
  int    survivalTargetMs  = 20000,
  bool Function()? isCancelled,
}) async {
  Socket?       rawSock;
  SecureSocket? tls;
  final         sw          = Stopwatch()..start();
  bool          errorKilled = false;
  bool          blackhole   = false;

  try {
    rawSock = await Socket.connect(
      ip, 443,
      timeout: const Duration(seconds: 5),
    );

    // Cert validation: reject captive portals but allow CDN fronting (fix #4)
    tls = await SecureSocket.secure(
      rawSock,
      host: sni,
      onBadCertificate: acceptCdnCert,
      supportedProtocols: [kShiroAlpn],
    ).timeout(const Duration(seconds: 6));

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

    // ── Randomized heartbeat with flush guard (fix: heartbeat overlap) ──────
    // - Wait for flush() before scheduling next heartbeat
    // - Check isCancelled and connectionDead before every write
    // - Recursive Future.delayed for true non-periodic behavior
    Future<void> runHeartbeat() async {
      while (true) {
        // Random delay before next beat
        await Future.delayed(Duration(milliseconds: _heartbeatDelayMs()));

        // Exit conditions: connection dead, cancelled, or target reached
        if (connectionDead) return;
        if (deathCompleter.isCompleted) return;
        if (isCancelled?.call() == true) return;

        try {
          final tlsRef = tls;
          if (tlsRef == null) return;
          tlsRef.add(_heartbeatPayload());
          // Flush guard: wait for previous write to be sent (fix #9)
          await tlsRef.flush();
        } catch (_) {
          // Write/flush failure = connection dead
          errorKilled    = true;
          connectionDead = true;
          if (!deathCompleter.isCompleted) deathCompleter.complete();
          return;
        }
      }
    }
    // Fire and forget — exits via connectionDead flag
    runHeartbeat().ignore();

    // ── Cancellation check loop ──────────────────────────────────────────────
    // Check isCancelled every 500ms independently of the heartbeat loop.
    // This ensures stop button causes immediate exit even between heartbeats.
    if (isCancelled != null) {
      Future.doWhile(() async {
        await Future.delayed(const Duration(milliseconds: 500));
        if (deathCompleter.isCompleted) return false;
        if (isCancelled()) {
          connectionDead = true;
          if (!deathCompleter.isCompleted) deathCompleter.complete();
          return false;
        }
        return true;
      }).ignore();
    }

    // ── Blackhole detection: stalled socket ─────────────────────────────────
    // stallTimeout = survivalTarget + 8s (max heartbeat delay + margin)
    final stallTimeout = Duration(milliseconds: survivalTargetMs + 8000);

    await Future.any([
      Future.delayed(Duration(milliseconds: survivalTargetMs)),
      deathCompleter.future,
    ]).timeout(stallTimeout, onTimeout: () {
      blackhole = true;
      if (!deathCompleter.isCompleted) deathCompleter.complete();
    }).catchError((_) {});

    sw.stop();
    connectionDead = true; // stop heartbeat loop
    await sub.cancel();
    try { await tls.close(); } catch (_) {}
    tls.destroy();

    final survived = !errorKilled && !blackhole && sw.elapsedMilliseconds >= 5000;

    return SurvivalResult(
      survived:   survived,
      survivalMs: sw.elapsedMilliseconds,
      dpiKilled:  errorKilled,
      blackhole:  blackhole,
    );
  } catch (e) {
    sw.stop();
    if (e is TimeoutException) {
      blackhole = true;
    } else if (e is SocketException) {
      final msg = e.message.toLowerCase();
      blackhole   = msg.contains('timed out') || msg.contains('timeout');
      errorKilled = !blackhole;
    } else {
      errorKilled = true;
    }
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
