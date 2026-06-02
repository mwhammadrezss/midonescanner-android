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
// p13: tlsFragmentationMode — heartbeat payload split into chunks
// p14: fakeIdlePattern — occasional silence between heartbeats
// p15: adaptiveHeartbeatInterval — interval adapts to connection stability
// p16: dpiSuspicionScore — probability score instead of boolean

import 'dart:async';
import 'dart:io';
import 'dart:math';
import 'probe_engine.dart'; // for kShiroSni, kShiroAlpn, acceptCdnCert

class SurvivalResult {
  final bool survived;
  final int  survivalMs;
  final bool dpiKilled;
  final bool blackhole;
  // p16: dpiSuspicionScore — probability 0.0-1.0 that DPI interfered
  final double dpiSuspicionScore;

  const SurvivalResult({
    required this.survived,
    required this.survivalMs,
    required this.dpiKilled,
    required this.blackhole,
    this.dpiSuspicionScore = 0.0,
  });
}

final _rng = Random.secure();

// Random payload: 8–64 bytes (non-periodic size)
List<int> _heartbeatPayload() {
  final size = 8 + _rng.nextInt(57); // 8..64
  return List.generate(size, (_) => _rng.nextInt(256));
}

// p13: tlsFragmentationMode — split payload into 2-4 random chunks
List<List<int>> _fragmentedPayload() {
  final full = _heartbeatPayload();
  final chunks = 2 + _rng.nextInt(3); // 2..4 chunks
  final result = <List<int>>[];
  var start = 0;
  for (int i = 0; i < chunks - 1 && start < full.length; i++) {
    final end = start + 1 + _rng.nextInt((full.length - start).clamp(1, 20));
    result.add(full.sublist(start, end.clamp(start + 1, full.length)));
    start = end.clamp(start + 1, full.length);
  }
  if (start < full.length) result.add(full.sublist(start));
  return result;
}

// Random delay: 3000–7000ms (non-periodic interval)
int _heartbeatDelayMs() => 3000 + _rng.nextInt(4001); // 3000..7000

// p15: adaptive interval based on observed stability
int _adaptiveHeartbeatDelayMs(int survivalMs, bool hadErrors) {
  if (hadErrors) {
    // More aggressive: shorter interval to detect death faster
    return 2000 + _rng.nextInt(2000);
  }
  if (survivalMs > 10000) {
    // Stable — relax to longer interval (less detectable)
    return 4000 + _rng.nextInt(5000);
  }
  return _heartbeatDelayMs();
}

// p16: calculate DPI suspicion score
double _calcDpiSuspicion({
  required bool errorKilled,
  required bool blackhole,
  required int survivalMs,
  required bool survived,
}) {
  if (survived) return 0.0;
  if (errorKilled) {
    if (survivalMs < 5000) return 0.9;
    if (survivalMs < 10000) return 0.6;
    return 0.4;
  }
  if (blackhole) return 0.4;
  return 0.1;
}

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
  bool          hadErrors   = false;

  try {
    rawSock = await Socket.connect(
      ip, 443,
      timeout: const Duration(seconds: 5),
    );

    // Cert validation: reject captive portals but allow CDN fronting
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
        hadErrors      = true;
        if (!deathCompleter.isCompleted) deathCompleter.complete();
      },
      onDone: () {
        connectionDead = true;
        if (!deathCompleter.isCompleted) deathCompleter.complete();
      },
      cancelOnError: true,
    );

    // ── p13+p14+p15: Adaptive fragmented heartbeat with fake idle ──────────
    // - Randomly use fragmented or normal payload
    // - Occasionally inject fake silence (p14)
    // - Adapt interval based on stability (p15)
    Future<void> runHeartbeat() async {
      while (true) {
        // p15: adaptive interval
        final delay = _adaptiveHeartbeatDelayMs(
          sw.elapsedMilliseconds,
          hadErrors,
        );
        await Future.delayed(Duration(milliseconds: delay));

        // p14: fakeIdlePattern — 20% chance of injecting longer silence
        if (_rng.nextDouble() < 0.20) {
          await Future.delayed(Duration(milliseconds: 2000 + _rng.nextInt(3000)));
        }

        if (connectionDead) return;
        if (deathCompleter.isCompleted) return;
        if (isCancelled?.call() == true) return;

        try {
          final tlsRef = tls;
          if (tlsRef == null) return;

          // p13: fragmentation — randomly split payload into chunks
          if (_rng.nextBool()) {
            final chunks = _fragmentedPayload();
            for (final chunk in chunks) {
              tlsRef.add(chunk);
              // Small inter-chunk delay for more natural pattern
              if (chunk != chunks.last) {
                await Future.delayed(
                  Duration(microseconds: 200 + _rng.nextInt(800)),
                );
              }
            }
          } else {
            tlsRef.add(_heartbeatPayload());
          }

          await tlsRef.flush();
        } catch (_) {
          errorKilled    = true;
          connectionDead = true;
          if (!deathCompleter.isCompleted) deathCompleter.complete();
          return;
        }
      }
    }
    runHeartbeat().ignore();

    // ── Cancellation check loop ──────────────────────────────────────────────
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

    // ── Early blackhole detection: if no activity within 5s, bail out ──────
    Future.delayed(const Duration(milliseconds: 5000), () {
      if (!deathCompleter.isCompleted && !connectionDead && !hadErrors) {
        // No data, no error, no heartbeat response — likely a blackhole
        blackhole = true;
        connectionDead = true;
        if (!deathCompleter.isCompleted) deathCompleter.complete();
      }
    }).ignore();

    // ── Blackhole detection: stalled socket (tightened: +4000 instead of +8000)
    final stallTimeout = Duration(milliseconds: survivalTargetMs + 4000);

    await Future.any([
      Future.delayed(Duration(milliseconds: survivalTargetMs)),
      deathCompleter.future,
    ]).timeout(stallTimeout, onTimeout: () {
      blackhole = true;
      if (!deathCompleter.isCompleted) deathCompleter.complete();
    }).catchError((_) {});

    sw.stop();
    connectionDead = true; // BUGFIX: set before sub.cancel() to stop heartbeat loop immediately
    await sub.cancel();
    try { await tls.close(); } catch (_) {}
    tls.destroy();

    // BUG 2 FIX: use survivalTargetMs not hardcoded 5000ms
    final survived = !errorKilled && !blackhole && sw.elapsedMilliseconds >= survivalTargetMs;

    return SurvivalResult(
      survived:   survived,
      survivalMs: sw.elapsedMilliseconds,
      dpiKilled:  errorKilled,
      blackhole:  blackhole,
      dpiSuspicionScore: _calcDpiSuspicion(
        errorKilled: errorKilled,
        blackhole: blackhole,
        survivalMs: sw.elapsedMilliseconds,
        survived: survived,
      ),
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
    final survived = false;
    return SurvivalResult(
      survived:   survived,
      survivalMs: sw.elapsedMilliseconds,
      dpiKilled:  errorKilled,
      blackhole:  blackhole,
      dpiSuspicionScore: _calcDpiSuspicion(
        errorKilled: errorKilled,
        blackhole: blackhole,
        survivalMs: sw.elapsedMilliseconds,
        survived: survived,
      ),
    );
  } finally {
    try { tls?.destroy();     } catch (_) {}
    try { rawSock?.destroy(); } catch (_) {}
  }
}
