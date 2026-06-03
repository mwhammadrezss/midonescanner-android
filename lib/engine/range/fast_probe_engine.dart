// lib/engine/range/fast_probe_engine.dart
// Real TCP port 443 probe — no TLS, just connectivity check for speed

import 'dart:async';
import 'dart:io';

class FastProbeResult {
  final String ip;
  final double tcpMs;
  final bool alive;
  final bool timedOut;

  const FastProbeResult({
    required this.ip,
    required this.tcpMs,
    required this.alive,
    required this.timedOut,
  });
}

class FastProbeEngine {
  final int defaultTimeoutMs;

  const FastProbeEngine({this.defaultTimeoutMs = 1200});

  Future<FastProbeResult> probe(String ip, {int? timeoutMs}) async {
    final timeout = timeoutMs ?? defaultTimeoutMs;
    Socket? sock;
    final sw = Stopwatch()..start();
    try {
      sock = await Socket.connect(
        ip,
        443,
        timeout: Duration(milliseconds: timeout),
      );
      sw.stop();
      final tcpMs = sw.elapsedMicroseconds / 1000.0;
      return FastProbeResult(ip: ip, tcpMs: tcpMs, alive: true, timedOut: false);
    } on TimeoutException {
      sw.stop();
      return FastProbeResult(ip: ip, tcpMs: timeout.toDouble(), alive: false, timedOut: true);
    } on SocketException {
      sw.stop();
      return FastProbeResult(ip: ip, tcpMs: sw.elapsedMicroseconds / 1000.0, alive: false, timedOut: false);
    } catch (_) {
      sw.stop();
      return FastProbeResult(ip: ip, tcpMs: sw.elapsedMicroseconds / 1000.0, alive: false, timedOut: false);
    } finally {
      try {
        await sock?.close();
      } catch (_) {}
      try {
        sock?.destroy();
      } catch (_) {}
    }
  }
}
