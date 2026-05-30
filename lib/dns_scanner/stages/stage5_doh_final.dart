// ================================================================
// MidOne DNS Scanner — Stage 5: DoH Check + Final Ranking
// ================================================================
//
// Goal:   Final ranking with composite score. DoH is a BONUS,
//         not a primary metric.
//
// Final score formula:
//
//   score = (freedom × 0.60)
//         + (latencyNorm × 0.20)
//         + (jitterNorm  × 0.20)   ← was 0.15, raised so weights sum to 1.0
//         − (packetLossPenalty)    ← lossRate × 40 pts, applied after weighted sum
//         + (dohBonus    × 0.05)   ← additive bonus, max 5 pts
//
//   All components are normalized to [0, 100].
//
// Tie-breaking:
//   Equal final score (within ±0.5) → DoH support wins.
//
// Output: Top [stage5KeepTop] servers with finalScore + finalRank.
// ================================================================

import 'dart:async';
import 'dart:io';
import 'package:http/http.dart' as http;

import '../dns_resolver.dart';
import '../models.dart';

class Stage5DoHFinal {
  static Future<List<DNSServer>> run(
    List<DNSServer> candidates,
    ScanConfig config, {
    void Function(ScanProgress)? onProgress,
  }) async {
    // ── Check DoH support for each candidate ────────────────────
    int tested = 0;

    await concurrentMap<DNSServer, DNSServer>(
      candidates,
      (server) async {
        server.currentStage = ScanStage.stage5Doh;

        final (:supported, :latencyMs) = await _checkDoH(server.ip, config);
        server.supportsDoH   = supported;
        server.dohLatencyMs  = latencyMs;

        tested++;
        // FIX: guard against candidates.length == 0 to avoid division by zero.
        // In practice scanner.dart stops early if candidates is empty, but
        // defensive coding here keeps Stage 5 self-contained.
        final pct = candidates.isEmpty
            ? 0.95
            : 0.80 + tested / candidates.length * 0.15;
        onProgress?.call(ScanProgress(
          stage: ScanStage.stage5Doh,
          tested: tested,
          total: candidates.length,
          survivors: candidates.length,
          message: 'DoH check: $tested/${candidates.length}',
          percentage: pct,
        ));

        return server;
      },
      concurrency: 10, // DoH is expensive — limit parallelism
    );

    // ── Compute final scores ────────────────────────────────────
    _computeFinalScores(candidates, config);

    // ── Sort: primary = finalScore desc, secondary = DoH support ──
    candidates.sort((a, b) {
      final diff = (b.finalScore ?? 0) - (a.finalScore ?? 0);
      if (diff.abs() > 0.5) return diff.sign.toInt();
      // Tie-break: DoH support
      final aDoH = (a.supportsDoH ?? false) ? 1 : 0;
      final bDoH = (b.supportsDoH ?? false) ? 1 : 0;
      return bDoH - aDoH;
    });

    final top = candidates.take(config.stage5KeepTop).toList();

    // Assign final ranks
    for (int i = 0; i < top.length; i++) {
      top[i].finalRank = i + 1;
      top[i].currentStage = ScanStage.complete;
    }

    // FIX: top.first throws StateError on an empty list. Stage 4's fallback
    // guarantees at least one server, but we guard here too so Stage 5 is
    // self-contained and safe even if called independently.
    final summaryMsg = top.isEmpty
        ? 'Scan complete — no servers passed final ranking.'
        : 'Scan complete! Top ${top.length} DNS servers ranked. '
          'Winner: ${top.first.ip} '
          '(score: ${top.first.finalScore?.toStringAsFixed(1)})';

    onProgress?.call(ScanProgress(
      stage: ScanStage.stage5Doh,
      tested: candidates.length,
      total: candidates.length,
      survivors: top.length,
      message: summaryMsg,
      percentage: 1.0,
    ));

    return top;
  }

  // ── Final score computation ──────────────────────────────────

  static void _computeFinalScores(List<DNSServer> servers, ScanConfig config) {
    // Guard: nothing to score — should not happen in normal flow because
    // Stage 4 guarantees at least one server, but defensive here so that
    // _computeFinalScores is safe if called independently.
    if (servers.isEmpty) return;

    // Find normalization bounds across the candidate set
    final latencies = servers
        .map((s) => s.avgLatencyMs ?? 9999.0)
        .toList();
    final jitters = servers
        .map((s) => s.jitterMs ?? 999.0)
        .toList();

    final minLat  = latencies.reduce((a, b) => a < b ? a : b);
    final maxLat  = latencies.reduce((a, b) => a > b ? a : b);
    final minJit  = jitters.reduce((a, b) => a < b ? a : b);
    final maxJit  = jitters.reduce((a, b) => a > b ? a : b);

    for (final s in servers) {
      // Freedom: 0–100
      final freedomPts = (s.freedomScore ?? 0) * 100;

      // Latency: normalize to 0–100 (higher = better = lower latency)
      final latencyPts = _normalizeInverse(
        s.avgLatencyMs ?? maxLat,
        minLat,
        maxLat,
      );

      // Jitter: normalize to 0–100 (higher = better = lower jitter)
      final jitterPts = _normalizeInverse(
        s.jitterMs ?? maxJit,
        minJit,
        maxJit,
      );

      // FIX #9: Packet loss is now a first-class penalty applied AFTER the
      // weighted sum, not folded silently into jitter with a 0.1 multiplier.
      // The old formula: (jitterPts - lossRate*100 * 0.1) * 0.15
      // meant 100% packet loss only deducted 1.5 pts — barely noticeable.
      // New formula: each 10% packet loss removes 4 pts (max 40 pts at 100%).
      // A server dropping half its packets loses ~20 pts, which is meaningful
      // on a 0–100 scale.
      final lossRate    = s.packetLossRate ?? 0.0;
      final lossPenalty = lossRate * 40.0; // 0% loss → 0 pts, 100% → −40 pts

      // DoH bonus: flat 5 points if supported
      final dohBonus = (s.supportsDoH ?? false) ? 5.0 : 0.0;

      // FIX #8: Divide by totalWeight so scores are correct even when a
      // caller passes custom weights that don't sum to exactly 1.0.
      // With the default weights (0.60+0.20+0.20=1.0) this is a no-op.
      final tw = config.totalWeight;
      final raw =
          (freedomPts * config.weightFreedom +
           latencyPts * config.weightLatency +
           jitterPts  * config.weightJitter) / tw;

      s.finalScore = clamp(raw - lossPenalty + dohBonus, 0, 100);
    }
  }

  /// Normalize value to [0, 100] where lower input = higher score.
  static double _normalizeInverse(double value, double min, double max) {
    if ((max - min).abs() < 0.001) return 100.0; // All equal
    final normalized = (value - min) / (max - min);
    return clamp((1.0 - normalized) * 100.0, 0.0, 100.0);
  }

  // ── DoH support check ────────────────────────────────────────

  /// Known DoH-capable servers: IP → canonical hostname.
  /// Connecting via hostname avoids TLS certificate mismatch errors
  /// that occur when using a raw IP address in HTTPS requests.
  /// Sources: official provider documentation (verified 2026-05).
  static const _knownDoHHosts = <String, String>{
    // Cloudflare — https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/
    '1.1.1.1':           'cloudflare-dns.com',
    '1.0.0.1':           'cloudflare-dns.com',
    // Google — https://developers.google.com/speed/public-dns/docs/doh
    '8.8.8.8':           'dns.google',
    '8.8.4.4':           'dns.google',
    // Quad9 — https://www.quad9.net/support/faq/ (endpoint: /dns-query)
    '9.9.9.9':           'dns.quad9.net',
    '149.112.112.112':   'dns.quad9.net',
    // AdGuard — https://adguard-dns.io/en/public-dns.html (DoH: dns.adguard-dns.com/dns-query)
    '94.140.14.14':      'dns.adguard-dns.com',
    '94.140.15.15':      'dns.adguard-dns.com',
    // NextDNS: requires a personal config ID — cannot be used as a generic
    // known-host entry. Removed to avoid false-positive DoH detection.
  };

  /// Try to use the DNS server as a DoH endpoint.
  ///
  /// Strategy:
  ///   1. If the IP is a known DoH provider, query its canonical hostname
  ///      so TLS certificate validation succeeds.
  ///   2. Otherwise, attempt connection with a custom HttpClient that
  ///      accepts self-signed / IP certificates (common on private DNS).
  static Future<({bool supported, double? latencyMs})> _checkDoH(
    String serverIp,
    ScanConfig config,
  ) async {
    // ── Path 1: known provider with valid hostname ────────────
    final knownHost = _knownDoHHosts[serverIp];
    if (knownHost != null) {
      final urls = [
        'https://$knownHost/dns-query?name=example.com&type=A',
        'https://$knownHost/resolve?name=example.com&type=A',
      ];
      for (final url in urls) {
        try {
          final start = DateTime.now();
          final response = await http
              .get(Uri.parse(url),
                  headers: {'Accept': 'application/dns-json'})
              .timeout(config.dohTimeout);
          final elapsed =
              DateTime.now().difference(start).inMicroseconds / 1000.0;
          if (response.statusCode == 200) {
            return (supported: true, latencyMs: elapsed);
          }
        } on SocketException {
          continue;
        } on TimeoutException {
          continue;
        } catch (_) {
          continue;
        }
      }
      return (supported: false, latencyMs: null);
    }

    // ── Path 2: unknown server — bypass cert validation ───────
    // Many private/regional DNS servers that support DoH use
    // self-signed certificates or serve DoH on their IP directly.
    final paths = [
      '/dns-query?name=example.com&type=A',
      '/resolve?name=example.com&type=A',
    ];

    for (final path in paths) {
      HttpClient? client;
      try {
        client = HttpClient()
          ..badCertificateCallback = (_, __, ___) => true
          ..connectionTimeout = config.dohTimeout;

        final start = DateTime.now();
        final request = await client
            .getUrl(Uri.parse('https://$serverIp$path'))
            .timeout(config.dohTimeout);
        request.headers
          ..set('Accept', 'application/dns-json')
          ..set('Host', serverIp);

        final response = await request.close().timeout(config.dohTimeout);
        final elapsed =
            DateTime.now().difference(start).inMicroseconds / 1000.0;

        if (response.statusCode == 200) {
          return (supported: true, latencyMs: elapsed);
        }
      } on SocketException {
        continue;
      } on TimeoutException {
        continue;
      } on HandshakeException {
        // TLS failed even with relaxed validation → no DoH
        continue;
      } catch (_) {
        continue;
      } finally {
        client?.close(force: true);
      }
    }

    return (supported: false, latencyMs: null);
  }
}
