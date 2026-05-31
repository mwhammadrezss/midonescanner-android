// lib/engine/deep_scan_engine.dart
// ─── 7-Stage Deep Scan Engine ────────────────────────────────────────────────
//
// Pipeline:
//   Stage 0  → Fast TCP prefilter (40 concurrent, 4s)
//   Stage 1  → CDN Family probe — all 6 families, max 25s/IP, max 8s/family
//   Stage 2  → Filter: keep top 10% or top 30, whichever is smaller
//   Stage 3  → 25s TLS survival test (tunnelSurvivalTest)
//   Stage 4  → HTTP/2 ALPN check
//   Stage 5  → Bandwidth test (4s window)
//   Stage 6  → Connection reuse (3 consecutive TLS sessions)
//   Stage 6.5→ WebSocket Bonus — ONLY when bestFamily == 'Cloudflare'
//              wsOk=true → +5 score | wsOk=false/null → +0
//   Stage 7  → CDN intelligence update + final ScanResult assembly

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import '../models/scan_result.dart';
import '../geo/geoip.dart';
import '../utils/stats_utils.dart';
import '../storage/scan_history.dart';
import 'probe_engine.dart';
import 'tunnel_engine.dart';
import 'concurrency_engine.dart';
import 'subnet_cache.dart';
import 'soft_blacklist.dart';
import 'grading_engine.dart';

// ─── CDN Family definitions ───────────────────────────────────────────────────
class _CdnFamily {
  final String name;
  final List<String> snis;
  const _CdnFamily(this.name, this.snis);
}

const _kCdnFamilies = <_CdnFamily>[
  _CdnFamily('Google',     ['www.google.com', 'google.com', 'fonts.googleapis.com']),
  _CdnFamily('Cloudflare', ['speed.cloudflare.com', 'cloudflare.com']),
  _CdnFamily('Fastly',     ['global.fastly.net']),
  _CdnFamily('Akamai',     ['a248.e.akamai.net']),
  _CdnFamily('GitHub',     ['github.com']),
  _CdnFamily('Microsoft',  ['ajax.aspnetcdn.com']),
];

// ─── Internal data classes ────────────────────────────────────────────────────
class _FamilyResult {
  final String family;
  final String bestSni;
  final double latencyMs;
  final double tlsMs;
  final bool   alive;

  const _FamilyResult({
    required this.family,
    required this.bestSni,
    required this.latencyMs,
    required this.tlsMs,
    required this.alive,
  });
}

class _Stage1IpResult {
  final String ip;
  final String country;
  final String flag;
  final List<_FamilyResult> families;
  double stage1Score = 0.0;

  _Stage1IpResult({
    required this.ip,
    required this.country,
    required this.flag,
    required this.families,
  });

  _FamilyResult? get bestFamily {
    final alive = families.where((f) => f.alive).toList();
    if (alive.isEmpty) return null;
    alive.sort((a, b) => a.latencyMs.compareTo(b.latencyMs));
    return alive.first;
  }
}

// ─── Subnet → preferred CDN family (session-lifetime cache) ──────────────────
final _subnetFamilyPref = <String, String>{};

String _subnetKey(String ip) {
  final parts = ip.split('.');
  if (parts.length < 3) return ip;
  return '${parts[0]}.${parts[1]}.${parts[2]}';
}

// ─── Shared RNG ───────────────────────────────────────────────────────────────
final _rng = Random.secure();

// ─── Stage 1 helper: probe one CDN family for one IP ─────────────────────────
// Tries SNIs in the family sequentially; stops at first success (intra-family
// early exit). Respects per-family budget and per-IP total stopwatch.
Future<_FamilyResult> _probeFamilyForIp(
  String ip,
  _CdnFamily family,
  Stopwatch totalSw,
  int familyBudgetMs,
  bool Function() isCancelled,
) async {
  for (final sni in family.snis) {
    if (isCancelled()) {
      return _FamilyResult(family: family.name, bestSni: sni, latencyMs: 9999, tlsMs: 9999, alive: false);
    }
    // FIX BUG-1: clamp() on int returns num, not int — use .toInt()
    final remaining = (25000 - totalSw.elapsedMilliseconds).clamp(0, familyBudgetMs).toInt();
    if (remaining < 500) {
      return _FamilyResult(family: family.name, bestSni: sni, latencyMs: 9999, tlsMs: 9999, alive: false);
    }
    final timeoutMs = remaining.clamp(500, familyBudgetMs).toInt();

    Socket?       rawSock;
    SecureSocket? tls;
    try {
      final sw = Stopwatch()..start();
      rawSock = await Socket.connect(ip, 443, timeout: Duration(milliseconds: timeoutMs));
      final tcpMs = sw.elapsedMicroseconds / 1000.0;

      tls = await SecureSocket.secure(
        rawSock,
        host: sni,
        onBadCertificate: acceptCdnCert,
        supportedProtocols: [kShiroAlpn],
      ).timeout(Duration(milliseconds: timeoutMs));

      sw.stop();
      final totalMs = sw.elapsedMicroseconds / 1000.0;
      final tlsMs   = totalMs - tcpMs;

      try { await tls.close().timeout(const Duration(seconds: 3)); } catch (_) {}
      tls.destroy();
      rawSock.destroy();

      return _FamilyResult(
        family:    family.name,
        bestSni:   sni,
        latencyMs: totalMs,
        tlsMs:     tlsMs,
        alive:     true,
      );
    } catch (_) {
      // try next SNI in same family
    } finally {
      try { tls?.destroy();     } catch (_) {}
      try { rawSock?.destroy(); } catch (_) {}
    }
  }

  return _FamilyResult(
    family:    family.name,
    bestSni:   family.snis.first,
    latencyMs: 9999,
    tlsMs:     9999,
    alive:     false,
  );
}

// ─── Stage 1 helper: compute stage1Score ─────────────────────────────────────
// familyScore  50% — fraction of alive CDN families
// latencyScore 30% — best alive latency (logarithmic)
// stabilityScore 20% — count of alive families beyond 1
double _computeStage1Score(_Stage1IpResult r) {
  final aliveFamilies = r.families.where((f) => f.alive).toList();
  if (aliveFamilies.isEmpty) return 0.0;

  final familyScore = (aliveFamilies.length / _kCdnFamilies.length) * 50.0;

  final bestLatency  = aliveFamilies.map((f) => f.latencyMs).reduce(min);
  final logMax       = log(1001);
  final latencyScore = (1.0 - (log(bestLatency.clamp(0, 9999) + 1) / logMax).clamp(0.0, 1.0)) * 30.0;

  final stabilityScore =
      ((aliveFamilies.length - 1) / (_kCdnFamilies.length - 1)).clamp(0.0, 1.0) * 20.0;

  return (familyScore + latencyScore + stabilityScore).clamp(0.0, 100.0);
}

// ─── Stage 4 helper: HTTP/2 ALPN check ───────────────────────────────────────
Future<bool> _checkH2Alpn(String ip, String sni) async {
  Socket?       rawSock;
  SecureSocket? tls;
  try {
    rawSock = await Socket.connect(ip, 443, timeout: const Duration(seconds: 4));
    tls = await SecureSocket.secure(
      rawSock,
      host: sni,
      onBadCertificate: acceptCdnCert,
      supportedProtocols: ['h2', 'http/1.1'],
    ).timeout(const Duration(seconds: 6));
    final isH2 = tls.selectedProtocol == 'h2';
    try { await tls.close().timeout(const Duration(seconds: 3)); } catch (_) {}
    tls.destroy();
    return isH2;
  } catch (_) {
    return false;
  } finally {
    try { tls?.destroy();     } catch (_) {}
    try { rawSock?.destroy(); } catch (_) {}
  }
}

// ─── Stage 6 helper: connection reuse test ───────────────────────────────────
// 3 consecutive TLS sessions. Returns 0.0–1.0: 1.0 = all succeed, low jitter.
Future<double> _testConnectionReuse(
  String ip,
  String sni,
  bool Function() isCancelled,
) async {
  final latencies = <double>[];
  for (int i = 0; i < 3; i++) {
    if (isCancelled()) break;
    final result = await androidTlsProbe(ip, sni: sni);
    if (result != null) latencies.add(result.latencyMs);
    if (i < 2) await Future.delayed(const Duration(milliseconds: 300));
  }
  if (latencies.isEmpty) return 0.0;
  final successRate   = latencies.length / 3.0;
  final jitter        = latencies.length >= 2 ? calcJitter(latencies) : 0.0;
  final jitterPenalty = (jitter / 500.0).clamp(0.0, 0.5);
  return (successRate - jitterPenalty).clamp(0.0, 1.0);
}

// ─── Stage 6.5 helper: WebSocket Bonus — Cloudflare ONLY ─────────────────────
// Two-phase DPI test:
//   Phase 1 — 2s idle hold: detects DPI that RSTs idle TLS connections
//   Phase 2 — WS Upgrade:   detects DPI that filters WebSocket headers
//
// NEVER rejects an IP. Only used as +5 score bonus.
// Sec-WebSocket-Key is randomly generated per-call (not a fixed fingerprint).
//
// FIX BUG-2: Do NOT use tls.first — it consumes the single-subscription stream
// and makes tls.listen() crash with "Bad state: Stream already listened to".
// Instead, open ONE StreamSubscription at the start and reuse it for both phases.
Future<bool?> _wsBonus(
  String ip,
  String sni, {
  int totalBudgetMs = 8000,
}) async {
  Socket?       raw;
  SecureSocket? tls;
  StreamSubscription<List<int>>? sub;

  // Random base64 WS key (16 random bytes) — not a fixed fingerprint
  final keyBytes = List<int>.generate(16, (_) => _rng.nextInt(256));
  final wsKey    = base64.encode(keyBytes);

  try {
    // TCP + TLS — 1/3 of budget each
    raw = await Socket.connect(
      ip, 443,
      timeout: Duration(milliseconds: totalBudgetMs ~/ 3),
    );
    tls = await SecureSocket.secure(
      raw,
      host: sni,
      onBadCertificate: acceptCdnCert,
    ).timeout(Duration(milliseconds: totalBudgetMs ~/ 3));

    tls.setOption(SocketOption.tcpNoDelay, true);

    // ── Phase 1: 2s idle hold ────────────────────────────────────────────────
    // Open ONE subscription here and keep it alive for Phase 2 as well.
    // Timeout is EXPECTED (server is waiting for us to speak first).
    // Any non-timeout error (RST / EOF) = DPI killed the connection.
    bool idleKilled       = false;
    final idleCompleter   = Completer<void>();

    sub = tls.listen(
      (_) {
        // Server pushed data before we sent anything — unexpected but OK
        if (!idleCompleter.isCompleted) idleCompleter.complete();
      },
      onError: (_) {
        idleKilled = true;
        if (!idleCompleter.isCompleted) idleCompleter.complete();
      },
      onDone: () {
        idleKilled = true;
        if (!idleCompleter.isCompleted) idleCompleter.complete();
      },
      cancelOnError: false,
    );

    try {
      await idleCompleter.future.timeout(const Duration(seconds: 2));
    } on TimeoutException {
      // Expected — server is waiting, connection alive
    }

    if (idleKilled) return false;

    // ── Phase 2: WebSocket Upgrade ───────────────────────────────────────────
    // Reuse the same subscription, just swap out the onData/onDone/onError
    // handlers — this avoids opening a second subscription (which would throw).
    final wsRequest =
        'GET / HTTP/1.1\r\n'
        'Host: $sni\r\n'
        'Upgrade: websocket\r\n'
        'Connection: Upgrade\r\n'
        'Sec-WebSocket-Key: $wsKey\r\n'
        'Sec-WebSocket-Version: 13\r\n'
        '\r\n';

    try {
      tls.write(wsRequest);
    } catch (_) {
      return false;
    }

    final buf         = StringBuffer();
    final wsCompleter = Completer<bool>();

    sub.onData((chunk) {
      buf.write(utf8.decode(chunk, allowMalformed: true));
      if (buf.toString().contains('HTTP/') && !wsCompleter.isCompleted) {
        wsCompleter.complete(true);
      }
    });
    sub.onDone(() {
      if (!wsCompleter.isCompleted) wsCompleter.complete(false);
    });
    sub.onError((_) {
      if (!wsCompleter.isCompleted) wsCompleter.complete(false);
    });

    final ok = await wsCompleter.future.timeout(
      Duration(milliseconds: totalBudgetMs ~/ 3),
      onTimeout: () => false,
    );

    await sub.cancel();
    sub = null;
    return ok;

  } catch (_) {
    return false;
  } finally {
    try { await sub?.cancel(); } catch (_) {}
    try { tls?.destroy();      } catch (_) {}
    try { raw?.destroy();      } catch (_) {}
  }
}

// ─── Final score computation ──────────────────────────────────────────────────
// Weights: stability 25%, survival 20%, latency 18%, bandwidth 15%, h2 12%, reuse 10%
// WS Bonus: +5 only when bestFamily == 'Cloudflare' AND wsOk == true
double _computeFinalScore({
  required double  stabilityScore,
  required bool    survived,
  required int     survivalMs,
  required double  bestLatencyMs,
  required double? bandwidthKBs,
  required bool    h2Supported,
  required double  reuseScore,
  required bool    wsBonus,
}) {
  // stability (25%)
  final stab = stabilityScore.clamp(0.0, 100.0) / 100.0 * 25.0;

  // survival (20%)
  final survivalRatio = survived ? 1.0 : (survivalMs / 25000.0).clamp(0.0, 1.0);
  final surv = survivalRatio * 20.0;

  // latency (18%) — logarithmic
  final logMax   = log(1001);
  final latScore = (1.0 - (log(bestLatencyMs.clamp(0, 9999) + 1) / logMax).clamp(0.0, 1.0)) * 18.0;

  // bandwidth (15%) — saturates at 500 KB/s
  final bwScore = bandwidthKBs != null
      ? (bandwidthKBs / 500.0).clamp(0.0, 1.0) * 15.0
      : 0.0;

  // h2 (12%) — binary
  final h2Score = h2Supported ? 12.0 : 0.0;

  // reuse (10%)
  final reuseWeighted = reuseScore * 10.0;

  // WS bonus (+5, Cloudflare only)
  final wsScore = wsBonus ? 5.0 : 0.0;

  return (stab + surv + latScore + bwScore + h2Score + reuseWeighted + wsScore)
      .clamp(0.0, 100.0);
}

// ─── PUBLIC API ───────────────────────────────────────────────────────────────
/// Runs the complete 7-stage deep scan pipeline.
/// Returns a list of [ScanResult] sorted best-to-worst.
Future<List<ScanResult>> runDeepScanEngine(
  List<String> ips, {
  void Function(int done, int total, ScanResult result)? onProgress,
  void Function(int liveCount, int totalCount)? onPrefilterDone,
  bool Function()? isCancelled,
}) async {
  final cancelCheck = isCancelled ?? () => false;
  final results     = <ScanResult>[];

  // ── STAGE 0: Fast TCP prefilter ───────────────────────────────────────────
  const int _prefilterConcurrency = 40;
  const int _prefilterTimeoutMs   = 4000;
  final prefilterSem = Semaphore(_prefilterConcurrency);

  final prefilterResults = await Future.wait(ips.map((ip) async {
    if (cancelCheck()) return null;
    await prefilterSem.acquire();
    try {
      if (cancelCheck()) return null;
      Socket? s;
      try {
        s = await Socket.connect(ip, 443,
            timeout: const Duration(milliseconds: _prefilterTimeoutMs));
        s.destroy();
        return ip;
      } catch (_) {
        SoftBlacklist().recordFailure(ip);
        SubnetMemoryCache().recordFailure(ip);
        return null;
      }
    } finally {
      prefilterSem.release();
    }
  }));

  final liveIps = prefilterResults.whereType<String>().toList();
  onPrefilterDone?.call(liveIps.length, ips.length);
  if (liveIps.isEmpty || cancelCheck()) return results;

  // progress: total = liveIps count so UI shows 0→100% over all live IPs
  final _progressTotal = liveIps.length;

  // progress: start event (0%) — signals deep scan has begun
  {
    final _startResult = ScanResult(
      ip: liveIps.first, latencyMs: 0, jitterMs: 0, isAlive: false,
      grade: '-', country: '', flag: '', loss: 0, reliability: 0,
      score: null, survivalMs: null, retransmits: 0,
      phase: ScanPhase.tlsFail, tier: IpTier.dead, dpiSuspicion: 0,
    );
    onProgress?.call(0, _progressTotal, _startResult);
  }

  // ── STAGE 1: CDN Family probe ─────────────────────────────────────────────
  // 6 concurrent IPs. Per IP: max 25s total, max 8s per family.
  // All 6 families always tested (no inter-family early exit).
  // Stage 7 intelligence: preferred family for this subnet tested first.
  const int _stage1Concurrency = 6;
  final stage1Sem     = Semaphore(_stage1Concurrency);
  final stage1Results = <_Stage1IpResult>[];

  await Future.wait(liveIps.map((ip) async {
    if (cancelCheck()) return;
    await stage1Sem.acquire();
    try {
      if (cancelCheck()) return;

      final (country, flag) = GeoIPOffline().lookupFull(ip);
      final ipTotalSw       = Stopwatch()..start();

      // Stage 7: preferred family first for this subnet
      final preferred       = _subnetFamilyPref[_subnetKey(ip)];
      final orderedFamilies = preferred != null
          ? [
              ..._kCdnFamilies.where((f) => f.name == preferred),
              ..._kCdnFamilies.where((f) => f.name != preferred),
            ]
          : _kCdnFamilies;

      final familyResults = <_FamilyResult>[];
      for (final family in orderedFamilies) {
        if (cancelCheck()) break;
        if (ipTotalSw.elapsedMilliseconds >= 25000) break;
        final result = await _probeFamilyForIp(
            ip, family, ipTotalSw, 8000, cancelCheck);
        familyResults.add(result);
      }

      final ipResult = _Stage1IpResult(
        ip:       ip,
        country:  country,
        flag:     flag,
        families: familyResults,
      );
      ipResult.stage1Score = _computeStage1Score(ipResult);
      stage1Results.add(ipResult);
    } finally {
      stage1Sem.release();
    }
  }));

  if (cancelCheck()) return results;

  // ── STAGE 2: Filter — top 10% or top 30 ──────────────────────────────────
  stage1Results.sort((a, b) => b.stage1Score.compareTo(a.stage1Score));
  // FIX: int.clamp() returns num, min(int,num) returns num → .toInt() to guarantee int
  final keepCount = min(
    30,
    (stage1Results.length * 0.10).ceil().clamp(1, stage1Results.length).toInt(),
  );
  final winners = stage1Results.take(keepCount).toList();
  if (winners.isEmpty || cancelCheck()) return results;

  // ── STAGES 3–7: Elite verification ───────────────────────────────────────
  const int _eliteConcurrency = 4;
  final eliteSem = Semaphore(_eliteConcurrency);
  // progress: track how many of the liveIps total we have "processed"
  // Stage 1 already tested all liveIps; elite stage processes winners subset.
  // We map eliteDone onto the full liveIps range so the bar reaches 100%.
  // Formula: done = stage1Count + eliteDone * (remaining / winners.count)
  final _stage1Count = liveIps.length - winners.length; // IPs filtered out
  int eliteDone  = 0;

  await Future.wait(winners.map((w) async {
    if (cancelCheck()) return;
    await eliteSem.acquire();
    try {
      if (cancelCheck()) return;

      final bestFamilyResult = w.bestFamily;
      if (bestFamilyResult == null) return; // dead IP — skip

      final bestSni    = bestFamilyResult.bestSni;
      final bestFamily = bestFamilyResult.family;
      final bestLat    = bestFamilyResult.latencyMs;
      final bestTlsMs  = bestFamilyResult.tlsMs;

      // ── STAGE 3: 25s TLS survival test ───────────────────────────────────
      final survival = await tunnelSurvivalTest(
        w.ip,
        sni:              bestSni,
        survivalTargetMs: 25000,
        isCancelled:      cancelCheck,
      );
      if (cancelCheck()) return;

      // ── STAGE 4: HTTP/2 ALPN check ────────────────────────────────────────
      final h2 = await _checkH2Alpn(w.ip, bestSni);
      if (cancelCheck()) return;

      // ── STAGE 5: Bandwidth test (4s window) ───────────────────────────────
      final bandwidth = await measureBandwidthKBs(
          w.ip, sni: bestSni, testDurationMs: 4000);
      if (cancelCheck()) return;

      // ── STAGE 6: Connection reuse (3 consecutive sessions) ────────────────
      final reuseScore = await _testConnectionReuse(w.ip, bestSni, cancelCheck);
      if (cancelCheck()) return;

      // ── STAGE 6.5: WebSocket Bonus — CLOUDFLARE ONLY ─────────────────────
      // Runs ONLY when bestFamily == 'Cloudflare'.
      // wsOk=true → +5 score | wsOk=false/null → +0
      // NEVER rejects the IP regardless of result.
      bool wsBonus = false;
      if (bestFamily == 'Cloudflare') {
        try {
          final wsOk = await _wsBonus(w.ip, bestSni, totalBudgetMs: 8000)
              .timeout(const Duration(seconds: 10), onTimeout: () => false);
          wsBonus = wsOk == true;
        } catch (_) {
          wsBonus = false; // any error → no bonus, keep IP
        }
      }
      if (cancelCheck()) return;

      // ── STAGE 7: CDN intelligence update ─────────────────────────────────
      _subnetFamilyPref[_subnetKey(w.ip)] = bestFamily;
      SubnetMemoryCache().recordSuccess(w.ip, bestLat, bestSni);
      if (survival.survived) {
        SoftBlacklist().recordSuccess(w.ip);
      } else {
        SoftBlacklist().recordFailure(w.ip);
      }

      // ── Stability score from alive family fraction ────────────────────────
      final aliveFamilyCount = w.families.where((f) => f.alive).length;
      final stabilityScore   = (aliveFamilyCount / _kCdnFamilies.length) * 100.0;
      final reliability      = aliveFamilyCount / _kCdnFamilies.length;

      // ── Final score ───────────────────────────────────────────────────────
      final finalScore = _computeFinalScore(
        stabilityScore: stabilityScore,
        survived:       survival.survived,
        survivalMs:     survival.survivalMs,
        bestLatencyMs:  bestLat,
        bandwidthKBs:   bandwidth,
        h2Supported:    h2,
        reuseScore:     reuseScore,
        wsBonus:        wsBonus,
      );

      // ── Phase + tier mapping ──────────────────────────────────────────────
      final phase = survival.dpiKilled
          ? ScanPhase.dpiFail
          : survival.survived
              ? ScanPhase.passed
              : ScanPhase.survivalFail;
      final tier = calcTier(survival.survivalMs, phase);

      // ── Build ScanResult ──────────────────────────────────────────────────
      final scanResult = ScanResult(
        ip:                 w.ip,
        latencyMs:          bestLat,
        jitterMs:           0,
        isAlive:            survival.survived || phase == ScanPhase.passed,
        grade:              calcGradeFromScore(finalScore, phase),
        country:            w.country,
        flag:               w.flag,
        loss:               0,
        reliability:        reliability,
        score:              finalScore,
        survivalMs:         survival.survivalMs,
        retransmits:        0,
        phase:              phase,
        tier:               tier,
        speedKBs:           bandwidth,
        sniUsed:            bestSni,
        tcpLatencyMs:       bestLat - bestTlsMs,
        tlsHandshakeMs:     bestTlsMs,
        dpiSuspicion:       survival.dpiSuspicionScore,
        bestFamily:         bestFamily,
        h2Supported:        h2,
        wsOk:               bestFamily == 'Cloudflare' ? wsBonus : null,
      );

      results.add(scanResult);
      ScanHistoryService().recordProviderResult(w.country, scanResult.isAlive);
      ScanHistoryService().recordRecentResult(scanResult.isAlive);

      eliteDone++;
      // Map onto full liveIps range: stage1Count already done + elite progress
      final _eliteProgressDone = _stage1Count + eliteDone;
      onProgress?.call(_eliteProgressDone, _progressTotal, scanResult);
    } finally {
      eliteSem.release();
    }
  }));

  // progress: done event (100%) — all processing complete
  if (_progressTotal > 0 && results.isNotEmpty) {
    onProgress?.call(_progressTotal, _progressTotal, results.last);
  }

  // ── Sort best to worst ────────────────────────────────────────────────────
  results.sort((a, b) {
    final sa = a.score ?? 0.0;
    final sb = b.score ?? 0.0;
    if (sa != sb) return sb.compareTo(sa);
    return a.latencyMs.compareTo(b.latencyMs);
  });

  // ── Persist session ───────────────────────────────────────────────────────
  final aliveResults = results.where((r) => r.isAlive).toList();
  if (aliveResults.isNotEmpty) {
    ScanHistoryService().saveGoodIps(aliveResults.map((r) => r.ip).toList());
    ScanHistoryService().saveScanSession(
      time:         DateTime.now(),
      totalScanned: ips.length,
      aliveCount:   aliveResults.length,
      topIps:       aliveResults.take(5).map((r) => r.ip).toList(),
    );
  }

  return results;
}
