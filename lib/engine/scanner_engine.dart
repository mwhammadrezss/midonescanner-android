// lib/engine/scanner_engine.dart
// ─── 8-Phase Android TLS Tunnel Survivability Scanner ───────────────────────
import 'dart:async';
import 'dart:math';
import '../models/scan_result.dart';
import '../geo/geoip.dart';
import 'probe_engine.dart';
import 'tunnel_engine.dart';
import 'grading_engine.dart';
import 'concurrency_engine.dart';
import '../utils/stats_utils.dart';

export '../models/scan_result.dart';
export '../utils/ip_utils.dart';

// ── Public constant re-exported for UI ──────────────────────────────────────
const shiroSni = kShiroSni;

enum ScanMode { normal, deep }

// ── Survival target per mode ─────────────────────────────────────────────────
const _survivalNormal = 20000;  // 20 s
const _survivalDeep   = 30000;  // 30 s

// ─── scanOneIp — full 8-phase pipeline ──────────────────────────────────────
Future<ScanResult> scanOneIp(
  String ip, {
  ScanMode mode        = ScanMode.normal,
  List<String>? snis,  // for deep mode: list of SNIs to try
}) async {
  final (country, flag)  = GeoIPOffline().lookupFull(ip);
  final survivalTarget   = mode == ScanMode.deep ? _survivalDeep : _survivalNormal;
  final repeats          = mode == ScanMode.deep ? 5 : 3;
  final effectiveSnis    = (mode == ScanMode.deep && snis != null && snis.isNotEmpty)
      ? snis
      : [kShiroSni];

  // ── dead-result helper ────────────────────────────────────────────────────
  ScanResult dead(ScanPhase phase) => ScanResult(
    ip: ip, latencyMs: 9999, jitterMs: 0,
    isAlive: false, grade: 'F', country: country, flag: flag,
    loss: 100, reliability: 0,
    score: 0, survivalMs: 0, retransmits: 0,
    phase: phase,
  );

  // ─── NORMAL MODE ──────────────────────────────────────────────────────────
  if (mode == ScanMode.normal) {
    final sni = kShiroSni;

    // Phase 1+2+3+4: TCP → TLS → ServerHello → ApplicationData
    final first = await probeWithRetry(ip, sni: sni, retries: 5);
    if (first == null) return dead(ScanPhase.tlsFail);

    // Phase 6: Stability — repeat × 3
    final samples   = <double>[first.latencyMs];
    int   failed    = 0;
    int   totalRetx = first.retransmits;

    for (int i = 1; i < repeats; i++) {
      final r = await androidTlsProbe(ip, sni: sni);
      if (r != null) {
        samples.add(r.latencyMs);
        totalRetx += r.retransmits;
      } else {
        failed++;
      }
      await Future.delayed(const Duration(milliseconds: 200));
    }

    final lossPercent  = ((failed / repeats) * 100).round();
    final reliability  = samples.length / repeats;
    final safeSamples  = samples.isNotEmpty ? samples.toList() : <double>[first.latencyMs];
    final avg          = safeSamples.reduce((a, b) => a + b) / safeSamples.length;
    final jitter       = calcJitter(safeSamples);

    if (lossPercent >= 67) return dead(ScanPhase.stabilityFail);

    // Phase 5+7: Tunnel Survival + DPI Resistance
    final survival = await tunnelSurvivalTest(
      ip, sni: sni, survivalTargetMs: survivalTarget);

    final phase = survival.dpiKilled
        ? ScanPhase.dpiFail
        : survival.survived
            ? ScanPhase.passed
            : ScanPhase.survivalFail;

    // Bandwidth test (Normal mode — always google.com)
    double? speedKBs;
    if (survival.survived || phase == ScanPhase.passed) {
      speedKBs = await measureBandwidthKBs(ip, sni: sni);
    }

    // Phase 8: Final Score
    final score = calcScore(
      survived:         survival.survived,
      survivalMs:       survival.survivalMs,
      survivalTargetMs: survivalTarget,
      avgLatencyMs:     avg,
      jitterMs:         jitter,
      retransmits:      totalRetx,
      reliability:      reliability,
    );

    final grade = calcGradeFromScore(score, phase);

    return ScanResult(
      ip:          ip,
      latencyMs:   double.parse(avg.toStringAsFixed(1)),
      jitterMs:    double.parse(jitter.toStringAsFixed(1)),
      isAlive:     survival.survived || phase == ScanPhase.passed,
      grade:       grade,
      country:     country,
      flag:        flag,
      loss:        lossPercent,
      reliability: double.parse(reliability.toStringAsFixed(2)),
      score:       score,
      survivalMs:  survival.survivalMs,
      retransmits: totalRetx,
      phase:       phase,
      speedKBs:    speedKBs,
      sniUsed:     sni,
    );
  }

  // ─── DEEP MODE — test each SNI, keep best result ──────────────────────────
  ScanResult? bestResult;

  for (final sni in effectiveSnis) {
    // Phase 1+2+3+4
    final first = await probeWithRetry(ip, sni: sni, retries: 5);
    if (first == null) continue;

    // Phase 6: Stability
    final samples   = <double>[first.latencyMs];
    int   failed    = 0;
    int   totalRetx = first.retransmits;

    for (int i = 1; i < repeats; i++) {
      final r = await androidTlsProbe(ip, sni: sni);
      if (r != null) {
        samples.add(r.latencyMs);
        totalRetx += r.retransmits;
      } else {
        failed++;
      }
      await Future.delayed(const Duration(milliseconds: 200));
    }

    final lossPercent  = ((failed / repeats) * 100).round();
    final reliability  = samples.length / repeats;
    final safeSamples  = samples.isNotEmpty ? samples.toList() : <double>[first.latencyMs];
    final avg          = safeSamples.reduce((a, b) => a + b) / safeSamples.length;
    final jitter       = calcJitter(safeSamples);

    if (lossPercent >= 67) continue; // skip unstable SNI

    // Phase 5+7: Tunnel Survival
    final survival = await tunnelSurvivalTest(
      ip, sni: sni, survivalTargetMs: survivalTarget);

    final phase = survival.dpiKilled
        ? ScanPhase.dpiFail
        : survival.survived
            ? ScanPhase.passed
            : ScanPhase.survivalFail;

    // Bandwidth
    double? speedKBs;
    if (survival.survived || phase == ScanPhase.passed) {
      speedKBs = await measureBandwidthKBs(ip, sni: sni);
    }

    final score = calcScore(
      survived:         survival.survived,
      survivalMs:       survival.survivalMs,
      survivalTargetMs: survivalTarget,
      avgLatencyMs:     avg,
      jitterMs:         jitter,
      retransmits:      totalRetx,
      reliability:      reliability,
    );

    final grade = calcGradeFromScore(score, phase);

    final candidate = ScanResult(
      ip:          ip,
      latencyMs:   double.parse(avg.toStringAsFixed(1)),
      jitterMs:    double.parse(jitter.toStringAsFixed(1)),
      isAlive:     survival.survived || phase == ScanPhase.passed,
      grade:       grade,
      country:     country,
      flag:        flag,
      loss:        lossPercent,
      reliability: double.parse(reliability.toStringAsFixed(2)),
      score:       score,
      survivalMs:  survival.survivalMs,
      retransmits: totalRetx,
      phase:       phase,
      speedKBs:    speedKBs,
      sniUsed:     sni,
    );

    // Keep best: prefer survived + higher score
    if (bestResult == null) {
      bestResult = candidate;
    } else {
      final prevScore = bestResult.score ?? 0;
      final newScore  = candidate.score  ?? 0;
      if (candidate.isAlive && !bestResult.isAlive) {
        bestResult = candidate;
      } else if (candidate.isAlive == bestResult.isAlive && newScore > prevScore) {
        bestResult = candidate;
      }
    }
  }

  return bestResult ?? dead(ScanPhase.tlsFail);
}

// ─── runScanningEngine ───────────────────────────────────────────────────────
Future<List<ScanResult>> runScanningEngine(
  List<String> ips, {
  ScanMode mode           = ScanMode.normal,
  int concurrency         = 4,
  List<String>? deepSnis, // SNIs selected by user for deep mode
  void Function(int done, int total, ScanResult result)? onProgress,
  void Function(int liveCount, int totalCount)? onPrefilterDone,
  bool Function()? isCancelled,
}) async {
  final results = <ScanResult>[];
  int   done    = 0;

  // ── Step 0: Quick TCP pre-filter (concurrency 50) ────────────────────────
  // Eliminates clearly dead/fake IPs before running expensive full scan.
  final liveIps   = <String>[];
  final prefilterSem = Semaphore(50);
  int   prefilterDone = 0;

  await Future.wait(ips.map((ip) async {
    if (isCancelled?.call() == true) return;
    await prefilterSem.acquire();
    try {
      if (isCancelled?.call() == true) return;
      final alive = await quickTcpCheck(ip, timeoutMs: 1500);
      if (alive) {
        liveIps.add(ip);
      }
      prefilterDone++;
      // Report pre-filter progress as negative total (UI can detect)
      // fakeCount = prefilterDone - liveIps.length (used in status)
    } finally {
      prefilterSem.release();
    }
  }));

  onPrefilterDone?.call(liveIps.length, ips.length);

  if (liveIps.isEmpty) return results;

  // ── Step 1: Full scan on live IPs only ───────────────────────────────────
  final adaptiveConcurrency = min(calcConcurrency(liveIps.length), 4);
  final sem                 = Semaphore(adaptiveConcurrency);
  final totalLive           = liveIps.length;

  await Future.wait(liveIps.map((ip) async {
    if (isCancelled?.call() == true) return;
    await sem.acquire();
    try {
      if (isCancelled?.call() == true) return;
      final r = await scanOneIp(ip, mode: mode, snis: deepSnis);
      results.add(r);
      done++;
      onProgress?.call(done, totalLive, r);
    } finally {
      sem.release();
    }
  }));

  // ── Step 2: Sort by ShirKhorshid connection priority ────────────────────
  // Priority: Grade A survived > Grade B survived > any survived >
  //           partial (tlsFail/survivalFail) > dead
  results.sort((a, b) {
    final tierA = _priority(a);
    final tierB = _priority(b);
    if (tierA != tierB) return tierA.compareTo(tierB);
    // Within same tier: higher score first, then lower latency
    final sa = a.score ?? 0.0;
    final sb = b.score ?? 0.0;
    if (sa != sb) return sb.compareTo(sa);
    return a.latencyMs.compareTo(b.latencyMs);
  });

  return results;
}

// ── Priority tier for sorting ────────────────────────────────────────────────
// Lower number = higher priority
int _priority(ScanResult r) {
  if (!r.isAlive) {
    // Partial: got TLS but no survival
    if (r.phase == ScanPhase.survivalFail || r.phase == ScanPhase.dpiFail) return 4;
    return 5; // completely dead
  }
  final score = r.score ?? 0;
  if (score >= 80) return 1; // Grade A survived
  if (score >= 65) return 2; // Grade B survived
  return 3;                  // Survived but lower grade
}


