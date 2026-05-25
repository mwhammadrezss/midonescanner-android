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
  ScanMode mode = ScanMode.normal,
}) async {
  final (country, flag) = GeoIPOffline().lookupFull(ip);
  final survivalTarget  = mode == ScanMode.deep ? _survivalDeep : _survivalNormal;
  final repeats         = mode == ScanMode.deep ? 5 : 3;

  // ── dead-result helper ────────────────────────────────────────────────────
  ScanResult dead(ScanPhase phase) => ScanResult(
    ip: ip, latencyMs: 9999, jitterMs: 0,
    isAlive: false, grade: 'F', country: country, flag: flag,
    loss: 100, reliability: 0,
    score: 0, survivalMs: 0, retransmits: 0,
    phase: phase,
  );

  // ══ PHASE 1+2+3+4: TCP → TLS → ServerHello → ApplicationData ═════════════
  final first = await probeWithRetry(ip, retries: 3);
  if (first == null) return dead(ScanPhase.tlsFail);

  // ══ PHASE 6 (Stability): repeat probe × repeats ════════════════════════════
  final samples     = <double>[first.latencyMs];
  int   failed      = 0;
  int   totalRetx   = first.retransmits;

  for (int i = 1; i < repeats; i++) {
    final r = await androidTlsProbe(ip);
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
  final drift        = calcDrift(safeSamples);

  // Stability gate: if loss ≥ 67% on probes → unstable
  if (lossPercent >= 67) return dead(ScanPhase.stabilityFail);

  // ══ PHASE 5+7: Tunnel Survival + DPI Resistance ════════════════════════════
  final survival = await tunnelSurvivalTest(ip, survivalTargetMs: survivalTarget);

  final phase = survival.dpiKilled
      ? ScanPhase.dpiFail
      : survival.survived
          ? ScanPhase.passed
          : ScanPhase.survivalFail;

  // ══ PHASE 8: Final Score ════════════════════════════════════════════════════
  final score = calcScore(
    survived:          survival.survived,
    survivalMs:        survival.survivalMs,
    survivalTargetMs:  survivalTarget,
    avgLatencyMs:      avg,
    jitterMs:          jitter,
    retransmits:       totalRetx,
    reliability:       reliability,
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
  );
}

// ─── runScanningEngine ───────────────────────────────────────────────────────
Future<List<ScanResult>> runScanningEngine(
  List<String> ips, {
  ScanMode mode = ScanMode.normal,
  int concurrency = 4,   // lower default: survival tests are long
  void Function(int done, int total, ScanResult result)? onProgress,
  bool Function()? isCancelled,
}) async {
  final results             = <ScanResult>[];
  int   done                = 0;
  final adaptiveConcurrency = min(calcConcurrency(ips.length), 4);
  final sem                 = Semaphore(adaptiveConcurrency);

  await Future.wait(ips.map((ip) async {
    if (isCancelled?.call() == true) return;
    await sem.acquire();
    try {
      if (isCancelled?.call() == true) return;
      final r = await scanOneIp(ip, mode: mode);
      results.add(r);
      done++;
      onProgress?.call(done, ips.length, r);
    } finally {
      sem.release();
    }
  }));

  // Sort: alive first, then by score descending
  results.sort((a, b) {
    if (a.isAlive != b.isAlive) return a.isAlive ? -1 : 1;
    final sa = a.score ?? 0;
    final sb = b.score ?? 0;
    return sb.compareTo(sa);
  });

  return results;
}
