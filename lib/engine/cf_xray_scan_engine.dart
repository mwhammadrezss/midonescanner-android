// lib/engine/cf_xray_scan_engine.dart
// ─── CF + Config two-phase scanner — SENPAI-SYNC ─────────────────────────────
//
// SENPAI-SYNC changes (mirrors SenPaiScanner exactly):
//   1. CfPhase1Result: latencies[], lossPercent, avgMs, minMs, maxMs, jitterMs
//   2. IsHealthy(): loss<50% AND avg>0 AND tlsOk AND 2xx-3xx AND colo (+ wsOk if WS)
//   3. cfHttpProbeMulti: cfg.Tries per IP (default 4, like SenPai)
//   4. Rate limiting: maxProbesPerSec throttle (mirrors SenPai rate.Limiter)
//   5. RunList equivalent: top edges re-validated with 10s timeout after Phase1
//   6. Sort modes: avg (default), loss, jitter, colo, speed (mirrors SenPai SortBy)
//   7. Default concurrency=50, timeout=5s, count=500, tries=4 (SenPai defaults)

import 'dart:async';
import '../xray/config_parser.dart';
import '../xray/xray_validator.dart';
import 'cf_ip_ranges.dart';
import 'probe_engine.dart' show cfHttpProbeMulti, cfWsProbe, CfHttpResult,
    CfMultiProbeResult, cfHttpProbe;

// ─── Validation mode ──────────────────────────────────────────────────────────

enum CfValidationMode {
  wsProbe,    // Mode A: WS probe (fast, no binary)
  xrayBinary, // Mode B: xray binary (deep, real traffic)
}

// ─── Sort mode — mirrors SenPai result.SortBy ─────────────────────────────────
enum CfSortMode {
  avg,    // sort by average latency (SenPai SortByAvg — default)
  loss,   // sort by packet loss %  (SenPai SortByLoss)
  jitter, // sort by jitter         (SenPai SortByJitter)
  colo,   // sort by colo name      (SenPai SortByColo)
  speed,  // sort by throughput     (SenPai SortBySpeed — Phase 2 only)
}

// ─── Phase 1 result — SENPAI-SYNC ────────────────────────────────────────────
// Now carries full multi-try stats: latencies[], loss%, avg/min/max/jitter
// Mirrors SenPai result.Result

class CfPhase1Result {
  final String ip;
  final bool   isEdge;      // IsHealthy() — loss<50% AND CF edge criteria
  final double latencyMs;   // backward compat (= avgMs)
  final String colo;
  final bool   tlsOk;
  final int    httpStatus;
  final bool?  wsOk;

  // Multi-try stats (SENPAI-SYNC)
  final List<double> latencies;   // per-try latencies; 0 = failed (SenPai Latencies[])
  final double avgMs;             // mean of successful tries  (SenPai Avg())
  final double minMs;             // best try latency           (SenPai Min())
  final double maxMs;             // worst try latency          (SenPai Max())
  final double jitterMs;          // std-dev of latencies       (SenPai Jitter())
  final double lossPercent;       // failed/total * 100         (SenPai Loss())

  const CfPhase1Result({
    required this.ip,
    required this.isEdge,
    required this.latencyMs,
    required this.colo,
    required this.tlsOk,
    required this.httpStatus,
    this.wsOk,
    this.latencies    = const [],
    this.avgMs        = 0,
    this.minMs        = 0,
    this.maxMs        = 0,
    this.jitterMs     = 0,
    this.lossPercent  = 0,
  });

  /// Build from a CfMultiProbeResult + optional wsOk
  factory CfPhase1Result.fromMulti(
    CfMultiProbeResult multi,
    String ip, {
    bool? wsOk,
    bool? requireWs,
  }) {
    // IsHealthy() — mirrors SenPai result.IsHealthy() for ModeHTTP + RequireWS
    bool healthy = multi.isCloudflareEdge;
    if (healthy && (requireWs == true)) {
      healthy = wsOk == true;
    }
    return CfPhase1Result(
      ip:           ip,
      isEdge:       healthy,
      latencyMs:    multi.avgMs,
      colo:         multi.colo,
      tlsOk:        multi.tlsOk,
      httpStatus:   multi.httpStatus,
      wsOk:         wsOk,
      latencies:    multi.latencies,
      avgMs:        multi.avgMs,
      minMs:        multi.minMs,
      maxMs:        multi.maxMs,
      jitterMs:     multi.jitterMs,
      lossPercent:  multi.lossPercent,
    );
  }
}

// ─── Phase 2 result ───────────────────────────────────────────────────────────

class CfPhase2Result {
  final CfPhase1Result       phase1;
  final XrayValidationResult validation;

  const CfPhase2Result({required this.phase1, required this.validation});

  bool   get success => validation.success;
  String get ip      => phase1.ip;
}

// ─── Sort helpers — mirrors SenPai compareResults() ──────────────────────────

List<CfPhase1Result> sortPhase1(List<CfPhase1Result> results, CfSortMode mode) {
  final sorted = List<CfPhase1Result>.from(results);
  sorted.sort((a, b) {
    // Healthy first — mirrors SenPai sortRank()
    final aRank = a.isEdge ? 0 : (a.avgMs > 0 || a.lossPercent < 100 ? 1 : 2);
    final bRank = b.isEdge ? 0 : (b.avgMs > 0 || b.lossPercent < 100 ? 1 : 2);
    if (aRank != bRank) return aRank.compareTo(bRank);

    // SENPAI-SYNC: mirrors compareResults() secondary+tertiary keys exactly
    switch (mode) {
      case CfSortMode.loss:
        // SenPai: loss → avg → jitter
        final c1 = a.lossPercent.compareTo(b.lossPercent);
        if (c1 != 0) return c1;
        final c2 = a.avgMs.compareTo(b.avgMs);
        if (c2 != 0) return c2;
        return a.jitterMs.compareTo(b.jitterMs);
      case CfSortMode.jitter:
        // SenPai: jitter → loss → avg
        final c1 = a.jitterMs.compareTo(b.jitterMs);
        if (c1 != 0) return c1;
        final c2 = a.lossPercent.compareTo(b.lossPercent);
        if (c2 != 0) return c2;
        return a.avgMs.compareTo(b.avgMs);
      case CfSortMode.colo:
        // SenPai: colo → avg → loss
        final c1 = a.colo.compareTo(b.colo);
        if (c1 != 0) return c1;
        final c2 = a.avgMs.compareTo(b.avgMs);
        if (c2 != 0) return c2;
        return a.lossPercent.compareTo(b.lossPercent);
      case CfSortMode.speed:
        // Phase1 has no throughput; fall back to avg → loss (SenPai behaviour)
        final c1 = a.avgMs.compareTo(b.avgMs);
        if (c1 != 0) return c1;
        return a.lossPercent.compareTo(b.lossPercent);
      case CfSortMode.avg:
      default:
        // SenPai: avg → loss → jitter
        final c1 = a.avgMs.compareTo(b.avgMs);
        if (c1 != 0) return c1;
        final c2 = a.lossPercent.compareTo(b.lossPercent);
        if (c2 != 0) return c2;
        final c3 = a.jitterMs.compareTo(b.jitterMs);
        if (c3 != 0) return c3;
    }
    // SENPAI-SYNC: final tiebreakers = cmpBool(tlsOk), cmpBool(wsOk), cmpString(ip)
    // mirrors compareResults() last 3 lines exactly
    final tTls = (a.tlsOk == b.tlsOk) ? 0 : (a.tlsOk ? -1 : 1);
    if (tTls != 0) return tTls;
    final tWs = ((a.wsOk ?? false) == (b.wsOk ?? false))
        ? 0 : ((a.wsOk ?? false) ? -1 : 1);
    if (tWs != 0) return tWs;
    return a.ip.compareTo(b.ip);
  });
  return sorted;
}

List<CfPhase2Result> sortPhase2(List<CfPhase2Result> results, CfSortMode mode) {
  final sorted = List<CfPhase2Result>.from(results);
  sorted.sort((a, b) {
    // Success first — mirrors SenPai sortRank (healthy=0 > partial=1 > dead=2)
    final aRank = a.success ? 0 : (a.phase1.avgMs > 0 ? 1 : 2);
    final bRank = b.success ? 0 : (b.phase1.avgMs > 0 ? 1 : 2);
    if (aRank != bRank) return aRank.compareTo(bRank);

    // SENPAI-SYNC: compareResults() secondary+tertiary keys for phase2
    switch (mode) {
      case CfSortMode.speed:
        // SenPai SortBySpeed: throughput DESC → avg → loss
        final c1 = b.validation.throughputKBs.compareTo(a.validation.throughputKBs);
        if (c1 != 0) return c1;
        final c2 = a.validation.latencyMs.compareTo(b.validation.latencyMs);
        if (c2 != 0) return c2;
        return a.phase1.lossPercent.compareTo(b.phase1.lossPercent);
      case CfSortMode.loss:
        // SenPai SortByLoss: loss → avg → jitter
        final c1 = a.phase1.lossPercent.compareTo(b.phase1.lossPercent);
        if (c1 != 0) return c1;
        final c2 = a.validation.latencyMs.compareTo(b.validation.latencyMs);
        if (c2 != 0) return c2;
        return a.phase1.jitterMs.compareTo(b.phase1.jitterMs);
      case CfSortMode.jitter:
        // SenPai SortByJitter: jitter → loss → avg
        final c1 = a.phase1.jitterMs.compareTo(b.phase1.jitterMs);
        if (c1 != 0) return c1;
        final c2 = a.phase1.lossPercent.compareTo(b.phase1.lossPercent);
        if (c2 != 0) return c2;
        return a.validation.latencyMs.compareTo(b.validation.latencyMs);
      case CfSortMode.colo:
        // SenPai SortByColo: colo → avg → loss
        final c1 = a.phase1.colo.compareTo(b.phase1.colo);
        if (c1 != 0) return c1;
        final c2 = a.validation.latencyMs.compareTo(b.validation.latencyMs);
        if (c2 != 0) return c2;
        return a.phase1.lossPercent.compareTo(b.phase1.lossPercent);
      case CfSortMode.avg:
      default:
        // SenPai SortByAvg: avg → loss → jitter
        final c1 = a.validation.latencyMs.compareTo(b.validation.latencyMs);
        if (c1 != 0) return c1;
        final c2 = a.phase1.lossPercent.compareTo(b.phase1.lossPercent);
        if (c2 != 0) return c2;
        final c3 = a.phase1.jitterMs.compareTo(b.phase1.jitterMs);
        if (c3 != 0) return c3;
    }
    // SENPAI-SYNC: final tiebreakers = cmpBool(tlsOk), cmpBool(wsOk), cmpString(ip)
    final tTls = (a.phase1.tlsOk == b.phase1.tlsOk) ? 0 : (a.phase1.tlsOk ? -1 : 1);
    if (tTls != 0) return tTls;
    final tWs = ((a.phase1.wsOk ?? false) == (b.phase1.wsOk ?? false))
        ? 0 : ((a.phase1.wsOk ?? false) ? -1 : 1);
    if (tWs != 0) return tWs;
    return a.phase1.ip.compareTo(b.phase1.ip);
  });
  return sorted;
}

// ─── Scanner callbacks ────────────────────────────────────────────────────────

typedef OnPhase1Progress = void Function(CfPhase1Result result, int done, int total);
typedef OnPhase2Progress = void Function(CfPhase2Result result, int done, int total);
typedef IsCancelledFn    = bool Function();

// ─── Main scanner — SENPAI-SYNC ──────────────────────────────────────────────

/// Runs a two-phase CF+Config scan — now fully mirrors SenPaiScanner behaviour:
///
/// Phase 1: cfHttpProbeMulti (tries=4 per IP, loss%, avg/min/max/jitter)
///          + cfWsProbe if config is WS/xhttp
///          IsHealthy(): loss<50% AND avg>0 AND tlsOk AND 2xx AND colo
///
/// Phase 2:
///   Mode A: WS probe result = Phase 2 (no extra calls)
///   Mode B: xray binary deep validation (max concurrency=3)
///
/// Rate limiting: maxProbesPerSec (mirrors SenPai rate.Limiter)
/// RunList: top edges re-probed with 10s timeout (mirrors SenPai RunList)
Future<List<CfPhase2Result>> runCfXrayScanner({
  required List<String>         ips,
  required int                  sampleCount,
  required int                  concurrency,
  required int                  timeoutMs,
  required XrayConfig?          config,
  required int                  topN,
  required OnPhase1Progress     onPhase1Progress,
  required OnPhase2Progress     onPhase2Progress,
  required IsCancelledFn        isCancelled,
  List<String>?                 cidrFilter,
  CfValidationMode              validationMode = CfValidationMode.wsProbe,
  int                           tries          = 4,    // SENPAI-SYNC: SenPai default = 4
  double                        maxProbesPerSec = 0,   // SENPAI-SYNC: rate limit (0 = unlimited)
  CfSortMode                    sortMode       = CfSortMode.avg,
}) async {
  // ── Prepare IP list ────────────────────────────────────────────────────────
  final List<String> scanIps = ips.isNotEmpty
      ? ips
      : sampleCfIps(count: sampleCount, cidrFilter: cidrFilter);

  // ── Derive WS probe settings from config ──────────────────────────────────
  final bool requireWs = config != null &&
      (config.network == 'ws' ||
       config.network == 'xhttp' ||
       config.network == 'splithttp');

  final String wsSni  = (config != null && config.effectiveSni.isNotEmpty)
      ? config.effectiveSni : 'speed.cloudflare.com';
  final String wsHost = (config != null && config.host.isNotEmpty)
      ? config.host : wsSni;
  final String wsPath = (config != null && config.path.isNotEmpty &&
                          config.path != '/')
      ? config.path : '/';

  // ── Phase 1: multi-try CF probe — SENPAI-SYNC ─────────────────────────────
  final phase1Results = <CfPhase1Result>[];
  int p1Done = 0;
  final total1 = scanIps.length;

  final sem = _Semaphore(concurrency);
  // Rate limiter — mirrors SenPai rate.Limiter
  final rateLimiter = maxProbesPerSec > 0
      ? _RateLimiter(maxProbesPerSec) : null;

  await Future.wait(scanIps.map((ip) async {
    if (isCancelled()) return;
    await sem.acquire();
    try {
      if (isCancelled()) return;
      if (rateLimiter != null) await rateLimiter.wait();

      // SENPAI-SYNC: multi-try probe (tries=4 default)
      final multi = await cfHttpProbeMulti(
        ip,
        tries:    tries,
        budgetMs: timeoutMs,
      );

      // WS probe — only on confirmed CF edges
      bool? wsOk;
      if (multi.isCloudflareEdge) {
        if (requireWs) {
          wsOk = await cfWsProbe(
            ip,
            sni:          wsSni,
            wsHost:       wsHost,
            wsPath:       wsPath,
            totalBudgetMs: timeoutMs,
          );
        } else if (config != null) {
          wsOk = null; // TCP/gRPC: CF edge sufficient
        } else {
          wsOk = await cfWsProbe(ip, totalBudgetMs: timeoutMs);
        }
      }

      // Build result using IsHealthy() logic
      final r = CfPhase1Result.fromMulti(
        multi, ip, wsOk: wsOk, requireWs: requireWs,
      );
      phase1Results.add(r);
      p1Done++;
      onPhase1Progress(r, p1Done, total1);
    } finally {
      sem.release();
    }
  }));

  // ── No config: Phase 1 only ───────────────────────────────────────────────
  if (config == null) {
    final sorted = sortPhase1(phase1Results, sortMode);
    return sorted.map((p1) => CfPhase2Result(
          phase1: p1,
          validation: XrayValidationResult(
            ip: p1.ip, port: 443, success: p1.isEdge, latencyMs: p1.avgMs),
        )).toList();
  }

  // ── Collect CF edge IPs — healthy ones sorted by sortMode ─────────────────
  final List<CfPhase1Result> edgeIps =
      sortPhase1(phase1Results.where((r) => r.isEdge).toList(), sortMode);

  // ══════════════════════════════════════════════════════════════════════════
  // MODE B: Xray binary deep validation
  // ══════════════════════════════════════════════════════════════════════════
  if (validationMode == CfValidationMode.xrayBinary) {
    // SENPAI-SYNC RunList: re-validate top edges with 10s timeout floor
    final validateTimeoutMs = timeoutMs < 10000 ? 10000 : timeoutMs;

    final phase2Results = <CfPhase2Result>[];
    int p2Done = 0;
    final total2 = edgeIps.length;
    final xraySem = _Semaphore(concurrency < 3 ? concurrency : 3);

    await Future.wait(edgeIps.map((p1) async {
      if (isCancelled()) return;
      await xraySem.acquire();
      try {
        if (isCancelled()) return;
        final validation = await validateConfig(
          config, p1.ip, timeoutMs: validateTimeoutMs);
        final r = CfPhase2Result(phase1: p1, validation: validation);
        phase2Results.add(r);
        p2Done++;
        onPhase2Progress(r, p2Done, total2);
      } finally {
        xraySem.release();
      }
    }));

    return sortPhase2(phase2Results, sortMode);
  }

  // ══════════════════════════════════════════════════════════════════════════
  // MODE A: WS probe validation
  // ══════════════════════════════════════════════════════════════════════════
  final List<CfPhase1Result> validated;
  if (requireWs) {
    validated = phase1Results
        .where((r) => r.isEdge && r.wsOk == true)
        .toList();
  } else {
    validated = phase1Results.where((r) => r.isEdge).toList();
  }

  // SENPAI-SYNC sort by selected mode
  final sortedValidated = sortPhase1(validated, sortMode);

  final phase2Results = <CfPhase2Result>[];
  for (int i = 0; i < sortedValidated.length; i++) {
    if (isCancelled()) break;
    final p1 = sortedValidated[i];
    final r = CfPhase2Result(
      phase1: p1,
      validation: XrayValidationResult(
        ip:        p1.ip,
        port:      config.port,
        success:   true,
        latencyMs: p1.avgMs,
        transport: config.network,
      ),
    );
    phase2Results.add(r);
    onPhase2Progress(r, i + 1, sortedValidated.length);
  }

  return phase2Results;
}

// ─── Simple semaphore ─────────────────────────────────────────────────────────

class _Semaphore {
  final int _max;
  int _count = 0;
  final _queue = <Completer<void>>[];

  _Semaphore(this._max);

  Future<void> acquire() async {
    if (_count < _max) { _count++; return; }
    final c = Completer<void>();
    _queue.add(c);
    await c.future;
  }

  void release() {
    if (_queue.isNotEmpty) {
      _queue.removeAt(0).complete();
    } else {
      _count--;
    }
  }
}

// ─── Rate limiter — mirrors SenPai rate.Limiter ───────────────────────────────
class _RateLimiter {
  final double _perSec;
  DateTime _lastTick = DateTime.fromMillisecondsSinceEpoch(0);

  _RateLimiter(this._perSec);

  Future<void> wait() async {
    if (_perSec <= 0) return;
    final intervalMs = (1000.0 / _perSec).round();
    final now        = DateTime.now();
    final elapsed    = now.difference(_lastTick).inMilliseconds;
    if (elapsed < intervalMs) {
      await Future.delayed(Duration(milliseconds: intervalMs - elapsed));
    }
    _lastTick = DateTime.now();
  }
}
