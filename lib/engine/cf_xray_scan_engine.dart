// lib/engine/cf_xray_scan_engine.dart
// ─── CF + Xray two-phase scanner ─────────────────────────────────────────────
// Mirrors SenPaiScanner's two-phase approach:
//   Phase 1: Fast CF edge detection (TLS + HTTP /cdn-cgi/trace)
//   Phase 2: Xray config validation on top-N phase-1 results
//
// Used by the CF tab in main.dart when a config URL is provided.

import 'dart:async';
import '../xray/config_parser.dart';
import '../xray/xray_validator.dart';
import 'cf_ip_ranges.dart';
import 'probe_engine.dart' show cfHttpProbe, cfWsProbe, CfHttpResult;

// ─── Phase 1 result ───────────────────────────────────────────────────────────

class CfPhase1Result {
  final String ip;
  final bool isEdge;
  final double latencyMs;
  final String colo;
  final bool tlsOk;
  final int httpStatus;
  final bool? wsOk;

  const CfPhase1Result({
    required this.ip,
    required this.isEdge,
    required this.latencyMs,
    required this.colo,
    required this.tlsOk,
    required this.httpStatus,
    this.wsOk,
  });
}

// ─── Phase 2 result ───────────────────────────────────────────────────────────

class CfPhase2Result {
  final CfPhase1Result phase1;
  final XrayValidationResult validation;

  const CfPhase2Result({required this.phase1, required this.validation});

  bool get success => validation.success;
  String get ip => phase1.ip;
}

// ─── Scanner callbacks ────────────────────────────────────────────────────────

typedef OnPhase1Progress = void Function(
  CfPhase1Result result,
  int done,
  int total,
);

typedef OnPhase2Progress = void Function(
  CfPhase2Result result,
  int done,
  int total,
);

typedef IsCancelledFn = bool Function();

// ─── Main scanner ─────────────────────────────────────────────────────────────

/// Runs a two-phase CF+Xray scan.
///
/// [ips]: list of IPs to probe in phase 1; if empty, samples randomly from CF ranges.
/// [sampleCount]: how many random IPs to sample when [ips] is empty.
/// [concurrency]: parallel probes in phase 1.
/// [timeoutMs]: per-probe timeout in ms.
/// [config]: optional xray config URL for phase 2; null = phase 1 only.
/// [topN]: how many phase-1 results to validate in phase 2 (0 = all healthy).
Future<List<CfPhase2Result>> runCfXrayScanner({
  required List<String> ips,
  required int sampleCount,
  required int concurrency,
  required int timeoutMs,
  required XrayConfig? config,
  required int topN,
  required OnPhase1Progress onPhase1Progress,
  required OnPhase2Progress onPhase2Progress,
  required IsCancelledFn isCancelled,
  List<String>? cidrFilter,
}) async {
  // ── Prepare IP list ────────────────────────────────────────────────────────
  final List<String> scanIps;
  if (ips.isNotEmpty) {
    scanIps = ips;
  } else {
    scanIps = sampleCfIps(count: sampleCount, cidrFilter: cidrFilter);
  }

  // ── Phase 1: CF edge detection ────────────────────────────────────────────
  final phase1Results = <CfPhase1Result>[];
  int p1Done = 0;
  final total1 = scanIps.length;

  final sem = _Semaphore(concurrency);

  await Future.wait(scanIps.map((ip) async {
    if (isCancelled()) return;
    await sem.acquire();
    try {
      if (isCancelled()) return;
      final t = DateTime.now();
      final http = await cfHttpProbe(ip,
          totalBudgetMs: timeoutMs);
      final elapsed = DateTime.now().difference(t).inMicroseconds / 1000.0;

      bool? ws;
      if (http.isCloudflareEdge) {
        ws = await cfWsProbe(ip);
      }

      final r = CfPhase1Result(
        ip: ip,
        isEdge: http.isCloudflareEdge,
        latencyMs: elapsed,
        colo: http.colo,
        tlsOk: http.tlsOk,
        httpStatus: http.httpStatus,
        wsOk: ws,
      );
      phase1Results.add(r);
      p1Done++;
      onPhase1Progress(r, p1Done, total1);
    } finally {
      sem.release();
    }
  }));

  if (config == null) {
    // Phase 1 only — wrap in CfPhase2Result with empty validation
    return phase1Results.map((p1) => CfPhase2Result(
          phase1: p1,
          validation: XrayValidationResult(
            ip: p1.ip,
            port: 443,
            success: p1.isEdge,
            latencyMs: p1.latencyMs,
          ),
        )).toList();
  }

  // ── Phase 2: Xray validation ──────────────────────────────────────────────

  // Sort phase 1 by latency, edge first
  final edgeResults = phase1Results
      .where((r) => r.isEdge)
      .toList()
    ..sort((a, b) => a.latencyMs.compareTo(b.latencyMs));

  final topResults =
      (topN > 0 && topN < edgeResults.length) ? edgeResults.take(topN).toList() : edgeResults;

  if (topResults.isEmpty) return [];

  final phase2Results = <CfPhase2Result>[];
  int p2Done = 0;
  final total2 = topResults.length;

  final sem2 = _Semaphore(concurrency > 5 ? 5 : concurrency); // xray is heavier

  await Future.wait(topResults.map((p1) async {
    if (isCancelled()) return;
    await sem2.acquire();
    try {
      if (isCancelled()) return;
      final validation = await validateConfig(
        config,
        p1.ip,
        timeoutMs: timeoutMs,
      );
      final r = CfPhase2Result(phase1: p1, validation: validation);
      phase2Results.add(r);
      p2Done++;
      onPhase2Progress(r, p2Done, total2);
    } finally {
      sem2.release();
    }
  }));

  // Sort: success first, then by latency
  phase2Results.sort((a, b) {
    if (a.success != b.success) return a.success ? -1 : 1;
    return a.validation.latencyMs.compareTo(b.validation.latencyMs);
  });

  return phase2Results;
}

// ─── Simple semaphore ─────────────────────────────────────────────────────────

class _Semaphore {
  final int _max;
  int _count = 0;
  final _queue = <Completer<void>>[];

  _Semaphore(this._max);

  Future<void> acquire() async {
    if (_count < _max) {
      _count++;
      return;
    }
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
