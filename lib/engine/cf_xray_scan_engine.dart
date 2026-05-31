// lib/engine/cf_xray_scan_engine.dart
// ─── CF + Config two-phase scanner (SenPaiScanner-style engine) ───────────────
// Mirrors SenPaiScanner's probe approach exactly:
//   Phase 1: TLS + HTTP GET /cdn-cgi/trace (CF edge detection)
//            + WebSocket probe with config path/host/sni (RequireWebSocket mode)
//   Phase 2: ALL Phase-1 validated IPs listed — no xray binary, no topN cut-off
//
// SenPai engine equivalence (internal/prober/prober.go):
//   prober.Config.Mode             = ModeHTTP
//   prober.Config.RequireWebSocket = (config.network == ws/xhttp/splithttp)
//   prober.Config.WebSocketHost    = config.host || config.effectiveSni
//   prober.Config.WebSocketPath    = config.path
//   prober.Config.SNI              = config.effectiveSni
//
// Result.IsHealthy() ≡ isEdge && (wsOk == true if requireWS)
// All healthy IPs are surfaced — no artificial top-N limit.

import 'dart:async';
import '../xray/config_parser.dart';
import '../xray/xray_validator.dart';
import 'cf_ip_ranges.dart';
import 'probe_engine.dart' show cfHttpProbe, cfWsProbe, CfHttpResult;


// ─── Validation mode ──────────────────────────────────────────────────────────

/// Controls which Phase-2 validation method is used.
enum CfValidationMode {
  /// Fast WS probe (Mode A): uses cfWsProbe / config path matching. No xray binary.
  wsProbe,
  /// Deep xray binary validation (Mode B): runs xray.exe, tests real traffic + speed.
  xrayBinary,
}

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

/// Runs a two-phase CF+Config scan (SenPaiScanner-style engine).
///
/// Phase 1: HTTP /cdn-cgi/trace + optional WS probe with config settings.
///   - Mirrors SenPai prober.Config.RequireWebSocket behaviour.
///   - WS probe uses config path/host/sni when config is WS/xhttp type.
///
/// Phase 2: ALL IPs that passed Phase 1 validation are returned.
///   - No topN cut-off — every working IP is listed.
///   - No xray binary required — validation is done in Phase 1.
///
/// [ips]: explicit IPs to probe; empty = random sample from CF ranges.
/// [sampleCount]: how many random IPs to sample when [ips] is empty.
/// [concurrency]: parallel probes.
/// [timeoutMs]: per-probe total budget in ms.
/// [config]: proxy config (vless/trojan URL); null = Phase 1 only.
/// [topN]: kept for API compatibility; ignored (all results returned).
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
  CfValidationMode validationMode = CfValidationMode.wsProbe,
}) async {
  // ── Prepare IP list ────────────────────────────────────────────────────────
  final List<String> scanIps;
  if (ips.isNotEmpty) {
    scanIps = ips;
  } else {
    scanIps = sampleCfIps(count: sampleCount, cidrFilter: cidrFilter);
  }

  // ── Derive WS probe settings from config (SenPai RequireWebSocket) ────────
  // Mirrors: prober.Config{RequireWebSocket, WebSocketHost, WebSocketPath, SNI}
  final bool requireWs = config != null &&
      (config.network == 'ws' ||
       config.network == 'xhttp' ||
       config.network == 'splithttp');

  // SNI: config sni → config host → address (mirrors prober.go SNI resolution)
  final String wsSni = (config != null && config.effectiveSni.isNotEmpty)
      ? config.effectiveSni
      : 'speed.cloudflare.com';

  // WebSocketHost: config host field (Host header in WS upgrade request)
  final String wsHost = (config != null && config.host.isNotEmpty)
      ? config.host
      : wsSni;

  // WebSocketPath: config path (e.g. /ray, /ws, /vmess)
  final String wsPath = (config != null && config.path.isNotEmpty &&
                          config.path != '/')
      ? config.path
      : '/';

  // ── Phase 1: CF edge detection + config WS probe ──────────────────────────
  final phase1Results = <CfPhase1Result>[];
  int p1Done = 0;
  final total1 = scanIps.length;

  final sem = _Semaphore(concurrency);

  await Future.wait(scanIps.map((ip) async {
    if (isCancelled()) return;
    await sem.acquire();
    try {
      if (isCancelled()) return;

      // Step 1: HTTP /cdn-cgi/trace (SenPai ModeHTTP)
      final t = DateTime.now();
      final http = await cfHttpProbe(ip, totalBudgetMs: timeoutMs);
      final elapsed = DateTime.now().difference(t).inMicroseconds / 1000.0;

      // Step 2: WS probe — only on confirmed CF edges
      bool? ws;
      if (http.isCloudflareEdge) {
        if (requireWs) {
          // SenPai RequireWebSocket = true: probe with config path/host/sni
          // This is the core of the SenPai engine — tests the actual config path
          ws = await cfWsProbe(
            ip,
            sni: wsSni,
            wsHost: wsHost,
            wsPath: wsPath,
            totalBudgetMs: timeoutMs,
          );
        } else if (config != null) {
          // Non-WS config (tcp/grpc): CF edge is sufficient — mark ws=null
          ws = null;
        } else {
          // No config: standard CF WS probe with default Cloudflare SNI
          ws = await cfWsProbe(ip, totalBudgetMs: timeoutMs);
        }
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

  // ── No config: Phase 1 only ───────────────────────────────────────────────
  if (config == null) {
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

  // ── Gather CF edge IPs sorted by latency (shared by both modes) ──────────
  final List<CfPhase1Result> edgeIps = phase1Results
      .where((r) => r.isEdge)
      .toList()
    ..sort((a, b) => a.latencyMs.compareTo(b.latencyMs));

  // ══════════════════════════════════════════════════════════════════════════
  // MODE B: Xray binary deep validation
  // ══════════════════════════════════════════════════════════════════════════
  if (validationMode == CfValidationMode.xrayBinary) {
    final phase2Results = <CfPhase2Result>[];
    int p2Done = 0;
    final total2 = edgeIps.length;

    // Use reduced concurrency for xray (heavier process)
    final xrayConcurrency = concurrency < 3 ? concurrency : 3;
    final xraySem = _Semaphore(xrayConcurrency);

    await Future.wait(edgeIps.map((p1) async {
      if (isCancelled()) return;
      await xraySem.acquire();
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
        xraySem.release();
      }
    }));

    // Sort: successes first, then by latency
    phase2Results.sort((a, b) {
      if (a.success && !b.success) return -1;
      if (!a.success && b.success) return 1;
      return a.phase1.latencyMs.compareTo(b.phase1.latencyMs);
    });
    return phase2Results;
  }

  // ══════════════════════════════════════════════════════════════════════════
  // MODE A (default): WS probe validation — keep existing logic
  // ══════════════════════════════════════════════════════════════════════════

  // ── Phase 2: Collect ALL config-validated IPs (SenPai IsHealthy()) ────────
  // IsHealthy() ≡ tlsOk && httpStatus<400 && (!requireWS || wsHealthy)
  final List<CfPhase1Result> validated;
  if (requireWs) {
    // WS/xhttp config: must pass both CF edge AND WS probe with config settings
    validated = phase1Results
        .where((r) => r.isEdge && r.wsOk == true)
        .toList();
  } else {
    // TCP/gRPC config: CF edge alone confirms the IP works with this config
    validated = phase1Results.where((r) => r.isEdge).toList();
  }

  // Sort by latency — fastest first (mirrors SenPai result ordering)
  validated.sort((a, b) => a.latencyMs.compareTo(b.latencyMs));

  // Report Phase 2 — synchronous, no extra network calls
  final phase2Results = <CfPhase2Result>[];
  for (int i = 0; i < validated.length; i++) {
    if (isCancelled()) break;
    final p1 = validated[i];
    final r = CfPhase2Result(
      phase1: p1,
      validation: XrayValidationResult(
        ip: p1.ip,
        port: config.port,
        success: true,
        latencyMs: p1.latencyMs,
        transport: config.network,
      ),
    );
    phase2Results.add(r);
    onPhase2Progress(r, i + 1, validated.length);
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
