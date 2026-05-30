// lib/engine/scanner_engine.dart
// ─── Android TLS Tunnel Survivability Scanner ────────────────────────────────
import 'dart:async';
import 'dart:math';
import '../models/scan_result.dart';
import '../geo/geoip.dart';
import 'probe_engine.dart';
import 'tunnel_engine.dart';
import 'grading_engine.dart';
import 'concurrency_engine.dart';
import 'subnet_cache.dart';
import 'soft_blacklist.dart';
import 'adaptive_concurrency.dart';
import 'range/fast_probe_engine.dart';
import '../utils/stats_utils.dart';
import '../storage/scan_history.dart';
import '../utils/logger.dart';
import 'deep_scan_engine.dart';

export '../models/scan_result.dart';
export '../utils/ip_utils.dart';

const shiroSni = kShiroSni;

enum ScanMode { normal, deep }

// Survival targets
const _survivalNormal = 20000;
const _survivalDeep   = 20000;

// Module-level cancellation passthrough
bool Function()? _currentIsCancelled;

// ─── scanOneIp ───────────────────────────────────────────────────────────────
Future<ScanResult> scanOneIp(
  String ip, {
  ScanMode mode        = ScanMode.normal,
  List<String>? snis,
  bool Function()? isCancelled,
  String? normalSniOverride,
}) async {
  _currentIsCancelled = isCancelled;
  final (country, flag) = GeoIPOffline().lookupFull(ip);
  final survivalTarget  = mode == ScanMode.deep ? _survivalDeep : _survivalNormal;
  final repeats         = mode == ScanMode.deep ? 5 : 3;

  // p3: check subnet cache for best SNI first
  final subnetBestSni = SubnetMemoryCache().bestSniForSubnet(ip);

  final effectiveSnis = (mode == ScanMode.deep && snis != null && snis.isNotEmpty)
      ? snis
      : (mode == ScanMode.deep ? kDeepSniPresets : [kShiroSni]);

  final orderedSnis = (mode == ScanMode.deep &&
          subnetBestSni != null &&
          !effectiveSnis.contains(subnetBestSni))
      ? [subnetBestSni, ...effectiveSnis]
      : effectiveSnis;

  ScanResult dead(ScanPhase phase) => ScanResult(
        ip: ip,
        latencyMs: 9999,
        jitterMs: 0,
        isAlive: false,
        grade: 'F',
        country: country,
        flag: flag,
        loss: 100,
        reliability: 0,
        score: 0,
        survivalMs: 0,
        retransmits: 0,
        phase: phase,
        tier: IpTier.dead,
      );

  // ─── NORMAL MODE ──────────────────────────────────────────────────────────
  if (mode == ScanMode.normal) {
    final sniToUse = normalSniOverride ?? kShiroSni;
    final subnetTimeout = SubnetMemoryCache().adaptiveTimeoutHint(ip);
    final result = await _scanWithSni(
      ip, sniToUse, survivalTarget, repeats,
      country: country, flag: flag, dead: dead,
      subnetTimeoutHint: subnetTimeout,
    );
    if (result.isAlive) {
      SubnetMemoryCache().recordSuccess(ip, result.latencyMs, sniToUse);
      SoftBlacklist().recordSuccess(ip);
    } else {
      SubnetMemoryCache().recordFailure(ip);
      SoftBlacklist().recordFailure(ip);
    }
    ScanHistoryService().recordProviderResult(country, result.isAlive);
    ScanHistoryService().recordRecentResult(result.isAlive);
    return result;
  }

  // ─── DEEP MODE — try each SNI with family early-exit ─────────────────────
  ScanResult? bestResult;
  bool googleFamilyPassed = false;
  bool cloudflareFamilyPassed = false;

  for (final sni in orderedSnis) {
    if (googleFamilyPassed && kSniGoogleFamily.contains(sni)) continue;
    if (cloudflareFamilyPassed && kSniCloudflareFamily.contains(sni)) continue;

    final subnetTimeout = SubnetMemoryCache().adaptiveTimeoutHint(ip);
    final candidate = await _scanWithSni(
      ip, sni, survivalTarget, repeats,
      country: country, flag: flag, dead: dead,
      subnetTimeoutHint: subnetTimeout,
    );

    if (candidate.tier != IpTier.dead && candidate.tier != IpTier.weak) {
      if (kSniGoogleFamily.contains(sni)) googleFamilyPassed = true;
      if (kSniCloudflareFamily.contains(sni)) cloudflareFamilyPassed = true;
      SubnetMemoryCache().recordSuccess(ip, candidate.latencyMs, sni);
    }

    if (bestResult == null) {
      bestResult = candidate;
    } else {
      final tierA = candidate.tier.index;
      final tierB = bestResult.tier.index;
      if (tierA < tierB) {
        bestResult = candidate;
      } else if (tierA == tierB &&
          (candidate.score ?? 0) > (bestResult.score ?? 0)) {
        bestResult = candidate;
      }
    }

    if (bestResult?.tier == IpTier.excellent) break;
  }

  final finalResult = bestResult ?? dead(ScanPhase.tlsFail);
  ScanHistoryService().recordProviderResult(country, finalResult.isAlive);
  ScanHistoryService().recordRecentResult(finalResult.isAlive);
  return finalResult;
}

// ── Single SNI pipeline ───────────────────────────────────────────────────────
Future<ScanResult> _scanWithSni(
  String ip,
  String sni,
  int survivalTarget,
  int repeats, {
  required String country,
  required String flag,
  required ScanResult Function(ScanPhase) dead,
  int? subnetTimeoutHint,
}) async {
  StructuredLogger().log(phase: 'probe_start', ip: ip, sni: sni);

  final first = await probeWithRetry(ip, sni: sni, retries: 5);
  if (first == null) {
    StructuredLogger()
        .log(phase: 'probe_fail', ip: ip, sni: sni, error: 'TLS fail');
    return dead(ScanPhase.tlsFail);
  }

  final firstTimings = first.timings;

  // ── cf1: Cloudflare HTTP probe — always runs, independent of TLS SNI ──────
  // Uses speed.cloudflare.com as SNI regardless of what TLS SNI was used.
  // Mirrors SenPai probeHTTP: confirms real CF edge + captures colo BEFORE
  // committing to the expensive 20s survival test.
  // If this IP is NOT a real CF edge → fail fast, skip survival test.
  const _cfProbeSni = 'speed.cloudflare.com';
  final cfResult = await cfHttpProbe(ip, sni: _cfProbeSni);
  final int?    cfHttpStatus = cfResult.httpStatus;
  final String? cfColo       = cfResult.colo.isNotEmpty ? cfResult.colo : null;
  StructuredLogger().log(
    phase: 'cf_http',
    ip: ip,
    sni: _cfProbeSni,
    event: 'status=$cfHttpStatus colo=${cfColo ?? "?"}',
  );
  // Not a confirmed CF edge → fail fast
  if (!cfResult.isCloudflareEdge) {
    return dead(ScanPhase.tlsFail);
  }

  // ── ws2: WebSocket DPI probe — runs after CF HTTP confirmed ─────────────
  // Always uses speed.cloudflare.com — independent of TLS SNI.
  // Mirrors SenPai probeHTTP → probeWebSocket call.
  final bool? cfWsOk = await cfWsProbe(ip, sni: _cfProbeSni);
  StructuredLogger().log(
    phase: 'cf_ws',
    ip: ip,
    sni: _cfProbeSni,
    event: 'wsOk=$cfWsOk',
  );

  final samples = <double>[first.latencyMs];
  int   failed  = 0;

  final adaptiveMs = adaptiveServerHelloMs(
    first.latencyMs,
    subnetHintMs: subnetTimeoutHint,
  );

  for (int i = 1; i < repeats; i++) {
    final r = await androidTlsProbe(ip, sni: sni, serverHelloMs: adaptiveMs);
    if (r != null) {
      samples.add(r.latencyMs);
    } else {
      failed++;
    }
    await Future.delayed(const Duration(milliseconds: 200));
  }

  if (samples.isEmpty) return dead(ScanPhase.stabilityFail);

  final lossPercent = repeats > 1
      ? ((failed / (repeats - 1)) * 100).round().clamp(0, 100)
      : 0;
  final reliability = samples.length / repeats;
  final avg         = samples.reduce((a, b) => a + b) / samples.length;
  final jitter      = calcJitter(samples);

  final survival = await tunnelSurvivalTest(
    ip,
    sni: sni,
    survivalTargetMs: survivalTarget,
    isCancelled: _currentIsCancelled,
  );

  final phase = survival.dpiKilled
      ? ScanPhase.dpiFail
      : survival.survived
          ? ScanPhase.passed
          : ScanPhase.survivalFail;

  final tier = calcTier(survival.survivalMs, phase);

  final isAlive = tier != IpTier.dead && tier != IpTier.weak
      ? true
      : phase == ScanPhase.passed;

  double? speedKBs;
  if (tier == IpTier.excellent ||
      tier == IpTier.good ||
      tier == IpTier.usable) {
    speedKBs = await measureBandwidthKBs(ip, sni: sni);
  }

  // cf1: cfHttpProbe already ran above (before survival test) for Cloudflare SNIs

  final trustBonus = SubnetMemoryCache().trustBonus(ip);

  final score = calcScore(
    survived:         survival.survived,
    survivalMs:       survival.survivalMs,
    survivalTargetMs: survivalTarget,
    avgLatencyMs:     avg,
    reliability:      reliability,
    subnetTrustBonus: trustBonus,
  );

  final confidence = calcConfidenceScore(
    reliability: reliability,
    sampleCount: samples.length,
    survivalMs:  survival.survivalMs,
  );

  final rui = calcRealUsabilityIndex(
    survived:       survival.survived,
    survivalMs:     survival.survivalMs,
    reliability:    reliability,
    tlsHandshakeMs: firstTimings?.tlsMs ?? avg,
  );

  final grade = calcGradeFromScore(score, phase);

  StructuredLogger().log(
    phase: 'probe_done',
    ip: ip,
    sni: sni,
    event: 'tier=${tier.name} grade=$grade survival=${survival.survivalMs}ms',
  );

  return ScanResult(
    ip:                 ip,
    latencyMs:          double.parse(avg.toStringAsFixed(1)),
    jitterMs:           double.parse(jitter.toStringAsFixed(1)),
    isAlive:            isAlive,
    grade:              grade,
    country:            country,
    flag:               flag,
    loss:               lossPercent,
    reliability:        double.parse(reliability.toStringAsFixed(2)),
    score:              score,
    survivalMs:         survival.survivalMs,
    retransmits:        0,
    phase:              phase,
    tier:               tier,
    speedKBs:           speedKBs,
    sniUsed:            sni,
    tcpLatencyMs:       firstTimings != null
        ? double.parse(firstTimings.tcpMs.toStringAsFixed(1))
        : null,
    tlsHandshakeMs:     firstTimings != null
        ? double.parse(firstTimings.tlsMs.toStringAsFixed(1))
        : null,
    dpiSuspicion:       survival.dpiSuspicionScore,
    confidenceScore:    confidence,
    realUsabilityIndex: rui,
    httpStatus:         cfHttpStatus,
    colo:               cfColo,
    wsOk:               cfWsOk,
  );
}

// ─── runScanningEngine ────────────────────────────────────────────────────────
Future<List<ScanResult>> runScanningEngine(
  List<String> ips, {
  ScanMode mode           = ScanMode.normal,
  int concurrency         = 4,
  List<String>? deepSnis,
  void Function(int done, int total, ScanResult result)? onProgress,
  void Function(int liveCount, int totalCount)? onPrefilterDone,
  bool Function()? isCancelled,
  String? normalSniOverride,
  bool isCfScan           = false,
}) async {
  // ── Deep mode: delegate entirely to the 7-stage deep scan engine ──────────
  if (mode == ScanMode.deep) {
    return runDeepScanEngine(
      ips,
      onProgress:      onProgress,
      onPrefilterDone: onPrefilterDone,
      isCancelled:     isCancelled,
    );
  }

  final results     = <ScanResult>[];
  int   done        = 0;
  final cancelCheck = isCancelled ?? () => false;

  _currentIsCancelled = cancelCheck;

  AdaptiveConcurrencyController().reset();

  // p10: separate deprioritized IPs
  final filteredIps      = ips.where((ip) => !SoftBlacklist().isDeprioritized(ip)).toList();
  final deprioritizedIps = ips.where((ip) => SoftBlacklist().isDeprioritized(ip)).toList();

  // ── Step 0: Fast TCP probe ────────────────────────────────────────────────
  const int _fastConcurrency = 40;
  const int _fastTimeoutMs   = 4000;

  final _fastProbe   = FastProbeEngine(defaultTimeoutMs: _fastTimeoutMs);
  final prefilterSem = Semaphore(_fastConcurrency);

  final liveIpResults = await Future.wait(filteredIps.map((ip) async {
    if (cancelCheck()) return null;
    await prefilterSem.acquire();
    try {
      if (cancelCheck()) return null;
      final result = await _fastProbe.probe(ip, timeoutMs: _fastTimeoutMs);
      if (!result.alive) {
        SoftBlacklist().recordFailure(ip);
        SubnetMemoryCache().recordFailure(ip);
      }
      return result.alive ? ip : null;
    } finally {
      prefilterSem.release();
    }
  }));
  var liveIps = liveIpResults.whereType<String>().toList();

  if (!cancelCheck() && deprioritizedIps.isNotEmpty) {
    final depriSem = Semaphore(10);
    final depriResults = await Future.wait(deprioritizedIps.map((ip) async {
      if (cancelCheck()) return null;
      await depriSem.acquire();
      try {
        final alive = await quickTlsCheck(ip, timeoutMs: 3000);
        return alive ? ip : null;
      } finally {
        depriSem.release();
      }
    }));
    liveIps.addAll(depriResults.whereType<String>());
  }

  onPrefilterDone?.call(liveIps.length, ips.length);
  if (liveIps.isEmpty) return results;

  // ── Step 1: Full scan on live IPs ─────────────────────────────────────────
  final adaptiveCtrl    = AdaptiveConcurrencyController();
  final baseConcurrency = mode == ScanMode.deep
      ? min(concurrency, 4)
      : min(concurrency, 8);
  adaptiveCtrl.seed(baseConcurrency);

  int _activeScans = 0;
  final _scanCompleters = <Completer<void>>[];
  final totalLive = liveIps.length;

  await Future.wait(liveIps.map((ip) async {
    if (cancelCheck()) return;

    while (_activeScans >= adaptiveCtrl.current) {
      final c = Completer<void>();
      _scanCompleters.add(c);
      await c.future;
    }
    _activeScans++;

    try {
      if (cancelCheck()) return;
      final r = await scanOneIp(ip, mode: mode, snis: deepSnis, normalSniOverride: normalSniOverride, isCfScan: isCfScan);
      results.add(r);
      done++;
      onProgress?.call(done, totalLive, r);

      if (r.isAlive) {
        adaptiveCtrl.recordSuccess();
      } else {
        adaptiveCtrl.recordError();
      }
    } finally {
      _activeScans--;
      if (_scanCompleters.isNotEmpty) {
        _scanCompleters.removeAt(0).complete();
      }
    }
  }));

  // ── Step 2: Sort by tier → score → latency ────────────────────────────────
  results.sort((a, b) {
    if (a.tier.index != b.tier.index) {
      return a.tier.index.compareTo(b.tier.index);
    }
    final sa = a.score ?? 0.0;
    final sb = b.score ?? 0.0;
    if (sa != sb) return sb.compareTo(sa);
    return a.latencyMs.compareTo(b.latencyMs);
  });

  // p31+p33: persist session history
  final aliveResults = results.where((r) => r.isAlive).toList();
  if (aliveResults.isNotEmpty) {
    ScanHistoryService()
        .saveGoodIps(aliveResults.map((r) => r.ip).toList());
    ScanHistoryService().saveScanSession(
      time: DateTime.now(),
      totalScanned: results.length,
      aliveCount: aliveResults.length,
      topIps: aliveResults.take(5).map((r) => r.ip).toList(),
    );
  }

  return results;
}
