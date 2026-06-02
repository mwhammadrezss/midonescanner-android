// lib/engine/scanner_engine.dart
// ─── Android TLS Tunnel Survivability Scanner ────────────────────────────────
// UPGRADED:
//   - TCP prefilter: 40 → 100 concurrent, 4000ms → 3000ms timeout
//   - Normal scan baseConcurrency: 8 → 20
//   - Replaced manual activeScans/Completers with clean Semaphore pattern
// OPTIMIZED:
//   - _survivalNormal: 12000 → 10000 (faster scan cycle)
//   - _survivalDeep:   15000 → 12000 (faster deep scan cycle)
//
// BUGFIX v7.3.0:
//   - FIX #2: isAlive now correctly tied to survival.survived — not just tier.
//             Before: any IP with tier >= usable (survivalMs > 0 after fake
//             blackhole kill) was marked isAlive=true. Now: must have
//             survived the full tunnel test OR passed dpiFail gate.
//   - FIX #3: Bandwidth SNI guard — always use 'speed.cloudflare.com' for BW
//             test when effectiveSni is NOT in Cloudflare family. Using an
//             arbitrary Google/Akamai SNI for the download request returned
//             the root HTML page (a few KB) instead of a real BW payload,
//             making every non-CF IP show ~10–50 KB/s regardless of real speed.
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

// Survival targets — OPTIMIZED: reduced for faster scan cycles
const _survivalNormal = 10000;  // was 12000
const _survivalDeep   = 12000;  // was 15000

// ─── scanOneIp ───────────────────────────────────────────────────────────────
Future<ScanResult> scanOneIp(
  String ip, {
  ScanMode mode        = ScanMode.normal,
  List<String>? snis,
  bool Function()? isCancelled,
  String? normalSniOverride,
  bool isCfScan        = false,
}) async {
  final (country, flag) = GeoIPOffline().lookupFull(ip);
  final survivalTarget  = mode == ScanMode.deep ? _survivalDeep : _survivalNormal;
  final repeats         = mode == ScanMode.deep ? 3 : 2;

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
      runCfProbe: isCfScan,
      isCancelled: isCancelled,
    );
    if (result.isAlive) {
      SubnetMemoryCache().recordSuccess(ip, result.latencyMs, result.sniUsed ?? sniToUse);
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
    if (isCancelled?.call() == true) break;
    if (googleFamilyPassed && kSniGoogleFamily.contains(sni)) continue;
    if (cloudflareFamilyPassed && kSniCloudflareFamily.contains(sni)) continue;

    final subnetTimeout = SubnetMemoryCache().adaptiveTimeoutHint(ip);
    final candidate = await _scanWithSni(
      ip, sni, survivalTarget, repeats,
      country: country, flag: flag, dead: dead,
      subnetTimeoutHint: subnetTimeout,
      runCfProbe: kSniCloudflareFamily.contains(sni) || isCfScan,
      isCancelled: isCancelled,
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
  bool runCfProbe = false,
  bool Function()? isCancelled,
}) async {
  StructuredLogger().log(phase: 'probe_start', ip: ip, sni: sni);

  final first = await probeWithRetry(ip, sni: sni, retries: 2, sniRotation: runCfProbe);
  if (first == null) {
    StructuredLogger()
        .log(phase: 'probe_fail', ip: ip, sni: sni, error: 'TLS fail');
    return dead(ScanPhase.tlsFail);
  }

  final effectiveSni  = first.sniUsed;
  final firstTimings  = first.timings;

  int?    cfHttpStatus;
  String? cfColo;
  bool?   cfWsOk;
  if (runCfProbe) {
    final _cfProbeSni = kSniCloudflareFamily.contains(effectiveSni)
        ? effectiveSni
        : 'speed.cloudflare.com';
    final cfResult = await cfHttpProbe(ip, sni: _cfProbeSni);
    cfHttpStatus = cfResult.httpStatus;
    cfColo       = cfResult.colo.isNotEmpty ? cfResult.colo : null;
    StructuredLogger().log(
      phase: 'cf_http',
      ip: ip,
      sni: _cfProbeSni,
      event: 'status=$cfHttpStatus colo=${cfColo ?? "?"}',
    );
    if (!cfResult.isCloudflareEdge) {
      return dead(ScanPhase.tlsFail);
    }
    cfWsOk = await cfWsProbe(ip, sni: _cfProbeSni);
    StructuredLogger().log(
      phase: 'cf_ws',
      ip: ip,
      sni: _cfProbeSni,
      event: 'wsOk=$cfWsOk',
    );
  }

  final samples = <double>[first.latencyMs];
  int   failed  = 0;

  final adaptiveMs = adaptiveServerHelloMs(
    first.latencyMs,
    subnetHintMs: subnetTimeoutHint,
  );

  for (int i = 1; i < repeats; i++) {
    final r = await androidTlsProbe(ip, sni: effectiveSni, serverHelloMs: adaptiveMs);
    if (r != null) {
      samples.add(r.latencyMs);
    } else {
      failed++;
    }
    await Future.delayed(const Duration(milliseconds: 200));
  }

  if (samples.isEmpty) return dead(ScanPhase.stabilityFail);

  final lossPercent = repeats > 1
      ? ((failed / repeats) * 100).round().clamp(0, 100)
      : 0;
  final reliability = samples.length / repeats;
  final avg         = samples.reduce((a, b) => a + b) / samples.length;
  final jitter      = calcJitter(samples);

  final survival = await tunnelSurvivalTest(
    ip,
    sni: effectiveSni,
    survivalTargetMs: survivalTarget,
    isCancelled: isCancelled,
  );

  final phase = survival.dpiKilled
      ? ScanPhase.dpiFail
      : survival.survived
          ? ScanPhase.passed
          : ScanPhase.survivalFail;

  final tier = calcTier(survival.survivalMs, phase);

  // FIX #2: isAlive must be grounded in survival.survived, not just tier.
  // Old code: any IP reaching tier >= usable (survivalMs > 0 after the
  // premature 5s blackhole kill) was marked alive. That's what caused the
  // "weird results" — every IP looked usable with survivalMs≈5000.
  // New logic:
  //   • passed phase         → always alive (survived full tunnel)
  //   • dpiFail phase        → alive only if survivalMs ≥ 5000 (partial tunnel ok)
  //   • survivalFail phase   → alive only if tier is at least usable
  //                            AND survivalMs ≥ 5000 (got meaningful data)
  //   • cfWsOk gate: non-null cfWsOk=false always kills the IP (CF WS mode)
  final bool baseAlive;
  switch (phase) {
    case ScanPhase.passed:
      baseAlive = true;
      break;
    case ScanPhase.dpiFail:
      baseAlive = survival.survivalMs >= 5000;
      break;
    case ScanPhase.survivalFail:
      baseAlive = tier != IpTier.dead &&
                  tier != IpTier.weak &&
                  survival.survivalMs >= 5000;
      break;
    default:
      baseAlive = false;
  }
  final isAlive = baseAlive && (cfWsOk == null || cfWsOk == true);

  // FIX #3: Bandwidth SNI guard.
  // Only 'speed.cloudflare.com' has a proper /__down?bytes=N endpoint.
  // For all other SNIs the BW test was downloading the root HTML page
  // (a few KB) → reported speed was always artificially low (~10-50 KB/s).
  // Fix: use speed.cloudflare.com as the BW SNI when effectiveSni is not
  // in the Cloudflare family; this gives a real download measurement.
  double? speedKBs;
  if (tier == IpTier.excellent ||
      tier == IpTier.good ||
      tier == IpTier.usable) {
    final bwSni = kSniCloudflareFamily.contains(effectiveSni)
        ? effectiveSni
        : 'speed.cloudflare.com';
    speedKBs = await measureBandwidthKBs(ip, sni: bwSni);
  }

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
    event: 'tier=${tier.name} grade=$grade survival=${survival.survivalMs}ms alive=$isAlive',
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
    sniUsed:            effectiveSni,
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

  AdaptiveConcurrencyController().reset();

  // p10: separate deprioritized IPs
  final filteredIps      = ips.where((ip) => !SoftBlacklist().isDeprioritized(ip)).toList();
  final deprioritizedIps = ips.where((ip) => SoftBlacklist().isDeprioritized(ip)).toList();

  // ── Step 0: Fast TCP probe — UPGRADED: 100 concurrent, 3000ms timeout ────
  const int _fastConcurrency = 100;
  const int _fastTimeoutMs   = 3000;

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
  final adaptiveCtrl = AdaptiveConcurrencyController();
  final baseConcurrency = min(concurrency, 20);
  adaptiveCtrl.seed(baseConcurrency);

  final totalLive = liveIps.length;

  // progress: start event (0%)
  if (totalLive > 0) {
    final _startResult = ScanResult(
      ip: liveIps.first, latencyMs: 0, jitterMs: 0, isAlive: false,
      grade: '-', country: '', flag: '', loss: 0, reliability: 0,
      score: null, survivalMs: null, retransmits: 0,
      phase: ScanPhase.tlsFail, tier: IpTier.dead, dpiSuspicion: 0,
    );
    onProgress?.call(0, totalLive, _startResult);
  }

  int _prevConcurrency = adaptiveCtrl.current;
  final scanSem = Semaphore(_prevConcurrency);

  await Future.wait(liveIps.map((ip) async {
    if (cancelCheck()) return;
    await scanSem.acquire();
    try {
      if (cancelCheck()) return;
      final r = await scanOneIp(
        ip,
        mode: mode,
        snis: deepSnis,
        normalSniOverride: normalSniOverride,
        isCfScan: isCfScan,
      );
      results.add(r);
      done++;
      onProgress?.call(done, totalLive, r);
      if (r.isAlive) {
        adaptiveCtrl.recordSuccess();
      } else {
        adaptiveCtrl.recordError();
      }
      final newConcurrency = adaptiveCtrl.current;
      if (newConcurrency > _prevConcurrency) {
        scanSem.expand(newConcurrency - _prevConcurrency);
        _prevConcurrency = newConcurrency;
      }
    } finally {
      scanSem.release();
    }
  }));

  // progress: done event (100%)
  if (totalLive > 0 && results.isNotEmpty) {
    onProgress?.call(totalLive, totalLive, results.last);
  }

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
