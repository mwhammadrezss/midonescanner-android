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
import '../utils/stats_utils.dart';
import '../storage/scan_history.dart';
import '../utils/logger.dart';

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

  // If subnet has a best SNI and it's not already in the list, prepend it
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
    final subnetTimeout = SubnetMemoryCache().adaptiveTimeoutHint(ip);
    final result = await _scanWithSni(
      ip, kShiroSni, survivalTarget, repeats,
      country: country, flag: flag, dead: dead,
      subnetTimeoutHint: subnetTimeout,
    );
    if (result.isAlive) {
      SubnetMemoryCache().recordSuccess(ip, result.latencyMs, kShiroSni);
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

  // BUG 1 FIX: check samples.isEmpty BEFORE calling tunnelSurvivalTest
  // (avoids wasting 20s survival test when all repeat probes failed)
  if (samples.isEmpty) return dead(ScanPhase.stabilityFail);

  final lossPercent = repeats > 1 // BUGFIX: denominator is probes that can fail (repeats-1)
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
    event:
        'tier=${tier.name} grade=$grade survival=${survival.survivalMs}ms',
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
}) async {
  final results     = <ScanResult>[];
  int   done        = 0;
  final cancelCheck = isCancelled ?? () => false;

  _currentIsCancelled = cancelCheck;

  AdaptiveConcurrencyController().reset();

  // p10: separate deprioritized IPs
  final filteredIps      = ips.where((ip) => !SoftBlacklist().isDeprioritized(ip)).toList();
  final deprioritizedIps = ips.where((ip) => SoftBlacklist().isDeprioritized(ip)).toList();

  // ── Step 0: Quick TLS pre-filter ─────────────────────────────────────────
  // BUG 5 FIX: collect results via return value instead of concurrent .add()
  final prefilterSem = Semaphore(50);

  final liveIpResults = await Future.wait(filteredIps.map((ip) async {
    if (cancelCheck()) return null;
    await prefilterSem.acquire();
    try {
      if (cancelCheck()) return null;
      final alive = await quickTlsCheck(ip, timeoutMs: 3000);
      if (!alive) {
        SoftBlacklist().recordFailure(ip);
        SubnetMemoryCache().recordFailure(ip);
      }
      return alive ? ip : null;
    } finally {
      prefilterSem.release();
    }
  }));
  // BUG 5 FIX: safe collect — no concurrent mutation
  var liveIps = liveIpResults.whereType<String>().toList();

  // p10: deprioritized IPs scanned last with lower concurrency
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
    // BUG 5 FIX: safe collect for deprioritized IPs too
    liveIps.addAll(depriResults.whereType<String>());
  }

  onPrefilterDone?.call(liveIps.length, ips.length);
  if (liveIps.isEmpty) return results;

  // ── Step 1: Full scan on live IPs ────────────────────────────────────────
  // BUG 6 FIX: use passed-in concurrency param instead of always computing from calcConcurrency
  final adaptiveCtrl   = AdaptiveConcurrencyController();
  final baseConcurrency = mode == ScanMode.deep
      ? min(concurrency, 4)
      : min(concurrency, 8);
  adaptiveCtrl.seed(baseConcurrency);

  // BUG 4 FIX: use dynamic active-count approach so adaptiveCtrl.current
  // is respected live instead of a fixed Semaphore that never resizes.
  int _activeScans = 0;
  final _scanCompleters = <Completer<void>>[];
  final totalLive = liveIps.length;

  await Future.wait(liveIps.map((ip) async {
    if (cancelCheck()) return;

    // Wait until a slot is available at the CURRENT adaptive limit
    while (_activeScans >= adaptiveCtrl.current) {
      final c = Completer<void>();
      _scanCompleters.add(c);
      await c.future;
    }
    _activeScans++;

    try {
      if (cancelCheck()) return;
      final r = await scanOneIp(ip, mode: mode, snis: deepSnis);
      results.add(r);
      done++;
      onProgress?.call(done, totalLive, r);

      // p30: update adaptive controller — this now actually affects concurrency
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

  // ── Step 2: Sort by tier → score → latency ───────────────────────────────
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
