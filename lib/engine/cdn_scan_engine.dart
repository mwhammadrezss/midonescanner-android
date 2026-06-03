// lib/engine/cdn_scan_engine.dart
// CDN scan pipeline — aligned with working midonescanner-android-main.zip logic.
// TCP prefilter → TLS multi-try → tunnel survival → bandwidth (Normal / Deep).

import 'dart:async';
import 'dart:math';

import '../models/scan_result.dart';
import '../geo/geoip.dart';
import '../storage/scan_history.dart';
import '../utils/stats_utils.dart';
import '../utils/logger.dart';
import 'adaptive_concurrency.dart';
import 'concurrency_engine.dart';
import 'grading_engine.dart';
import 'probe_engine.dart';
import 'range/fast_probe_engine.dart';
import 'soft_blacklist.dart';
import 'subnet_cache.dart';
import 'tunnel_engine.dart';

import 'scanner_engine.dart' show ScanMode;

bool Function()? _cdnIsCancelled;

/// CDN scan entry — same contract as legacy runScanningEngine for the CDN tab.
Future<List<ScanResult>> runCdnScanEngine(
  List<String> ips, {
  ScanMode mode = ScanMode.normal,
  int concurrency = 8,
  List<String>? deepSnis,
  void Function(int done, int total, ScanResult result)? onProgress,
  void Function(int liveCount, int totalCount)? onPrefilterDone,
  bool Function()? isCancelled,
  int tlsRepeats = 0,
}) async {
  final results = <ScanResult>[];
  int done = 0;
  final cancelCheck = isCancelled ?? () => false;
  _cdnIsCancelled = cancelCheck;

  AdaptiveConcurrencyController().reset();

  final filteredIps =
      ips.where((ip) => !SoftBlacklist().isDeprioritized(ip)).toList();
  final deprioritizedIps =
      ips.where((ip) => SoftBlacklist().isDeprioritized(ip)).toList();

  // Step 0 — fast TCP prefilter (same as working zip)
  const fastConcurrency = 40;
  const fastTimeoutMs = 4000;
  final fastProbe = FastProbeEngine(defaultTimeoutMs: fastTimeoutMs);
  final prefilterSem = Semaphore(fastConcurrency);

  final liveIpResults = await Future.wait(filteredIps.map((ip) async {
    if (cancelCheck()) return null;
    await prefilterSem.acquire();
    try {
      if (cancelCheck()) return null;
      final result = await fastProbe.probe(ip, timeoutMs: fastTimeoutMs);
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
  if (liveIps.isEmpty || cancelCheck()) return results;

  final adaptiveCtrl = AdaptiveConcurrencyController();
  final baseConcurrency = mode == ScanMode.deep
      ? min(concurrency, 4)
      : min(concurrency, 8);
  adaptiveCtrl.seed(baseConcurrency);

  int activeScans = 0;
  final scanCompleters = <Completer<void>>[];
  final totalLive = liveIps.length;

  await Future.wait(liveIps.map((ip) async {
    if (cancelCheck()) return;

    while (activeScans >= adaptiveCtrl.current) {
      final c = Completer<void>();
      scanCompleters.add(c);
      await c.future;
    }
    activeScans++;

    try {
      if (cancelCheck()) return;
      final r = await _cdnScanOneIp(
        ip,
        mode: mode,
        snis: deepSnis,
        tlsRepeats: tlsRepeats,
      );
      results.add(r);
      done++;
      onProgress?.call(done, totalLive, r);
      if (r.isAlive) {
        adaptiveCtrl.recordSuccess();
      } else {
        adaptiveCtrl.recordError();
      }
    } finally {
      activeScans--;
      if (scanCompleters.isNotEmpty) {
        scanCompleters.removeAt(0).complete();
      }
    }
  }));

  results.sort((a, b) {
    if (a.tier.index != b.tier.index) {
      return a.tier.index.compareTo(b.tier.index);
    }
    final sa = a.score ?? 0.0;
    final sb = b.score ?? 0.0;
    if (sa != sb) return sb.compareTo(sa);
    return a.latencyMs.compareTo(b.latencyMs);
  });

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

Future<ScanResult> _cdnScanOneIp(
  String ip, {
  ScanMode mode = ScanMode.normal,
  List<String>? snis,
  int tlsRepeats = 0,
}) async {
  final (country, flag) = GeoIPOffline().lookupFull(ip);
  const survivalTarget = 20000;
  final repeats = tlsRepeats > 0
      ? tlsRepeats.clamp(1, 6)
      : (mode == ScanMode.deep ? 5 : 3);

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

  if (mode == ScanMode.normal) {
    final subnetTimeout = SubnetMemoryCache().adaptiveTimeoutHint(ip);
    final result = await _cdnScanWithSni(
      ip,
      kShiroSni,
      survivalTarget,
      repeats,
      country: country,
      flag: flag,
      dead: dead,
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

  ScanResult? bestResult;
  var googleFamilyPassed = false;
  var cloudflareFamilyPassed = false;

  for (final sni in orderedSnis) {
    if (_cdnIsCancelled?.call() == true) break;
    if (googleFamilyPassed && kSniGoogleFamily.contains(sni)) continue;
    if (cloudflareFamilyPassed && kSniCloudflareFamily.contains(sni)) continue;

    final subnetTimeout = SubnetMemoryCache().adaptiveTimeoutHint(ip);
    final candidate = await _cdnScanWithSni(
      ip,
      sni,
      survivalTarget,
      repeats,
      country: country,
      flag: flag,
      dead: dead,
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

Future<ScanResult> _cdnScanWithSni(
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

  final effectiveSni = first.sniUsed ?? sni;
  final firstTimings = first.timings;

  final samples = <double>[first.latencyMs];
  var failed = 0;

  final adaptiveMs = adaptiveServerHelloMs(
    first.latencyMs,
    subnetHintMs: subnetTimeoutHint,
  );

  for (var i = 1; i < repeats; i++) {
    final r =
        await androidTlsProbe(ip, sni: effectiveSni, serverHelloMs: adaptiveMs);
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
  final avg = samples.reduce((a, b) => a + b) / samples.length;
  final jitter = calcJitter(samples);

  final survival = await tunnelSurvivalTest(
    ip,
    sni: effectiveSni,
    survivalTargetMs: survivalTarget,
    isCancelled: _cdnIsCancelled,
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
    speedKBs = await measureBandwidthKBs(ip, sni: effectiveSni);
  }

  final trustBonus = SubnetMemoryCache().trustBonus(ip);
  final score = calcScore(
    survived: survival.survived,
    survivalMs: survival.survivalMs,
    survivalTargetMs: survivalTarget,
    avgLatencyMs: avg,
    reliability: reliability,
    subnetTrustBonus: trustBonus,
  );

  final confidence = calcConfidenceScore(
    reliability: reliability,
    sampleCount: samples.length,
    survivalMs: survival.survivalMs,
  );

  final rui = calcRealUsabilityIndex(
    survived: survival.survived,
    survivalMs: survival.survivalMs,
    reliability: reliability,
    tlsHandshakeMs: firstTimings?.tlsMs ?? avg,
  );

  final grade = calcGradeFromScore(score, phase);

  return ScanResult(
    ip: ip,
    latencyMs: double.parse(avg.toStringAsFixed(1)),
    jitterMs: double.parse(jitter.toStringAsFixed(1)),
    isAlive: isAlive,
    grade: grade,
    country: country,
    flag: flag,
    loss: lossPercent,
    reliability: double.parse(reliability.toStringAsFixed(2)),
    score: score,
    survivalMs: survival.survivalMs,
    retransmits: 0,
    phase: phase,
    tier: tier,
    speedKBs: speedKBs,
    sniUsed: effectiveSni,
    tcpLatencyMs: firstTimings != null
        ? double.parse(firstTimings.tcpMs.toStringAsFixed(1))
        : null,
    tlsHandshakeMs: firstTimings != null
        ? double.parse(firstTimings.tlsMs.toStringAsFixed(1))
        : null,
    dpiSuspicion: survival.dpiSuspicionScore,
    confidenceScore: confidence,
    realUsabilityIndex: rui,
  );
}

/// CDN Normal — Fast: TCP:443 only, no tunnel (very fast, like range Akamai).
Future<List<ScanResult>> runCdnFastScanEngine(
  List<String> ips, {
  void Function(int done, int total, ScanResult result)? onProgress,
  void Function(int liveCount, int totalCount)? onPrefilterDone,
  bool Function()? isCancelled,
}) async {
  final results = <ScanResult>[];
  var done = 0;
  final cancelCheck = isCancelled ?? () => false;

  const concurrency = 100;
  const timeoutMs = 1500;
  final probe = FastProbeEngine(defaultTimeoutMs: timeoutMs);
  final sem = Semaphore(concurrency);

  final liveResults = await Future.wait(ips.map((ip) async {
    if (cancelCheck()) return null;
    await sem.acquire();
    try {
      if (cancelCheck()) return null;
      final (country, flag) = GeoIPOffline().lookupFull(ip);
      final r = await probe.probe(ip, timeoutMs: timeoutMs);
      if (!r.alive) return null;
      final latency = r.tcpMs;
      return ScanResult(
        ip: ip,
        latencyMs: double.parse(latency.toStringAsFixed(1)),
        jitterMs: 0,
        isAlive: true,
        grade: latency < 80 ? 'A' : latency < 150 ? 'B' : latency < 300 ? 'C' : 'D',
        country: country,
        flag: flag,
        loss: 0,
        reliability: 1.0,
        score: (100 - (latency / 8).clamp(0, 90)).toDouble(),
        survivalMs: null,
        retransmits: 0,
        phase: ScanPhase.passed,
        tier: latency < 100
            ? IpTier.excellent
            : latency < 200
                ? IpTier.good
                : IpTier.usable,
        dpiSuspicion: 0,
        tcpLatencyMs: latency,
      );
    } finally {
      sem.release();
    }
  }));

  final live = liveResults.whereType<ScanResult>().toList();
  onPrefilterDone?.call(live.length, ips.length);
  if (live.isEmpty || cancelCheck()) return results;

  for (final r in live) {
    if (cancelCheck()) break;
    results.add(r);
    done++;
    onProgress?.call(done, live.length, r);
  }

  results.sort((a, b) => a.latencyMs.compareTo(b.latencyMs));
  return results;
}
