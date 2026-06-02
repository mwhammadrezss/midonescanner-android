// lib/engine/range/range_scan_engine.dart
// Main Range Scan orchestrator — ties all subsystems together

import 'dart:async';

import 'adaptive_concurrency.dart';
import 'smart_timeout_manager.dart';
import 'smart_batch_scheduler.dart';
import 'candidate_filter.dart';
import 'fast_probe_engine.dart';
import 'live_result_store.dart';
import 'live_ranker.dart';
import 'deep_result_ranker.dart';
import 'pause_resume_controller.dart';
import 'worker_pool.dart';
import 'isolate_pool_manager.dart';
import 'deep_scan_bridge.dart';
import 'subnet_sampler.dart';
import 'cidr_provider_service.dart';
import '../../models/scan_result.dart';
import '../../geo/geoip.dart';

export 'live_result_store.dart';

enum RangeScanMode { fastProbeOnly, normalScan, deepScan }

class RangeScanStats {
  int totalProbed = 0;
  int totalAlive = 0;
  int totalFiltered = 0;
  int totalDeepScanned = 0;
  int currentConcurrency = 200;
  double avgTcpMs = 0;
  DateTime? startTime;
  int _tcpSamples = 0;

  Duration get elapsed =>
      startTime != null ? DateTime.now().difference(startTime!) : Duration.zero;

  double get probeRate {
    final secs = elapsed.inSeconds;
    return secs > 0 ? totalProbed / secs : 0;
  }

  void addTcpSample(double ms) {
    _tcpSamples++;
    avgTcpMs = ((avgTcpMs * (_tcpSamples - 1)) + ms) / _tcpSamples;
  }

  void reset() {
    totalProbed = 0;
    totalAlive = 0;
    totalFiltered = 0;
    totalDeepScanned = 0;
    avgTcpMs = 0;
    _tcpSamples = 0;
    startTime = DateTime.now();
  }

  RangeScanStats copy() => RangeScanStats()
    ..totalProbed = totalProbed
    ..totalAlive = totalAlive
    ..totalFiltered = totalFiltered
    ..totalDeepScanned = totalDeepScanned
    ..currentConcurrency = currentConcurrency
    ..avgTcpMs = avgTcpMs
    ..startTime = startTime
    .._tcpSamples = _tcpSamples;
}

class RangeScanEngine {
  final RangeAdaptiveConcurrency _concurrency = RangeAdaptiveConcurrency();
  final SmartTimeoutManager _timeoutManager = SmartTimeoutManager();
  final SmartBatchScheduler _batchScheduler = SmartBatchScheduler();
  final CandidateFilter _filter = CandidateFilter();
  final FastProbeEngine _probeEngine = const FastProbeEngine();
  final LiveResultStore _resultStore = LiveResultStore();
  final LiveRanker _ranker = LiveRanker();
  final DeepResultRanker _deepRanker = DeepResultRanker();
  final PauseResumeController _pauseController = PauseResumeController();
  final IsolatePoolManager _isolatePool = IsolatePoolManager(maxWorkers: 4);
  final DeepScanBridge _deepBridge = DeepScanBridge();

  WorkerPool? _workerPool;
  bool _cancelled = false;
  final RangeScanStats _stats = RangeScanStats();

  RangeScanStats get stats => _stats.copy();
  Stream<RangeScanResult> get resultStream => _resultStore.stream;
  List<RangeScanResult> get results => _resultStore.results;
  bool get isCancelled => _cancelled;

  Future<void> scan({
    required String cidr,
    required RangeScanMode mode,
    int? concurrencyOverride,
    RangeCdnProvider? provider,
    bool Function()? isCancelled,
    void Function(RangeScanStats)? onStatsUpdate,
  }) async {
    final cancelCheck = isCancelled ?? () => false;
    final isCfScan = provider == RangeCdnProvider.cloudflare;

    // 1. Init
    _stats.reset();
    if (concurrencyOverride != null) _concurrency.set(concurrencyOverride);

    _workerPool?.dispose();
    _workerPool = WorkerPool(concurrency: _concurrency.current);

    await _isolatePool.initialize();

    // 2. Expand CIDR — off main thread
    final maxSample = mode == RangeScanMode.fastProbeOnly ? 500 : 300;
    final rawIps = await _isolatePool.expandCidr(cidr, maxSample);

    if (rawIps.isEmpty || cancelCheck() || _cancelled) return;

    // 3. Filter private IPs
    final ips = rawIps.where((ip) => !SubnetSampler.isPrivate(ip)).toList();
    if (ips.isEmpty) return;

    // 4. Fast TCP probe stage
    final probeResults = <FastProbeResult>[];
    final pool = _workerPool!;
    pool.concurrency = _concurrency.current;

    await pool.runBatch<String>(
      ips,
      (ip) async {
        if (cancelCheck() || _cancelled) return;
        await _pauseController.waitIfPaused();
        if (cancelCheck() || _cancelled) return;

        final result = await _probeEngine.probe(
          ip,
          timeoutMs: _timeoutManager.timeoutMs,
        );

        probeResults.add(result);
        _stats.totalProbed++;

        if (result.alive) {
          _timeoutManager.add(result.tcpMs);
          _stats.addTcpSample(result.tcpMs);
          _stats.totalAlive++;
          _concurrency.recordSuccess();
        } else if (result.timedOut) {
          _concurrency.recordTimeout();
        } else {
          _concurrency.recordError();
        }

        // Dynamically update pool concurrency
        pool.concurrency = _concurrency.current;
        _stats.currentConcurrency = _concurrency.current;
        onStatsUpdate?.call(_stats.copy());
      },
      isCancelled: () => cancelCheck() || _cancelled,
    );

    if (cancelCheck() || _cancelled) return;

    // 5. Filter candidates
    final candidates = _filter.filterBatch(probeResults, maxRttMs: 800);
    _stats.totalFiltered = candidates.length;

    // Update scheduler with results
    final timeouts = probeResults.where((r) => r.timedOut).length;
    _batchScheduler.update(
      successes: candidates.length,
      timeouts: timeouts,
      total: probeResults.length,
    );

    // UPGRADED: apply SmartBatchScheduler recommendation to concurrency
    final recommended = _batchScheduler.nextBatchSize(_concurrency.current);
    if (recommended != _concurrency.current) {
      _concurrency.set(recommended);
      pool.concurrency = _concurrency.current;
    }

    if (candidates.isEmpty) return;

    // 6. Fast-probe-only mode: score and store directly
    if (mode == RangeScanMode.fastProbeOnly) {
      for (final probe in candidates) {
        if (cancelCheck() || _cancelled) break;
        final s = _ranker.score(probe);
        final g = _ranker.grade(s);
        final (country, flag) = GeoIPOffline().lookupFull(probe.ip);
        _resultStore.add(RangeScanResult(
          ip: probe.ip,
          tcpMs: probe.tcpMs,
          grade: g,
          score: s,
          country: country,
          flag: flag,
          discoveredAt: DateTime.now(),
        ));
      }
      onStatsUpdate?.call(_stats.copy());
      return;
    }

    // 7. Normal/Deep scan: bridge into full scanner — UPGRADED concurrency
    final deepMode = mode == RangeScanMode.deepScan;
    final deepConcurrency = deepMode ? 6 : 16;

    await _deepBridge.scanBatch(
      candidates.map((r) => r.ip).toList(),
      deepMode: deepMode,
      concurrency: deepConcurrency,
      isCfScan: isCfScan,
      isCancelled: () => cancelCheck() || _cancelled,
      onResult: (scanResult) {
        if (cancelCheck() || _cancelled) return;

        _stats.totalDeepScanned++;

        final probe = candidates.firstWhere(
          (p) => p.ip == scanResult.ip,
          orElse: () => FastProbeResult(
            ip: scanResult.ip,
            tcpMs: scanResult.latencyMs,
            alive: scanResult.isAlive,
            timedOut: false,
          ),
        );

        double score;
        String grade;

        if (scanResult.isAlive) {
          score = _deepRanker.calculate(
            latency: scanResult.latencyMs,
            jitter: scanResult.jitterMs,
            reliability: scanResult.reliability,
            survivalMs: scanResult.survivalMs?.toDouble(),
          );
          grade = _deepRanker.grade(score);
        } else {
          score = 0;
          grade = 'F';
        }

        _resultStore.add(RangeScanResult(
          ip: scanResult.ip,
          tcpMs: probe.tcpMs,
          tlsMs: scanResult.tlsHandshakeMs,
          latencyMs: scanResult.latencyMs,
          jitterMs: scanResult.jitterMs,
          grade: grade,
          score: score,
          deepScanned: true,
          country: scanResult.country,
          flag: scanResult.flag,
          sniUsed: scanResult.sniUsed,
          discoveredAt: DateTime.now(),
        ));

        onStatsUpdate?.call(_stats.copy());
      },
    );
  }

  /// Scan multiple CIDRs sequentially
  Future<void> scanMultiple({
    required List<String> cidrs,
    required RangeScanMode mode,
    int? concurrencyOverride,
    RangeCdnProvider? provider,
    bool Function()? isCancelled,
    void Function(RangeScanStats)? onStatsUpdate,
  }) async {
    for (final cidr in cidrs) {
      if (_cancelled || (isCancelled?.call() ?? false)) break;
      await scan(
        cidr: cidr,
        mode: mode,
        concurrencyOverride: concurrencyOverride,
        provider: provider,
        isCancelled: isCancelled,
        onStatsUpdate: onStatsUpdate,
      );
    }
  }

  void pause() => _pauseController.pause();

  void resume() => _pauseController.resume();

  void cancel() {
    _cancelled = true;
    _pauseController.resume(); // unblock any waiting fibers
  }

  void reset() {
    _cancelled = false;
    _pauseController.reset();
    _resultStore.clear();
    _concurrency.reset();
    _timeoutManager.reset();
    _stats.reset();
  }

  void dispose() {
    cancel();
    _resultStore.dispose();
    _workerPool?.dispose();
    _isolatePool.dispose();
  }
}
