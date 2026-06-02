// lib/engine/isolate_scan_engine.dart
// ─── Multi-Isolate Parallel Scan Engine ──────────────────────────────────────
//
// Strategy:
//   - Detect number of logical CPU cores at runtime
//   - Split IP list into N chunks (N = min(cores, 4) on Android, min(cores, 8) on Windows)
//   - Each chunk runs in its own Dart Isolate — true parallel execution
//   - Results collected via _TopNResults (top-100 retention, sorted)
//   - Workers stream results in batches of 5 via _WorkerBatch
//   - Isolate.kill() used on cancel for immediate resource release
//
// Architecture:
//   main isolate
//     ├── sends geoip bytes + config to each worker
//     ├── Isolate 0 → chunk 0 (scanOneIp × N)
//     ├── Isolate 1 → chunk 1
//     ├── ...
//     └── collects _WorkerBatch / _WorkerDone via ReceivePort
//
// Platform concurrency:
//   Android : min(cpuCores, 4)  isolates × 20 concurrency = up to 80 parallel
//   Windows : min(cpuCores, 8)  isolates × 32 concurrency = up to 256 parallel

import 'dart:async';
import 'dart:io';
import 'dart:isolate';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter/services.dart' show rootBundle;

import '../models/scan_result.dart';
import '../geo/geoip.dart';
import 'scanner_engine.dart';
import 'soft_blacklist.dart';
import 'subnet_cache.dart';
import 'adaptive_concurrency.dart';
import 'range/fast_probe_engine.dart';
import 'concurrency_engine.dart';

// ─── Platform-aware config ────────────────────────────────────────────────────

int get _numCpuCores {
  try {
    return Platform.numberOfProcessors;
  } catch (_) {
    return 2;
  }
}

int get _maxIsolates {
  if (Platform.isWindows || Platform.isLinux || Platform.isMacOS) {
    return min(_numCpuCores, 8);
  }
  // Android/iOS: battery-safe limit
  return min(_numCpuCores, 4);
}

int get _isolateConcurrency {
  if (Platform.isWindows || Platform.isLinux || Platform.isMacOS) {
    return 32;
  }
  return 20; // Android
}

int get _isolatePrefilterConcurrency {
  if (Platform.isWindows || Platform.isLinux || Platform.isMacOS) {
    return 120;
  }
  return 60;
}

// ─── Message types (Isolate ↔ Main) ──────────────────────────────────────────

class _WorkerConfig {
  final SendPort replyPort;
  final List<String> ips;
  final ScanMode mode;
  final List<String>? deepSnis;
  final String? normalSniOverride;
  final bool isCfScan;
  final int concurrency;
  final int prefilterConcurrency;
  final Uint8List? geoipBytes;

  const _WorkerConfig({
    required this.replyPort,
    required this.ips,
    required this.mode,
    this.deepSnis,
    this.normalSniOverride,
    this.isCfScan = false,
    required this.concurrency,
    required this.prefilterConcurrency,
    this.geoipBytes,
  });
}

class _WorkerPrefilterDone {
  final int liveCount;
  final int totalCount;
  const _WorkerPrefilterDone(this.liveCount, this.totalCount);
}

// Kept for backward compat — workers no longer send this; batching via _WorkerBatch instead
class _WorkerProgress {
  final int done;
  final int total;
  final ScanResult result;
  final int workerIndex;
  const _WorkerProgress(this.done, this.total, this.result, this.workerIndex);
}

// NEW: Workers send results in batches of 5 for reduced IPC overhead
class _WorkerBatch {
  final List<ScanResult> results;
  final int workerDone;
  final int workerTotal;
  const _WorkerBatch(this.results, this.workerDone, this.workerTotal);
}

// NEW: Sent by worker after its final _WorkerResult — main uses this to close port
class _WorkerDone {
  final int workerIndex;
  const _WorkerDone(this.workerIndex);
}

class _WorkerResult {
  final List<ScanResult> results;
  final int workerIndex;
  final Map<String, int> blacklistFails;
  final Map<String, _SubnetEntry> subnetCache;

  const _WorkerResult({
    required this.results,
    required this.workerIndex,
    required this.blacklistFails,
    required this.subnetCache,
  });
}

class _SubnetEntry {
  final int successes;
  final int failures;
  final double avgRtt;
  final String? bestSni;
  const _SubnetEntry(this.successes, this.failures, this.avgRtt, this.bestSni);
}

// NEW: Top-N result retention — keeps the best 100 results, sorted by tier→score→latency
// Prunes lazily (only when buffer exceeds 2× capacity) to avoid frequent sorts.
class _TopNResults {
  final int maxCapacity;
  final List<ScanResult> _results = [];

  _TopNResults({this.maxCapacity = 100});

  void addAll(List<ScanResult> items) {
    for (final r in items) _results.add(r);
    // Lazy prune: only sort+trim when buffer is 2× capacity
    if (_results.length > maxCapacity * 2) _prune();
  }

  /// Final prune — call once after all workers complete
  void finalize() => _prune();

  List<ScanResult> get results => List.unmodifiable(_results);

  void _prune() {
    _results.sort(_compareResults);
    if (_results.length > maxCapacity) {
      _results.removeRange(maxCapacity, _results.length);
    }
  }

  static int _compareResults(ScanResult a, ScanResult b) {
    if (a.tier.index != b.tier.index) return a.tier.index.compareTo(b.tier.index);
    final sa = a.score ?? 0.0;
    final sb = b.score ?? 0.0;
    if (sa != sb) return sb.compareTo(sa);
    return a.latencyMs.compareTo(b.latencyMs);
  }
}

// ─── Worker Isolate entry point ───────────────────────────────────────────────

Future<void> _workerMain(_WorkerConfig config) async {
  try {
    // Initialize GeoIP in this isolate from pre-loaded bytes
    if (config.geoipBytes != null) {
      try {
        GeoIPOffline().initWithBytes(config.geoipBytes!);
      } catch (_) {
        // GeoIP init failed — continue without geo data
      }
    }

    final results = <ScanResult>[];

    // ── Prefilter: fast TCP ─────────────────────────────────────────────────
    final fastProbe = FastProbeEngine(defaultTimeoutMs: 3000);
    final prefilterSem = Semaphore(config.prefilterConcurrency);

    final liveRaw = await Future.wait(config.ips.map((ip) async {
      await prefilterSem.acquire();
      try {
        final r = await fastProbe.probe(ip, timeoutMs: 3000);
        if (!r.alive) {
          try { SoftBlacklist().recordFailure(ip); } catch (_) {}
          try { SubnetMemoryCache().recordFailure(ip); } catch (_) {}
        }
        return r.alive ? ip : null;
      } catch (_) {
        return null;
      } finally {
        prefilterSem.release();
      }
    }));
    final liveIps = liveRaw.whereType<String>().toList();

    config.replyPort.send(_WorkerPrefilterDone(liveIps.length, config.ips.length));

    if (liveIps.isEmpty) {
      config.replyPort.send(_WorkerResult(
        results: [],
        workerIndex: -1,
        blacklistFails: {},
        subnetCache: {},
      ));
      config.replyPort.send(const _WorkerDone(-1));
      return;
    }

    // ── Full scan ───────────────────────────────────────────────────────────
    final adaptiveCtrl = AdaptiveConcurrencyController();
    adaptiveCtrl.seed(config.concurrency);
    final scanSem = Semaphore(config.concurrency);
    final total = liveIps.length;

    bool _localCancelled = false;
    int done = 0;
    final batch = <ScanResult>[];
    const batchSize = 5;

    await Future.wait(liveIps.map((ip) async {
      if (_localCancelled) return;
      await scanSem.acquire();
      try {
        if (_localCancelled) return;
        final r = await scanOneIp(
          ip,
          mode: config.mode,
          snis: config.deepSnis,
          normalSniOverride: config.normalSniOverride,
          isCfScan: config.isCfScan,
          isCancelled: () => _localCancelled,
        );
        results.add(r);
        done++;
        batch.add(r);
        if (batch.length >= batchSize) {
          config.replyPort.send(_WorkerBatch(List.from(batch), done, total));
          batch.clear();
        }
        if (r.isAlive) adaptiveCtrl.recordSuccess();
        else           adaptiveCtrl.recordError();
      } catch (_) {
        done++;
        final dead = ScanResult(
          ip: ip, latencyMs: 9999, jitterMs: 0, isAlive: false,
          grade: 'F', country: '', flag: '', loss: 100, reliability: 0,
          score: 0, survivalMs: 0, retransmits: 0,
          phase: ScanPhase.tlsFail, tier: IpTier.dead,
        );
        results.add(dead);
        batch.add(dead);
        if (batch.length >= batchSize) {
          config.replyPort.send(_WorkerBatch(List.from(batch), done, total));
          batch.clear();
        }
      } finally {
        scanSem.release();
      }
    }));

    // Flush remaining batch
    if (batch.isNotEmpty) {
      config.replyPort.send(_WorkerBatch(List.from(batch), done, total));
    }

    config.replyPort.send(_WorkerResult(
      results: results,
      workerIndex: -1,
      blacklistFails: {},
      subnetCache: {},
    ));
    config.replyPort.send(const _WorkerDone(-1));

  } catch (_) {
    // CRITICAL: Always send _WorkerResult + _WorkerDone so main isolate doesn't hang
    config.replyPort.send(_WorkerResult(
      results: [],
      workerIndex: -1,
      blacklistFails: {},
      subnetCache: {},
    ));
    config.replyPort.send(const _WorkerDone(-1));
  }
}

// ─── Main entry point ─────────────────────────────────────────────────────────

Future<List<ScanResult>> runIsolateScanEngine(
  List<String> ips, {
  ScanMode mode              = ScanMode.normal,
  List<String>? deepSnis,
  void Function(int done, int total, ScanResult result)? onProgress,
  void Function(int liveCount, int totalCount)? onPrefilterDone,
  bool Function()? isCancelled,
  String? normalSniOverride,
  bool isCfScan              = false,
}) async {
  final cancelCheck = isCancelled ?? () => false;
  final numIsolates = _maxIsolates;
  final concurrency = _isolateConcurrency;
  final prefilterConc = _isolatePrefilterConcurrency;

  // Load geoip bytes once — pass to all isolates
  Uint8List? geoBytes;
  try {
    final bd = await rootBundle.load('assets/geo/ipcountry.bin');
    geoBytes = bd.buffer.asUint8List();
  } catch (_) {}

  // ── Split IPs into chunks ─────────────────────────────────────────────────
  final chunkSize = (ips.length / numIsolates).ceil();
  final chunks = <List<String>>[];
  for (int i = 0; i < ips.length; i += chunkSize) {
    chunks.add(ips.sublist(i, min(i + chunkSize, ips.length)));
  }

  final totalIps = ips.length;
  int totalDone = 0;
  int totalLive = 0;
  int prefiltersDone = 0;
  bool prefilterReported = false;

  // NEW: Top-100 retention instead of unbounded allResults list
  final topResults = _TopNResults(maxCapacity: 100);

  final completer = Completer<void>();
  int workersRemaining = chunks.length;

  // NEW: Track isolate refs and ports for Isolate.kill() on cancel
  final isolateRefs = <Isolate>[];
  final receivePorts = <ReceivePort>[];

  // NEW: Cancel poll timer — checks every 300ms, kills all isolates immediately
  final cancelPoll = Timer.periodic(const Duration(milliseconds: 300), (_) {
    if (cancelCheck() && !completer.isCompleted) {
      for (final iso in isolateRefs) {
        try { iso.kill(priority: Isolate.immediate); } catch (_) {}
      }
      for (final port in receivePorts) {
        try { port.close(); } catch (_) {}
      }
      if (!completer.isCompleted) completer.complete();
    }
  });

  // ── Spawn one isolate per chunk ───────────────────────────────────────────
  for (int wi = 0; wi < chunks.length; wi++) {
    if (cancelCheck()) break;

    final receivePort = ReceivePort();
    receivePorts.add(receivePort);

    final config = _WorkerConfig(
      replyPort: receivePort.sendPort,
      ips: chunks[wi],
      mode: mode,
      deepSnis: deepSnis,
      normalSniOverride: normalSniOverride,
      isCfScan: isCfScan,
      concurrency: concurrency,
      prefilterConcurrency: prefilterConc,
      geoipBytes: geoBytes,
    );

    // Dedup guard: port close + workers counter, called at most once per worker
    bool workerFinished = false;
    void finishWorker() {
      if (workerFinished) return;
      workerFinished = true;
      try { receivePort.close(); } catch (_) {}
      workersRemaining--;
      if (workersRemaining <= 0 && !completer.isCompleted) {
        completer.complete();
      }
    }

    receivePort.listen((msg) {
      if (cancelCheck()) {
        finishWorker();
        return;
      }

      if (msg is _WorkerPrefilterDone) {
        totalLive += msg.liveCount;
        prefiltersDone++;
        if (!prefilterReported && prefiltersDone >= chunks.length) {
          prefilterReported = true;
          onPrefilterDone?.call(totalLive, totalIps);
        }
      } else if (msg is _WorkerBatch) {
        // NEW: Batch result streaming — accumulate into TopN, fire progress per result
        topResults.addAll(msg.results);
        totalDone += msg.results.length;
        if (onProgress != null && msg.results.isNotEmpty) {
          // Fire progress for the last result in the batch (most recent)
          onProgress(totalDone, totalLive > 0 ? totalLive : totalIps, msg.results.last);
        }
      } else if (msg is _WorkerDone) {
        // NEW: Worker signals completion — close port and decrement counter
        finishWorker();
      } else if (msg is _WorkerResult) {
        // Results already streamed via _WorkerBatch — no-op here
        // (kept for protocol completeness; results list in _WorkerResult is redundant)
      } else if (msg == null) {
        // null = isolate exited (onExit signal)
        finishWorker();
      } else if (msg is List) {
        // List = isolate uncaught error [errorString, stackTraceString]
        finishWorker();
      }
    }, onDone: () {
      finishWorker();
    });

    try {
      final iso = await Isolate.spawn(
        _workerMain,
        config,
        onError: receivePort.sendPort,
        onExit:  receivePort.sendPort,
      );
      isolateRefs.add(iso);
    } catch (_) {
      receivePort.close();
      workersRemaining--;
      if (workersRemaining <= 0 && !completer.isCompleted) completer.complete();
    }
  }

  if (!completer.isCompleted) await completer.future;

  // Stop the cancel poll timer
  cancelPoll.cancel();

  // Final prune + sort of top-100 results
  topResults.finalize();

  return topResults.results.toList();
}
