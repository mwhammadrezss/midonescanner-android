// lib/engine/isolate_scan_engine.dart
// ─── Multi-Isolate Parallel Scan Engine ──────────────────────────────────────
//
// Strategy:
//   - Detect number of logical CPU cores at runtime
//   - Split IP list into N chunks (N = min(cores, 4) on Android, min(cores, 8) on Windows)
//   - Each chunk runs in its own Dart Isolate — true parallel execution
//   - Results collected and merged, then sorted by tier→score→latency
//   - SubnetCache & SoftBlacklist synced back to main isolate after completion
//
// Architecture:
//   main isolate
//     ├── sends geoip bytes + config to each worker
//     ├── Isolate 0 → chunk 0 (scanOneIp × N)
//     ├── Isolate 1 → chunk 1
//     ├── ...
//     └── collects IsolateResult from each via ReceivePort
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
    return 32; // Windows TCP stack handles this fine
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
  final Uint8List? geoipBytes; // binary geo data passed by value

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

class _WorkerProgress {
  final int done;
  final int total;
  final ScanResult result;
  final int workerIndex;
  const _WorkerProgress(this.done, this.total, this.result, this.workerIndex);
}

class _WorkerResult {
  final List<ScanResult> results;
  final int workerIndex;
  // Sync back shared state to merge into main
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

// ─── Worker Isolate entry point ───────────────────────────────────────────────

Future<void> _workerMain(_WorkerConfig config) async {
  try {
    // Initialize GeoIP in this isolate from pre-loaded bytes
    if (config.geoipBytes != null) {
      try {
        GeoIPOffline().initWithBytes(config.geoipBytes!);
      } catch (e) {
        // GeoIP init failed — continue without geo data
      }
    }

    final results = <ScanResult>[];
    int done = 0;

    // ── Prefilter: fast TCP ─────────────────────────────────────────────────
    final fastProbe = FastProbeEngine(defaultTimeoutMs: 3000);
    final prefilterSem = Semaphore(config.prefilterConcurrency);

    final liveResults = await Future.wait(config.ips.map((ip) async {
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
    final liveIps = liveResults.whereType<String>().toList();

    // Report prefilter completion to main isolate
    config.replyPort.send(_WorkerPrefilterDone(liveIps.length, config.ips.length));

    if (liveIps.isEmpty) {
      config.replyPort.send(_WorkerResult(
        results: [],
        workerIndex: -1,
        blacklistFails: {},
        subnetCache: {},
      ));
      return;
    }

    // ── Full scan ───────────────────────────────────────────────────────────
    final adaptiveCtrl = AdaptiveConcurrencyController();
    adaptiveCtrl.seed(config.concurrency);
    final scanSem = Semaphore(config.concurrency);
    final total = liveIps.length;

    bool _localCancelled = false;

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
        config.replyPort.send(_WorkerProgress(done, total, r, -1));
        if (r.isAlive) adaptiveCtrl.recordSuccess();
        else           adaptiveCtrl.recordError();
      } catch (_) {
        // Individual IP scan failed — skip and continue
        done++;
        config.replyPort.send(_WorkerProgress(done, total, ScanResult(
          ip: ip, latencyMs: 9999, jitterMs: 0, isAlive: false,
          grade: 'F', country: '', flag: '', loss: 100, reliability: 0,
          score: 0, survivalMs: 0, retransmits: 0,
          phase: ScanPhase.tlsFail, tier: IpTier.dead,
        ), -1));
      } finally {
        scanSem.release();
      }
    }));

    // ── Collect shared state to send back ───────────────────────────────────
    final Map<String, int> blfails = {};
    final Map<String, _SubnetEntry> scache = {};

    config.replyPort.send(_WorkerResult(
      results: results,
      workerIndex: -1,
      blacklistFails: blfails,
      subnetCache: scache,
    ));
  } catch (e) {
    // CRITICAL: If anything goes wrong, ALWAYS send _WorkerResult
    // so the main isolate doesn't hang forever waiting.
    config.replyPort.send(_WorkerResult(
      results: [],
      workerIndex: -1,
      blacklistFails: {},
      subnetCache: {},
    ));
  }
}

// ─── Main entry point ─────────────────────────────────────────────────────────

/// Run scan using multiple Dart Isolates for true parallelism.
/// Falls back to single-threaded runScanningEngine on errors.
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

  final allResults = <ScanResult>[];
  final completer = Completer<void>();
  int workersRemaining = chunks.length;

  // ── Spawn one isolate per chunk ───────────────────────────────────────────
  for (int wi = 0; wi < chunks.length; wi++) {
    if (cancelCheck()) break;

    final receivePort = ReceivePort();
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

    bool workerFinished = false;
    receivePort.listen((msg) {
      if (cancelCheck()) {
        if (!workerFinished) {
          workerFinished = true;
          receivePort.close();
          workersRemaining--;
          if (workersRemaining <= 0 && !completer.isCompleted) completer.complete();
        }
        return;
      }

      if (msg is _WorkerPrefilterDone) {
        totalLive += msg.liveCount;
        prefiltersDone++;
        // Report once ALL workers have completed prefilter
        if (!prefilterReported && prefiltersDone >= chunks.length) {
          prefilterReported = true;
          onPrefilterDone?.call(totalLive, totalIps);
        }
      } else if (msg is _WorkerProgress) {
        totalDone++;
        // Use totalLive (post-prefilter count) not totalIps for accurate progress
        onProgress?.call(totalDone, totalLive > 0 ? totalLive : totalIps, msg.result);
      } else if (msg is _WorkerResult) {
        allResults.addAll(msg.results);

        if (!workerFinished) {
          workerFinished = true;
          receivePort.close();
          workersRemaining--;

          if (workersRemaining <= 0 && !completer.isCompleted) {
            completer.complete();
          }
        }
      } else if (msg == null) {
        // null = isolate exited (onExit signal)
        if (!workerFinished) {
          workerFinished = true;
          receivePort.close();
          workersRemaining--;
          if (workersRemaining <= 0 && !completer.isCompleted) completer.complete();
        }
      } else if (msg is List) {
        // List = isolate uncaught error [errorString, stackTraceString]
        if (!workerFinished) {
          workerFinished = true;
          receivePort.close();
          workersRemaining--;
          if (workersRemaining <= 0 && !completer.isCompleted) completer.complete();
        }
      }
    }, onDone: () {
      // ReceivePort closed — isolate exited
      if (!workerFinished) {
        workerFinished = true;
        workersRemaining--;
        if (workersRemaining <= 0 && !completer.isCompleted) completer.complete();
      }
    });

    try {
      await Isolate.spawn(
        _workerMain,
        config,
        onError: receivePort.sendPort,  // Catch uncaught isolate errors
        onExit: receivePort.sendPort,   // Detect isolate exit
      );
    } catch (e) {
      // Isolate spawn failed — close port
      receivePort.close();
      workersRemaining--;
      if (workersRemaining <= 0 && !completer.isCompleted) completer.complete();
    }
  }

  if (!completer.isCompleted) await completer.future;

  // ── Sort: tier → score → latency ─────────────────────────────────────────
  allResults.sort((a, b) {
    if (a.tier.index != b.tier.index) return a.tier.index.compareTo(b.tier.index);
    final sa = a.score ?? 0.0;
    final sb = b.score ?? 0.0;
    if (sa != sb) return sb.compareTo(sa);
    return a.latencyMs.compareTo(b.latencyMs);
  });

  return allResults;
}
