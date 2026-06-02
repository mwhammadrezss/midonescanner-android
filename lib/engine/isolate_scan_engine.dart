// lib/engine/isolate_scan_engine.dart
// ─── Multi-Isolate Parallel Scan Engine v2 ───────────────────────────────────
//
// Architecture (refactored):
//   1. Unified Prefilter Phase — FastProbe runs on ALL IPs in main isolate
//      before spawning workers. Gives accurate onPrefilterDone count.
//   2. Worker Isolates — only receive live (pre-filtered) IPs.
//   3. Result Streaming — workers send results in batches of 5 (backpressure).
//   4. True STOP — main isolate keeps Isolate refs and calls .kill() on cancel.
//   5. Top-N Retention — main isolate keeps only top 100 results in memory.
//   6. Dynamic Concurrency — mobile-safe limits based on CPU cores.

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
  return min(_numCpuCores, 4);
}

/// Dynamic prefilter concurrency — mobile-safe
int get _prefilterConcurrency => min(20, _numCpuCores * 5);

/// Dynamic per-isolate scan concurrency — mobile-safe
int get _workerScanConcurrency => min(16, _numCpuCores * 4);

// ─── Message types (Isolate ↔ Main) ──────────────────────────────────────────

class _WorkerConfig {
  final SendPort replyPort;
  final List<String> ips;
  final ScanMode mode;
  final List<String>? deepSnis;
  final String? normalSniOverride;
  final bool isCfScan;
  final int concurrency;
  final Uint8List? geoipBytes;

  const _WorkerConfig({
    required this.replyPort,
    required this.ips,
    required this.mode,
    this.deepSnis,
    this.normalSniOverride,
    this.isCfScan = false,
    required this.concurrency,
    this.geoipBytes,
  });
}

/// Streamed batch of results from worker → main
class _WorkerBatch {
  final List<ScanResult> results;
  final int workerDone; // cumulative done count for this worker
  final int workerTotal; // total IPs assigned to this worker
  const _WorkerBatch(this.results, this.workerDone, this.workerTotal);
}

/// Sent when worker finishes all its work
class _WorkerDone {
  final int workerIndex;
  const _WorkerDone(this.workerIndex);
}

// ─── Worker Isolate entry point ───────────────────────────────────────────────

Future<void> _workerMain(_WorkerConfig config) async {
  // Initialize GeoIP in this isolate
  if (config.geoipBytes != null) {
    GeoIPOffline().initWithBytes(config.geoipBytes!);
  }

  final total = config.ips.length;
  if (total == 0) {
    config.replyPort.send(const _WorkerDone(-1));
    return;
  }

  // ── Full scan with streaming results ──────────────────────────────────────
  final adaptiveCtrl = AdaptiveConcurrencyController();
  adaptiveCtrl.seed(config.concurrency);
  final scanSem = Semaphore(config.concurrency);

  int done = 0;
  final batch = <ScanResult>[];
  const batchSize = 5; // backpressure: send every 5 results

  await Future.wait(config.ips.map((ip) async {
    await scanSem.acquire();
    try {
      final r = await scanOneIp(
        ip,
        mode: config.mode,
        snis: config.deepSnis,
        normalSniOverride: config.normalSniOverride,
        isCfScan: config.isCfScan,
      );
      done++;
      batch.add(r);

      if (r.isAlive) adaptiveCtrl.recordSuccess();
      else           adaptiveCtrl.recordError();

      // Stream batch when full
      if (batch.length >= batchSize) {
        config.replyPort.send(_WorkerBatch(List.from(batch), done, total));
        batch.clear();
      }
    } finally {
      scanSem.release();
    }
  }));

  // Flush remaining results
  if (batch.isNotEmpty) {
    config.replyPort.send(_WorkerBatch(List.from(batch), done, total));
    batch.clear();
  }

  config.replyPort.send(const _WorkerDone(-1));
}

// ─── Top-N result manager ─────────────────────────────────────────────────────

class _TopNResults {
  final int maxCapacity;
  final List<ScanResult> _results = [];

  _TopNResults({this.maxCapacity = 100});

  List<ScanResult> get results => _results;
  int get length => _results.length;

  void addAll(List<ScanResult> items) {
    for (final r in items) {
      _results.add(r);
    }
    // Only prune if significantly over capacity
    if (_results.length > maxCapacity * 2) {
      _prune();
    }
  }

  void finalize() => _prune();

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

// ─── Main entry point ─────────────────────────────────────────────────────────

/// Run scan using multiple Dart Isolates for true parallelism.
/// Prefilter runs in main isolate for accurate counts; workers only scan live IPs.
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

  // Load geoip bytes once — pass to all isolates
  Uint8List? geoBytes;
  try {
    final bd = await rootBundle.load('assets/geo/ipcountry.bin');
    geoBytes = bd.buffer.asUint8List();
  } catch (_) {}

  // ══════════════════════════════════════════════════════════════════════════
  // PHASE 1: Unified Prefilter (runs in main isolate for accurate counting)
  // ══════════════════════════════════════════════════════════════════════════

  final fastProbe = FastProbeEngine(defaultTimeoutMs: 3000);
  final prefilterSem = Semaphore(_prefilterConcurrency);
  final totalOriginal = ips.length;

  final liveIpResults = await Future.wait(ips.map((ip) async {
    if (cancelCheck()) return null;
    await prefilterSem.acquire();
    try {
      if (cancelCheck()) return null;
      final r = await fastProbe.probe(ip, timeoutMs: 3000);
      if (!r.alive) {
        SoftBlacklist().recordFailure(ip);
        SubnetMemoryCache().recordFailure(ip);
      }
      return r.alive ? ip : null;
    } finally {
      prefilterSem.release();
    }
  }));

  final liveIps = liveIpResults.whereType<String>().toList();

  // Report prefilter results — single, accurate callback
  onPrefilterDone?.call(liveIps.length, totalOriginal);

  if (liveIps.isEmpty || cancelCheck()) {
    return [];
  }

  // ══════════════════════════════════════════════════════════════════════════
  // PHASE 2: Spawn worker isolates with only live IPs
  // ══════════════════════════════════════════════════════════════════════════

  final numIsolates = min(_maxIsolates, liveIps.length); // don't spawn more than IPs
  final concurrency = _workerScanConcurrency;

  // Split live IPs into chunks
  final chunkSize = (liveIps.length / numIsolates).ceil();
  final chunks = <List<String>>[];
  for (int i = 0; i < liveIps.length; i += chunkSize) {
    chunks.add(liveIps.sublist(i, min(i + chunkSize, liveIps.length)));
  }

  final totalLive = liveIps.length;
  int totalDone = 0;
  int workersRemaining = chunks.length;

  // Top-N result accumulator (memory-safe)
  final topResults = _TopNResults(maxCapacity: 100);

  // Track isolate refs for true STOP
  final isolateRefs = <Isolate>[];
  final receivePorts = <ReceivePort>[];

  final completer = Completer<void>();

  // Send initial progress event (0%)
  if (totalLive > 0 && onProgress != null) {
    final startResult = ScanResult(
      ip: liveIps.first, latencyMs: 0, jitterMs: 0, isAlive: false,
      grade: '-', country: '', flag: '', loss: 0, reliability: 0,
      score: null, survivalMs: null, retransmits: 0,
      phase: ScanPhase.tlsFail, tier: IpTier.dead, dpiSuspicion: 0,
    );
    onProgress(0, totalLive, startResult);
  }

  // ── Spawn isolates ────────────────────────────────────────────────────────
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
      geoipBytes: geoBytes,
    );

    receivePort.listen((msg) {
      if (cancelCheck()) return; // Don't process if cancelled

      if (msg is _WorkerBatch) {
        // Stream results into top-N accumulator
        topResults.addAll(msg.results);
        totalDone += msg.results.length;

        // Report progress for each result in batch
        if (onProgress != null && msg.results.isNotEmpty) {
          onProgress(totalDone, totalLive, msg.results.last);
        }
      } else if (msg is _WorkerDone) {
        workersRemaining--;
        receivePort.close();
        if (workersRemaining <= 0 && !completer.isCompleted) {
          completer.complete();
        }
      }
    });

    try {
      final iso = await Isolate.spawn(_workerMain, config);
      isolateRefs.add(iso);
    } catch (e) {
      receivePort.close();
      workersRemaining--;
      if (workersRemaining <= 0 && !completer.isCompleted) {
        completer.complete();
      }
    }
  }

  // ── Wait for completion or cancellation ───────────────────────────────────
  if (!completer.isCompleted) {
    // Poll for cancellation while waiting
    final cancelPoll = Timer.periodic(const Duration(milliseconds: 300), (_) {
      if (cancelCheck() && !completer.isCompleted) {
        // TRUE STOP: kill all worker isolates immediately
        for (final iso in isolateRefs) {
          iso.kill(priority: Isolate.immediate);
        }
        for (final port in receivePorts) {
          port.close();
        }
        if (!completer.isCompleted) completer.complete();
      }
    });

    await completer.future;
    cancelPoll.cancel();
  }

  // ── Finalize: sort and return top results ─────────────────────────────────
  topResults.finalize();
  return topResults.results;
}
