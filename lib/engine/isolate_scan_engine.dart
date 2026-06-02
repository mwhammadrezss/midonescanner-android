// lib/engine/isolate_scan_engine.dart
// ─── Multi-Isolate Parallel Scan Engine ──────────────────────────────────────
//
// Strategy:
//   - Detect number of logical CPU cores at runtime
//   - Split IP list into N chunks (N = min(cores, 4) on Android, min(cores, 8) on Windows)
//   - Each chunk runs in its own Dart Isolate — true parallel execution
//   - Results collected via _TopNResults (top-100 retention, sorted)
//   - Workers stream results in batches of 5 via _WorkerBatch
//   - Cooperative cancellation via _WorkerReady cancel port; Isolate.kill() as fallback
//
// Cancellation flow:
//   1. Main sends 'cancel' to each worker's cancelPort (cooperative)
//   2. Workers stop accepting new IPs immediately; active IPs finish normally
//   3. After 2 s grace period, Isolate.kill() fires for any still-running worker
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
  return min(_numCpuCores, 4);
}

int get _isolateConcurrency {
  if (Platform.isWindows || Platform.isLinux || Platform.isMacOS) return 32;
  return 20;
}

int get _isolatePrefilterConcurrency {
  if (Platform.isWindows || Platform.isLinux || Platform.isMacOS) return 120;
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

/// FIX #2: Worker sends this as its FIRST message — contains the SendPort
/// that main uses to deliver cooperative cancel signals.
class _WorkerReady {
  final SendPort cancelPort;
  const _WorkerReady(this.cancelPort);
}

class _WorkerPrefilterDone {
  final int liveCount;
  final int totalCount;
  const _WorkerPrefilterDone(this.liveCount, this.totalCount);
}

// Kept for backward compat — no longer sent by workers.
class _WorkerProgress {
  final int done;
  final int total;
  final ScanResult result;
  final int workerIndex;
  const _WorkerProgress(this.done, this.total, this.result, this.workerIndex);
}

class _WorkerBatch {
  final List<ScanResult> results;
  final int workerDone;
  final int workerTotal;
  const _WorkerBatch(this.results, this.workerDone, this.workerTotal);
}

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

// ─── Top-N result retention ───────────────────────────────────────────────────

class _TopNResults {
  final int maxCapacity;
  final List<ScanResult> _results = [];

  _TopNResults({this.maxCapacity = 100});

  void addAll(List<ScanResult> items) {
    for (final r in items) _results.add(r);
    if (_results.length > maxCapacity * 2) _prune();
  }

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
  // ── FIX #2: Cooperative cancellation setup ──────────────────────────────────
  // Create a local ReceivePort for cancel signals from main.
  // Send its SendPort to main immediately so main can cancel us without Isolate.kill().
  final _cancelPort = ReceivePort();
  bool _localCancelled = false;
  _cancelPort.listen((msg) {
    if (msg == 'cancel') _localCancelled = true;
  });
  config.replyPort.send(_WorkerReady(_cancelPort.sendPort));
  // ─────────────────────────────────────────────────────────────────────────────

  try {
    if (config.geoipBytes != null) {
      try {
        GeoIPOffline().initWithBytes(config.geoipBytes!);
      } catch (_) {}
    }

    final results = <ScanResult>[];

    // ── Prefilter: fast TCP ─────────────────────────────────────────────────
    final fastProbe = FastProbeEngine(defaultTimeoutMs: 2000);
    final prefilterSem = Semaphore(config.prefilterConcurrency);

    final liveRaw = await Future.wait(config.ips.map((ip) async {
      // FIX #2: check cancel before every new IP in prefilter too
      if (_localCancelled) return null;
      await prefilterSem.acquire();
      try {
        if (_localCancelled) return null;
        final r = await fastProbe.probe(ip, timeoutMs: 2000);
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
      config.replyPort.send(_WorkerResult(results: [], workerIndex: -1, blacklistFails: {}, subnetCache: {}));
      config.replyPort.send(const _WorkerDone(-1));
      return;
    }

    // ── Full scan ───────────────────────────────────────────────────────────
    final adaptiveCtrl = AdaptiveConcurrencyController();
    adaptiveCtrl.seed(config.concurrency);
    final scanSem = Semaphore(config.concurrency);
    final total = liveIps.length;

    int done = 0;
    final batch = <ScanResult>[];
    const batchSize = 5;

    await Future.wait(liveIps.map((ip) async {
      // FIX #2: check before acquiring semaphore
      if (_localCancelled) return;

      // FIX #1: _acquired flag so finally can safely release even if acquire() throws
      bool _acquired = false;
      try {
        await scanSem.acquire();
        _acquired = true;

        // FIX #2: check again after acquiring (may have been cancelled while waiting)
        if (_localCancelled) return;

        // FIX #1: scanOneIp() is fully isolated — any exception produces a dead result,
        //         never propagates to Future.wait(), never stops the worker.
        final r = await scanOneIp(
          ip,
          mode: config.mode,
          snis: config.deepSnis,
          normalSniOverride: config.normalSniOverride,
          isCfScan: config.isCfScan,
          isCancelled: () => _localCancelled,  // FIX #2: cooperative cancel inside scanOneIp
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
        // FIX #1: catch ANY exception (including scanOneIp crash, timeout, socket error)
        // Worker continues scanning remaining IPs — this IP just gets a dead result.
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
        // FIX #1: release only if we successfully acquired — avoids double-release
        if (_acquired) scanSem.release();
      }
    }));

    // Flush remaining batch
    if (batch.isNotEmpty) {
      config.replyPort.send(_WorkerBatch(List.from(batch), done, total));
    }

    config.replyPort.send(_WorkerResult(results: results, workerIndex: -1, blacklistFails: {}, subnetCache: {}));
    config.replyPort.send(const _WorkerDone(-1));

  } catch (_) {
    // Top-level safety net — always complete the protocol
    config.replyPort.send(_WorkerResult(results: [], workerIndex: -1, blacklistFails: {}, subnetCache: {}));
    config.replyPort.send(const _WorkerDone(-1));
  } finally {
    // FIX #2: always close cancel port to free resources
    _cancelPort.close();
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

  Uint8List? geoBytes;
  try {
    final bd = await rootBundle.load('assets/geo/ipcountry.bin');
    geoBytes = bd.buffer.asUint8List();
  } catch (_) {}

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

  final topResults = _TopNResults(maxCapacity: 9999); // FIX: was 100 — caused 0 results on large scans
  final completer = Completer<void>();
  int workersRemaining = chunks.length;

  final isolateRefs   = <Isolate>[];
  final receivePorts  = <ReceivePort>[];
  // FIX #2: collect each worker's cancel SendPort for cooperative signalling
  final workerCancelPorts = <SendPort>[];
  bool _cancelSignalSent = false;

  // FIX #2: Two-phase cancellation
  //   Phase 1 (immediate): send 'cancel' to every worker → they stop starting new IPs
  //                         and pass isCancelled=true into active scanOneIp calls
  //   Phase 2 (2 s later): Isolate.kill() for any worker that hasn't finished yet
  //   This replaces the old single-phase Isolate.kill() approach.
  final cancelPoll = Timer.periodic(const Duration(milliseconds: 300), (_) {
    if (!cancelCheck() || _cancelSignalSent) return;
    _cancelSignalSent = true;

    // Phase 1: cooperative signal
    for (final port in workerCancelPorts) {
      try { port.send('cancel'); } catch (_) {}
    }

    // Phase 2: force kill after 2 s grace period
    Future.delayed(const Duration(milliseconds: 2000), () {
      for (final iso in isolateRefs) {
        try { iso.kill(priority: Isolate.immediate); } catch (_) {}
      }
      for (final port in receivePorts) {
        try { port.close(); } catch (_) {}
      }
      if (!completer.isCompleted) completer.complete();
    });
  });

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

    bool workerFinished = false;
    void finishWorker() {
      if (workerFinished) return;
      workerFinished = true;
      try { receivePort.close(); } catch (_) {}
      workersRemaining--;
      // FIX: if this worker crashed before sending _WorkerPrefilterDone,
      // increment prefiltersDone here so we don't wait forever
      if (prefiltersDone < chunks.length) {
        prefiltersDone++;
        if (!prefilterReported && prefiltersDone >= chunks.length) {
          prefilterReported = true;
          onPrefilterDone?.call(totalLive, totalIps);
        }
      }
      if (workersRemaining <= 0 && !completer.isCompleted) completer.complete();
    }

    receivePort.listen((msg) {
      // FIX #2: _WorkerReady is the first message — collect cancel port
      if (msg is _WorkerReady) {
        workerCancelPorts.add(msg.cancelPort);
        // If cancel was already requested before this worker was ready, signal it now
        if (_cancelSignalSent) {
          try { msg.cancelPort.send('cancel'); } catch (_) {}
        }
        return;
      }

      if (msg is _WorkerPrefilterDone) {
        totalLive += msg.liveCount;
        prefiltersDone++;
        // FIX: fire onPrefilterDone after ALL isolates report (or immediately if
        // we already have data and a later isolate finishes last). Previously this
        // gate could deadlock if one isolate crashed before sending _WorkerPrefilterDone,
        // meaning prefiltersDone never reached chunks.length and _total stayed at
        // the raw IP count — causing progress % to be wrong and UI to show stale state.
        if (!prefilterReported && prefiltersDone >= chunks.length) {
          prefilterReported = true;
          onPrefilterDone?.call(totalLive, totalIps);
        } else if (!prefilterReported && totalLive > 0 && prefiltersDone >= 1) {
          // Partial report: at least one isolate done — update UI with what we have
          // so progress bar doesn't freeze. Will be overwritten when all done.
          onPrefilterDone?.call(totalLive, totalIps);
        }
      } else if (msg is _WorkerBatch) {
        topResults.addAll(msg.results);
        totalDone += msg.results.length;
        if (onProgress != null && msg.results.isNotEmpty) {
          onProgress(totalDone, totalLive > 0 ? totalLive : totalIps, msg.results.last);
        }
      } else if (msg is _WorkerDone) {
        finishWorker();
      } else if (msg is _WorkerResult) {
        // no-op: data already received via _WorkerBatch
      } else if (msg == null) {
        // null = isolate onExit signal
        finishWorker();
      } else if (msg is List) {
        // List = isolate uncaught error
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

  cancelPoll.cancel();
  topResults.finalize();
  return topResults.results.toList();
}
