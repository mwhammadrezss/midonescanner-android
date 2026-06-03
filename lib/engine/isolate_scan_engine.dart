// lib/engine/isolate_scan_engine.dart
// ─── Multi-Isolate Parallel Scan Engine ──────────────────────────────────────

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

/// Process [items] in chunks to avoid OOM from huge Future.wait lists.
Future<void> _forEachBatched<T>(
  List<T> items,
  Future<void> Function(T item) fn, {
  int batchSize = 80,
  bool Function()? shouldStop,
}) async {
  for (var i = 0; i < items.length; i += batchSize) {
    if (shouldStop?.call() == true) return;
    final end = min(i + batchSize, items.length);
    await Future.wait(items.sublist(i, end).map(fn));
  }
}

class _WorkerConfig {
  final SendPort replyPort;
  final int workerIndex;
  final List<String> ips;
  final ScanMode mode;
  final List<String>? deepSnis;
  final String? normalSniOverride;
  final bool isCfScan;
  final int concurrency;
  final int prefilterConcurrency;
  final int tlsRepeats;
  final Uint8List? geoipBytes;

  const _WorkerConfig({
    required this.replyPort,
    required this.workerIndex,
    required this.ips,
    required this.mode,
    this.deepSnis,
    this.normalSniOverride,
    this.isCfScan = false,
    required this.concurrency,
    required this.prefilterConcurrency,
    this.tlsRepeats = 2,
    this.geoipBytes,
  });
}

class _WorkerReady {
  final SendPort cancelPort;
  final int workerIndex;
  const _WorkerReady(this.cancelPort, this.workerIndex);
}

class _WorkerPrefilterDone {
  final int liveCount;
  final int totalCount;
  final int workerIndex;
  const _WorkerPrefilterDone(this.liveCount, this.totalCount, this.workerIndex);
}

class _WorkerBatch {
  final List<ScanResult> results;
  final int workerDone;
  final int workerTotal;
  final int workerIndex;
  const _WorkerBatch(this.results, this.workerDone, this.workerTotal, this.workerIndex);
}

class _WorkerDone {
  final int workerIndex;
  const _WorkerDone(this.workerIndex);
}

class _WorkerResult {
  final List<ScanResult> results;
  final int workerIndex;
  const _WorkerResult({required this.results, required this.workerIndex});
}

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

Future<void> _workerMain(_WorkerConfig config) async {
  final _cancelPort = ReceivePort();
  bool _localCancelled = false;
  _cancelPort.listen((msg) {
    if (msg == 'cancel') _localCancelled = true;
  });
  config.replyPort.send(_WorkerReady(_cancelPort.sendPort, config.workerIndex));

  bool cancelled() => _localCancelled;

  try {
    if (config.geoipBytes != null) {
      try {
        GeoIPOffline().initWithBytes(config.geoipBytes!);
      } catch (_) {}
    }

    final results = <ScanResult>[];
    final fastProbe = FastProbeEngine(defaultTimeoutMs: 2000);
    final prefilterSem = Semaphore(config.prefilterConcurrency);
    final liveIps = <String>[];

    await _forEachBatched<String>(
      config.ips,
      (ip) async {
        if (cancelled()) return;
        await prefilterSem.acquire();
        try {
          if (cancelled()) return;
          final r = await fastProbe.probe(ip, timeoutMs: 2000);
          if (r.alive) {
            liveIps.add(ip);
          } else {
            try { SoftBlacklist().recordFailure(ip); } catch (_) {}
            try { SubnetMemoryCache().recordFailure(ip); } catch (_) {}
          }
        } catch (_) {
        } finally {
          prefilterSem.release();
        }
      },
      batchSize: 100,
      shouldStop: cancelled,
    );

    config.replyPort.send(
        _WorkerPrefilterDone(liveIps.length, config.ips.length, config.workerIndex));

    if (liveIps.isEmpty || cancelled()) {
      config.replyPort.send(
          _WorkerResult(results: results, workerIndex: config.workerIndex));
      config.replyPort.send(_WorkerDone(config.workerIndex));
      return;
    }

    final adaptiveCtrl = AdaptiveConcurrencyController();
    adaptiveCtrl.seed(config.concurrency);
    final scanSem = Semaphore(config.concurrency);
    final total = liveIps.length;
    int done = 0;
    final batch = <ScanResult>[];
    const batchSize = 5;

    Future<void> flushBatch() async {
      if (batch.isEmpty) return;
      config.replyPort.send(
          _WorkerBatch(List.from(batch), done, total, config.workerIndex));
      batch.clear();
    }

    await _forEachBatched<String>(
      liveIps,
      (ip) async {
        if (cancelled()) return;
        bool acquired = false;
        try {
          await scanSem.acquire();
          acquired = true;
          if (cancelled()) return;

          final r = await scanOneIp(
            ip,
            mode: config.mode,
            snis: config.deepSnis,
            normalSniOverride: config.normalSniOverride,
            isCfScan: config.isCfScan,
            isCancelled: cancelled,
            tlsRepeats: config.tlsRepeats,
          );
          results.add(r);
          done++;
          batch.add(r);
          if (batch.length >= batchSize) await flushBatch();
          if (r.isAlive) adaptiveCtrl.recordSuccess();
          else adaptiveCtrl.recordError();
        } catch (_) {
          done++;
          final dead = ScanResult(
            ip: ip,
            latencyMs: 9999,
            jitterMs: 0,
            isAlive: false,
            grade: 'F',
            country: '',
            flag: '',
            loss: 100,
            reliability: 0,
            score: 0,
            survivalMs: 0,
            retransmits: 0,
            phase: ScanPhase.tlsFail,
            tier: IpTier.dead,
          );
          results.add(dead);
          batch.add(dead);
          if (batch.length >= batchSize) await flushBatch();
        } finally {
          if (acquired) scanSem.release();
        }
      },
      batchSize: 50,
      shouldStop: cancelled,
    );

    await flushBatch();

    // Recovery path: if batches were lost, main can still merge full results
    if (results.isNotEmpty && done > 0) {
      config.replyPort.send(
          _WorkerResult(results: results, workerIndex: config.workerIndex));
    }
    config.replyPort.send(_WorkerDone(config.workerIndex));
  } catch (_) {
    config.replyPort.send(
        _WorkerResult(results: [], workerIndex: config.workerIndex));
    config.replyPort.send(_WorkerDone(config.workerIndex));
  } finally {
    _cancelPort.close();
  }
}

Future<List<ScanResult>> runIsolateScanEngine(
  List<String> ips, {
  ScanMode mode = ScanMode.normal,
  List<String>? deepSnis,
  void Function(int done, int total, ScanResult result)? onProgress,
  void Function(int liveCount, int totalCount)? onPrefilterDone,
  bool Function()? isCancelled,
  String? normalSniOverride,
  bool isCfScan = false,
  int tlsRepeats = 2,
}) async {
  if (ips.isEmpty) return [];

  final cancelCheck = isCancelled ?? () => false;
  final numIsolates = min(_maxIsolates, ips.length);
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
  final prefilterDoneWorkers = <int>{};
  bool prefilterReported = false;

  final topResults = _TopNResults(maxCapacity: 99999);
  final completer = Completer<void>();
  int workersRemaining = chunks.length;

  final isolateRefs = <Isolate>[];
  final receivePorts = <ReceivePort>[];
  final workerCancelPorts = <SendPort>[];
  bool cancelSignalSent = false;

  void tryReportPrefilter() {
    if (prefilterReported || prefilterDoneWorkers.length < chunks.length) return;
    prefilterReported = true;
    onPrefilterDone?.call(totalLive, totalIps);
  }

  final cancelPoll = Timer.periodic(const Duration(milliseconds: 300), (_) {
    if (!cancelCheck() || cancelSignalSent) return;
    cancelSignalSent = true;
    for (final port in workerCancelPorts) {
      try {
        port.send('cancel');
      } catch (_) {}
    }
    Future.delayed(const Duration(milliseconds: 2000), () {
      for (final iso in isolateRefs) {
        try {
          iso.kill(priority: Isolate.immediate);
        } catch (_) {}
      }
      for (final port in receivePorts) {
        try {
          port.close();
        } catch (_) {}
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
      workerIndex: wi,
      ips: chunks[wi],
      mode: mode,
      deepSnis: deepSnis,
      normalSniOverride: normalSniOverride,
      isCfScan: isCfScan,
      concurrency: concurrency,
      prefilterConcurrency: prefilterConc,
      tlsRepeats: tlsRepeats.clamp(1, 6),
      geoipBytes: geoBytes,
    );

    bool workerFinished = false;
    void finishWorker({bool countPrefilter = false}) {
      if (workerFinished) return;
      workerFinished = true;
      try {
        receivePort.close();
      } catch (_) {}
      workersRemaining--;
      if (countPrefilter && !prefilterDoneWorkers.contains(wi)) {
        prefilterDoneWorkers.add(wi);
        tryReportPrefilter();
      }
      if (workersRemaining <= 0 && !completer.isCompleted) completer.complete();
    }

    receivePort.listen((msg) {
      if (msg is _WorkerReady) {
        workerCancelPorts.add(msg.cancelPort);
        if (cancelSignalSent) {
          try {
            msg.cancelPort.send('cancel');
          } catch (_) {}
        }
        return;
      }

      if (msg is _WorkerPrefilterDone) {
        totalLive += msg.liveCount;
        prefilterDoneWorkers.add(msg.workerIndex);
        tryReportPrefilter();
      } else if (msg is _WorkerBatch) {
        topResults.addAll(msg.results);
        totalDone += msg.results.length;
        if (onProgress != null && msg.results.isNotEmpty) {
          onProgress(
            totalDone,
            totalLive > 0 ? totalLive : totalIps,
            msg.results.last,
          );
        }
      } else if (msg is _WorkerResult) {
        // Fallback when batch messages were dropped (e.g. isolate killed mid-flight)
        if (totalDone == 0 && msg.results.isNotEmpty) {
          topResults.addAll(msg.results);
          totalDone = msg.results.length;
          if (onProgress != null) {
            onProgress(
              totalDone,
              totalLive > 0 ? totalLive : totalIps,
              msg.results.last,
            );
          }
        }
      } else if (msg is _WorkerDone) {
        finishWorker(countPrefilter: true);
      } else if (msg == null) {
        finishWorker(countPrefilter: true);
      } else if (msg is List) {
        finishWorker(countPrefilter: true);
      }
    }, onDone: () {
      finishWorker(countPrefilter: true);
    });

    try {
      final iso = await Isolate.spawn(
        _workerMain,
        config,
        onError: receivePort.sendPort,
        onExit: receivePort.sendPort,
      );
      isolateRefs.add(iso);
    } catch (_) {
      receivePort.close();
      workersRemaining--;
      prefilterDoneWorkers.add(wi);
      tryReportPrefilter();
      if (workersRemaining <= 0 && !completer.isCompleted) completer.complete();
    }
  }

  if (!completer.isCompleted) await completer.future;

  cancelPoll.cancel();
  topResults.finalize();
  return topResults.results.toList();
}
