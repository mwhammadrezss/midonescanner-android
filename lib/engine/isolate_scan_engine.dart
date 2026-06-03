// lib/engine/isolate_scan_engine.dart
// ─── Multi-Isolate Parallel Scan Engine ──────────────────────────────────────
//
// Large IP lists: batched prefilter + scan to avoid socket exhaustion (was:
// Future.wait over entire chunk → mass false "dead" on prefilter, 0 full scans).

import 'dart:async';
import 'dart:io';
import 'dart:isolate';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter/services.dart' show rootBundle;

import '../models/scan_result.dart';
import '../geo/geoip.dart';
import 'scanner_engine.dart';
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

/// Fewer isolates on large lists → less aggregate socket pressure.
int _isolatesForIpCount(int totalIps) {
  final cap = _maxIsolates;
  if (totalIps <= 32) return min(cap, max(1, totalIps));
  if (totalIps <= 256) return min(cap, 4);
  if (totalIps <= 2000) return min(cap, 4);
  return min(cap, 2);
}

/// Per-isolate prefilter slots so total ≈ [_globalPrefilterCap].
int _globalPrefilterCap = 64;

int _prefilterConcurrencyFor(int totalIps, int numIsolates) {
  _globalPrefilterCap = totalIps > 500
      ? (Platform.isAndroid ? 48 : 96)
      : (Platform.isAndroid ? 64 : 128);
  return max(4, (_globalPrefilterCap / numIsolates).ceil());
}

int _scanConcurrencyFor(int totalIps, int numIsolates) {
  final base = _isolateConcurrency;
  if (totalIps <= 64) return base;
  if (totalIps <= 500) return min(base, 24);
  return min(base, max(8, base ~/ 2));
}

const int _prefilterTimeoutMs = 3000;
const int _prefilterBatchSize = 48;
const int _scanBatchSize = 32;

// ─── Message types (Isolate ↔ Main) ──────────────────────────────────────────

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
    this.geoipBytes,
  });
}

class _WorkerReady {
  final SendPort cancelPort;
  const _WorkerReady(this.cancelPort);
}

class _WorkerPrefilterDone {
  final int workerIndex;
  final int liveCount;
  final int totalCount;
  const _WorkerPrefilterDone(this.workerIndex, this.liveCount, this.totalCount);
}

class _WorkerPrefilterProgress {
  final int workerIndex;
  final int done;
  final int total;
  const _WorkerPrefilterProgress(this.workerIndex, this.done, this.total);
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
  const _WorkerResult({required this.results, required this.workerIndex});
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

// ─── Batched prefilter (TCP :443) ─────────────────────────────────────────────

Future<List<String>> _batchedPrefilter({
  required List<String> ips,
  required FastProbeEngine fastProbe,
  required Semaphore sem,
  required bool Function() isCancelled,
  required void Function(int done, int total)? onBatchProgress,
}) async {
  final live = <String>[];
  for (int i = 0; i < ips.length; i += _prefilterBatchSize) {
    if (isCancelled()) break;
    final batch = ips.sublist(i, min(i + _prefilterBatchSize, ips.length));
    final batchLive = await Future.wait(batch.map((ip) async {
      if (isCancelled()) return null;
      await sem.acquire();
      try {
        if (isCancelled()) return null;
        final r = await fastProbe.probe(ip, timeoutMs: _prefilterTimeoutMs);
        // Do NOT SoftBlacklist / SubnetMemoryCache on TCP-only prefilter —
        // failures are often socket pressure, not the IP being dead.
        return r.alive ? ip : null;
      } catch (_) {
        return null;
      } finally {
        sem.release();
      }
    }));
    live.addAll(batchLive.whereType<String>());
    onBatchProgress?.call(min(i + batch.length, ips.length), ips.length);
    if (ips.length > 128 && i + _prefilterBatchSize < ips.length) {
      await Future.delayed(const Duration(milliseconds: 25));
    }
  }
  return live;
}

// ─── Worker Isolate entry point ───────────────────────────────────────────────

Future<void> _workerMain(_WorkerConfig config) async {
  final _cancelPort = ReceivePort();
  bool _localCancelled = false;
  _cancelPort.listen((msg) {
    if (msg == 'cancel') _localCancelled = true;
  });
  config.replyPort.send(_WorkerReady(_cancelPort.sendPort));

  bool cancelled() => _localCancelled;

  try {
    if (config.geoipBytes != null) {
      try {
        GeoIPOffline().initWithBytes(config.geoipBytes!);
      } catch (_) {}
    }

    final results = <ScanResult>[];

    final fastProbe = FastProbeEngine(defaultTimeoutMs: _prefilterTimeoutMs);
    final prefilterSem = Semaphore(config.prefilterConcurrency);

    final liveIps = await _batchedPrefilter(
      ips: config.ips,
      fastProbe: fastProbe,
      sem: prefilterSem,
      isCancelled: cancelled,
      onBatchProgress: (done, total) {
        config.replyPort.send(
          _WorkerPrefilterProgress(config.workerIndex, done, total),
        );
      },
    );

    config.replyPort.send(
      _WorkerPrefilterDone(config.workerIndex, liveIps.length, config.ips.length),
    );

    if (liveIps.isEmpty) {
      config.replyPort.send(
        _WorkerResult(results: [], workerIndex: config.workerIndex),
      );
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

    for (int i = 0; i < liveIps.length; i += _scanBatchSize) {
      if (cancelled()) break;
      final ipBatch = liveIps.sublist(i, min(i + _scanBatchSize, liveIps.length));

      await Future.wait(ipBatch.map((ip) async {
        if (cancelled()) return;

        bool acquired = false;
        try {
          await scanSem.acquire();
          acquired = true;
          if (cancelled()) return;

          ScanResult r;
          try {
            r = await scanOneIp(
              ip,
              mode: config.mode,
              snis: config.deepSnis,
              normalSniOverride: config.normalSniOverride,
              isCfScan: config.isCfScan,
              isCancelled: cancelled,
            );
          } catch (_) {
            r = ScanResult(
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
          }

          results.add(r);
          done++;
          batch.add(r);
          if (batch.length >= batchSize) {
            config.replyPort.send(_WorkerBatch(List.from(batch), done, total));
            batch.clear();
          }
          if (r.isAlive) {
            adaptiveCtrl.recordSuccess();
          } else {
            adaptiveCtrl.recordError();
          }
        } finally {
          if (acquired) scanSem.release();
        }
      }));

      if (liveIps.length > 64 && i + _scanBatchSize < liveIps.length) {
        await Future.delayed(const Duration(milliseconds: 30));
      }
    }

    if (batch.isNotEmpty) {
      config.replyPort.send(_WorkerBatch(List.from(batch), done, total));
    }

    config.replyPort.send(
      _WorkerResult(results: results, workerIndex: config.workerIndex),
    );
    config.replyPort.send(_WorkerDone(config.workerIndex));
  } catch (_) {
    config.replyPort.send(
      _WorkerResult(results: [], workerIndex: config.workerIndex),
    );
    config.replyPort.send(_WorkerDone(config.workerIndex));
  } finally {
    _cancelPort.close();
  }
}

// ─── Main entry point ─────────────────────────────────────────────────────────

Future<List<ScanResult>> runIsolateScanEngine(
  List<String> ips, {
  ScanMode mode = ScanMode.normal,
  List<String>? deepSnis,
  void Function(int done, int total, ScanResult result)? onProgress,
  void Function(int liveCount, int totalCount)? onPrefilterDone,
  void Function(int done, int total)? onPrefilterProgress,
  bool Function()? isCancelled,
  String? normalSniOverride,
  bool isCfScan = false,
}) async {
  if (ips.isEmpty) return [];

  Uint8List? geoBytes;
  try {
    final bd = await rootBundle.load('assets/geo/ipcountry.bin');
    geoBytes = bd.buffer.asUint8List();
  } catch (_) {}

  final cancelCheck = isCancelled ?? () => false;
  final numIsolates = _isolatesForIpCount(ips.length);
  final concurrency = _scanConcurrencyFor(ips.length, numIsolates);
  final prefilterConc = _prefilterConcurrencyFor(ips.length, numIsolates);

  final chunkSize = (ips.length / numIsolates).ceil();
  final chunks = <List<String>>[];
  for (int i = 0; i < ips.length; i += chunkSize) {
    chunks.add(ips.sublist(i, min(i + chunkSize, ips.length)));
  }

  final totalIps = ips.length;
  int totalDone = 0;
  int totalLive = 0;
  final prefilterProgressByWorker = <int, int>{};
  final workersPrefilterReported = <int>{};

  final topResults = _TopNResults(maxCapacity: min(20000, ips.length + 500));
  final completer = Completer<void>();
  int workersRemaining = chunks.length;

  final isolateRefs = <Isolate>[];
  final receivePorts = <ReceivePort>[];
  final workerCancelPorts = <SendPort>[];
  bool _cancelSignalSent = false;

  final cancelPoll = Timer.periodic(const Duration(milliseconds: 300), (_) {
    if (!cancelCheck() || _cancelSignalSent) return;
    _cancelSignalSent = true;

    for (final port in workerCancelPorts) {
      try {
        port.send('cancel');
      } catch (_) {}
    }

    Future.delayed(const Duration(seconds: 5), () {
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

  bool prefilterReported = false;
  void maybeReportPrefilterDone() {
    if (prefilterReported) return;
    if (workersPrefilterReported.length < chunks.length) return;
    prefilterReported = true;
    onPrefilterDone?.call(totalLive, totalIps);
  }

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
      geoipBytes: geoBytes,
    );

    bool workerFinished = false;
    void finishWorker(int workerIndex) {
      if (workerFinished) return;
      workerFinished = true;
      try {
        receivePort.close();
      } catch (_) {}

      if (!workersPrefilterReported.contains(workerIndex)) {
        workersPrefilterReported.add(workerIndex);
        maybeReportPrefilterDone();
      }

      workersRemaining--;
      if (workersRemaining <= 0 && !completer.isCompleted) completer.complete();
    }

    receivePort.listen((msg) {
      if (msg is _WorkerReady) {
        workerCancelPorts.add(msg.cancelPort);
        if (_cancelSignalSent) {
          try {
            msg.cancelPort.send('cancel');
          } catch (_) {}
        }
        return;
      }

      if (msg is _WorkerPrefilterProgress) {
        prefilterProgressByWorker[msg.workerIndex] = msg.done;
        final sum = prefilterProgressByWorker.values.fold<int>(0, (a, b) => a + b);
        onPrefilterProgress?.call(min(sum, totalIps), totalIps);
        return;
      }

      if (msg is _WorkerPrefilterDone) {
        totalLive += msg.liveCount;
        if (workersPrefilterReported.add(msg.workerIndex)) {
          maybeReportPrefilterDone();
        }
      } else if (msg is _WorkerBatch) {
        topResults.addAll(msg.results);
        if (msg.results.isNotEmpty) {
          // FIX(denom-race): only use totalLive after ALL prefilter counts are in.
          // If first batch arrives before _WorkerPrefilterDone, totalLive is
          // partial (could be 0). Sending 0 as denom makes main.dart skip the
          // _total update safely until onPrefilterDone sets the real value.
          final denom = prefilterReported ? totalLive : 0;
          for (final r in msg.results) {
            totalDone++;
            onProgress?.call(totalDone, denom, r);
          }
        }
      } else if (msg is _WorkerDone) {
        finishWorker(msg.workerIndex);
      } else if (msg is _WorkerResult) {
        if (msg.results.isNotEmpty) {
          topResults.addAll(msg.results);
        }
      } else if (msg == null) {
        finishWorker(wi);
      } else if (msg is List) {
        finishWorker(wi);
      }
    }, onDone: () {
      finishWorker(wi);
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
      finishWorker(wi);
    }
  }

  if (!completer.isCompleted) await completer.future;

  cancelPoll.cancel();
  topResults.finalize();
  return topResults.results.toList();
}
