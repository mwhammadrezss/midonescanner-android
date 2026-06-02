// lib/engine/range/deep_scan_bridge.dart
// Bridge from range scan candidates into the full TLS/tunnel scanner

import 'dart:async';
import '../scanner_engine.dart';
import '../../models/scan_result.dart';
import '../concurrency_engine.dart';

class DeepScanBridge {
  /// Full scan of a single IP
  Future<ScanResult> scanFull(String ip, {bool deepMode = false, bool isCfScan = false}) {
    return scanOneIp(
      ip,
      mode: deepMode ? ScanMode.deep : ScanMode.normal,
      isCfScan: isCfScan,
    );
  }

  /// Scan a batch of IPs with concurrency control
  Future<List<ScanResult>> scanBatch(
    List<String> ips, {
    bool deepMode = false,
    int concurrency = 4,
    bool isCfScan = false,
    bool Function()? isCancelled,
    void Function(ScanResult)? onResult,
  }) async {
    final results = <ScanResult>[];
    final sem = Semaphore(concurrency.clamp(1, 24));
    final cancelCheck = isCancelled ?? () => false;

    await Future.wait(ips.map((ip) async {
      if (cancelCheck()) return;
      await sem.acquire();
      try {
        if (cancelCheck()) return;
        final r = await scanOneIp(
          ip,
          mode: deepMode ? ScanMode.deep : ScanMode.normal,
          isCfScan: isCfScan,
        );
        results.add(r);
        onResult?.call(r);
      } finally {
        sem.release();
      }
    }));

    return results;
  }
}
