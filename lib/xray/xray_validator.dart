// Xray config validator — real xray-core when available, TLS fallback otherwise.

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'config_parser.dart';
import 'xray_process_runner.dart';
import '../services/xray_binary_service.dart';

export 'xray_process_runner.dart' show XrayRunResult;

class XrayValidationResult {
  final String ip;
  final int port;
  final bool success;
  final double latencyMs;
  final double throughputKBs;
  final String transport;
  final String error;
  final int retries;
  final bool usedRealXray;

  const XrayValidationResult({
    required this.ip,
    required this.port,
    required this.success,
    this.latencyMs = 0,
    this.throughputKBs = 0,
    this.transport = '',
    this.error = '',
    this.retries = 0,
    this.usedRealXray = false,
  });

  double get throughputMbps => (throughputKBs * 8) / 1024;

  factory XrayValidationResult.fromRun(XrayRunResult r, {bool usedRealXray = true}) {
    return XrayValidationResult(
      ip: r.ip,
      port: r.port,
      success: r.success,
      latencyMs: r.latencyMs,
      throughputKBs: r.throughputKBs,
      transport: r.transport,
      error: r.error,
      retries: r.retries,
      usedRealXray: usedRealXray,
    );
  }
}

const _defaultTimeoutMs = 15000;

Future<XrayValidationResult> validateConfig(
  XrayConfig cfg,
  String ip, {
  int timeoutMs = _defaultTimeoutMs,
}) async {
  if (await XrayBinaryService.instance.isAvailable()) {
    var res = await runXrayValidation(cfg, ip, timeoutMs: timeoutMs);
    if (!res.success) {
      await Future.delayed(const Duration(milliseconds: 500));
      final res2 = await runXrayValidation(cfg, ip, timeoutMs: timeoutMs);
      if (res2.success) {
        return XrayValidationResult.fromRun(
          XrayRunResult(
            ip: res2.ip,
            port: res2.port,
            success: true,
            latencyMs: res2.latencyMs,
            throughputKBs: res2.throughputKBs,
            transport: res2.transport,
            retries: 1,
          ),
        );
      }
      return XrayValidationResult.fromRun(
        XrayRunResult(
          ip: res.ip,
          port: res.port,
          success: false,
          error: res2.error.isNotEmpty ? res2.error : res.error,
          transport: res.transport,
          retries: 1,
        ),
      );
    }
    return XrayValidationResult.fromRun(res);
  }

  final swapped = cfg.withAddress(ip);
  var res = await _validateWithTls(swapped, timeoutMs: timeoutMs);
  if (!res.success) {
    await Future.delayed(const Duration(milliseconds: 500));
    final res2 = await _validateWithTls(swapped, timeoutMs: timeoutMs);
    if (res2.success) {
      return XrayValidationResult(
        ip: res2.ip,
        port: res2.port,
        success: true,
        latencyMs: res2.latencyMs,
        throughputKBs: res2.throughputKBs,
        transport: res2.transport,
        retries: 1,
        usedRealXray: false,
      );
    }
    return XrayValidationResult(
      ip: res.ip,
      port: res.port,
      success: false,
      transport: res.transport,
      error: res.error,
      retries: 1,
      usedRealXray: false,
    );
  }
  return res;
}

Future<XrayValidationResult> _validateWithTls(
  XrayConfig cfg, {
  int timeoutMs = _defaultTimeoutMs,
}) async {
  final sni = cfg.effectiveSni;
  final port = cfg.port;
  final sw = Stopwatch()..start();
  try {
    final sock = await Socket.connect(
      cfg.address,
      port,
      timeout: Duration(milliseconds: timeoutMs),
    );
    if (cfg.security == 'tls' || cfg.security == 'reality') {
      final tls = await SecureSocket.secure(
        sock,
        host: sni,
        onBadCertificate: (_) => cfg.insecure,
      ).timeout(Duration(milliseconds: timeoutMs));
      await tls.close();
      tls.destroy();
    } else {
      await sock.close();
      sock.destroy();
    }
    sw.stop();
    return XrayValidationResult(
      ip: cfg.address,
      port: port,
      success: true,
      latencyMs: sw.elapsedMilliseconds.toDouble(),
      transport: cfg.network,
      usedRealXray: false,
    );
  } catch (e) {
    sw.stop();
    return XrayValidationResult(
      ip: cfg.address,
      port: port,
      success: false,
      latencyMs: sw.elapsedMilliseconds.toDouble(),
      transport: cfg.network,
      error: e.toString(),
      usedRealXray: false,
    );
  }
}
