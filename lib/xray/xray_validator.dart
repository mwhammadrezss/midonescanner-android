// lib/xray/xray_validator.dart
// ─── Xray config validator ────────────────────────────────────────────────────
// Xray binary mode removed — uses TLS connectivity check only.

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'config_parser.dart';

/// Result of validating a single config against an IP.
class XrayValidationResult {
  final String ip;
  final int port;
  final bool success;
  final double latencyMs;
  final double throughputKBs;
  final String transport;
  final String error;
  final int retries;

  const XrayValidationResult({
    required this.ip,
    required this.port,
    required this.success,
    this.latencyMs = 0,
    this.throughputKBs = 0,
    this.transport = '',
    this.error = '',
    this.retries = 0,
  });

  @override
  String toString() =>
      'XrayValidationResult(ip=$ip, success=$success, latency=${latencyMs.toStringAsFixed(0)}ms, '
      'speed=${throughputKBs.toStringAsFixed(0)}KB/s, err=$error)';
}

const _defaultTimeoutMs = 15000;

/// Validates a config by swapping in [ip] as the endpoint address.
/// Uses TLS connectivity check (no xray binary required).
Future<XrayValidationResult> validateConfig(
  XrayConfig cfg,
  String ip, {
  int timeoutMs = _defaultTimeoutMs,
}) async {
  final swapped = cfg.withAddress(ip);
  XrayValidationResult res = await _validateWithTls(swapped, timeoutMs: timeoutMs);
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
      );
    }
    return XrayValidationResult(
      ip: res.ip,
      port: res.port,
      success: false,
      transport: res.transport,
      error: res.error,
      retries: 1,
    );
  }
  return res;
}

// ─── Lightweight TLS check (no xray binary) ──────────────────────────────────

Future<XrayValidationResult> _validateWithTls(
  XrayConfig cfg, {
  int timeoutMs = _defaultTimeoutMs,
}) async {
  Socket? rawSock;
  SecureSocket? tls;
  try {
    final start = DateTime.now();
    rawSock = await Socket.connect(
      cfg.address,
      cfg.port,
      timeout: Duration(milliseconds: timeoutMs ~/ 4),
    );
    tls = await SecureSocket.secure(
      rawSock,
      host: cfg.effectiveSni,
      onBadCertificate: (_) => true,
    ).timeout(Duration(milliseconds: timeoutMs ~/ 2));

    tls.write(
      'GET /cdn-cgi/trace HTTP/1.1\r\n'
      'Host: ${cfg.effectiveSni}\r\n'
      'User-Agent: MidONe/1.0\r\n'
      'Connection: close\r\n\r\n',
    );

    final buf = StringBuffer();
    final completer = Completer<void>();
    final sub = tls.listen(
      (chunk) {
        buf.write(utf8.decode(chunk, allowMalformed: true));
        if (buf.length > 2048 && !completer.isCompleted) completer.complete();
      },
      onDone: () { if (!completer.isCompleted) completer.complete(); },
      onError: (_) { if (!completer.isCompleted) completer.complete(); },
    );
    await completer.future
        .timeout(Duration(milliseconds: timeoutMs ~/ 4))
        .catchError((_) {});
    await sub.cancel();

    final latency = DateTime.now().difference(start).inMicroseconds / 1000.0;
    final body = buf.toString();
    final isCf = body.contains('colo=');

    return XrayValidationResult(
      ip: cfg.address,
      port: cfg.port,
      success: isCf,
      latencyMs: latency,
      transport: cfg.network,
      error: isCf ? '' : 'Not a CF edge or config mismatch',
    );
  } catch (e) {
    return XrayValidationResult(
      ip: cfg.address,
      port: cfg.port,
      success: false,
      transport: cfg.network,
      error: e.toString(),
    );
  } finally {
    try { tls?.destroy(); } catch (_) {}
    try { rawSock?.destroy(); } catch (_) {}
  }
}
