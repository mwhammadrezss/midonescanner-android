// Runs embedded xray-core and validates config through SOCKS (SenPai runner.go).

import 'dart:async';
import 'dart:io';

import 'config_parser.dart';
import 'socks_http.dart';
import 'xray_config_builder.dart';
import '../services/xray_binary_service.dart';

int _nextSocksPort = 20000;
int _allocPort() {
  _nextSocksPort++;
  if (_nextSocksPort > 60000) _nextSocksPort = 20001;
  return _nextSocksPort;
}

Future<bool> _waitForPort(int port, Duration timeout) async {
  final end = DateTime.now().add(timeout);
  while (DateTime.now().isBefore(end)) {
    try {
      final s = await Socket.connect('127.0.0.1', port,
          timeout: const Duration(milliseconds: 200));
      await s.close();
      s.destroy();
      return true;
    } catch (_) {
      await Future.delayed(const Duration(milliseconds: 100));
    }
  }
  return false;
}

Future<Process?> _startXray(String binary, String configPath) async {
  try {
    return await Process.start(
      binary,
      ['run', '-c', configPath],
      mode: ProcessStartMode.normal,
      runInShell: false,
    );
  } catch (_) {
    return null;
  }
}

/// SenPai-style validation: xray instance + trace + speed through SOCKS.
Future<XrayRunResult> runXrayValidation(
  XrayConfig cfg,
  String ip, {
  int timeoutMs = 15000,
}) async {
  final binary = await XrayBinaryService.instance.getPath();
  if (binary == null) {
    return XrayRunResult(
      ip: ip,
      port: cfg.port,
      success: false,
      error: 'xray binary not found — bundle assets/xray or place xray.exe beside app',
      transport: cfg.network,
    );
  }

  final swapped = cfg.withAddress(ip);
  final socksPort = _allocPort();
  final configJson = buildXrayConfigJson(swapped, socksPort);

  final tmp = await Directory.systemTemp.createTemp('midone-xray-');
  final configFile = File('${tmp.path}${Platform.pathSeparator}config.json');
  await configFile.writeAsString(configJson);

  Process? proc;
  try {
    proc = await _startXray(binary, configFile.path);
    if (proc == null) {
      return XrayRunResult(
        ip: ip,
        port: cfg.port,
        success: false,
        error: 'failed to start xray process',
        transport: cfg.network,
      );
    }

    if (!await _waitForPort(socksPort, const Duration(seconds: 3))) {
      return XrayRunResult(
        ip: ip,
        port: cfg.port,
        success: false,
        error: 'socks port not ready',
        transport: cfg.network,
      );
    }

    final timeout = Duration(milliseconds: timeoutMs);
    final trace = await socksHttpGet(
      '127.0.0.1',
      socksPort,
      Uri.parse('https://cp.cloudflare.com/cdn-cgi/trace'),
      timeout: timeout,
    );

    if (!trace.ok) {
      return XrayRunResult(
        ip: ip,
        port: cfg.port,
        success: false,
        latencyMs: trace.latencyMs,
        error: trace.error ?? 'connectivity failed',
        transport: cfg.network,
      );
    }

    double throughputBps = 0;
    final speedUrl =
        'https://speed.cloudflare.com/__down?bytes=${128 * 1024}';
    final dl = await socksHttpDownload(
      '127.0.0.1',
      socksPort,
      speedUrl,
      maxBytes: 128 * 1024,
      timeout: Duration(
        milliseconds: (timeoutMs ~/ 2).clamp(8000, 30000),
      ),
    );
    throughputBps = dl.bps;

    return XrayRunResult(
      ip: ip,
      port: cfg.port,
      success: true,
      latencyMs: trace.latencyMs,
      throughputKBs: throughputBps / 1024,
      transport: cfg.network,
    );
  } finally {
    try {
      proc?.kill(ProcessSignal.sigterm);
    } catch (_) {}
    try {
      await tmp.delete(recursive: true);
    } catch (_) {}
  }
}

class XrayRunResult {
  final String ip;
  final int port;
  final bool success;
  final double latencyMs;
  final double throughputKBs;
  final String transport;
  final String error;
  final int retries;

  const XrayRunResult({
    required this.ip,
    required this.port,
    required this.success,
    this.latencyMs = 0,
    this.throughputKBs = 0,
    this.transport = '',
    this.error = '',
    this.retries = 0,
  });

  double get throughputMbps => (throughputKBs * 8) / 1024;
}
