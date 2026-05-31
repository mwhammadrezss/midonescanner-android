// lib/xray/xray_validator.dart
// ─── Xray config validator ────────────────────────────────────────────────────
// Mirrors SenPaiScanner internal/xraytest/runner.go — adapted for Dart/Flutter.
//
// Since xray-core cannot be embedded in Flutter as a Go library,
// this validates a config by:
//   1. Running `xray` binary (if present on device) via Process.run
//   2. Routing an HTTP request through the SOCKS5 proxy it creates
//   3. Checking /cdn-cgi/trace response contains "colo="
//
// On Android, xray binary is bundled in the app's native libraries or
// downloaded to app's filesDir and executed from there.
//
// Fallback: If no xray binary, performs a lightweight TLS probe
// (same as CF tab scanner — confirms the IP works as CF edge).

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'package:path_provider/path_provider.dart';

import 'config_parser.dart';

/// Result of validating a single config against an IP.
class XrayValidationResult {
  final String ip;
  final int port;
  final bool success;
  final double latencyMs;   // time-to-first-byte in ms
  final double throughputKBs; // download speed in KB/s; 0 if not measured
  final String transport;   // ws, grpc, xhttp, tcp
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

/// Validates a config by swapping in [ip] as the endpoint address,
/// then running a connectivity + speed test.
///
/// [timeoutMs] controls the total budget per test attempt.
Future<XrayValidationResult> validateConfig(
  XrayConfig cfg,
  String ip, {
  int timeoutMs = _defaultTimeoutMs,
}) async {
  final swapped = cfg.withAddress(ip);
  XrayValidationResult res = await _validateOnce(swapped, timeoutMs: timeoutMs);
  if (!res.success) {
    // Single retry — DPI is flaky (mirrors SenPai)
    await Future.delayed(const Duration(milliseconds: 500));
    final res2 = await _validateOnce(swapped, timeoutMs: timeoutMs);
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

Future<XrayValidationResult> _validateOnce(
  XrayConfig cfg, {
  int timeoutMs = _defaultTimeoutMs,
}) async {
  // Try xray binary first; fall back to lightweight TLS probe
  final xrayBin = await _findXrayBinary();
  if (xrayBin != null) {
    return _validateWithXray(cfg, xrayBin, timeoutMs: timeoutMs);
  }
  // Fallback: direct TLS connectivity check (no xray binary)
  return _validateWithTls(cfg, timeoutMs: timeoutMs);
}

// ─── Xray binary path detection ───────────────────────────────────────────────

Future<String?> _findXrayBinary() async {
  // Check common locations
  final candidates = <String>[];

  if (Platform.isAndroid) {
    try {
      final dir = await getApplicationSupportDirectory();
      candidates.add('${dir.path}/xray');
      candidates.add('${dir.path}/xray-core');
    } catch (_) {}
    try {
      final dir = await getApplicationDocumentsDirectory();
      candidates.add('${dir.path}/xray');
    } catch (_) {}
    // Native lib dir (if bundled as .so and renamed)
    candidates.add('/data/app/xray');
  } else if (Platform.isLinux || Platform.isMacOS) {
    candidates.addAll(['/usr/local/bin/xray', '/usr/bin/xray', '/opt/xray/xray']);
  } else if (Platform.isWindows) {
    // PRIMARY: xray.exe bundled next to midone_scanner.exe (shipped in ZIP)
    try {
      final exeDir = File(Platform.resolvedExecutable).parent.path;
      candidates.add('$exeDir\\xray.exe');
      candidates.add('$exeDir\\xray-core.exe');
    } catch (_) {}
    // FALLBACK: well-known install locations
    candidates.addAll([
      r'C:\Program Files\xray\xray.exe',
      r'C:\xray\xray.exe',
    ]);
  }

  for (final path in candidates) {
    if (File(path).existsSync()) return path;
  }
  return null;
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// Expose the private [_findXrayBinary] as a public API.
Future<String?> findXrayBinary() => _findXrayBinary();

// ─── Xray binary validation ───────────────────────────────────────────────────

Future<XrayValidationResult> _validateWithXray(
  XrayConfig cfg,
  String xrayBin, {
  int timeoutMs = _defaultTimeoutMs,
}) async {
  final socksPort = 20000 + Random().nextInt(10000);
  final configJson = _buildXrayConfigJson(cfg, socksPort);

  // Write config to temp file
  Directory? tmpDir;
  File? tmpFile;
  Process? xrayProcess;

  try {
    tmpDir = await Directory.systemTemp.createTemp('xray_');
    tmpFile = File('${tmpDir.path}/config.json');
    await tmpFile.writeAsString(configJson);

    // Start xray
    xrayProcess = await Process.start(
      xrayBin,
      ['run', '-c', tmpFile.path],
      environment: {'XRAY_LOCATION_ASSET': tmpDir.path},
    );

    // Wait for SOCKS port to be ready
    final portReady = await _waitForPort('127.0.0.1', socksPort,
        timeout: const Duration(seconds: 5));
    if (!portReady) {
      return XrayValidationResult(
        ip: cfg.address,
        port: cfg.port,
        success: false,
        transport: cfg.network,
        error: 'SOCKS port not ready after 5s',
      );
    }

    // Connectivity check via SOCKS5
    final start = DateTime.now();
    final connectResult = await _socks5ConnectivityCheck(
      socksPort,
      timeout: Duration(milliseconds: timeoutMs),
    );
    final latency = DateTime.now().difference(start).inMicroseconds / 1000.0;

    if (!connectResult.success) {
      return XrayValidationResult(
        ip: cfg.address,
        port: cfg.port,
        success: false,
        transport: cfg.network,
        error: connectResult.error,
      );
    }

    // Speed test (best-effort)
    double throughput = 0;
    try {
      throughput = await _measureSocks5Speed(
        socksPort,
        timeout: Duration(milliseconds: (timeoutMs / 2).round()),
      );
    } catch (_) {}

    return XrayValidationResult(
      ip: cfg.address,
      port: cfg.port,
      success: true,
      latencyMs: latency,
      throughputKBs: throughput,
      transport: cfg.network,
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
    xrayProcess?.kill();
    try { tmpFile?.deleteSync(); } catch (_) {}
    try { tmpDir?.deleteSync(recursive: true); } catch (_) {}
  }
}

// ─── Lightweight TLS fallback (no xray binary) ───────────────────────────────

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

    // HTTP GET /cdn-cgi/trace to confirm CF edge
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

// ─── SOCKS5 helpers ──────────────────────────────────────────────────────────

class _ConnResult {
  final bool success;
  final String error;
  const _ConnResult({required this.success, this.error = ''});
}

Future<_ConnResult> _socks5ConnectivityCheck(
  int socksPort, {
  required Duration timeout,
}) async {
  Socket? sock;
  try {
    sock = await Socket.connect('127.0.0.1', socksPort, timeout: timeout);
    // SOCKS5 handshake — no auth
    sock.add([0x05, 0x01, 0x00]);
    await sock.flush();

    final buf = <int>[];
    final completer = Completer<void>();
    final sub = sock.listen(
      (d) {
        buf.addAll(d);
        if (buf.length >= 2 && !completer.isCompleted) completer.complete();
      },
      onDone: () { if (!completer.isCompleted) completer.complete(); },
      onError: (_) { if (!completer.isCompleted) completer.complete(); },
    );
    await completer.future.timeout(const Duration(seconds: 3)).catchError((_) {});
    await sub.cancel();

    if (buf.length < 2 || buf[0] != 0x05 || buf[1] == 0xFF) {
      return const _ConnResult(success: false, error: 'SOCKS5 handshake failed');
    }
    return const _ConnResult(success: true);
  } catch (e) {
    return _ConnResult(success: false, error: e.toString());
  } finally {
    try { sock?.destroy(); } catch (_) {}
  }
}

Future<double> _measureSocks5Speed(int socksPort, {required Duration timeout}) async {
  // Route HTTP GET through SOCKS5 proxy to measure real download speed in KB/s
  Socket? sock;
  try {
    sock = await Socket.connect('127.0.0.1', socksPort, timeout: timeout);
    sock.setOption(SocketOption.tcpNoDelay, true);

    // ── SOCKS5 handshake (no auth) ────────────────────────────────────────
    sock.add([0x05, 0x01, 0x00]);
    await sock.flush();

    // Read server choice
    final handshakeBuf = <int>[];
    final handshakeCompleter = Completer<void>();
    final handshakeSub = sock.listen(
      (d) {
        handshakeBuf.addAll(d);
        if (handshakeBuf.length >= 2 && !handshakeCompleter.isCompleted) {
          handshakeCompleter.complete();
        }
      },
      onDone: () { if (!handshakeCompleter.isCompleted) handshakeCompleter.complete(); },
      onError: (_) { if (!handshakeCompleter.isCompleted) handshakeCompleter.complete(); },
      cancelOnError: true,
    );
    await handshakeCompleter.future
        .timeout(const Duration(seconds: 3))
        .catchError((_) {});
    await handshakeSub.cancel();

    if (handshakeBuf.length < 2 || handshakeBuf[0] != 0x05 || handshakeBuf[1] == 0xFF) {
      return 0.0;
    }

    // ── SOCKS5 CONNECT to speed.cloudflare.com:80 ────────────────────────
    const host = 'speed.cloudflare.com';
    final hostBytes = utf8.encode(host);
    final connectCmd = <int>[
      0x05, 0x01, 0x00,       // VER, CMD=CONNECT, RSV
      0x03,                   // ATYP=domain
      hostBytes.length,       // domain length
      ...hostBytes,           // domain
      0x00, 0x50,             // port 80 (big-endian)
    ];
    sock.add(connectCmd);
    await sock.flush();

    // Read CONNECT response (at least 10 bytes)
    final connectBuf = <int>[];
    final connectCompleter = Completer<void>();
    final connectSub = sock.listen(
      (d) {
        connectBuf.addAll(d);
        if (connectBuf.length >= 10 && !connectCompleter.isCompleted) {
          connectCompleter.complete();
        }
      },
      onDone: () { if (!connectCompleter.isCompleted) connectCompleter.complete(); },
      onError: (_) { if (!connectCompleter.isCompleted) connectCompleter.complete(); },
      cancelOnError: true,
    );
    await connectCompleter.future
        .timeout(const Duration(seconds: 5))
        .catchError((_) {});
    await connectSub.cancel();

    if (connectBuf.length < 2 || connectBuf[1] != 0x00) {
      return 0.0; // CONNECT rejected
    }

    // ── HTTP GET ~100KB ───────────────────────────────────────────────────
    const httpReq =
        'GET /__down?bytes=102400 HTTP/1.1\r\n'
        'Host: speed.cloudflare.com\r\n'
        'User-Agent: MidONe/1.0\r\n'
        'Connection: close\r\n\r\n';
    sock.add(utf8.encode(httpReq));
    await sock.flush();

    // Read until ~100KB downloaded or timeout
    int bytesRead = 0;
    bool headersDone = false;
    final startTime = DateTime.now();
    final downloadCompleter = Completer<void>();
    final downloadSub = sock.listen(
      (d) {
        if (!headersDone) {
          // Skip past HTTP headers
          final chunk = utf8.decode(d, allowMalformed: true);
          final sep = chunk.indexOf('\r\n\r\n');
          if (sep >= 0) {
            headersDone = true;
            bytesRead += d.length - (sep + 4);
          }
        } else {
          bytesRead += d.length;
        }
        if (bytesRead >= 102400 && !downloadCompleter.isCompleted) {
          downloadCompleter.complete();
        }
      },
      onDone: () { if (!downloadCompleter.isCompleted) downloadCompleter.complete(); },
      onError: (_) { if (!downloadCompleter.isCompleted) downloadCompleter.complete(); },
      cancelOnError: true,
    );
    await downloadCompleter.future.timeout(timeout).catchError((_) {});
    await downloadSub.cancel();

    final elapsed = DateTime.now().difference(startTime).inMicroseconds / 1e6;
    if (elapsed <= 0 || bytesRead <= 0) return 0.0;
    return bytesRead / 1024.0 / elapsed; // KB/s
  } catch (_) {
    return 0.0;
  } finally {
    try { sock?.destroy(); } catch (_) {}
  }
}

Future<bool> _waitForPort(String host, int port, {required Duration timeout}) async {
  final deadline = DateTime.now().add(timeout);
  while (DateTime.now().isBefore(deadline)) {
    try {
      final sock = await Socket.connect(host, port,
          timeout: const Duration(milliseconds: 200));
      sock.destroy();
      return true;
    } catch (_) {
      await Future.delayed(const Duration(milliseconds: 100));
    }
  }
  return false;
}

// ─── Xray config JSON builder ─────────────────────────────────────────────────

String _buildXrayConfigJson(XrayConfig cfg, int socksPort) {
  final config = {
    'log': {'loglevel': 'none', 'access': '', 'error': ''},
    'dns': {
      'servers': ['1.1.1.1', '8.8.8.8']
    },
    'inbounds': [
      {
        'tag': 'socks-in',
        'port': socksPort,
        'listen': '127.0.0.1',
        'protocol': 'socks',
        'sniffing': {
          'enabled': true,
          'destOverride': ['http', 'tls'],
        },
        'settings': {'udp': true},
      }
    ],
    'outbounds': [
      _buildOutbound(cfg),
      {'tag': 'direct', 'protocol': 'freedom', 'settings': {}},
    ],
  };

  const encoder = JsonEncoder.withIndent('  ');
  return encoder.convert(config);
}

Map<String, dynamic> _buildOutbound(XrayConfig cfg) {
  if (cfg.protocol == 'trojan') return _buildTrojanOutbound(cfg);
  return _buildVlessOutbound(cfg);
}

Map<String, dynamic> _buildVlessOutbound(XrayConfig cfg) {
  final user = <String, dynamic>{
    'id': cfg.uuid,
    'encryption': cfg.encryption,
  };
  if (cfg.flow.isNotEmpty) user['flow'] = cfg.flow;

  return {
    'tag': 'proxy',
    'protocol': 'vless',
    'settings': {
      'vnext': [
        {
          'address': cfg.address,
          'port': cfg.port,
          'users': [user],
        }
      ]
    },
    'streamSettings': _buildStreamSettings(cfg),
  };
}

Map<String, dynamic> _buildTrojanOutbound(XrayConfig cfg) {
  return {
    'tag': 'proxy',
    'protocol': 'trojan',
    'settings': {
      'servers': [
        {'address': cfg.address, 'port': cfg.port, 'password': cfg.password}
      ]
    },
    'streamSettings': _buildStreamSettings(cfg),
  };
}

Map<String, dynamic> _buildStreamSettings(XrayConfig cfg) {
  final stream = <String, dynamic>{
    'network': cfg.network,
    'security': cfg.security,
  };

  if (cfg.security == 'tls') {
    final tls = <String, dynamic>{};
    if (cfg.sni.isNotEmpty) tls['serverName'] = cfg.sni;
    if (cfg.fingerprint.isNotEmpty) tls['fingerprint'] = cfg.fingerprint;
    if (cfg.insecure) tls['allowInsecure'] = true;
    if (cfg.alpn.isNotEmpty) tls['alpn'] = cfg.alpn;
    stream['tlsSettings'] = tls;
  }

  switch (cfg.network) {
    case 'ws':
      final ws = <String, dynamic>{'path': cfg.path};
      if (cfg.host.isNotEmpty) ws['headers'] = {'Host': cfg.host};
      stream['wsSettings'] = ws;
      break;
    case 'grpc':
      final grpc = <String, dynamic>{'serviceName': cfg.serviceName};
      if (cfg.authority.isNotEmpty) grpc['authority'] = cfg.authority;
      if (cfg.mode == 'multi') grpc['multiMode'] = true;
      stream['grpcSettings'] = grpc;
      break;
    case 'xhttp':
    case 'splithttp':
      final xhttp = <String, dynamic>{'path': cfg.path};
      if (cfg.host.isNotEmpty) xhttp['headers'] = {'Host': cfg.host};
      if (cfg.mode.isNotEmpty) xhttp['mode'] = cfg.mode;
      stream['xhttpSettings'] = xhttp;
      break;
  }

  return stream;
}
