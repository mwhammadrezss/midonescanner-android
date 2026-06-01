// lib/xray/xray_validator.dart
// ─── Xray config validator ────────────────────────────────────────────────────
// Mirrors SenPaiScanner internal/xraytest/runner.go — adapted for Dart/Flutter.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'package:path_provider/path_provider.dart';

import 'config_parser.dart';
import 'xray_android_bootstrap.dart';

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
Future<XrayValidationResult> validateConfig(
  XrayConfig cfg,
  String ip, {
  int timeoutMs = _defaultTimeoutMs,
}) async {
  final swapped = cfg.withAddress(ip);
  XrayValidationResult res = await _validateOnce(swapped, originalCfg: cfg, timeoutMs: timeoutMs);
  if (!res.success) {
    await Future.delayed(const Duration(milliseconds: 500));
    final res2 = await _validateOnce(swapped, originalCfg: cfg, timeoutMs: timeoutMs);
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
  XrayConfig? originalCfg,
  int timeoutMs = _defaultTimeoutMs,
}) async {
  final xrayBin = await _findXrayBinary();
  if (xrayBin != null) {
    return _validateWithXray(cfg, xrayBin, speedTestCfg: originalCfg, timeoutMs: timeoutMs);
  }
  return _validateWithTls(cfg, timeoutMs: timeoutMs);
}

// ─── Xray binary path detection ───────────────────────────────────────────────

Future<String?> _findXrayBinary() async {
  final candidates = <String>[];

  if (Platform.isAndroid) {
    // Try bootstrap first — auto-extracts binary from assets if needed
    try {
      final bootstrapped = await XrayAndroidBootstrap.getXrayPath();
      if (bootstrapped != null) return bootstrapped;
    } catch (_) {}

    try {
      final dir = await getApplicationSupportDirectory();
      candidates.add('${dir.path}/xray');
      candidates.add('${dir.path}/xray-core');
    } catch (_) {}
    try {
      final dir = await getApplicationDocumentsDirectory();
      candidates.add('${dir.path}/xray');
    } catch (_) {}
    candidates.add('/data/app/xray');
  } else if (Platform.isLinux || Platform.isMacOS) {
    candidates.addAll(['/usr/local/bin/xray', '/usr/bin/xray', '/opt/xray/xray']);
  } else if (Platform.isWindows) {
    try {
      final exeDir = File(Platform.resolvedExecutable).parent.path;
      candidates.add('$exeDir\\xray.exe');
      candidates.add('$exeDir\\xray-core.exe');
    } catch (_) {}
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

Future<String?> findXrayBinary() => _findXrayBinary();

// ─── Xray binary validation ───────────────────────────────────────────────────

Future<XrayValidationResult> _validateWithXray(
  XrayConfig cfg,
  String xrayBin, {
  XrayConfig? speedTestCfg,
  int timeoutMs = _defaultTimeoutMs,
}) async {
  final socksPort = 20000 + Random().nextInt(10000);
  final configJson = _buildXrayConfigJson(cfg, socksPort);

  Directory? tmpDir;
  File? tmpFile;
  Process? xrayProcess;
  StringBuffer? stderrBuf;

  try {
    tmpDir = await Directory.systemTemp.createTemp('xray_');
    tmpFile = File('${tmpDir.path}/config.json');
    await tmpFile.writeAsString(configJson);

    // Get geo assets dir (geoip.dat + geosite.dat extracted from APK)
    final geoDir = (await XrayAndroidBootstrap.getAssetDir()) ?? tmpDir.path;

    xrayProcess = await Process.start(
      xrayBin,
      ['run', '-c', tmpFile.path],
      environment: {'XRAY_LOCATION_ASSET': geoDir},
    );

    // Capture stderr from xray process for diagnostics
    stderrBuf = StringBuffer();
    xrayProcess.stderr
        .transform(const SystemEncoding().decoder)
        .listen((s) { stderrBuf.write(s); });

    final portReady = await _waitForPort('127.0.0.1', socksPort,
        timeout: const Duration(seconds: 5));
    if (!portReady) {
      // Give stderr a moment to buffer
      await Future.delayed(const Duration(milliseconds: 200));
      final stderrMsg = stderrBuf.toString().trim();
      final errDetail = stderrMsg.isNotEmpty
          ? 'SOCKS port not ready after 5s\nXray stderr: $stderrMsg'
          : 'SOCKS port not ready after 5s';
      return XrayValidationResult(
        ip: cfg.address,
        port: cfg.port,
        success: false,
        transport: cfg.network,
        error: errDetail,
      );
    }

    // Connectivity check via SOCKS5 — full tunnel through xray
    final start = DateTime.now();
    final connectResult = await _socks5ConnectivityCheck(
      socksPort,
      timeout: Duration(milliseconds: timeoutMs),
    );
    final latency = connectResult.latencyMs > 0
        ? connectResult.latencyMs
        : DateTime.now().difference(start).inMicroseconds / 1000.0;

    if (!connectResult.success) {
      return XrayValidationResult(
        ip: cfg.address,
        port: cfg.port,
        success: false,
        transport: cfg.network,
        error: connectResult.error,
      );
    }

    // Speed test (best-effort), use speedTestCfg for host/path strategy
    double throughput = 0;
    try {
      throughput = await _measureSocks5Speed(
        socksPort,
        timeout: Duration(milliseconds: (timeoutMs / 2).round()),
        cfg: speedTestCfg,
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
    // Include any xray stderr in the error message for diagnostics
    await Future.delayed(const Duration(milliseconds: 100));
    final stderrMsg = stderrBuf?.toString().trim() ?? '';
    final errMsg = stderrMsg.isNotEmpty
        ? '${e.toString()}\nXray stderr: $stderrMsg'
        : e.toString();
    return XrayValidationResult(
      ip: cfg.address,
      port: cfg.port,
      success: false,
      transport: cfg.network,
      error: errMsg,
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
  final double latencyMs;
  const _ConnResult({required this.success, this.error = '', this.latencyMs = 0});
}

// Helper: read exactly [count] bytes from a socket with timeout
Future<List<int>?> _readBytes(Socket sock, int count, Duration timeout) async {
  final buf = <int>[];
  final completer = Completer<void>();
  StreamSubscription? sub;
  sub = sock.listen(
    (data) {
      buf.addAll(data);
      if (buf.length >= count && !completer.isCompleted) completer.complete();
    },
    onDone: () { if (!completer.isCompleted) completer.complete(); },
    onError: (_) { if (!completer.isCompleted) completer.complete(); },
    cancelOnError: true,
  );
  try {
    await completer.future.timeout(timeout);
  } catch (_) {}
  await sub.cancel();
  return buf.length >= count ? buf.sublist(0, count) : null;
}

// SOCKS5 CONNECT tunnel to cp.cloudflare.com:443, then TLS, then GET /cdn-cgi/trace
// Verify body contains "colo=" — proves real traffic flowed through xray
//
// FIX: Do NOT use _readBytes() here — it calls sock.listen() internally which
// marks the stream as "already listened to", causing SecureSocket.secure() to
// throw "Bad state: Stream has already been listened to".
// Instead: use a single StreamController to buffer all incoming bytes,
// then read from that buffer synchronously after SecureSocket.secure().
Future<_ConnResult> _socks5ConnectivityCheck(int socksPort, {required Duration timeout}) async {
  Socket? sock;
  SecureSocket? tls;
  StreamSubscription? sub;
  try {
    // 1. Connect to SOCKS5 proxy
    sock = await Socket.connect('127.0.0.1', socksPort,
        timeout: const Duration(seconds: 5));

    // Buffer all bytes from sock into a list — ONE listener only
    final rxBuf = <int>[];
    final rxCompleter = Completer<void>();
    sock.listen(
      (data) {
        rxBuf.addAll(data);
        if (!rxCompleter.isCompleted) rxCompleter.complete();
      },
      onDone: () { if (!rxCompleter.isCompleted) rxCompleter.complete(); },
      onError: (_) { if (!rxCompleter.isCompleted) rxCompleter.complete(); },
      cancelOnError: false,
    );

    // Helper: wait until rxBuf has at least [n] bytes
    Future<bool> waitBytes(int n, Duration tout) async {
      final deadline = DateTime.now().add(tout);
      while (rxBuf.length < n) {
        if (DateTime.now().isAfter(deadline)) return false;
        await Future.delayed(const Duration(milliseconds: 20));
      }
      return true;
    }

    // 2. SOCKS5 greeting: VER=5, NMETHODS=1, METHOD=0 (no auth)
    sock.add([0x05, 0x01, 0x00]);
    await sock.flush();

    // 3. Read 2-byte server method selection
    if (!await waitBytes(2, const Duration(seconds: 3))) {
      return const _ConnResult(success: false, error: 'SOCKS5 greeting timeout');
    }
    if (rxBuf[0] != 0x05 || rxBuf[1] != 0x00) {
      return const _ConnResult(success: false, error: 'SOCKS5 auth failed');
    }
    rxBuf.removeRange(0, 2);

    // 4. SOCKS5 CONNECT to cp.cloudflare.com:443
    const host = 'cp.cloudflare.com';
    const port = 443;
    final hostBytes = utf8.encode(host);
    sock.add([
      0x05, 0x01, 0x00, 0x03,
      hostBytes.length, ...hostBytes,
      (port >> 8) & 0xFF, port & 0xFF,
    ]);
    await sock.flush();

    // 5. Read 4-byte CONNECT response header
    if (!await waitBytes(4, const Duration(seconds: 5))) {
      return const _ConnResult(success: false, error: 'SOCKS5 CONNECT timeout');
    }
    if (rxBuf[0] != 0x05 || rxBuf[1] != 0x00) {
      final code = rxBuf[1];
      return _ConnResult(success: false, error: 'SOCKS5 CONNECT failed (code $code)');
    }
    // Drain the full CONNECT response (bound addr varies by ATYP)
    // Wait a bit for remaining bytes then clear buffer
    await Future.delayed(const Duration(milliseconds: 80));
    rxBuf.clear();

    // 6. TLS upgrade — sock stream is NOT re-listened here;
    //    SecureSocket.secure() takes ownership of the raw socket connection
    //    (the existing listener above will stop receiving after handoff).
    tls = await SecureSocket.secure(
      sock,
      host: host,
      onBadCertificate: (_) => true,
    ).timeout(const Duration(seconds: 8));

    // 7. HTTP GET /cdn-cgi/trace
    final startTime = DateTime.now();
    tls.write(
      'GET /cdn-cgi/trace HTTP/1.1\r\n'
      'Host: $host\r\n'
      'User-Agent: MidONe/1.0\r\n'
      'Connection: close\r\n\r\n',
    );
    await tls.flush();

    // 8. Read response and verify colo=
    final buf = StringBuffer();
    final completer = Completer<void>();
    sub = tls.listen(
      (chunk) {
        buf.write(utf8.decode(chunk, allowMalformed: true));
        if (buf.toString().contains('colo=') && !completer.isCompleted) {
          completer.complete();
        }
      },
      onDone: () { if (!completer.isCompleted) completer.complete(); },
      onError: (_) { if (!completer.isCompleted) completer.complete(); },
      cancelOnError: true,
    );
    await completer.future
        .timeout(Duration(milliseconds: timeout.inMilliseconds ~/ 3))
        .catchError((_) {});

    final latencyMs = DateTime.now().difference(startTime).inMicroseconds / 1000.0;
    final body = buf.toString();
    if (!body.contains('colo=')) {
      return _ConnResult(success: false, error: 'No colo= in trace response (traffic did not flow through proxy)');
    }
    return _ConnResult(success: true, latencyMs: latencyMs);
  } catch (e) {
    return _ConnResult(success: false, error: e.toString());
  } finally {
    try { await sub?.cancel(); } catch (_) {}
    try { tls?.destroy(); } catch (_) {}
    try { sock?.destroy(); } catch (_) {}
  }
}

Future<double> _measureSocks5Speed(int socksPort, {
  required Duration timeout,
  XrayConfig? cfg,
}) async {
  // Strategy 1: Download from config host/path
  if (cfg != null && cfg.host.isNotEmpty) {
    try {
      final speed = await _downloadViaSocks5(
        socksPort: socksPort,
        host: cfg.host,
        port: 443,
        path: cfg.path.isNotEmpty ? cfg.path : '/',
        bytes: 524288,
        timeout: timeout,
        tls: true,
      );
      if (speed > 0) return speed / 1024;
    } catch (_) {}
  }

  // Strategy 2: speed.cloudflare.com/__down?bytes=524288
  try {
    final speed = await _downloadViaSocks5(
      socksPort: socksPort,
      host: 'speed.cloudflare.com',
      port: 443,
      path: '/__down?bytes=524288',
      bytes: 524288,
      timeout: timeout,
      tls: true,
    );
    if (speed > 0) return speed / 1024;
  } catch (_) {}

  // Strategy 3: burst fallback — 4 parallel GETs to cp.cloudflare.com/cdn-cgi/trace
  try {
    final start = DateTime.now();
    int totalBytes = 0;
    final futures = List.generate(4, (_) => _downloadViaSocks5(
      socksPort: socksPort,
      host: 'cp.cloudflare.com',
      port: 443,
      path: '/cdn-cgi/trace',
      bytes: 32768,
      timeout: timeout,
      tls: true,
    ));
    final results = await Future.wait(futures, eagerError: false).catchError((_) => <double>[]);
    for (final r in results) { if (r > 0) totalBytes += 32768; }
    final elapsed = DateTime.now().difference(start).inSeconds;
    if (totalBytes > 0 && elapsed > 0) return (totalBytes / elapsed) / 1024;
  } catch (_) {}

  return 0.0;
}

// Downloads via SOCKS5 CONNECT tunnel, returns bytes/second
// FIX: Same as _socks5ConnectivityCheck — use single sock.listen() + rxBuf
// to avoid "Bad state: Stream has already been listened to" when calling
// SecureSocket.secure() after _readBytes() has already listened to the stream.
Future<double> _downloadViaSocks5({
  required int socksPort,
  required String host,
  required int port,
  required String path,
  required int bytes,
  required Duration timeout,
  bool tls = true,
}) async {
  Socket? sock;
  SecureSocket? tlsSock;
  try {
    sock = await Socket.connect('127.0.0.1', socksPort,
        timeout: const Duration(seconds: 5));

    // Single listener — buffer all incoming bytes
    final rxBuf = <int>[];
    sock.listen(
      (data) => rxBuf.addAll(data),
      onError: (_) {},
      cancelOnError: false,
    );

    Future<bool> waitBytes(int n, Duration tout) async {
      final deadline = DateTime.now().add(tout);
      while (rxBuf.length < n) {
        if (DateTime.now().isAfter(deadline)) return false;
        await Future.delayed(const Duration(milliseconds: 20));
      }
      return true;
    }

    // SOCKS5 handshake
    sock.add([0x05, 0x01, 0x00]);
    await sock.flush();
    if (!await waitBytes(2, const Duration(seconds: 3))) return 0.0;
    if (rxBuf[1] != 0x00) return 0.0;
    rxBuf.removeRange(0, 2);

    // SOCKS5 CONNECT
    final hostBytes = utf8.encode(host);
    sock.add([
      0x05, 0x01, 0x00, 0x03,
      hostBytes.length, ...hostBytes,
      (port >> 8) & 0xFF, port & 0xFF,
    ]);
    await sock.flush();
    if (!await waitBytes(4, const Duration(seconds: 5))) return 0.0;
    if (rxBuf[1] != 0x00) return 0.0;
    await Future.delayed(const Duration(milliseconds: 80));
    rxBuf.clear();

    // TLS if needed
    IOSink sink;
    Stream<List<int>> stream;
    if (tls) {
      tlsSock = await SecureSocket.secure(sock, host: host,
          onBadCertificate: (_) => true)
          .timeout(const Duration(seconds: 8));
      sink = tlsSock;
      stream = tlsSock;
    } else {
      sink = sock;
      stream = sock;
    }

    // HTTP GET
    sink.write(
      'GET $path HTTP/1.1\r\nHost: $host\r\n'
      'User-Agent: MidONe/1.0\r\nConnection: close\r\n\r\n',
    );
    await sink.flush();

    // Download and measure
    final start = DateTime.now();
    int received = 0;
    bool headersDone = false;
    final completer = Completer<void>();
    StreamSubscription<List<int>>? dlSub;
    dlSub = stream.listen(
      (chunk) {
        if (!headersDone) {
          final s = utf8.decode(chunk, allowMalformed: true);
          final idx = s.indexOf('\r\n\r\n');
          if (idx >= 0) {
            headersDone = true;
            received += chunk.length - (idx + 4);
          }
        } else {
          received += chunk.length;
        }
        if (received >= bytes && !completer.isCompleted) completer.complete();
      },
      onDone: () { if (!completer.isCompleted) completer.complete(); },
      onError: (_) { if (!completer.isCompleted) completer.complete(); },
      cancelOnError: true,
    );
    await completer.future.timeout(timeout).catchError((_) {});
    await dlSub.cancel();

    final elapsed = DateTime.now().difference(start).inMicroseconds / 1e6;
    if (received < 4096 || elapsed <= 0) return 0.0;
    return received / elapsed; // bytes/s
  } catch (_) {
    return 0.0;
  } finally {
    try { tlsSock?.destroy(); } catch (_) {}
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
    'log': {'loglevel': 'warning', 'access': 'none', 'error': 'none'},
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
