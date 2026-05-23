import 'dart:async';
import 'dart:io';
import 'dart:math';

// ─── CDN Map ───────────────────────────────────────────────────────────────

class CdnInfo {
  final List<String> headers;
  final List<String> server;
  final List<String> snis;
  final String endpoint;
  const CdnInfo({
    required this.headers,
    required this.server,
    required this.snis,
    required this.endpoint,
  });
}

const Map<String, CdnInfo> cdnMap = {
  'Cloudflare': CdnInfo(
    headers: ['cf-ray', 'cf-cache-status', 'cf-request-id'],
    server: ['cloudflare'],
    snis: ['speed.cloudflare.com', 'cloudflare.com'],
    endpoint: '/__down?bytes=8000000',
  ),
  'Akamai': CdnInfo(
    headers: ['x-check-cacheable', 'x-serial', 'x-true-cache-key', 'akamai-origin-hop'],
    server: ['akamaighost', 'akamai'],
    snis: [
      'a248.e.akamai.net', 'a77.net.akamai.net', 'a104.net.akamai.net',
      'a184.net.akamai.net', 'ds-aksb.akamaized.net', 'ak.net.akamaized.net'
    ],
    endpoint: '/',
  ),
  'Google': CdnInfo(
    headers: ['x-goog-generation', 'x-guploader-uploadid', 'x-goog-hash'],
    server: ['gws', 'google frontend', 'esf', 'sffe'],
    snis: ['fonts.googleapis.com', 'google.com', 'www.google.com'],
    endpoint: '/',
  ),
  'Amazon': CdnInfo(
    headers: ['x-amz-cf-id', 'x-amz-cf-pop', 'x-amz-request-id'],
    server: ['amazons3', 'cloudfront'],
    snis: ['d1.cloudfront.net', 'aws.amazon.com'],
    endpoint: '/',
  ),
  'Azure': CdnInfo(
    headers: ['x-azure-ref', 'x-msedge-ref', 'x-ec-custom-error'],
    server: ['microsoft-azure', 'ecd'],
    snis: ['ajax.aspnetcdn.com'],
    endpoint: '/',
  ),
  'Fastly': CdnInfo(
    headers: ['x-served-by', 'x-fastly-request-id', 'x-cache-hits'],
    server: ['varnish'],
    snis: ['global.fastly.net'],
    endpoint: '/',
  ),
  'Iranian': CdnInfo(
    headers: [],
    server: [],
    snis: ['aparat.com', 'snapp.ir', 'digikala.com', 'telewebion.com', 'varzesh3.com'],
    endpoint: '/',
  ),
};

List<String> get allSnis {
  final list = <String>[];
  for (final info in cdnMap.values) {
    for (final s in info.snis) {
      if (!list.contains(s)) list.add(s);
    }
  }
  return list;
}

// ─── Config ────────────────────────────────────────────────────────────────

class ScanConfig {
  final int threads;
  final Duration connectTimeout;
  final Duration tlsTimeout;
  final Duration readTimeout;
  final Duration testDuration;
  final int minBytes;
  final double throttleThreshold;
  final int reliabilityTries;
  final int reliabilityMin;

  const ScanConfig({
    this.threads = 20,
    this.connectTimeout = const Duration(milliseconds: 2500),
    this.tlsTimeout = const Duration(milliseconds: 3000),
    this.readTimeout = const Duration(milliseconds: 5000),
    this.testDuration = const Duration(seconds: 5),
    this.minBytes = 4096,
    this.throttleThreshold = 0.40,
    this.reliabilityTries = 5,
    this.reliabilityMin = 3,
  });
}

// ─── Result Model ──────────────────────────────────────────────────────────

class ScanResult {
  final String ip;
  final String sni;
  final String cdn;
  final double speed; // KB/s
  final int latency; // ms
  final double jitter;
  final bool throttled;
  final int throttlePct;
  final int reliability;
  final double score;

  ScanResult({
    required this.ip,
    required this.sni,
    required this.cdn,
    required this.speed,
    required this.latency,
    required this.jitter,
    required this.throttled,
    required this.throttlePct,
    required this.reliability,
    required this.score,
  });

  String get grade {
    if (throttled) return 'THROTTLED';
    if (speed > 300 && reliability >= 4) return 'S ★★★';
    if (speed > 200) return 'A ★★';
    if (speed > 100) return 'B ★';
    if (speed > 50) return 'C';
    return 'D';
  }

  String get gradeColor {
    if (throttled) return 'red';
    if (speed > 300) return 'green';
    if (speed > 200) return 'lightgreen';
    if (speed > 100) return 'yellow';
    if (speed > 50) return 'orange';
    return 'red';
  }

  String get relBar => '█' * reliability + '░' * (5 - reliability);
}

// ─── Engine ────────────────────────────────────────────────────────────────

class ScannerEngine {
  final ScanConfig config;
  bool _stopped = false;

  ScannerEngine({this.config = const ScanConfig()});

  void stop() => _stopped = true;
  void reset() => _stopped = false;

  // Parse IPs from text
  static List<String> parseIps(String text) {
    final ipRegex = RegExp(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b');
    final matches = ipRegex.allMatches(text).map((m) => m.group(1)!).toSet().toList();
    return matches.where((ip) => !_isPrivate(ip)).toList();
  }

  static bool _isPrivate(String ip) {
    final parts = ip.split('.').map(int.tryParse).toList();
    if (parts.length != 4 || parts.any((p) => p == null)) return true;
    final a = parts[0]!, b = parts[1]!;
    if (a == 10) return true;
    if (a == 172 && b >= 16 && b <= 31) return true;
    if (a == 192 && b == 168) return true;
    if (a == 127) return true;
    if (a == 169 && b == 254) return true;
    return false;
  }

  // TLS connect helper
  Future<SecureSocket?> _tlsConnect(String ip, String sni, Duration timeout) async {
    try {
      final socket = await SecureSocket.connect(
        ip, 443,
        onBadCertificate: (_) => true,
        supportedProtocols: ['http/1.1'],
        timeout: timeout,
      );
      return socket;
    } catch (_) {
      return null;
    }
  }

  // Stage 1: TLS handshake
  Future<(bool, int)> _stageTls(String ip, String sni) async {
    try {
      final t = DateTime.now();
      final socket = await _tlsConnect(ip, sni, config.tlsTimeout);
      if (socket == null) return (false, 9999);
      final ms = DateTime.now().difference(t).inMilliseconds;

      final req = 'HEAD / HTTP/1.1\r\nHost: $sni\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n';
      socket.write(req);

      final buf = StringBuffer();
      try {
        await socket.listen((data) {
          buf.write(String.fromCharCodes(data));
          if (buf.toString().contains('HTTP/')) throw 'done';
        }).asFuture().timeout(const Duration(seconds: 2));
      } catch (_) {}

      await socket.close();
      if (buf.toString().contains('HTTP/')) return (true, ms);
      if (ms < config.tlsTimeout.inMilliseconds * 0.9) return (true, ms);
    } catch (_) {}
    return (false, 9999);
  }

  // Stage 2: Reliability x5
  Future<(bool, int, int)> _stageReliability(String ip, String sni) async {
    int success = 0;
    final lats = <int>[];
    for (int i = 0; i < config.reliabilityTries; i++) {
      if (_stopped) break;
      final (ok, ms) = await _stageTls(ip, sni);
      if (ok) {
        success++;
        lats.add(ms);
      }
      await Future.delayed(const Duration(milliseconds: 100));
    }
    final reliable = success >= config.reliabilityMin;
    final avgLat = lats.isEmpty ? 9999 : (lats.reduce((a, b) => a + b) ~/ lats.length);
    return (reliable, success, avgLat);
  }

  // Stage 3: Bandwidth
  Future<Map<String, dynamic>?> _stageBandwidth(String ip, String sni, String endpoint) async {
    try {
      final socket = await _tlsConnect(ip, sni, config.connectTimeout);
      if (socket == null) return null;

      final req = 'GET $endpoint HTTP/1.1\r\nHost: $sni\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n';
      socket.write(req);

      final start = DateTime.now();
      int total = 0;
      int? firstByteMs;
      final samples = <double>[];
      DateTime lastSample = start;

      final completer = Completer<void>();
      final sub = socket.listen((data) {
        final now = DateTime.now();
        firstByteMs ??= now.difference(start).inMilliseconds;
        total += data.length;
        if (now.difference(lastSample).inMilliseconds >= 1000) {
          final elapsed = now.difference(start).inMilliseconds / 1000.0;
          samples.add((total / 1024) / max(elapsed, 0.001));
          lastSample = now;
        }
        if (now.difference(start) >= config.testDuration) {
          if (!completer.isCompleted) completer.complete();
        }
      }, onDone: () {
        if (!completer.isCompleted) completer.complete();
      }, onError: (_) {
        if (!completer.isCompleted) completer.complete();
      });

      await completer.future.timeout(
        config.testDuration + const Duration(seconds: 2),
        onTimeout: () {},
      );
      await sub.cancel();
      await socket.close();

      final elapsed = DateTime.now().difference(start).inMilliseconds / 1000.0;
      if (elapsed <= 0 || total < config.minBytes) return null;

      final speed = (total / 1024) / elapsed;
      final latency = firstByteMs ?? 0;

      double jitter = 0;
      if (samples.length > 1) {
        final mean = samples.reduce((a, b) => a + b) / samples.length;
        final variance = samples.map((s) => pow(s - mean, 2)).reduce((a, b) => a + b) / samples.length;
        jitter = sqrt(variance);
      }

      bool throttled = false;
      int throttlePct = 0;
      if (samples.length >= 3) {
        final mid = samples.length ~/ 2;
        final fAvg = samples.sublist(0, mid).reduce((a, b) => a + b) / mid;
        final sAvg = samples.sublist(mid).reduce((a, b) => a + b) / (samples.length - mid);
        if (fAvg > 0) {
          final drop = (fAvg - sAvg) / fAvg;
          throttlePct = (drop * 100).round();
          throttled = drop > config.throttleThreshold;
        }
      }

      return {
        'speed': double.parse(speed.toStringAsFixed(1)),
        'latency': latency,
        'jitter': double.parse(jitter.toStringAsFixed(1)),
        'throttled': throttled,
        'throttlePct': throttlePct,
      };
    } catch (_) {
      return null;
    }
  }

  // Detect CDN
  Future<(String, List<String>)> _detectCdn(String ip) async {
    for (final probe in ['aparat.com', 'a248.e.akamai.net', 'speed.cloudflare.com']) {
      try {
        final socket = await _tlsConnect(ip, probe, config.connectTimeout);
        if (socket == null) continue;

        final req = 'HEAD / HTTP/1.1\r\nHost: $probe\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n';
        socket.write(req);

        final buf = StringBuffer();
        try {
          await socket.listen((data) {
            buf.write(String.fromCharCodes(data));
            if (buf.toString().contains('\r\n\r\n')) throw 'done';
          }).asFuture().timeout(const Duration(seconds: 2));
        } catch (_) {}
        await socket.close();

        final hdrs = buf.toString().toLowerCase();
        String srv = '';
        for (final line in hdrs.split('\r\n')) {
          if (line.startsWith('server:')) {
            srv = line.split(':').skip(1).join(':').trim();
            break;
          }
        }

        for (final entry in cdnMap.entries) {
          if (entry.key == 'Iranian') continue;
          final info = entry.value;
          if (info.headers.any((h) => hdrs.contains(h))) {
            final rest = allSnis.where((s) => !info.snis.contains(s)).toList();
            return (entry.key, [...info.snis, ...rest]);
          }
          if (info.server.any((s) => srv.contains(s))) {
            final rest = allSnis.where((s) => !info.snis.contains(s)).toList();
            return (entry.key, [...info.snis, ...rest]);
          }
        }
      } catch (_) {}
    }
    return ('Unknown', allSnis);
  }

  // Score calculation
  static double calcScore(double speed, int latency, double jitter, bool throttled, int reliability) {
    final s = min(speed / 500, 1.0) * 55;
    final l = max(0, 1 - latency / 800) * 20;
    final j = max(0.0, 1 - jitter / max(speed, 1)) * 10;
    final t = throttled ? 0.0 : 5.0;
    final rel = (reliability / 5) * 10;
    return double.parse((s + l + j + t + rel).toStringAsFixed(1));
  }

  // Mode 1: Simple scan
  Future<void> scanMode1({
    required List<String> ips,
    required Function(int done, int total) onProgress,
    required Function(ScanResult) onResult,
    required Function(List<ScanResult>) onDone,
  }) async {
    reset();
    const sni = 'google.com';
    const endpoint = '/';
    final results = <ScanResult>[];
    int done = 0;

    final futures = ips.map((ip) async {
      if (_stopped) return;
      try {
        final (ok, _) = await _stageTls(ip, sni);
        if (!ok || _stopped) return;
        final bw = await _stageBandwidth(ip, sni, endpoint);
        if (bw == null || _stopped) return;
        final score = calcScore(
          bw['speed'], bw['latency'], bw['jitter'], bw['throttled'], 5,
        );
        final r = ScanResult(
          ip: ip, sni: sni, cdn: 'Auto',
          speed: bw['speed'], latency: bw['latency'],
          jitter: bw['jitter'], throttled: bw['throttled'],
          throttlePct: bw['throttlePct'], reliability: 5, score: score,
        );
        results.add(r);
        onResult(r);
      } catch (_) {}
      done++;
      onProgress(done, ips.length);
    });

    // Throttle concurrency
    await _runConcurrent(futures.toList(), config.threads);
    results.sort((a, b) => b.score.compareTo(a.score));
    onDone(results);
  }

  // Mode 2: Auto-SNI
  Future<void> scanMode2({
    required List<String> ips,
    required Function(int done, int total) onProgress,
    required Function(ScanResult) onResult,
    required Function(List<ScanResult>) onDone,
  }) async {
    reset();
    final results = <ScanResult>[];
    int done = 0;

    final futures = ips.map((ip) async {
      if (_stopped) return;
      try {
        final (cdnName, orderedSnis) = await _detectCdn(ip);
        final endpoint = cdnMap[cdnName]?.endpoint ?? '/';

        for (final sni in orderedSnis) {
          if (_stopped) break;
          final (ok, _) = await _stageTls(ip, sni);
          if (!ok) continue;
          final (reliable, relCount, _) = await _stageReliability(ip, sni);
          if (!reliable || _stopped) continue;
          final bw = await _stageBandwidth(ip, sni, endpoint);
          if (bw == null) continue;
          final score = calcScore(
            bw['speed'], bw['latency'], bw['jitter'], bw['throttled'], relCount,
          );
          final r = ScanResult(
            ip: ip, sni: sni, cdn: cdnName,
            speed: bw['speed'], latency: bw['latency'],
            jitter: bw['jitter'], throttled: bw['throttled'],
            throttlePct: bw['throttlePct'], reliability: relCount, score: score,
          );
          results.add(r);
          onResult(r);
        }
      } catch (_) {}
      done++;
      onProgress(done, ips.length);
    });

    await _runConcurrent(futures.toList(), config.threads);
    results.sort((a, b) => b.score.compareTo(a.score));
    onDone(results);
  }

  // Run N futures concurrently
  Future<void> _runConcurrent(List<Future<void>> futures, int concurrency) async {
    final queue = [...futures];
    final active = <Future<void>>[];
    while (queue.isNotEmpty || active.isNotEmpty) {
      while (active.length < concurrency && queue.isNotEmpty) {
        active.add(queue.removeAt(0));
      }
      if (active.isEmpty) break;
      await Future.any(active).catchError((_) {});
      active.removeWhere((f) => f is Future);
      // Simple approach: just await first batch
      if (active.length >= concurrency || queue.isEmpty) {
        await Future.wait(active.take(1).toList()).catchError((_) {});
        if (active.isNotEmpty) active.removeAt(0);
      }
    }
    if (futures.isNotEmpty) {
      await Future.wait(futures).catchError((_) {});
    }
  }
}
