// lib/scanner_engine.dart
// ─── MidONe Scanner Engine — Real TCP-based scanning ────────────────────────
import 'dart:async';
import 'dart:io';
import 'dart:math';
import 'geoip.dart';

// ─── Data model ──────────────────────────────────────────────────────────────

class ScanResult {
  final String ip;
  final double latencyMs;   // میانگین latency (ms)
  final double jitterMs;    // jitter
  final bool   isAlive;     // آیا اتصال موفق بود؟
  final String grade;       // A/B/C/D/F
  final String country;     // از GeoIP آفلاین
  final String flag;        // emoji flag
  final int    loss;        // packet loss درصد (0-100)
  final double reliability; // 0.0 - 1.0
  final double? bandwidth;  // Mbps

  const ScanResult({
    required this.ip,
    required this.latencyMs,
    required this.jitterMs,
    required this.isAlive,
    required this.grade,
    required this.country,
    required this.flag,
    required this.loss,
    required this.reliability,
    this.bandwidth,
  });
}

// ─── Private IP filter ────────────────────────────────────────────────────────

bool isPrivateOrReserved(String ip) {
  final parts = ip.split('.');
  if (parts.length != 4) return true;
  final o = parts.map((p) => int.tryParse(p) ?? -1).toList();
  if (o.any((x) => x < 0 || x > 255)) return true;

  // 0.0.0.0/8
  if (o[0] == 0) return true;
  // 10.0.0.0/8
  if (o[0] == 10) return true;
  // 100.64.0.0/10  (CGNAT)
  if (o[0] == 100 && o[1] >= 64 && o[1] <= 127) return true;
  // 127.0.0.0/8
  if (o[0] == 127) return true;
  // 169.254.0.0/16 (link-local)
  if (o[0] == 169 && o[1] == 254) return true;
  // 172.16.0.0/12
  if (o[0] == 172 && o[1] >= 16 && o[1] <= 31) return true;
  // 192.168.0.0/16
  if (o[0] == 192 && o[1] == 168) return true;
  // 224.0.0.0/4 (multicast)
  if (o[0] >= 224 && o[0] <= 239) return true;
  // 240.0.0.0/4 (reserved)
  if (o[0] >= 240) return true;

  return false;
}

List<String> validateAndExtractIps(String rawText) {
  final ipRegex = RegExp(
    r'\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))\b',
  );
  return ipRegex
      .allMatches(rawText)
      .map((m) => m.group(1)!)
      .where((ip) => !isPrivateOrReserved(ip))
      .toSet()   // dedup
      .toList();
}

// ─── TCP + TLS + HTTP probe ───────────────────────────────────────────────────

/// TCP + TLS + HTTP GET واقعی — SNI قابل تنظیم — latency یا null
Future<double?> _tcpProbe(String ip, int port, {int timeoutMs = 4000, String sni = 'speed.cloudflare.com'}) async {
  Socket? sock;
  try {
    final sw = Stopwatch()..start();

    sock = await Socket.connect(
      ip, port,
      timeout: Duration(milliseconds: timeoutMs),
    );

    final secSock = await SecureSocket.secure(
      sock,
      host: sni,
      onBadCertificate: (_) => true,
    );

    secSock.write(
      'GET / HTTP/1.1\r\n'
      'Host: $sni\r\n'
      'User-Agent: MidONe/1.0\r\n'
      'Connection: close\r\n\r\n',
    );

    final buf = StringBuffer();
    await secSock.listen((d) {
      buf.write(String.fromCharCodes(d));
      if (buf.length > 64) throw 'done';
    }).asFuture().timeout(Duration(milliseconds: 3000)).catchError((_) {});

    sw.stop();
    await secSock.close();

    final resp = buf.toString();
    if (resp.contains('HTTP/')) {
      return sw.elapsedMicroseconds / 1000.0;
    }
    return null;

  } catch (_) {
    return null;
  } finally {
    sock?.destroy();
  }
}

// SNIهایی که امتحان می‌کنیم تا IP جواب بده
const _sniCandidates = [
  'speed.cloudflare.com',
  'cloudflare.com',
  'google.com',
  'a248.e.akamai.net',
];

/// بهترین SNI که IP بهش جواب میده رو پیدا می‌کنه + latency
Future<({String sni, double latency})?> _findBestSni(String ip) async {
  for (final sni in _sniCandidates) {
    final lat = await _tcpProbe(ip, 443, timeoutMs: 4000, sni: sni);
    if (lat != null) return (sni: sni, latency: lat);
  }
  return null;
}

/// تست دانلود با همون SNI که IP بهش جواب داد
Future<double?> _bandwidthTest(String ip, String sni) async {
  final path = sni == 'speed.cloudflare.com' ? '/__down?bytes=102400' : '/';
  Socket? sock;
  try {
    sock = await Socket.connect(ip, 443,
        timeout: const Duration(seconds: 4));

    final secSock = await SecureSocket.secure(
      sock,
      host: sni,
      onBadCertificate: (_) => true,
    );

    secSock.write(
      'GET $path HTTP/1.1\r\n'
      'Host: $sni\r\n'
      'User-Agent: MidONe/1.0\r\n'
      'Connection: close\r\n\r\n',
    );

    int total = 0;
    final sw = Stopwatch()..start();

    await secSock.listen((d) {
      total += d.length;
      if (total >= 102400 || sw.elapsed.inSeconds >= 3) throw 'done';
    }).asFuture().timeout(const Duration(seconds: 4)).catchError((_) {});

    sw.stop();
    await secSock.close();

    if (total > 5000 && sw.elapsedMilliseconds > 0) {
      final mbps = (total * 8) / (sw.elapsedMilliseconds * 1000);
      return double.parse(mbps.toStringAsFixed(2));
    }
    return null;
  } catch (_) {
    return null;
  } finally {
    sock?.destroy();
  }
}

// ─── اسکن واقعی یک IP ────────────────────────────────────────────────────────

/// [repeats] = تعداد دفعات تست (Normal: 3، Deep: 5)
Future<ScanResult> scanOneIp(String ip, {int repeats = 3, bool testBandwidth = false}) async {
  final best = await _findBestSni(ip);

  if (best == null) {
    final (country, flag) = GeoIPOffline().lookupFull(ip);
    return ScanResult(
      ip: ip,
      latencyMs: 9999,
      jitterMs: 0,
      isAlive: false,
      grade: 'F',
      country: country,
      flag: flag,
      loss: 100,
      reliability: 0,
      bandwidth: null,
    );
  }

  final samples = <double>[best.latency];
  int failed = 0;

  for (int i = 1; i < repeats; i++) {
    final lat = await _tcpProbe(ip, 443, timeoutMs: 4000, sni: best.sni);
    if (lat != null) {
      samples.add(lat);
    } else {
      failed++;
    }
    await Future.delayed(const Duration(milliseconds: 150));
  }

  final lossPercent = ((failed / repeats) * 100).round();
  final reliability = samples.length / repeats;

  final avg = samples.reduce((a, b) => a + b) / samples.length;
  final jitter = samples.length > 1
      ? samples.map((s) => (s - avg).abs()).reduce((a, b) => a + b) /
            (samples.length - 1)
      : 0.0;

  // bandwidth با همون SNI که جواب داد
  double? bw;
  if (testBandwidth) {
    bw = await _bandwidthTest(ip, best.sni);
  }

  final (country, flag) = GeoIPOffline().lookupFull(ip);

  return ScanResult(
    ip: ip,
    latencyMs: double.parse(avg.toStringAsFixed(1)),
    jitterMs: double.parse(jitter.toStringAsFixed(1)),
    isAlive: true,
    grade: _calcGrade(avg, lossPercent, jitter),
    country: country,
    flag: flag,
    loss: lossPercent,
    reliability: double.parse(reliability.toStringAsFixed(2)),
    bandwidth: bw,
  );
}

String _calcGrade(double latMs, int lossPercent, double jitter) {
  if (lossPercent >= 50) return 'F';
  if (latMs < 80  && lossPercent == 0 && jitter < 15) return 'A';
  if (latMs < 150 && lossPercent <= 5 && jitter < 30) return 'B';
  if (latMs < 300 && lossPercent <= 15)                return 'C';
  if (latMs < 500 && lossPercent <= 30)                return 'D';
  return 'F';
}

// ─── موتور اسکن اصلی ─────────────────────────────────────────────────────────

enum ScanMode { normal, deep }

/// [onProgress] — callback بعد از هر IP: (done, total, result)
Future<List<ScanResult>> runScanningEngine(
  List<String> ips, {
  ScanMode mode = ScanMode.normal,
  int concurrency = 8,
  void Function(int done, int total, ScanResult result)? onProgress,
  bool Function()? isCancelled,
}) async {
  final repeats = mode == ScanMode.deep ? 5 : 3;
  final results = <ScanResult>[];
  int done = 0;

  // پردازش موازی با کنترل concurrency
  final sem = _Semaphore(concurrency);

  await Future.wait(ips.map((ip) async {
    if (isCancelled?.call() == true) return;
    await sem.acquire();
    try {
      if (isCancelled?.call() == true) return;
      final r = await scanOneIp(
        ip,
        repeats: repeats,
        testBandwidth: true,
      );
      results.add(r);
      done++;
      onProgress?.call(done, ips.length, r);
    } finally {
      sem.release();
    }
  }));

  // مرتب‌سازی: زنده‌ها اول، بعد بر اساس latency
  results.sort((a, b) {
    if (a.isAlive != b.isAlive) return a.isAlive ? -1 : 1;
    return a.latencyMs.compareTo(b.latencyMs);
  });

  return results;
}

// ─── Semaphore ساده برای کنترل concurrency ──────────────────────────────────

class _Semaphore {
  int _count;
  final _waiters = <Completer<void>>[];

  _Semaphore(this._count);

  Future<void> acquire() async {
    if (_count > 0) { _count--; return; }
    final c = Completer<void>();
    _waiters.add(c);
    await c.future;
  }

  void release() {
    if (_waiters.isNotEmpty) {
      final c = _waiters.removeAt(0);
      c.complete();
    } else {
      _count++;
    }
  }
}
