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

// ─── TCP latency probe ────────────────────────────────────────────────────────

// پورت‌هایی که برای probe استفاده می‌کنیم (ترتیب اهمیت)
const _probePorts = [443, 80, 8080, 8443, 2053];

/// یک probe به IP:port — latency بر حسب ms یا null در صورت timeout/خطا
Future<double?> _tcpProbe(String ip, int port, {int timeoutMs = 3000}) async {
  final sw = Stopwatch()..start();
  Socket? sock;
  try {
    sock = await Socket.connect(
      ip,
      port,
      timeout: Duration(milliseconds: timeoutMs),
    );
    sw.stop();
    return sw.elapsedMicroseconds / 1000.0;
  } catch (_) {
    return null;
  } finally {
    sock?.destroy();
  }
}

/// بهترین پورت پاسخگو رو پیدا می‌کنه و latency اولیه می‌ده
Future<({int port, double latency})?> _findBestPort(String ip) async {
  for (final port in _probePorts) {
    final lat = await _tcpProbe(ip, port, timeoutMs: 2000);
    if (lat != null) return (port: port, latency: lat);
  }
  return null;
}

// ─── اسکن واقعی یک IP ────────────────────────────────────────────────────────

/// [repeats] = تعداد دفعات تست (Normal: 3، Deep: 5)
Future<ScanResult> scanOneIp(String ip, {int repeats = 3}) async {
  // پیدا کردن پورت
  final best = await _findBestPort(ip);

  if (best == null) {
    // هیچ پورتی جواب نداد — IP مرده
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
    );
  }

  // چند بار اندازه می‌گیریم
  final samples = <double>[best.latency];
  int failed = 0;

  for (int i = 1; i < repeats; i++) {
    final lat = await _tcpProbe(ip, best.port, timeoutMs: 3000);
    if (lat != null) {
      samples.add(lat);
    } else {
      failed++;
    }
    // کمی صبر بین probeها (جلوگیری از rate-limit)
    await Future.delayed(const Duration(milliseconds: 150));
  }

  final lossPercent = ((failed / repeats) * 100).round();
  final reliability  = samples.length / repeats;

  // محاسبه میانگین و jitter
  final avg    = samples.reduce((a, b) => a + b) / samples.length;
  final mean   = avg;
  final jitter = samples.length > 1
      ? samples.map((s) => (s - mean).abs()).reduce((a, b) => a + b) /
            (samples.length - 1)
      : 0.0;

  // Grade
  final grade = _calcGrade(avg, lossPercent, jitter);

  final (country, flag) = GeoIPOffline().lookupFull(ip);

  return ScanResult(
    ip: ip,
    latencyMs: double.parse(avg.toStringAsFixed(1)),
    jitterMs: double.parse(jitter.toStringAsFixed(1)),
    isAlive: true,
    grade: grade,
    country: country,
    flag: flag,
    loss: lossPercent,
    reliability: double.parse(reliability.toStringAsFixed(2)),
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
      final r = await scanOneIp(ip, repeats: repeats);
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
