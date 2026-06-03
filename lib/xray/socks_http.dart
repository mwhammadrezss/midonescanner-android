// HTTP/HTTPS through SOCKS5 — mirrors SenPai xraytest proxy checks.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

const _traceUrl = 'https://cp.cloudflare.com/cdn-cgi/trace';
const _userAgent = 'midonescanner/1.0';

/// SOCKS5 CONNECT then TLS + HTTP GET; returns TTFB ms.
Future<({bool ok, double latencyMs, String? error})> socksHttpGet(
  String proxyHost,
  int proxyPort,
  Uri url, {
  Duration timeout = const Duration(seconds: 15),
}) async {
  final host = url.host;
  final port = url.scheme == 'https' ? 443 : 80;
  Socket? relay;
  SecureSocket? tls;
  try {
    relay = await _socks5Connect(proxyHost, proxyPort, host, port, timeout);
    final sw = Stopwatch()..start();
    if (url.scheme == 'https') {
      tls = await SecureSocket.secure(
        relay,
        host: host,
        onBadCertificate: (_) => true,
      ).timeout(timeout);
      relay = null;
    }
    final io = tls ?? relay!;
    final path = url.path.isEmpty ? '/' : '${url.path}${url.hasQuery ? '?${url.query}' : ''}';
    io.write(
      'GET $path HTTP/1.1\r\n'
      'Host: $host\r\n'
      'User-Agent: $_userAgent\r\n'
      'Connection: close\r\n\r\n',
    );

    final buf = StringBuffer();
    final done = Completer<void>();
    final sub = io.listen(
      (c) {
        buf.write(utf8.decode(c, allowMalformed: true));
        if (buf.length > 2048 && !done.isCompleted) done.complete();
      },
      onDone: () { if (!done.isCompleted) done.complete(); },
      onError: (_) { if (!done.isCompleted) done.complete(); },
      cancelOnError: true,
    );
    await done.future.timeout(timeout, onTimeout: () {});
    await sub.cancel();
    sw.stop();

    final body = buf.toString();
    final status = _parseStatus(body);
    if (status < 200 || status >= 400) {
      return (ok: false, latencyMs: sw.elapsedMilliseconds.toDouble(), error: 'HTTP $status');
    }
    if (url.host.contains('cloudflare.com') && !body.contains('colo=')) {
      return (ok: false, latencyMs: sw.elapsedMilliseconds.toDouble(), error: 'no colo in trace');
    }
    return (ok: true, latencyMs: sw.elapsedMilliseconds.toDouble(), error: null);
  } catch (e) {
    return (ok: false, latencyMs: 0.0, error: e.toString());
  } finally {
    try { await tls?.close(); } catch (_) {}
    try { tls?.destroy(); } catch (_) {}
    try { await relay?.close(); } catch (_) {}
    try { relay?.destroy(); } catch (_) {}
  }
}

/// Download bytes through SOCKS; returns throughput bytes/sec.
Future<({int bytes, double bps})> socksHttpDownload(
  String proxyHost,
  int proxyPort,
  String url, {
  int maxBytes = 131072,
  Duration timeout = const Duration(seconds: 20),
}) async {
  final uri = Uri.parse(url);
  final host = uri.host;
  final port = uri.scheme == 'https' ? 443 : 80;
  Socket? relay;
  SecureSocket? tls;
  try {
    relay = await _socks5Connect(proxyHost, proxyPort, host, port, timeout);
    if (uri.scheme == 'https') {
      tls = await SecureSocket.secure(relay, host: host, onBadCertificate: (_) => true)
          .timeout(timeout);
      relay = null;
    }
    final io = tls ?? relay!;
    final path = uri.path.isEmpty ? '/' : uri.path;
    io.write(
      'GET $path HTTP/1.1\r\n'
      'Host: $host\r\n'
      'User-Agent: $_userAgent\r\n'
      'Connection: close\r\n\r\n',
    );

    final sw = Stopwatch()..start();
    int total = 0;
    await for (final chunk in io) {
      total += chunk.length;
      if (total >= maxBytes) break;
      if (sw.elapsed > timeout) break;
    }
    sw.stop();
    final sec = sw.elapsedMicroseconds / 1e6;
    if (total < 4096 || sec <= 0) return (bytes: total, bps: 0.0);
    return (bytes: total, bps: total / sec);
  } catch (_) {
    return (bytes: 0, bps: 0.0);
  } finally {
    try { tls?.destroy(); } catch (_) {}
    try { relay?.destroy(); } catch (_) {}
  }
}

Future<Socket> _socks5Connect(
  String proxyHost,
  int proxyPort,
  String destHost,
  int destPort,
  Duration timeout,
) async {
  final proxy = await Socket.connect(proxyHost, proxyPort, timeout: timeout);
  proxy.write([0x05, 0x01, 0x00]); // VER, 1 method, no auth
  final methodResp = await _readExact(proxy, 2, timeout);
  if (methodResp.length < 2 || methodResp[0] != 0x05 || methodResp[1] != 0x00) {
    proxy.destroy();
    throw const SocketException('SOCKS5 auth failed');
  }

  final hostBytes = utf8.encode(destHost);
  final req = BytesBuilder();
  req.addByte(0x05);
  req.addByte(0x01); // CONNECT
  req.addByte(0x03); // domain
  req.addByte(hostBytes.length);
  req.add(hostBytes);
  req.addByte((destPort >> 8) & 0xff);
  req.addByte(destPort & 0xff);
  proxy.add(req.toBytes());

  final head = await _readExact(proxy, 4, timeout);
  if (head.length < 4 || head[0] != 0x05 || head[1] != 0x00) {
    proxy.destroy();
    throw const SocketException('SOCKS5 connect rejected');
  }
  final atyp = head[3];
  int extra = 0;
  if (atyp == 0x01) extra = 4 + 2;
  else if (atyp == 0x03) {
    final len = await _readExact(proxy, 1, timeout);
    extra = (len.isNotEmpty ? len[0] : 0) + 2;
  } else if (atyp == 0x04) extra = 16 + 2;
  if (extra > 0) await _readExact(proxy, extra, timeout);
  return proxy;
}

Future<List<int>> _readExact(Socket s, int n, Duration timeout) async {
  final buf = <int>[];
  final deadline = DateTime.now().add(timeout);
  while (buf.length < n) {
    if (DateTime.now().isAfter(deadline)) break;
    final remain = deadline.difference(DateTime.now());
    if (remain <= Duration.zero) break;
    final chunk = await s.first.timeout(remain);
    buf.addAll(chunk);
  }
  return buf;
}

int _parseStatus(String raw) {
  final line = raw.split('\n').firstWhere((l) => l.startsWith('HTTP/'), orElse: () => '');
  final parts = line.split(' ');
  if (parts.length >= 2) return int.tryParse(parts[1]) ?? -1;
  return -1;
}
