import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'dns_protocol.dart';
import 'models.dart';

class DnsResolver {
  static const int _dnsPort = 53;

  static Future<QueryResult> query(
    String serverIp,
    String domain, {
    int qtype = DnsType.a,
    Duration timeout = const Duration(milliseconds: 2000),
  }) async {
    final start = DateTime.now();
    try {
      final (:bytes, :txId) = DnsPacketBuilder.buildQuery(domain, qtype: qtype);
      final response = await _sendUdp(
        serverIp: serverIp,
        port: _dnsPort,
        payload: bytes,
        expectedTxId: txId,
        timeout: timeout,
      );
      final elapsed = DateTime.now().difference(start).inMicroseconds / 1000.0;
      if (response == null) return QueryResult.timeout();
      final parsed = DnsResponse.tryParse(response);
      if (parsed == null) return QueryResult.error('parse error');
      return QueryResult(
        success: true,
        latencyMs: elapsed,
        rcode: parsed.rcode,
        aRecords: parsed.aRecords,
        aaaaRecords: parsed.aaaaRecords,
      );
    } on SocketException catch (e) {
      return QueryResult.error('socket: ${e.message}');
    } catch (e) {
      return QueryResult.error(e.toString());
    }
  }

  static Future<List<QueryResult>> queryBurst(
    String serverIp,
    String domain, {
    required int count,
    Duration timeout = const Duration(milliseconds: 2000),
    int qtype = DnsType.a,
  }) {
    return Future.wait(
      List.generate(
        count,
        (_) => query(serverIp, domain, qtype: qtype, timeout: timeout),
      ),
    );
  }

  static Future<Uint8List?> _sendUdp({
    required String serverIp,
    required int port,
    required Uint8List payload,
    required int expectedTxId,
    required Duration timeout,
  }) async {
    RawDatagramSocket? sock;
    Timer? timer;
    try {
      sock = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0)
          .timeout(const Duration(seconds: 1));
      sock.send(payload, InternetAddress(serverIp), port);
      final completer = Completer<Uint8List?>();
      timer = Timer(timeout, () {
        if (!completer.isCompleted) completer.complete(null);
      });
      final localSock = sock;
      localSock.listen(
        (event) {
          if (completer.isCompleted) return;
          if (event != RawSocketEvent.read) return;
          final dg = localSock.receive();
          if (dg == null) return;
          if (dg.address.address != serverIp || dg.port != port) return;
          final data = Uint8List.fromList(dg.data);
          if (data.length >= 2) {
            final rxId = (data[0] << 8) | data[1];
            if (rxId == expectedTxId) completer.complete(data);
          }
        },
        onError: (_) {
          if (!completer.isCompleted) completer.complete(null);
        },
        onDone: () {
          if (!completer.isCompleted) completer.complete(null);
        },
        cancelOnError: true,
      );
      return await completer.future;
    } on TimeoutException {
      return null;
    } finally {
      timer?.cancel();
      sock?.close();
    }
  }
}

Future<List<T>> concurrentMap<S, T>(
  List<S> items,
  Future<T> Function(S item) task, {
  int concurrency = 30,
}) async {
  if (items.isEmpty) return [];
  final results = List<T?>.filled(items.length, null);
  var nextIndex = 0;

  Future<void> worker() async {
    while (true) {
      final i = nextIndex++;
      if (i >= items.length) return;
      results[i] = await task(items[i]);
    }
  }

  final workers = List.generate(
    concurrency.clamp(1, items.length),
    (_) => worker(),
  );
  await Future.wait(workers);
  return results.cast<T>();
}
