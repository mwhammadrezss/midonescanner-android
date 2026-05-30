import 'dart:math';
import 'dart:typed_data';

abstract class DnsType {
  static const int a     = 1;
  static const int ns    = 2;
  static const int cname = 5;
  static const int mx    = 15;
  static const int txt   = 16;
  static const int aaaa  = 28;
}

abstract class DnsClass {
  static const int inet = 1;
}

abstract class DnsRCode {
  static const int noError  = 0;
  static const int formErr  = 1;
  static const int servFail = 2;
  static const int nxDomain = 3;
  static const int notImp   = 4;
  static const int refused  = 5;
}

class DnsPacketBuilder {
  static final Random _rng = Random.secure();

  static ({Uint8List bytes, int txId}) buildQuery(
    String domain, {
    int qtype = DnsType.a,
  }) {
    final txId = _rng.nextInt(0xFFFF) + 1;
    final buf  = BytesBuilder(copy: false);

    buf
      ..addByte(txId >> 8)
      ..addByte(txId & 0xFF)
      ..addByte(0x01)
      ..addByte(0x00)
      ..addByte(0x00)..addByte(0x01)
      ..addByte(0x00)..addByte(0x00)
      ..addByte(0x00)..addByte(0x00)
      ..addByte(0x00)..addByte(0x00);

    _writeName(buf, domain);
    buf
      ..addByte(qtype >> 8)
      ..addByte(qtype & 0xFF)
      ..addByte(0x00)..addByte(0x01);

    return (bytes: buf.toBytes(), txId: txId);
  }

  static void _writeName(BytesBuilder buf, String domain) {
    for (final label in domain.split('.')) {
      if (label.isEmpty) continue;
      if (label.length > 63) {
        throw ArgumentError(
          'DNS label exceeds RFC 1035 limit of 63 octets '
          '(got ${label.length}): "$label"',
        );
      }
      buf.addByte(label.length);
      for (final c in label.codeUnits) buf.addByte(c);
    }
    buf.addByte(0x00);
  }
}

class DnsResponse {
  final int txId;
  final int rcode;
  final bool isAuthoritative;
  final bool isTruncated;
  final bool recursionAvailable;
  final List<String> aRecords;
  final List<String> aaaaRecords;
  final int answerCount;

  const DnsResponse({
    required this.txId,
    required this.rcode,
    required this.isAuthoritative,
    required this.isTruncated,
    required this.recursionAvailable,
    required this.aRecords,
    required this.aaaaRecords,
    required this.answerCount,
  });

  bool get isNxDomain  => rcode == DnsRCode.nxDomain;
  bool get isServFail  => rcode == DnsRCode.servFail;
  bool get isRefused   => rcode == DnsRCode.refused;
  bool get isNoError   => rcode == DnsRCode.noError;

  static DnsResponse? tryParse(Uint8List data) {
    try {
      return _parse(data);
    } catch (_) {
      return null;
    }
  }

  static DnsResponse _parse(Uint8List d) {
    if (d.length < 12) throw FormatException('too short');
    final txId  = _u16(d, 0);
    final flags = _u16(d, 2);
    final isQR  = (flags & 0x8000) != 0;
    if (!isQR) throw FormatException('not a response');
    final isAA = (flags & 0x0400) != 0;
    final isTC = (flags & 0x0200) != 0;
    final isRA = (flags & 0x0080) != 0;
    final rc   = flags & 0x000F;
    final qdCount = _u16(d, 4);
    final anCount = _u16(d, 6);
    int offset = 12;
    for (int q = 0; q < qdCount; q++) {
      offset = _skipName(d, offset);
      offset += 4;
    }
    final aRecs    = <String>[];
    final aaaaRecs = <String>[];
    for (int i = 0; i < anCount; i++) {
      offset = _skipName(d, offset);
      if (offset + 10 > d.length) break;
      final rtype    = _u16(d, offset);
      final rdLength = _u16(d, offset + 8);
      offset += 10;
      if (offset + rdLength > d.length) break;
      switch (rtype) {
        case DnsType.a:
          if (rdLength == 4) {
            aRecs.add('${d[offset]}.${d[offset+1]}.${d[offset+2]}.${d[offset+3]}');
          }
        case DnsType.aaaa:
          if (rdLength == 16) {
            final parts = List.generate(8,
              (i) => _u16(d, offset + i * 2).toRadixString(16));
            aaaaRecs.add(parts.join(':'));
          }
      }
      offset += rdLength;
    }
    return DnsResponse(
      txId: txId,
      rcode: rc,
      isAuthoritative: isAA,
      isTruncated: isTC,
      recursionAvailable: isRA,
      aRecords: aRecs,
      aaaaRecords: aaaaRecs,
      answerCount: anCount,
    );
  }

  static int _u16(Uint8List d, int i) => (d[i] << 8) | d[i + 1];

  static int _skipName(Uint8List d, int offset) {
    while (offset < d.length) {
      final len = d[offset];
      if (len == 0) return offset + 1;
      if ((len & 0xC0) == 0xC0) return offset + 2;
      offset += len + 1;
    }
    return offset;
  }
}

class RandomDomain {
  static final Random _rng = Random();
  static const _chars = 'abcdefghijklmnopqrstuvwxyz0123456789';

  static String generate() {
    final label = List.generate(
      16,
      (_) => _chars[_rng.nextInt(_chars.length)],
    ).join();
    return '$label.midone-test.invalid';
  }
}
