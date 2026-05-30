// lib/engine/range_ip_sampler.dart
// Samples random IPs from a list of CIDRs, skipping already-scanned IPs.

import 'dart:math';

class RangeIpSampler {
  /// Samples up to [requestedCount] random IPs from [allCidrs],
  /// excluding any IP already in [alreadyScanned].
  static Future<List<String>> sample({
    required List<String> allCidrs,
    required int requestedCount,
    required Set<String> alreadyScanned,
  }) async {
    final collected = <String>[];
    final rng = Random();

    for (final cidr in allCidrs) {
      if (collected.length >= requestedCount) break;

      final (network, total) = _cidrToNetworkAndTotal(cidr);
      if (total <= 0) continue;

      final startOffset = cidr.contains('/') &&
              int.parse(cidr.split('/')[1]) >= 31
          ? 0
          : 1;
      final endOffset =
          cidr.contains('/') && int.parse(cidr.split('/')[1]) >= 31
              ? total
              : total - 1;
      final usable = endOffset - startOffset;
      if (usable <= 0) continue;

      final needed = requestedCount - collected.length;

      if (usable <= 65536) {
        // Small CIDR: generate all indices, shuffle, pick non-scanned
        final indices = List<int>.generate(usable, (i) => startOffset + i);
        indices.shuffle(rng);
        for (final idx in indices) {
          if (collected.length >= requestedCount) break;
          final ip = _indexToIp(network, idx);
          if (!alreadyScanned.contains(ip)) {
            collected.add(ip);
          }
        }
      } else {
        // Large CIDR: generate random unique indices
        final sampleSize = min(needed * 4, 300000);
        final seen = <int>{};
        int attempts = 0;
        while (seen.length < sampleSize && attempts < sampleSize * 3) {
          seen.add(startOffset + rng.nextInt(usable));
          attempts++;
        }
        for (final idx in seen) {
          if (collected.length >= requestedCount) break;
          final ip = _indexToIp(network, idx);
          if (!alreadyScanned.contains(ip)) {
            collected.add(ip);
          }
        }
      }
    }

    return collected;
  }

  static String _indexToIp(int networkInt, int index) {
    final addr = networkInt + index;
    return '${(addr >> 24) & 0xFF}.${(addr >> 16) & 0xFF}.${(addr >> 8) & 0xFF}.${addr & 0xFF}';
  }

  static (int network, int total) _cidrToNetworkAndTotal(String cidr) {
    final parts = cidr.split('/');
    final octets = parts[0].split('.').map(int.parse).toList();
    final base = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
    final prefix = int.parse(parts[1]);
    final mask = prefix == 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF;
    final network = base & mask;
    final total = 1 << (32 - prefix);
    return (network, total);
  }
}
