import 'dart:convert';
import 'dart:io';
import '../models/cdn_provider.dart';

// ── CIDR math ────────────────────────────────────────────────────────────────

int cidrIpCount(String cidr) {
  final prefix = int.parse(cidr.split('/')[1]);
  final total = 1 << (32 - prefix);
  return prefix >= 31 ? total : total - 2;
}

// ── Scan-time estimator ──────────────────────────────────────────────────────
String _estimateScanTime(int ipCount) {
  final survivors    = (ipCount * 0.30).ceil();
  final prefilterSec = (ipCount / 50 * 0.05).ceil();
  final scanSec      = (survivors / 8 * 8).ceil();
  final totalSec     = prefilterSec + scanSec;
  if (totalSec < 60) return '~${totalSec}s';
  final m = totalSec ~/ 60;
  final s = totalSec % 60;
  return s == 0 ? '~${m}m' : '~${m}m ${s}s';
}

// ── selectTopRanges ──────────────────────────────────────────────────────────
// Returns up to 50 RangeOptions sorted by IP count ascending (smallest first).
// Cap raised from 7 → 50 so all CF /22 sub-ranges are visible.
// IP size cap raised: /22 = 1022 IPs; /20 = 4094; /18 = 16382.
// We keep a generous cap of 65536 (/16) to avoid RAM explosion from huge CIDRs
// like /8 or /9, while still allowing /13–/15 blocks when needed.
List<RangeOption> selectTopRanges(List<String> allCidrs) {
  List<RangeOption> _build(int maxIps) {
    return allCidrs
        .where((c) => c.contains('.') && c.contains('/'))
        .map((c) {
          final count = cidrIpCount(c);
          if (count <= 0 || count > maxIps) return null;
          final formatted = _formatCount(count);
          final timeEst   = _estimateScanTime(count);
          return RangeOption(
            cidr:    c,
            ipCount: count,
            label:   '$c — $formatted IPs · $timeEst',
            timeEst: timeEst,
          );
        })
        .whereType<RangeOption>()
        .toList()
      ..sort((a, b) => a.ipCount.compareTo(b.ipCount));
  }

  // Pass 1: up to /22 size (≤1022 IPs) — ideal for sub-range scanning
  var result = _build(1022);
  // Pass 2: up to /20 (≤4094)
  if (result.length < 5) result = _build(4094);
  // Pass 3: up to /18 (≤16382)
  if (result.length < 5) result = _build(16382);
  // Pass 4: up to /16 (≤65534) — generous cap, covers all CF official blocks
  if (result.length < 5) result = _build(65534);
  // Pass 5: no cap — absolute fallback (expandCidr's 16384 guard still applies)
  if (result.length < 3) {
    result = allCidrs
        .where((c) => c.contains('.') && c.contains('/'))
        .map((c) {
          final count = cidrIpCount(c);
          if (count <= 0) return null;
          final formatted = _formatCount(count);
          final timeEst   = _estimateScanTime(count);
          return RangeOption(
            cidr:    c,
            ipCount: count,
            label:   '$c — $formatted IPs · $timeEst',
            timeEst: timeEst,
          );
        })
        .whereType<RangeOption>()
        .toList()
      ..sort((a, b) => a.ipCount.compareTo(b.ipCount));
  }

  // Cap at 50 items max (up from 7) — UI is scrollable so this is fine
  return result.take(50).toList();
}

String _formatCount(int n) {
  if (n >= 1000000) return '${(n / 1000000).toStringAsFixed(1)}M';
  if (n >= 1000)    return '${(n / 1000).toStringAsFixed(n >= 10000 ? 0 : 1)}K';
  return '$n';
}

// ── Live fetch ───────────────────────────────────────────────────────────────

Future<List<RangeOption>> fetchCdnRanges(CdnProviderMeta meta) async {
  List<String> cidrs = [];

  if (meta.fetchUrl.isNotEmpty) {
    try {
      final client  = HttpClient()..connectionTimeout = const Duration(seconds: 8);
      final request = await client.getUrl(Uri.parse(meta.fetchUrl));
      final response = await request.close().timeout(const Duration(seconds: 8));
      final body = await response.transform(utf8.decoder).join();
      client.close();

      if (meta.provider == CdnProvider.cloudflare) {
        cidrs = body.split('\n').map((l) => l.trim()).where((l) => l.isNotEmpty).toList();
      } else if (meta.provider == CdnProvider.google) {
        final j = jsonDecode(body) as Map<String, dynamic>;
        final prefixes = j['prefixes'] as List<dynamic>;
        cidrs = prefixes
            .map((p) => (p as Map)['ipv4Prefix'] as String?)
            .whereType<String>()
            .toList();
      } else if (meta.provider == CdnProvider.amazon) {
        final j = jsonDecode(body) as Map<String, dynamic>;
        final prefixes = j['prefixes'] as List<dynamic>;
        cidrs = prefixes
            .where((p) => (p as Map)['service'] == 'CLOUDFRONT')
            .map((p) => (p as Map)['ip_prefix'] as String?)
            .whereType<String>()
            .toList();
      }
    } catch (_) {}
  }

  if (cidrs.isEmpty) cidrs = meta.fallback;
  return selectTopRanges(cidrs);
}

// ── Fetch ALL CIDRs ──────────────────────────────────────────────────────────
// For Cloudflare: merges live-fetched official blocks with the full fallback
// sub-range list, deduplicates, then returns sorted by prefix (largest first).

Future<List<String>> fetchAllCidrsForProvider(CdnProviderMeta meta) async {
  List<String> liveCidrs = [];

  if (meta.fetchUrl.isNotEmpty) {
    try {
      final client = HttpClient()..connectionTimeout = const Duration(seconds: 8);
      final request = await client.getUrl(Uri.parse(meta.fetchUrl));
      final response = await request.close().timeout(const Duration(seconds: 8));
      final body = await response.transform(utf8.decoder).join();
      client.close();

      if (meta.provider == CdnProvider.cloudflare) {
        liveCidrs = body
            .split('\n')
            .map((l) => l.trim())
            .where((l) => l.isNotEmpty && l.contains('.'))
            .toList();
      } else if (meta.provider == CdnProvider.google) {
        final j = jsonDecode(body) as Map<String, dynamic>;
        liveCidrs = (j['prefixes'] as List)
            .map((p) => (p as Map)['ipv4Prefix'] as String?)
            .whereType<String>()
            .toList();
      } else if (meta.provider == CdnProvider.amazon) {
        final j = jsonDecode(body) as Map<String, dynamic>;
        liveCidrs = (j['prefixes'] as List)
            .where((p) => (p as Map)['service'] == 'CLOUDFRONT')
            .map((p) => (p as Map)['ip_prefix'] as String?)
            .whereType<String>()
            .toList();
      }
    } catch (_) {}
  }

  // Merge live + fallback (for CF: sub-ranges not returned by official API)
  final merged = <String>{...liveCidrs, ...meta.fallback};
  final ipv4 = merged
      .where((c) => c.contains('.') && c.contains('/'))
      .toList();

  // Sort: larger prefix first (/24 before /13) — smaller ranges first in list
  ipv4.sort((a, b) {
    final pa = int.tryParse(a.split('/').last) ?? 0;
    final pb = int.tryParse(b.split('/').last) ?? 0;
    return pb.compareTo(pa);
  });
  return ipv4;
}

// ── CIDR expansion ───────────────────────────────────────────────────────────

List<String> expandCidr(String cidr) {
  final parts  = cidr.split('/');
  final ipStr  = parts[0];
  final prefix = int.parse(parts[1]);

  final octets = ipStr.split('.').map(int.parse).toList();
  final base   = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
  final mask   = prefix == 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF;
  final network = base & mask;
  final total  = 1 << (32 - prefix);

  if (total > 16384) return [];

  final startOffset = prefix >= 31 ? 0 : 1;
  final endOffset   = prefix >= 31 ? total : total - 1;

  final ips = <String>[];
  for (int i = startOffset; i < endOffset; i++) {
    final addr = network + i;
    ips.add(
      '${(addr >> 24) & 0xFF}.'
      '${(addr >> 16) & 0xFF}.'
      '${(addr >> 8)  & 0xFF}.'
      '${addr         & 0xFF}',
    );
  }
  return ips;
}
