import 'dart:convert';
import 'dart:io';
import '../models/cdn_provider.dart';

// ── CIDR math ────────────────────────────────────────────────────────────────

int cidrIpCount(String cidr) {
  final prefix = int.parse(cidr.split('/')[1]);
  final total = 1 << (32 - prefix);
  return prefix >= 31 ? total : total - 2; // /31, /32: no network/broadcast
}

// ── Scan-time estimator ──────────────────────────────────────────────────────
// Based on: prefilter ~50ms/IP at 50 concurrency + scan ~8s/IP at 8 concurrency.
// Rough estimate only — shown in UI so user knows what they're getting into.
String _estimateScanTime(int ipCount) {
  // Prefilter: ~(ipCount / 50) * 0.05s
  // Scan: assume ~30% survive prefilter, each takes ~8s, 8 concurrent
  final survivors   = (ipCount * 0.30).ceil();
  final prefilterSec = (ipCount / 50 * 0.05).ceil();
  final scanSec      = (survivors / 8 * 8).ceil();
  final totalSec     = prefilterSec + scanSec;
  if (totalSec < 60)  return '~${totalSec}s';
  final m = totalSec ~/ 60;
  final s = totalSec % 60;
  return s == 0 ? '~${m}m' : '~${m}m ${s}s';
}

// Returns up to 7 RangeOptions sorted by IP count ascending (smallest first).
// HARD CAP: ranges with more than 4096 IPs (/20 or larger) are excluded.
// This prevents RAM explosion from expanding huge CIDRs like /12 or /13.
// If all ranges exceed 4096 IPs, the cap is relaxed to 16384 (/18) as fallback.
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

  // Pass 1: strict cap (≤4096 IPs = /20 or smaller)
  var result = _build(4096);
  // Pass 2: relax to /18 (≤16384)
  if (result.length < 3) result = _build(16384);
  // Pass 3: no cap — take the 7 smallest whatever their size.
  // expandCidr's own 16384 guard still protects against RAM explosion.
  // This handles providers like Akamai whose fallback blocks are all /15+.
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

  return result.take(7).toList();
}

String _formatCount(int n) {
  if (n >= 1000000) return '${(n / 1000000).toStringAsFixed(1)}M';
  if (n >= 1000)    return '${(n / 1000).toStringAsFixed(n >= 10000 ? 0 : 1)}K';
  return '$n';
}

// ── Live fetch ───────────────────────────────────────────────────────────────

// Fetches CIDRs from the CDN's official URL, falls back to hardcoded list.
// Timeout: 8 seconds.
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
        // Plain text: one CIDR per line
        cidrs = body.split('\n').map((l) => l.trim()).where((l) => l.isNotEmpty).toList();

      } else if (meta.provider == CdnProvider.google) {
        // JSON: {"prefixes": [{"ipv4Prefix": "..."}]}
        final json = jsonDecode(body) as Map<String, dynamic>;
        final prefixes = json['prefixes'] as List<dynamic>;
        cidrs = prefixes
            .map((p) => (p as Map)['ipv4Prefix'] as String?)
            .whereType<String>()
            .toList();

      } else if (meta.provider == CdnProvider.amazon) {
        // JSON: {"prefixes": [{"ip_prefix": "...", "service": "CLOUDFRONT"}]}
        final json = jsonDecode(body) as Map<String, dynamic>;
        final prefixes = json['prefixes'] as List<dynamic>;
        cidrs = prefixes
            .where((p) => (p as Map)['service'] == 'CLOUDFRONT')
            .map((p) => (p as Map)['ip_prefix'] as String?)
            .whereType<String>()
            .toList();
      }
    } catch (_) {
      // Fetch failed → fall through to fallback below
    }
  }

  // Use fallback if fetch produced nothing
  if (cidrs.isEmpty) {
    cidrs = meta.fallback;
  }

  return selectTopRanges(cidrs);
}

// ── Fetch ALL CIDRs (no selectTopRanges cap) ─────────────────────────────────

/// Fetches ALL CIDRs for a provider without the 7-item selectTopRanges cap.
/// Returns ALL IPv4 CIDRs, sorted: larger prefix first (/24 before /13).
/// Falls back to meta.fallback on network failure.
Future<List<String>> fetchAllCidrsForProvider(CdnProviderMeta meta) async {
  List<String> cidrs = [];

  if (meta.fetchUrl.isNotEmpty) {
    try {
      final client = HttpClient()..connectionTimeout = const Duration(seconds: 8);
      final request = await client.getUrl(Uri.parse(meta.fetchUrl));
      final response = await request.close().timeout(const Duration(seconds: 8));
      final body = await response.transform(utf8.decoder).join();
      client.close();

      if (meta.provider == CdnProvider.cloudflare) {
        cidrs = body
            .split('\n')
            .map((l) => l.trim())
            .where((l) => l.isNotEmpty && l.contains('.'))
            .toList();
      } else if (meta.provider == CdnProvider.google) {
        final json = jsonDecode(body) as Map<String, dynamic>;
        cidrs = (json['prefixes'] as List)
            .map((p) => (p as Map)['ipv4Prefix'] as String?)
            .whereType<String>()
            .toList();
      } else if (meta.provider == CdnProvider.amazon) {
        final json = jsonDecode(body) as Map<String, dynamic>;
        cidrs = (json['prefixes'] as List)
            .where((p) => (p as Map)['service'] == 'CLOUDFRONT')
            .map((p) => (p as Map)['ip_prefix'] as String?)
            .whereType<String>()
            .toList();
      }
    } catch (_) {}
  }

  if (cidrs.isEmpty) cidrs = meta.fallback;

  // Filter IPv4 only, sort larger prefix first (/24 comes before /13)
  final ipv4 = cidrs
      .where((c) => c.contains('.') && c.contains('/'))
      .toList();
  ipv4.sort((a, b) {
    final pa = int.tryParse(a.split('/').last) ?? 0;
    final pb = int.tryParse(b.split('/').last) ?? 0;
    return pb.compareTo(pa); // /24 (larger number) first
  });
  return ipv4;
}

// ── CIDR expansion ───────────────────────────────────────────────────────────

// Expands a CIDR to a list of usable IPv4 strings (excludes network + broadcast).
// Example: "1.1.1.0/24" → ["1.1.1.1", ..., "1.1.1.254"]
// Safety guard: returns empty list if count > 16384 (shouldn't happen after
// selectTopRanges filtering, but defensive against direct calls).
List<String> expandCidr(String cidr) {
  final parts  = cidr.split('/');
  final ipStr  = parts[0];
  final prefix = int.parse(parts[1]);

  final octets = ipStr.split('.').map(int.parse).toList();
  final base   = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
  final mask   = prefix == 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF;
  final network = base & mask;
  final total  = 1 << (32 - prefix);

  // Safety guard — never expand more than 16384 IPs
  if (total > 16384) return [];

  // For /31 and /32: no network/broadcast exclusion per RFC 3021
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
