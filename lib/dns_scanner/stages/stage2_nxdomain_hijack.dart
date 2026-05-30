// ================================================================
// MidOne DNS Scanner — Stage 2A + 2B: NXDOMAIN & Hijack Detection
// ================================================================
//
// Stage 2A — NXDOMAIN Integrity
//   Query a provably-nonexistent domain.
//   A clean DNS must return RCODE=3 (NXDOMAIN).
//   If it returns NOERROR + an A record → DNS is hijacking NXDOMAIN.
//   This is the cheapest possible test (1 UDP packet).
//
// Stage 2B — Hijack Detection (known-blocked domains)
//   Query a domain that should be blocked on a censored network
//   (e.g. twitter.com in Iran).
//   Compare the IP returned by the DNS under test with the IP
//   from Source-of-Truth.
//   If they differ AND the returned IP is a known wall IP → hijack.
//   If they differ AND the returned IP is private/loopback → hijack.
//
//   We run 2A first because it's free. If 2A already eliminates the
//   server, we skip 2B entirely.
// ================================================================

import '../dns_protocol.dart';
import '../dns_resolver.dart';
import '../models.dart';
import '../source_of_truth.dart';

// ──────────────────────────────────────────────────────────────
// Stage 2A — NXDOMAIN Integrity
// ──────────────────────────────────────────────────────────────

class Stage2aNxdomain {
  static Future<List<DNSServer>> run(
    List<DNSServer> candidates,
    ScanConfig config, {
    void Function(ScanProgress)? onProgress,
  }) async {
    int tested = 0;

    final results = await concurrentMap<DNSServer, DNSServer>(
      candidates,
      (server) async {
        // Generate a random domain that provably doesn't exist
        final garbage = RandomDomain.generate();

        final result = await DnsResolver.query(
          server.ip,
          garbage,
          timeout: config.queryTimeout,
        );

        server.currentStage = ScanStage.stage2aNxdomain;

        if (!result.success) {
          // Timed out / unreachable — borderline; don't eliminate yet
          // (could be a transient network issue)
          server.nxdomainClean = null;
        } else if (result.isNxDomain) {
          // ✓ Correct: nonexistent domain → NXDOMAIN
          server.nxdomainClean = true;
        } else if (result.isNoError && result.aRecords.isNotEmpty) {
          // ✗ DNS returned an IP for a garbage domain → hijacking
          server.nxdomainClean = false;
          server.eliminated = true;
          server.eliminationReason = EliminationReason.nxdomainFailed;
          server.currentStage = ScanStage.eliminated;
        } else {
          // SERVFAIL / REFUSED — not hijacking but unreliable
          server.nxdomainClean = null;
        }

        server.nxdomainResponseCode = result.rcode;

        tested++;
        onProgress?.call(ScanProgress(
          stage: ScanStage.stage2aNxdomain,
          tested: tested,
          total: candidates.length,
          survivors: -1,
          message: 'NXDOMAIN check: $tested/${candidates.length}',
          percentage: 0.20 + tested / candidates.length * 0.10,
        ));

        return server;
      },
      concurrency: config.concurrencyStage2,
    );

    final survivors = results.where((s) => !s.eliminated).toList();

    onProgress?.call(ScanProgress(
      stage: ScanStage.stage2aNxdomain,
      tested: candidates.length,
      total: candidates.length,
      survivors: survivors.length,
      message:
          'Stage 2A: removed ${candidates.length - survivors.length} hijackers '
          '(${survivors.length} remain)',
      percentage: 0.30,
    ));

    return survivors;
  }
}

// ──────────────────────────────────────────────────────────────
// Stage 2B — Hijack Detection (IP comparison)
// ──────────────────────────────────────────────────────────────

class Stage2bHijack {
  // Domains likely to be censored; we check if DNS tampers with them.
  // These are used as a fallback only — config.freedomDomains takes priority.
  static const _fallbackTestDomains = [
    'twitter.com',
    'instagram.com',
    'facebook.com',
    'youtube.com',
    'telegram.org',
  ];

  static Future<List<DNSServer>> run(
    List<DNSServer> candidates,
    ScanConfig config,
    SourceOfTruth sot, {
    void Function(ScanProgress)? onProgress,
  }) async {
    // FIX #11: Use more domains for hijack detection to reduce false-negatives.
    // ISPs may only redirect a subset of blocked domains — checking only 3
    // makes it easy to slip through. We now use up to 10 domains.
    final testDomains = config.freedomDomains.isNotEmpty
        ? config.freedomDomains.take(10).toList()
        : _fallbackTestDomains;

    // Warm source-of-truth cache for test domains first
    await sot.warmCache(testDomains);

    int tested = 0;

    final results = await concurrentMap<DNSServer, DNSServer>(
      candidates,
      (server) async {
        server.currentStage = ScanStage.stage2bHijack;
        bool hijackFound = false;

        for (final domain in testDomains) {
          final result = await DnsResolver.query(
            server.ip,
            domain,
            timeout: config.queryTimeout,
          );

          if (!result.success || !result.hasRecords) continue;

          // Check 1: Is the returned IP a known wall IP or private/loopback?
          // This is an unambiguous signal — no legitimate DNS returns these.
          for (final ip in result.aRecords) {
            if (config.knownWallIPs.contains(ip) ||
                _isPrivateOrLoopback(ip)) {
              server.hijackDetected = true;
              server.hijackedIp = ip;
              server.hijackedDomain = domain;
              hijackFound = true;
              break;
            }
          }
          if (hijackFound) break;

          // Check 2: Compare with source-of-truth — but be lenient for CDN
          // domains (twitter, instagram, facebook use Anycast/CDN so IPs
          // differ by region). Only flag as hijack if the returned IP is
          // ALSO a known wall IP or private address (already caught above).
          // A plain IP mismatch alone is NOT sufficient evidence of hijacking
          // because legitimate regional DNS servers return region-local CDN IPs.
          // We skip the hard mismatch → eliminate logic to avoid false positives.
          //
          // The real hijack signal (wall IPs, private IPs, NXDOMAIN spoofing)
          // is already captured in Check 1 and Stage 2A respectively.
        }

        if (hijackFound) {
          server.eliminated = true;
          server.eliminationReason = EliminationReason.hijackDetected;
          server.currentStage = ScanStage.eliminated;
        } else {
          server.hijackDetected = false;
        }

        tested++;
        onProgress?.call(ScanProgress(
          stage: ScanStage.stage2bHijack,
          tested: tested,
          total: candidates.length,
          survivors: -1,
          message: 'Hijack check: $tested/${candidates.length}',
          percentage: 0.30 + tested / candidates.length * 0.10,
        ));

        return server;
      },
      concurrency: config.concurrencyStage2,
    );

    final survivors = results.where((s) => !s.eliminated).toList();

    onProgress?.call(ScanProgress(
      stage: ScanStage.stage2bHijack,
      tested: candidates.length,
      total: candidates.length,
      survivors: survivors.length,
      message:
          'Stage 2B: removed ${candidates.length - survivors.length} hijackers '
          '(${survivors.length} remain)',
      percentage: 0.40,
    ));

    return survivors;
  }

  // ── Helpers ──────────────────────────────────────────────────

  // FIX #10: Extended to detect IPv6 private/loopback addresses in addition
  // to IPv4. ISPs that return ::1 or fc00::/7 addresses for blocked domains
  // would previously bypass hijack detection entirely.
  static bool _isPrivateOrLoopback(String ip) {
    // ── IPv6 ──────────────────────────────────────────────────
    if (ip.contains(':')) {
      final lower = ip.toLowerCase();
      // Loopback ::1
      if (lower == '::1') return true;
      // Unique Local fc00::/7  (fc__ and fd__)
      if (lower.startsWith('fc') || lower.startsWith('fd')) return true;
      // Link-local fe80::/10
      if (lower.startsWith('fe80')) return true;
      return false;
    }

    // ── IPv4 ──────────────────────────────────────────────────
    final parts = ip.split('.').map(int.tryParse).toList();
    if (parts.length != 4 || parts.any((p) => p == null)) return false;
    final a = parts[0]!, b = parts[1]!;

    return a == 127 ||                      // 127.x.x.x loopback
        a == 10 ||                          // 10.x.x.x private
        (a == 172 && b >= 16 && b <= 31) || // 172.16-31.x.x private
        (a == 192 && b == 168);             // 192.168.x.x private
  }
}
