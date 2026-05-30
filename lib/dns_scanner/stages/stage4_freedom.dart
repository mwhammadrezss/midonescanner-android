// ================================================================
// MidOne DNS Scanner — Stage 4: Freedom Score
// ================================================================
//
// Goal:   Measure how "free" a DNS server is — does it correctly
//         resolve domains that are blocked by censored DNS servers?
//
// Method:
//   For each domain in [freedomDomains]:
//     1. Query the DNS under test.
//     2. Compare result with Source-of-Truth (DoH).
//     3. Classify:
//          • MATCH    → 1.0  (clean, correct IP)
//          • RESOLVED but wrong IP → 0.5  (suspicious, possible MitM)
//          • NXDOMAIN for existing domain → 0.0  (censored)
//          • Timeout → 0.0  (blocked or unresponsive)
//
//   freedomScore = weighted average across all domains.
//   Domains that the SoT also can't resolve (all providers blocked)
//   are skipped from the score — can't penalize a DNS for something
//   we can't verify.
//
// Output: Top [stage4KeepTop] servers sorted by freedomScore.
// ================================================================

import '../dns_resolver.dart';
import '../models.dart';
import '../source_of_truth.dart';

class Stage4Freedom {
  static Future<List<DNSServer>> run(
    List<DNSServer> candidates,
    ScanConfig config,
    SourceOfTruth sot, {
    void Function(ScanProgress)? onProgress,
  }) async {
    // Pre-warm SoT cache for all freedom domains
    onProgress?.call(ScanProgress(
      stage: ScanStage.stage4Freedom,
      tested: 0,
      total: candidates.length,
      survivors: candidates.length,
      message: 'Warming source-of-truth cache…',
      percentage: 0.55,
    ));
    await sot.warmCache(config.freedomDomains);

    // Find out which domains the SoT can actually resolve
    // (on very restricted networks some may be unreachable)
    final verifiableDomains = <String>[];
    for (final domain in config.freedomDomains) {
      final truth = await sot.resolve(domain);
      if (truth != null && truth.hasRecords) {
        verifiableDomains.add(domain);
      }
    }

    if (verifiableDomains.isEmpty) {
      // SoT completely failed — can't do freedom scoring meaningfully.
      // Keep all candidates but give them a neutral score.
      for (final s in candidates) s.freedomScore = 0.5;
      return candidates;
    }

    int tested = 0;

    final results = await concurrentMap<DNSServer, DNSServer>(
      candidates,
      (server) async {
        server.currentStage = ScanStage.stage4Freedom;

        // Query all verifiable domains in parallel (#13 fix: was sequential,
        // 10 domains × 2000ms timeout = up to 20s per server).
        final entries = await Future.wait(
          verifiableDomains.map((domain) async {
            final truth = await sot.resolve(domain);
            if (truth == null) return MapEntry(domain, null as FreedomResult?);

            final result = await DnsResolver.query(
              server.ip,
              domain,
              timeout: config.queryTimeout,
            );

            FreedomResult fr;

            if (!result.success) {
              // Timeout — treat as blocked
              fr = FreedomResult(
                domain: domain,
                resolved: false,
                matchesTruth: false,
                truthIp: truth.ips.firstOrNull,
              );
            } else if (result.isNxDomain) {
              // DNS claims this domain doesn't exist — censorship
              fr = FreedomResult(
                domain: domain,
                resolved: false,
                matchesTruth: false,
                truthIp: truth.ips.firstOrNull,
              );
            } else if (result.isNoError && result.hasRecords) {
              final matches = SourceOfTruth.ipsOverlap(
                result.aRecords,
                truth.ips,
              );
              fr = FreedomResult(
                domain: domain,
                resolved: true,
                matchesTruth: matches,
                receivedIp: result.aRecords.firstOrNull,
                truthIp: truth.ips.firstOrNull,
              );
            } else {
              // SERVFAIL / REFUSED — ambiguous
              fr = FreedomResult(
                domain: domain,
                resolved: false,
                matchesTruth: false,
                truthIp: truth.ips.firstOrNull,
              );
            }
            return MapEntry(domain, fr as FreedomResult?);
          }),
        );

        final domainResults = <String, FreedomResult>{};
        double totalScore = 0.0;
        int scoredCount = 0;

        for (final entry in entries) {
          final fr = entry.value;
          if (fr == null) continue;
          domainResults[entry.key] = fr;
          totalScore += fr.score;
          scoredCount++;
        }

        server.domainResults = domainResults;
        server.freedomScore  = scoredCount > 0 ? totalScore / scoredCount : 0.0;

        // Eliminate servers below minimum freedom threshold
        if ((server.freedomScore ?? 0) < 0.3) {
          server.eliminated = true;
          server.eliminationReason = EliminationReason.lowFreedomScore;
          server.currentStage = ScanStage.eliminated;
        }

        tested++;
        onProgress?.call(ScanProgress(
          stage: ScanStage.stage4Freedom,
          tested: tested,
          total: candidates.length,
          survivors: -1,
          message: 'Freedom score: $tested/${candidates.length}',
          percentage: 0.55 + tested / candidates.length * 0.25,
        ));

        return server;
      },
      concurrency: config.concurrencyStage4,
    );

    // FIX #2 (complete): separate not-eliminated from eliminated BEFORE
    // calling .first on any list. Both .first calls below are now guarded.
    final notEliminated = results
        .where((s) => !s.eliminated)
        .toList()
      ..sort((a, b) => (b.freedomScore ?? 0).compareTo(a.freedomScore ?? 0));

    List<DNSServer> top;
    String progressMsg;

    if (notEliminated.isNotEmpty) {
      top = notEliminated.take(config.stage4KeepTop).toList();
      progressMsg =
          'Stage 4 complete: ${top.length} servers in top cut '
          '(best freedom: ${((top.first.freedomScore ?? 0) * 100).toStringAsFixed(0)}%)';
    } else {
      // All servers scored below the freedom threshold.
      // Surface the least-bad one so the pipeline always produces a result.
      // (The scanner.dart empty-list guard above means results is non-empty
      //  at this point — Stage 1 already bailed out if input was empty.)
      final allSorted = results.toList()
        ..sort((a, b) => (b.freedomScore ?? 0).compareTo(a.freedomScore ?? 0));

      // allSorted is guaranteed non-empty here: candidates was non-empty
      // (scanner.dart stopped early if Stage1/2/3 returned []), and
      // concurrentMap returns one result per input item.
      final fallback = allSorted.first;
      fallback.eliminated = false; // reinstate so Stage 5 processes it
      top = [fallback];
      progressMsg =
          '⚠️ Stage 4: all servers below freedom threshold — '
          'showing best available '
          '(freedom: ${((fallback.freedomScore ?? 0) * 100).toStringAsFixed(0)}%)';
    }

    onProgress?.call(ScanProgress(
      stage: ScanStage.stage4Freedom,
      tested: candidates.length,
      total: candidates.length,
      survivors: top.length,
      message: progressMsg,
      percentage: 0.80,
    ));

    return top;
  }
}
