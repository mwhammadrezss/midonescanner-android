// lib/models/scan_result.dart

/// Phase labels for 8-step pipeline
enum ScanPhase {
  tcpFail,
  tlsFail,
  handshakeFail,
  completionFail,
  survivalFail,
  stabilityFail,
  dpiFail,
  passed,
}

class ScanResult {
  final String    ip;
  final double    latencyMs;
  final double    jitterMs;
  final bool      isAlive;
  final String    grade;
  final String    country;
  final String    flag;
  final int       loss;
  final double    reliability;

  // ── Survival fields ──────────────────────────────────────────────────────
  final double?   score;          // 0-100 weighted score
  final int?      survivalMs;     // how long tunnel stayed alive (ms)
  final int       retransmits;    // TCP retransmit count
  final ScanPhase phase;          // furthest phase reached

  // ── Bandwidth & SNI fields ───────────────────────────────────────────────
  final double?   speedKBs;       // download speed in KB/s (null if not tested)
  final String?   sniUsed;        // which SNI gave the best result

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
    this.score,
    this.survivalMs,
    this.retransmits = 0,
    this.phase = ScanPhase.tcpFail,
    this.speedKBs,
    this.sniUsed,
  });

  /// Human-readable phase label shown in UI
  String get phaseLabel {
    switch (phase) {
      case ScanPhase.tcpFail:        return 'TCP Fail';
      case ScanPhase.tlsFail:        return 'TLS Fail';
      case ScanPhase.handshakeFail:  return 'Handshake';
      case ScanPhase.completionFail: return 'TLS Incomplete';
      case ScanPhase.survivalFail:   return 'No Survival';
      case ScanPhase.stabilityFail:  return 'Unstable';
      case ScanPhase.dpiFail:        return 'DPI Killed';
      case ScanPhase.passed:         return 'Passed ✓';
    }
  }
}
