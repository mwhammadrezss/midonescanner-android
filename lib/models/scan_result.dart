// lib/models/scan_result.dart

/// Phase labels for pipeline
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

/// Soft usability classification — permissive, not elitist
enum IpTier {
  excellent,  // 20s+ survived
  good,       // 10s+ survived
  usable,     // 5s+ survived (TLS ok, short survival)
  weak,       // TLS handshake only, no survival
  dead,       // TCP/TLS fail
}

class ScanResult {
  final String    ip;
  final double    latencyMs;     // TCP + TLS combined (user-facing)
  final double    jitterMs;
  final bool      isAlive;
  final String    grade;
  final String    country;
  final String    flag;
  final int       loss;
  final double    reliability;

  // ── Survival fields ──────────────────────────────────────────────────────
  final double?   score;
  final int?      survivalMs;
  final int       retransmits;
  final ScanPhase phase;
  final IpTier    tier;

  // ── Bandwidth & SNI fields ───────────────────────────────────────────────
  final double?   speedKBs;
  final String?   sniUsed;

  // ── Diagnostic breakdown (separate TCP/TLS latency) ──────────────────────
  final double?   tcpLatencyMs;
  final double?   tlsHandshakeMs;

  // ── p16: DPI suspicion score (0.0 = clean, 1.0 = very likely DPI) ────────
  final double    dpiSuspicion;

  // ── p20: Confidence score — how trustworthy is this result ───────────────
  final double?   confidenceScore;

  // ── p24: Real usability index — survival + reliability + handshake speed ─
  final double?   realUsabilityIndex;

  // ── Cloudflare HTTP fields ────────────────────────────────────────────────
  // Populated when SNI is Cloudflare family (speed.cloudflare.com / cloudflare.com).
  // httpStatus: HTTP status from /cdn-cgi/trace (-1 = request failed, null = not attempted)
  // colo:       CF datacenter code e.g. "FRA" (null = not detected or not attempted)
  final int?      httpStatus;
  final String?   colo;

  // ── ws2: WebSocket DPI test field ─────────────────────────────────────────
  // Populated when SNI is Cloudflare family and cfHttpProbe confirmed a live CF edge.
  // wsOk: true = WebSocket-grade TLS survived idle hold + WS upgrade (DPI-permissive)
  //       false = connection was killed (DPI present)
  //       null = not attempted (non-CF SNI or HTTP probe failed)
  // Mirrors SenPai WSOk field.
  final bool?     wsOk;

  // ── Deep scan CDN fields ──────────────────────────────────────────────────
  // Populated by runDeepScanEngine (7-stage pipeline).
  // bestFamily: best CDN family name e.g. 'Cloudflare', 'Google', 'Akamai'
  // h2Supported: true = ALPN negotiated 'h2' during Stage 4
  final String?   bestFamily;
  final bool?     h2Supported;

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
    this.tier  = IpTier.dead,
    this.speedKBs,
    this.sniUsed,
    this.tcpLatencyMs,
    this.tlsHandshakeMs,
    this.dpiSuspicion = 0.0,
    this.confidenceScore,
    this.realUsabilityIndex,
    this.httpStatus,
    this.colo,
    this.wsOk,
    this.bestFamily,
    this.h2Supported,
  });

  String get phaseLabel {
    switch (phase) {
      case ScanPhase.tcpFail:        return 'TCP Fail';
      case ScanPhase.tlsFail:        return 'TLS Fail';
      case ScanPhase.handshakeFail:  return 'Handshake';
      case ScanPhase.completionFail: return 'TLS Incomplete';
      case ScanPhase.survivalFail:   return 'Weak';
      case ScanPhase.stabilityFail:  return 'Unstable';
      case ScanPhase.dpiFail:        return 'DPI Killed';
      case ScanPhase.passed:         return 'Passed \u2713';
    }
  }

  String get tierLabel {
    switch (tier) {
      case IpTier.excellent: return '\u2605\u2605\u2605 Excellent';
      case IpTier.good:      return '\u2605\u2605 Good';
      case IpTier.usable:    return '\u2605 Usable';
      case IpTier.weak:      return 'Weak';
      case IpTier.dead:      return 'Dead';
    }
  }
}
