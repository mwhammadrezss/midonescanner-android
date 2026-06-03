// ================================================================
// MidOne DNS Scanner — Models & Configuration
// ================================================================

import 'dart:math';

enum ScanStage {
  pending,
  stage1Latency,
  stage2aNxdomain,
  stage2bHijack,
  stage3BurstJitter,
  stage4Freedom,
  stage5Doh,
  complete,
  eliminated,
}

enum EliminationReason {
  highLatency,
  nxdomainFailed,
  hijackDetected,
  lowFreedomScore,
  highPacketLoss,
}

class DNSServer {
  final String ip;
  final String? name;
  final String? country;

  double? avgLatencyMs;
  double? minLatencyMs;
  bool? nxdomainClean;
  int? nxdomainResponseCode;
  bool? hijackDetected;
  String? hijackedIp;
  String? hijackedDomain;
  double? jitterMs;
  double? burstSuccessRate;
  double? packetLossRate;
  bool? supportsIPv6;
  double? freedomScore;
  Map<String, FreedomResult>? domainResults;
  int? latencyRank;
  bool? supportsDoH;
  double? dohLatencyMs;
  double? finalScore;
  int? finalRank;

  ScanStage currentStage = ScanStage.pending;
  bool eliminated = false;
  EliminationReason? eliminationReason;

  DNSServer({required this.ip, this.name, this.country});

  @override
  String toString() =>
      'DNS($ip | score=${finalScore?.toStringAsFixed(1) ?? "?"}'
      ' | freedom=${((freedomScore ?? 0) * 100).toStringAsFixed(0)}%'
      ' | latency=${avgLatencyMs?.toStringAsFixed(0) ?? "?"}ms)';
}

class QueryResult {
  final bool success;
  final double latencyMs;
  final int rcode;
  final List<String> aRecords;
  final List<String> aaaaRecords;
  final String? error;

  const QueryResult({
    required this.success,
    required this.latencyMs,
    required this.rcode,
    this.aRecords = const [],
    this.aaaaRecords = const [],
    this.error,
  });

  bool get isNxDomain => rcode == 3;
  bool get isServFail  => rcode == 2;
  bool get isRefused   => rcode == 5;
  bool get isNoError   => rcode == 0;
  bool get hasRecords  => aRecords.isNotEmpty || aaaaRecords.isNotEmpty;

  factory QueryResult.timeout() => const QueryResult(
        success: false, latencyMs: double.infinity, rcode: -1, error: 'timeout');

  factory QueryResult.error(String msg) => QueryResult(
        success: false, latencyMs: double.infinity, rcode: -1, error: msg);
}

class FreedomResult {
  final String domain;
  final bool resolved;
  final bool matchesTruth;
  final String? receivedIp;
  final String? truthIp;

  const FreedomResult({
    required this.domain,
    required this.resolved,
    required this.matchesTruth,
    this.receivedIp,
    this.truthIp,
  });

  double get score {
    if (!resolved) return 0.0;
    if (matchesTruth) return 1.0;
    return 0.5;
  }
}

class ScanProgress {
  final ScanStage stage;
  final int tested;
  final int total;
  final int survivors;
  final String message;
  final double percentage;

  const ScanProgress({
    required this.stage,
    required this.tested,
    required this.total,
    required this.survivors,
    required this.message,
    required this.percentage,
  });
}

class ScanConfig {
  final int stage1KeepTop;
  final int stage3KeepTop;
  final int stage4KeepTop;
  final int stage5KeepTop;
  final Duration queryTimeout;
  final Duration dohTimeout;
  final int burstCount;
  final int latencySamples;
  final int concurrencyStage1;
  final int concurrencyStage2;
  final int concurrencyStage3;
  final int concurrencyStage4;
  final Set<String> knownWallIPs;
  final List<String> freedomDomains;
  final double weightFreedom;
  final double weightLatency;
  final double weightJitter;
  final double weightDoH;
  final List<String> dohProviders;
  final int packetLossProbes;

  /// Iran gaming: prioritize latency/jitter/packet-loss; keep top 2 for apply.
  factory ScanConfig.gamingIran() => const ScanConfig(
        stage1KeepTop: 150,
        stage3KeepTop: 60,
        stage4KeepTop: 15,
        stage5KeepTop: 2,
        weightFreedom: 0.45,
        weightLatency: 0.30,
        weightJitter: 0.25,
        burstCount: 12,
        packetLossProbes: 8,
        freedomDomains: [
          'google.com', 'youtube.com', 'discord.com', 'telegram.org',
          'cloudflare.com', 'steampowered.com', 'epicgames.com',
        ],
      );

  const ScanConfig({
    this.stage1KeepTop   = 200,
    this.stage3KeepTop   = 80,
    this.stage4KeepTop   = 20,
    this.stage5KeepTop   = 5,
    this.queryTimeout    = const Duration(milliseconds: 2000),
    this.dohTimeout      = const Duration(milliseconds: 4000),
    this.burstCount      = 10,
    this.latencySamples  = 3,
    this.concurrencyStage1 = 50,
    this.concurrencyStage2 = 40,
    this.concurrencyStage3 = 30,
    this.concurrencyStage4 = 20,
    this.knownWallIPs    = const {
      '10.10.34.35', '10.10.34.36',
      '185.51.200.2', '5.200.14.70',
    },
    this.freedomDomains  = const [
      'google.com', 'youtube.com', 'twitter.com',
      'instagram.com', 'facebook.com', 'github.com',
      'telegram.org', 'whatsapp.com', 'reddit.com',
      'discord.com',
    ],
    this.weightFreedom   = 0.60,
    this.weightLatency   = 0.20,
    this.weightJitter    = 0.20,
    this.weightDoH       = 0.05,
    this.dohProviders    = const [
      'https://cloudflare-dns.com/dns-query',
      'https://dns.google/resolve',
      'https://dns.quad9.net/dns-query',
    ],
    this.packetLossProbes = 6,
  });

  double get totalWeight => weightFreedom + weightLatency + weightJitter;
}

double stdDev(List<double> values) {
  if (values.length < 2) return 0.0;
  final mean = values.reduce((a, b) => a + b) / values.length;
  final variance = values
      .map((v) => pow(v - mean, 2).toDouble())
      .reduce((a, b) => a + b) / values.length;
  return sqrt(variance);
}

double clamp(double v, double lo, double hi) => v < lo ? lo : (v > hi ? hi : v);
