enum CdnProvider { cloudflare, akamai, google, amazon }

class CdnProviderMeta {
  final CdnProvider provider;
  final String emoji;
  final String label;
  final String fetchUrl;
  final List<String> fallback;

  const CdnProviderMeta({
    required this.provider,
    required this.emoji,
    required this.label,
    required this.fetchUrl,
    required this.fallback,
  });
}

class RangeOption {
  final String cidr;
  final int ipCount;
  final String label;
  final String timeEst;

  const RangeOption({
    required this.cidr,
    required this.ipCount,
    required this.label,
    required this.timeEst,
  });
}

// ── Cloudflare IP ranges ──────────────────────────────────────────────────────
// Sources:
//   1. Official: https://www.cloudflare.com/ips-v4 (15 large blocks)
//   2. IRCF-style sub-ranges: popular /22–/24 sub-blocks used in Iran CDN scanning
//      These are all legitimate sub-ranges of official CF blocks, split for
//      granular scanning (smaller batches = faster results per run).
//
// 172.64.0.0/13 block → broken into /22 sub-ranges (172.64–172.71)
// 104.16.0.0/13 block → broken into /22 sub-ranges (104.16–104.23)
// 104.24.0.0/14 block → broken into /22 sub-ranges (104.24–104.27)
// 104.28.0.0/14 block → /22 sub-ranges (104.28–104.31) — also CF-owned
// 103.x extra blocks → known CF sub-allocations not in the main /22 blocks
const _kCfFallback = [
  // ── 172.64.0.0/13 → /22 sub-ranges (172.64–172.71) ──────────────────────
  '172.64.0.0/22',  '172.64.4.0/22',  '172.64.8.0/22',  '172.64.12.0/22',
  '172.65.0.0/22',  '172.65.4.0/22',  '172.65.8.0/22',  '172.65.12.0/22',
  '172.66.0.0/22',  '172.66.4.0/22',  '172.66.8.0/22',  '172.66.12.0/22',
  '172.67.0.0/22',  '172.67.4.0/22',  '172.67.8.0/22',  '172.67.12.0/22',
  '172.68.0.0/22',  '172.68.4.0/22',  '172.68.8.0/22',  '172.68.12.0/22',
  '172.69.0.0/22',  '172.69.4.0/22',  '172.69.8.0/22',  '172.69.12.0/22',
  '172.70.0.0/22',  '172.70.4.0/22',  '172.70.8.0/22',  '172.70.12.0/22',
  '172.71.0.0/22',  '172.71.4.0/22',

  // ── 104.16.0.0/13 → /22 sub-ranges (104.16–104.23) ──────────────────────
  '104.16.0.0/22',  '104.16.4.0/22',  '104.16.8.0/22',  '104.16.12.0/22',
  '104.17.0.0/22',  '104.17.4.0/22',  '104.17.8.0/22',  '104.17.12.0/22',
  '104.18.0.0/22',  '104.18.4.0/22',  '104.18.8.0/22',  '104.18.12.0/22',
  '104.19.0.0/22',  '104.19.4.0/22',  '104.19.8.0/22',  '104.19.12.0/22',
  '104.20.0.0/22',  '104.20.4.0/22',  '104.20.8.0/22',  '104.20.12.0/22',
  '104.21.0.0/22',  '104.21.4.0/22',  '104.21.8.0/22',  '104.21.12.0/22',
  '104.22.0.0/22',  '104.22.4.0/22',  '104.22.8.0/22',  '104.22.12.0/22',
  '104.23.0.0/22',  '104.23.4.0/22',  '104.23.8.0/22',  '104.23.12.0/22',

  // ── 104.24.0.0/14 → /22 sub-ranges (104.24–104.27) ──────────────────────
  '104.24.0.0/22',  '104.24.4.0/22',  '104.24.8.0/22',  '104.24.12.0/22',
  '104.25.0.0/22',  '104.25.4.0/22',  '104.25.8.0/22',  '104.25.12.0/22',
  '104.26.0.0/22',  '104.26.4.0/22',  '104.26.8.0/22',  '104.26.12.0/22',
  '104.27.0.0/22',  '104.27.4.0/22',  '104.27.8.0/22',  '104.27.12.0/22',

  // ── 104.28.0.0/14 → /22 sub-ranges (104.28–104.31) — CF-owned ───────────
  '104.28.0.0/22',  '104.28.4.0/22',  '104.28.8.0/22',  '104.28.12.0/22',
  '104.29.0.0/22',  '104.29.4.0/22',  '104.29.8.0/22',  '104.29.12.0/22',
  '104.30.0.0/22',  '104.30.4.0/22',  '104.30.8.0/22',  '104.30.12.0/22',
  '104.31.0.0/22',  '104.31.4.0/22',  '104.31.8.0/22',  '104.31.12.0/22',

  // ── Official top-level blocks (kept for completeness / fallback fetch) ───
  '173.245.48.0/20',
  '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
  '141.101.64.0/18', '108.162.192.0/18',
  '190.93.240.0/20', '188.114.96.0/20',
  '197.234.240.0/22', '198.41.128.0/17',
  '162.158.0.0/15',
  '131.0.72.0/22',

  // ── Extra 103.x CF sub-allocations (IRCF / community-verified) ──────────
  '103.160.204.0/22', '103.168.172.0/22',
  '103.172.110.0/22', '103.184.44.0/22',
  '103.204.12.0/22',  '103.235.4.0/22',
];

const kCdnProviders = [
  CdnProviderMeta(
    provider: CdnProvider.cloudflare,
    emoji: '☁️',
    label: 'Cloudflare',
    // Live fetch from official CF — returns 15 large blocks.
    // UI merges them with _kCfFallback sub-ranges so users get both.
    fetchUrl: 'https://www.cloudflare.com/ips-v4',
    fallback: _kCfFallback,
  ),
  CdnProviderMeta(
    provider: CdnProvider.akamai,
    emoji: '🌐',
    label: 'Akamai',
    fetchUrl: '',
    fallback: [
      '23.32.0.0/20',   '23.32.16.0/20',  '23.32.32.0/20',
      '23.64.0.0/20',   '23.64.16.0/20',  '23.64.32.0/20',
      '23.192.0.0/20',  '23.192.16.0/20', '23.192.32.0/20',
      '96.16.0.0/20',   '96.16.16.0/20',  '96.6.0.0/20',
      '92.122.0.0/20',  '92.122.16.0/20', '72.246.0.0/20',
      '72.246.16.0/20', '60.254.0.0/20',  '184.50.0.0/20',
      '184.24.0.0/20',  '2.16.0.0/20',    '2.16.16.0/20',
    ],
  ),
  CdnProviderMeta(
    provider: CdnProvider.google,
    emoji: '🔵',
    label: 'Google',
    fetchUrl: 'https://www.gstatic.com/ipranges/goog.json',
    fallback: [
      '8.8.8.0/24',       '8.34.208.0/20', '8.35.192.0/20',
      '23.236.48.0/20',   '23.251.128.0/19','34.0.0.0/9',
      '34.128.0.0/10',    '35.184.0.0/13', '66.102.0.0/20',
      '66.249.80.0/20',   '72.14.192.0/18','74.125.0.0/16',
      '104.154.0.0/15',   '104.196.0.0/14','108.59.80.0/20',
    ],
  ),
  CdnProviderMeta(
    provider: CdnProvider.amazon,
    emoji: '🟠',
    label: 'Amazon CloudFront',
    fetchUrl: 'https://ip-ranges.amazonaws.com/ip-ranges.json',
    fallback: [
      '13.32.0.0/15',   '13.35.0.0/16',  '52.46.0.0/18',
      '52.84.0.0/15',   '54.182.0.0/16', '54.192.0.0/16',
      '54.230.0.0/16',  '64.252.64.0/18','70.132.0.0/18',
      '99.84.0.0/16',   '143.204.0.0/16','204.246.164.0/22',
      '204.246.168.0/22','205.251.192.0/19','216.137.32.0/19',
    ],
  ),
];
