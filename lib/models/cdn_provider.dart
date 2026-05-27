enum CdnProvider { cloudflare, akamai, google, amazon }

class CdnProviderMeta {
  final CdnProvider provider;
  final String emoji;
  final String label;          // e.g. "Cloudflare"
  final String fetchUrl;       // official URL (empty string if no official URL)
  final List<String> fallback; // hardcoded fallback CIDRs

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
  final int ipCount;       // usable hosts = 2^(32-prefix) - 2
  final String label;     // e.g. "104.16.0.0/20 — 4,094 IPs · ~12m"
  final String timeEst;   // e.g. "~45s" for display next to IP count

  const RangeOption({
    required this.cidr,
    required this.ipCount,
    required this.label,
    required this.timeEst,
  });
}

const kCdnProviders = [
  CdnProviderMeta(
    provider: CdnProvider.cloudflare,
    emoji: '☁️',
    label: 'Cloudflare',
    fetchUrl: 'https://www.cloudflare.com/ips-v4',
    fallback: [
      '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22',
      '103.31.4.0/22',   '141.101.64.0/18', '108.162.192.0/18',
      '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22',
      '198.41.128.0/17', '162.158.0.0/15',  '104.16.0.0/13',
      '104.24.0.0/14',   '172.64.0.0/13',   '131.0.72.0/22',
    ],
  ),
  CdnProviderMeta(
    provider: CdnProvider.akamai,
    emoji: '🌐',
    label: 'Akamai',
    fetchUrl: '',   // No official public URL — always uses fallback
    // Akamai publishes large blocks (/10–/16); we subdivide them into
    // practical /20–/22 sub-ranges (≤4094 IPs each) so selectTopRanges
    // can actually show options instead of filtering everything out.
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
