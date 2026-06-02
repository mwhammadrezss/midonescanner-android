import 'dart:io';
import 'dart:typed_data';
import 'package:flutter/services.dart' show rootBundle;

// ─── Country code → name map ────────────────────────────────────────────────

const Map<String, String> _countryNames = {
  'AF': 'Afghanistan',   'AL': 'Albania',       'DZ': 'Algeria',
  'AD': 'Andorra',       'AO': 'Angola',        'AG': 'Antigua',
  'AR': 'Argentina',     'AM': 'Armenia',       'AU': 'Australia',
  'AT': 'Austria',       'AZ': 'Azerbaijan',    'BS': 'Bahamas',
  'BH': 'Bahrain',       'BD': 'Bangladesh',    'BB': 'Barbados',
  'BY': 'Belarus',       'BE': 'Belgium',       'BZ': 'Belize',
  'BJ': 'Benin',         'BT': 'Bhutan',        'BO': 'Bolivia',
  'BA': 'Bosnia',        'BW': 'Botswana',      'BR': 'Brazil',
  'BN': 'Brunei',        'BG': 'Bulgaria',      'BF': 'Burkina Faso',
  'BI': 'Burundi',       'CV': 'Cape Verde',    'KH': 'Cambodia',
  'CM': 'Cameroon',      'CA': 'Canada',        'CF': 'C. Africa',
  'TD': 'Chad',          'CL': 'Chile',         'CN': 'China',
  'CO': 'Colombia',      'KM': 'Comoros',       'CG': 'Congo',
  'CD': 'DR Congo',      'CR': 'Costa Rica',    'HR': 'Croatia',
  'CU': 'Cuba',          'CY': 'Cyprus',        'CZ': 'Czechia',
  'DK': 'Denmark',       'DJ': 'Djibouti',      'DO': 'Dominican R.',
  'EC': 'Ecuador',       'EG': 'Egypt',         'SV': 'El Salvador',
  'GQ': 'Eq. Guinea',    'ER': 'Eritrea',       'EE': 'Estonia',
  'SZ': 'Eswatini',      'ET': 'Ethiopia',      'FJ': 'Fiji',
  'FI': 'Finland',       'FR': 'France',        'GA': 'Gabon',
  'GM': 'Gambia',        'GE': 'Georgia',       'DE': 'Germany',
  'GH': 'Ghana',         'GR': 'Greece',        'GD': 'Grenada',
  'GT': 'Guatemala',     'GN': 'Guinea',        'GW': 'Guinea-Bissau',
  'GY': 'Guyana',        'HT': 'Haiti',         'HN': 'Honduras',
  'HK': 'Hong Kong',     'HU': 'Hungary',       'IS': 'Iceland',
  'IN': 'India',         'ID': 'Indonesia',     'IR': 'Iran',
  'IQ': 'Iraq',          'IE': 'Ireland',       'IL': 'Israel',
  'IT': 'Italy',         'JM': 'Jamaica',       'JP': 'Japan',
  'JO': 'Jordan',        'KZ': 'Kazakhstan',    'KE': 'Kenya',
  'KI': 'Kiribati',      'KW': 'Kuwait',        'KG': 'Kyrgyzstan',
  'LA': 'Laos',          'LV': 'Latvia',        'LB': 'Lebanon',
  'LS': 'Lesotho',       'LR': 'Liberia',       'LY': 'Libya',
  'LI': 'Liechtenstein', 'LT': 'Lithuania',     'LU': 'Luxembourg',
  'MG': 'Madagascar',    'MW': 'Malawi',        'MY': 'Malaysia',
  'MV': 'Maldives',      'ML': 'Mali',          'MT': 'Malta',
  'MH': 'Marshall Is.',  'MR': 'Mauritania',    'MU': 'Mauritius',
  'MX': 'Mexico',        'FM': 'Micronesia',    'MD': 'Moldova',
  'MC': 'Monaco',        'MN': 'Mongolia',      'ME': 'Montenegro',
  'MA': 'Morocco',       'MZ': 'Mozambique',    'MM': 'Myanmar',
  'NA': 'Namibia',       'NR': 'Nauru',         'NP': 'Nepal',
  'NL': 'Netherlands',   'NZ': 'New Zealand',   'NI': 'Nicaragua',
  'NE': 'Niger',         'NG': 'Nigeria',       'KP': 'North Korea',
  'MK': 'N. Macedonia',  'NO': 'Norway',        'OM': 'Oman',
  'PK': 'Pakistan',      'PW': 'Palau',         'PA': 'Panama',
  'PG': 'Papua NG',      'PY': 'Paraguay',      'PE': 'Peru',
  'PH': 'Philippines',   'PL': 'Poland',        'PT': 'Portugal',
  'QA': 'Qatar',         'RO': 'Romania',       'RU': 'Russia',
  'RW': 'Rwanda',        'KN': 'Saint Kitts',   'LC': 'Saint Lucia',
  'VC': 'St. Vincent',   'WS': 'Samoa',         'SM': 'San Marino',
  'ST': 'Sao Tome',      'SA': 'Saudi Arabia',  'SN': 'Senegal',
  'RS': 'Serbia',        'SC': 'Seychelles',    'SL': 'Sierra Leone',
  'SG': 'Singapore',     'SK': 'Slovakia',      'SI': 'Slovenia',
  'SB': 'Solomon Is.',   'SO': 'Somalia',       'ZA': 'South Africa',
  'SS': 'South Sudan',   'ES': 'Spain',         'LK': 'Sri Lanka',
  'SD': 'Sudan',         'SR': 'Suriname',      'SE': 'Sweden',
  'CH': 'Switzerland',   'SY': 'Syria',         'TW': 'Taiwan',
  'TJ': 'Tajikistan',    'TZ': 'Tanzania',      'TH': 'Thailand',
  'TL': 'Timor-Leste',   'TG': 'Togo',          'TO': 'Tonga',
  'TT': 'Trinidad',      'TN': 'Tunisia',       'TR': 'Turkey',
  'TM': 'Turkmenistan',  'TV': 'Tuvalu',        'UG': 'Uganda',
  'UA': 'Ukraine',       'AE': 'UAE',           'GB': 'UK',
  'US': 'USA',           'UY': 'Uruguay',       'UZ': 'Uzbekistan',
  'VU': 'Vanuatu',       'VE': 'Venezuela',     'VN': 'Vietnam',
  'YE': 'Yemen',         'ZM': 'Zambia',        'ZW': 'Zimbabwe',
  'TF': 'Fr. Territories',
};

String countryName(String code) => _countryNames[code.toUpperCase()] ?? code;

String codeToFlag(String code) {
  if (code.length != 2) return '🌐';
  final upper = code.toUpperCase();
  try {
    return String.fromCharCode(upper.codeUnitAt(0) + 127397) +
           String.fromCharCode(upper.codeUnitAt(1) + 127397);
  } catch (_) {
    return '🌐';
  }
}

// ─── GeoIP Offline ─────────────────────────────────────────────────────────

class GeoIPOffline {
  static final GeoIPOffline _instance = GeoIPOffline._();
  factory GeoIPOffline() => _instance;
  GeoIPOffline._();

  Uint32List? _starts;
  Uint32List? _ends;
  List<String>? _codes;
  bool _loading = false;
  bool _loaded = false;

  /// Initialize directly from raw bytes — for use inside Dart Isolates
  /// where rootBundle is unavailable.
  void initWithBytes(Uint8List bytes) {
    if (_loaded) return;
    const recSize = 10;
    final count = bytes.length ~/ recSize;
    final starts = Uint32List(count);
    final ends   = Uint32List(count);
    final codes  = List<String>.filled(count, '');
    for (int i = 0; i < count; i++) {
      final off = i * recSize;
      starts[i] = ((bytes[off]   & 0xFF) << 24) |
                  ((bytes[off+1] & 0xFF) << 16) |
                  ((bytes[off+2] & 0xFF) <<  8) |
                   (bytes[off+3] & 0xFF);
      ends[i]   = ((bytes[off+4] & 0xFF) << 24) |
                  ((bytes[off+5] & 0xFF) << 16) |
                  ((bytes[off+6] & 0xFF) <<  8) |
                   (bytes[off+7] & 0xFF);
      codes[i]  = String.fromCharCodes([bytes[off+8], bytes[off+9]]).trim();
    }
    _starts = starts;
    _ends   = ends;
    _codes  = codes;
    _loaded = true;
  }

  /// Returns the raw binary data if already loaded, null otherwise.
  /// Used to pass geo data to Isolates by value.
  Uint8List? getLoadedBytes() {
    if (!_loaded || _starts == null) return null;
    final count = _starts!.length;
    const recSize = 10;
    final buf = Uint8List(count * recSize);
    for (int i = 0; i < count; i++) {
      final off = i * recSize;
      final s = _starts![i];
      final e = _ends![i];
      buf[off]   = (s >> 24) & 0xFF;
      buf[off+1] = (s >> 16) & 0xFF;
      buf[off+2] = (s >>  8) & 0xFF;
      buf[off+3] =  s        & 0xFF;
      buf[off+4] = (e >> 24) & 0xFF;
      buf[off+5] = (e >> 16) & 0xFF;
      buf[off+6] = (e >>  8) & 0xFF;
      buf[off+7] =  e        & 0xFF;
      final code = _codes![i].padRight(2).substring(0, 2);
      buf[off+8] = code.codeUnitAt(0);
      buf[off+9] = code.codeUnitAt(1);
    }
    return buf;
  }

  Future<void> load() async {
    if (_loaded || _loading) return;
    _loading = true;
    try {
      final bytes = await rootBundle.load('assets/geo/ipcountry.bin');
      final buf = bytes.buffer.asUint8List();
      const recSize = 10; // 4 + 4 + 2
      final count = buf.length ~/ recSize;
      final starts = Uint32List(count);
      final ends   = Uint32List(count);
      final codes  = List<String>.filled(count, '');
      for (int i = 0; i < count; i++) {
        final off = i * recSize;
        // Big-endian uint32
        starts[i] = ((buf[off]   & 0xFF) << 24) |
                    ((buf[off+1] & 0xFF) << 16) |
                    ((buf[off+2] & 0xFF) <<  8) |
                     (buf[off+3] & 0xFF);
        ends[i]   = ((buf[off+4] & 0xFF) << 24) |
                    ((buf[off+5] & 0xFF) << 16) |
                    ((buf[off+6] & 0xFF) <<  8) |
                     (buf[off+7] & 0xFF);
        codes[i]  = String.fromCharCodes([buf[off+8], buf[off+9]]).trim();
      }
      _starts = starts;
      _ends   = ends;
      _codes  = codes;
      _loaded = true;
    } catch (_) {
      _loading = false;
    }
  }

  static int _ipToInt(String ip) {
    final parts = ip.split('.');
    if (parts.length != 4) return 0;
    int n = 0;
    for (final p in parts) {
      n = (n << 8) | (int.tryParse(p) ?? 0);
    }
    // Dart integers are 64-bit — mask to 32 bits for correct comparison
    return n & 0xFFFFFFFF;
  }

  String lookupCode(String ip) {
    if (!_loaded || _starts == null) return '';
    int n;
    try { n = _ipToInt(ip); } catch (_) { return ''; }
    int lo = 0, hi = _starts!.length - 1;
    while (lo <= hi) {
      final mid = (lo + hi) >> 1;
      final s = _starts![mid];
      final e = _ends![mid];
      if (n < s) {
        hi = mid - 1;
      } else if (n > e) {
        lo = mid + 1;
      } else {
        return _codes![mid];
      }
    }
    return '';
  }

  (String, String) lookupFull(String ip) {
    final code = lookupCode(ip);
    if (code.isEmpty) return ('', '🌐');
    return (countryName(code), codeToFlag(code));
  }
}

// ─── ISP Detection (چند fallback، فیلتر-مقاوم) ────────────────────────────

const Map<String, String> _iranIsps = {
  'hamrahe aval': 'همراه اول',
  'mci': 'همراه اول',
  'irancell': 'ایرانسل',
  'mtn irancell': 'ایرانسل',
  'rightel': 'رایتل',
  'shatel': 'شاتل',
  'mokhaberat': 'مخابرات',
  'asiatech': 'آسیاتک',
  'parsonline': 'پارس‌آنلاین',
  'afranet': 'افرانت',
  'pishgaman': 'پیشگامان',
  'respina': 'رسپینا',
  'tci': 'مخابرات',
  'itc': 'مخابرات',
};

String _normalizeIsp(String raw) {
  if (raw.isEmpty) return 'Unknown ISP';
  final lower = raw.toLowerCase();
  for (final entry in _iranIsps.entries) {
    if (lower.contains(entry.key)) return entry.value;
  }
  // برش متن طولانی
  return raw.length > 25 ? raw.substring(0, 25) : raw;
}

/// Tries multiple endpoints in order (فیلتر-مقاوم)
Future<String> detectIspName() async {
  // ── Endpoint 1: ipinfo.io/org (HTTPS — معمولاً از ایران در دسترسه) ──────
  try {
    final socket = await SecureSocket.connect(
      'ipinfo.io', 443,
      onBadCertificate: (_) => true,
      timeout: const Duration(seconds: 6),
    );
    const req =
        'GET /org HTTP/1.1\r\n'
        'Host: ipinfo.io\r\n'
        'User-Agent: curl/7.68.0\r\n'
        'Accept: */*\r\n'
        'Connection: close\r\n\r\n';
    socket.write(req);
    final buf = StringBuffer();
    try {
      await socket.listen((d) {
        buf.write(String.fromCharCodes(d));
        if (buf.toString().contains('\r\n\r\n')) throw 'done';
      }).asFuture().timeout(const Duration(seconds: 4));
    } catch (_) {}
    await socket.close();
    final resp = buf.toString();
    final sep = resp.indexOf('\r\n\r\n');
    if (sep >= 0) {
      final body = resp.substring(sep + 4).trim();
      // مثلاً: "AS44244 Iran Cell Service and Communication Company"
      // FIX#5: guard — skip JSON/HTML error responses (429, rate-limit, etc.)
      if (!body.startsWith('{') && !body.startsWith('<')) {
        final spaceIdx = body.indexOf(' ');
        if (spaceIdx > 0) {
          return _normalizeIsp(body.substring(spaceIdx + 1));
        }
      }
    }
  } catch (_) {}

  // ── Endpoint 2: ip-api.com/json (HTTP — سریع‌تره) ──────────────────────
  try {
    final socket = await Socket.connect(
      'ip-api.com', 80,
      timeout: const Duration(seconds: 5),
    );
    const req =
        'GET /json/?fields=isp HTTP/1.1\r\n'
        'Host: ip-api.com\r\n'
        'User-Agent: curl/7.68.0\r\n'
        'Connection: close\r\n\r\n';
    socket.write(req);
    final buf = StringBuffer();
    try {
      await socket.listen((d) {
        buf.write(String.fromCharCodes(d));
        if (buf.toString().contains('"isp"')) throw 'done';
      }).asFuture().timeout(const Duration(seconds: 4));
    } catch (_) {}
    socket.destroy();
    final match = RegExp(r'"isp"\s*:\s*"([^"]+)"').firstMatch(buf.toString());
    if (match != null) return _normalizeIsp(match.group(1) ?? '');
  } catch (_) {}

  // ── Endpoint 3: ipapi.co (HTTPS) ───────────────────────────────────────
  try {
    final socket = await SecureSocket.connect(
      'ipapi.co', 443,
      onBadCertificate: (_) => true,
      timeout: const Duration(seconds: 5),
    );
    const req =
        'GET /org HTTP/1.1\r\n'
        'Host: ipapi.co\r\n'
        'User-Agent: curl/7.68.0\r\n'
        'Connection: close\r\n\r\n';
    socket.write(req);
    final buf = StringBuffer();
    try {
      await socket.listen((d) {
        buf.write(String.fromCharCodes(d));
        if (buf.toString().contains('\r\n\r\n')) throw 'done';
      }).asFuture().timeout(const Duration(seconds: 4));
    } catch (_) {}
    await socket.close();
    final resp = buf.toString();
    final sep = resp.indexOf('\r\n\r\n');
    if (sep >= 0) {
      final body = resp.substring(sep + 4).trim();
      // FIX#5: guard — skip JSON/HTML error responses (429, rate-limit, etc.)
      if (!body.startsWith('{') && !body.startsWith('<')) {
        final spaceIdx = body.indexOf(' ');
        if (spaceIdx > 0) return _normalizeIsp(body.substring(spaceIdx + 1));
      }
    }
  } catch (_) {}

  return 'Unknown ISP';
}
