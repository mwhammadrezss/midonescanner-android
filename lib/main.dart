import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_local_notifications/flutter_local_notifications.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:path_provider/path_provider.dart';
import 'package:url_launcher/url_launcher.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'engine/scanner_engine.dart';
import 'engine/probe_engine.dart' show kDeepSniPresets;
import 'models/scan_result.dart' show ScanPhase, IpTier;
import 'utils/ip_utils.dart' show validateAndExtractIps;
import 'geoip.dart';
import 'utils/scan_profiles.dart';
import 'utils/logger.dart';
import 'engine/subnet_cache.dart';
import 'models/cdn_provider.dart';
import 'engine/range_engine.dart';
import 'storage/range_scan_storage.dart';
import 'engine/range_ip_sampler.dart';
import 'ui/range/range_history_page.dart';

// ─── Notifications ──────────────────────────────────────────────────────────

final _notifPlugin = FlutterLocalNotificationsPlugin();

Future<void> initNotifications() async {
  const androidSettings = AndroidInitializationSettings('@mipmap/ic_launcher');
  const settings = InitializationSettings(android: androidSettings);
  await _notifPlugin.initialize(settings);
}

Future<void> sendNotification(String title, String body) async {
  const androidDetails = AndroidNotificationDetails(
    'midone_scan', 'Scan Progress',
    channelDescription: 'MidONe Scanner progress notifications',
    importance: Importance.defaultImportance,
    priority: Priority.defaultPriority,
    showWhen: false,
  );
  const details = NotificationDetails(android: androidDetails);
  await _notifPlugin.show(0, title, body, details);
}

// ─── Forest Green Theme ─────────────────────────────────────────────────────

const bgColor      = Color(0xFF0A1A0F);
const cardColor    = Color(0xFF112216);
const card2Color   = Color(0xFF0D1A11);
const cardInner    = Color(0xFF1A3020);
const accentLime   = Color(0xFFC6F135);
const accentLime2  = Color(0xFFA8D400);
const textPrimary  = Color(0xFFFFFFFF);
const textSecond   = Color(0xFF8A9E8E);
const iconBg       = Color(0xFF1E3525);
const borderColor  = Color(0xFF2A4A30);
const statusGreen  = Color(0xFF1A3A1E);
const statusRed    = Color(0xFF3A1A1A);
const statusOrange = Color(0xFF3A2A1A);

Color gradeColor(ScanResult r) {
  if (!r.isAlive) return const Color(0xFFFF5252);
  switch (r.grade) {
    case 'A': return accentLime;
    case 'B': return const Color(0xFF80E060);
    case 'C': return const Color(0xFFE0E060);
    case 'D': return const Color(0xFFE0A060);
    default:  return const Color(0xFFFF5252);
  }
}

Color tierColor(IpTier tier) {
  switch (tier) {
    case IpTier.excellent: return accentLime;
    case IpTier.good:      return const Color(0xFF80E060);
    case IpTier.usable:    return const Color(0xFFFFD060);
    case IpTier.weak:      return const Color(0xFFFF8C40);
    case IpTier.dead:      return const Color(0xFFFF5252);
  }
}

// ─── App ────────────────────────────────────────────────────────────────────

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // p46: globalErrorBoundary
  FlutterError.onError = (details) {
    StructuredLogger().log(
      phase: 'flutter_error',
      ip: 'app',
      error: details.exception.toString(),
    );
  };

  await initNotifications();
  GeoIPOffline().load();
  runApp(const MidOneScannerApp());
}

class MidOneScannerApp extends StatelessWidget {
  const MidOneScannerApp({super.key});
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'MidONe Scanner SK',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        brightness: Brightness.dark,
        scaffoldBackgroundColor: bgColor,
        colorScheme: const ColorScheme.dark(
          primary: accentLime, secondary: accentLime2, surface: cardColor,
        ),
        textTheme: GoogleFonts.interTextTheme(ThemeData.dark().textTheme),
      ),
      home: const HomeScreen(),
    );
  }
}

// ─── Home Screen ────────────────────────────────────────────────────────────

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});
  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

// p50: AppLifecycleObserver mixin
class _HomeScreenState extends State<HomeScreen> with WidgetsBindingObserver {
  int _tab = 0;
  int _mode = 1;
  bool _scanning = false;
  bool _cancelled = false;
  bool _paused = false;         // p44: pause/resume
  int _done = 0, _total = 0, _okCount = 0, _thrCount = 0, _failCount = 0;
  int _prefilterLive = 0, _prefilterTotal = 0;
  bool _prefiltering = false;

  final _ipController = TextEditingController();
  List<ScanResult> _results = [];
  String _statusText = 'Ready to scan...';
  String _sortBy = 'latency';
  // BUG 9 FIX: removed _filterThrottled — dead code, no UI toggle existed.
  // The 'alive' advanced filter covers this use case.

  // p39: advanced filters
  String _advancedFilter = 'all'; // 'all', 'excellent', 'low_rtt', 'alive', 'ws_ok', 'ws_fail'
  String _coloFilter    = '';    // empty = all colos; e.g. 'FRA', 'AMS' — case-insensitive

  // p45: compact mode
  bool _compactMode = false;

  // p54: scan profile
  String _selectedProfile = 'balanced';

  // CDN profile for Normal mode
  String _normalCdnProfile = 'cdn_akamai'; // 'cdn_akamai' or 'cloudflare'

  // p55: hidden dev mode
  // BUG 10 FIX: added timestamp to enforce 2-second tap window
  int _titleTapCount = 0;
  DateTime? _lastTitleTap;
  bool _devMode = false;

  // p43: ETA
  DateTime? _scanStartTime;

  // p36: live metrics
  int _dpiKills = 0;

  // Deep mode SNI selection
  Set<String> _selectedSnis = {'www.google.com'};
  final _customSniController = TextEditingController();

  // Range v2 state
  String _rangeCdnProfile = 'cloudflare'; // 'cloudflare' or 'akamai'
  List<String> _rangeCidrs = [];
  String? _selectedRangeCidr;
  bool _loadingRangeCidrs = false;
  final _randomCountController = TextEditingController(text: '5000');
  int _scannedIpMemoryCount = 0;

  // Batched UI updates
  Timer? _batchTimer;
  final _pendingResults = <ScanResult>[];
  int _lastNotifPct = -1;

  // Sorted results cache
  bool _displayDirty = true;
  List<ScanResult> _cachedDisplay = [];

  // ISP & ping
  String _ispName = 'در حال بررسی...';
  String _pingText = 'Ping: -- ms';
  Timer? _ispTimer;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this); // p50
    _showWelcomePopupIfNeeded();
    _detectIsp();
    _ispTimer = Timer.periodic(const Duration(seconds: 30), (_) => _detectIsp());
    RangeScanStorage().scannedIpCount().then((count) {
      if (mounted) setState(() => _scannedIpMemoryCount = count);
    });
    // Use addPostFrameCallback so setState inside _loadRangeCidrs
    // runs after the first build frame — avoids setState-in-initState warning.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted) _loadRangeCidrs();
    });
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this); // p50
    _ispTimer?.cancel();
    _batchTimer?.cancel();
    _batchTimer = null;
    _customSniController.dispose();
    _ipController.dispose();
    _randomCountController.dispose();
    super.dispose();
  }

  // p50: graceful app lifecycle
  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.detached && _scanning) {
      _stopScan();
    }
  }

  Future<void> _detectIsp() async {
    final isp = await detectIspName();
    if (!mounted) return;
    setState(() { _ispName = 'اپراتور: $isp'; });
    _measurePing();
  }

  // BUG 8 FIX: properly destroy socket in finally to prevent native resource leak
  Future<void> _measurePing() async {
    SecureSocket? sock;
    try {
      final t = DateTime.now();
      sock = await SecureSocket.connect(
        '8.8.8.8', 443,
        onBadCertificate: (_) => true,
        timeout: const Duration(seconds: 3),
      );
      final ms = DateTime.now().difference(t).inMilliseconds;
      if (mounted) setState(() => _pingText = 'Ping: $ms ms');
    } catch (_) {
      if (mounted) setState(() => _pingText = 'Ping: -- ms');
    } finally {
      try { await sock?.close(); } catch (_) {}
      sock?.destroy();
    }
  }

  Future<void> _showWelcomePopupIfNeeded() async {
    final prefs = await SharedPreferences.getInstance();
    final shown = prefs.getBool('welcome_shown') ?? false;
    if (!shown && mounted) {
      await Future.delayed(const Duration(milliseconds: 600));
      if (mounted) _showWelcomeDialog();
      await prefs.setBool('welcome_shown', true);
    }
  }

  void _showWelcomeDialog() {
    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => Dialog(
        backgroundColor: cardColor,
        shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(24),
            side: const BorderSide(color: borderColor)),
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Image.asset('assets/icons/app_icon.png', width: 72, height: 72),
              const SizedBox(height: 16),
              Text('MidONe Scanner',
                  style: GoogleFonts.inter(
                      color: accentLime, fontWeight: FontWeight.w800, fontSize: 20)),
              const SizedBox(height: 8),
              // BUG 11 FIX: explicit RTL for Persian strings in welcome dialog
              Text('به کانال تلگرام ما بپیوندید!',
                  textDirection: TextDirection.rtl,
                  style: GoogleFonts.inter(
                      color: textPrimary, fontWeight: FontWeight.w700, fontSize: 15)),
              const SizedBox(height: 10),
              Text(
                'برای دریافت آخرین بروزرسانی و آی‌پی‌های جدید به کانال تلگرام ما جوین بشید.',
                textAlign: TextAlign.center,
                textDirection: TextDirection.rtl,
                style: GoogleFonts.inter(color: textSecond, fontSize: 13, height: 1.5),
              ),
              const SizedBox(height: 20),
              SizedBox(
                width: double.infinity,
                height: 48,
                child: ElevatedButton(
                  onPressed: () async {
                    final uri = Uri.parse('https://t.me/mmdrlx');
                    if (await canLaunchUrl(uri)) {
                      await launchUrl(uri, mode: LaunchMode.externalApplication);
                    }
                  },
                  style: ElevatedButton.styleFrom(
                    backgroundColor: accentLime,
                    foregroundColor: bgColor,
                    shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(14)),
                    elevation: 0,
                  ),
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Image.asset('assets/icons/telegram_icon.png', width: 20, height: 20),
                      const SizedBox(width: 8),
                      // BUG 11 FIX: RTL for mixed Persian/Latin button text
                      Text('جوین به @mmdrlx',
                          textDirection: TextDirection.rtl,
                          style: GoogleFonts.inter(
                              fontWeight: FontWeight.w800, fontSize: 14)),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 10),
              TextButton(
                onPressed: () => Navigator.pop(ctx),
                // BUG 11 FIX: RTL for Persian 'بعداً'
                child: Text('بعداً',
                    textDirection: TextDirection.rtl,
                    style: GoogleFonts.inter(color: textSecond, fontSize: 13)),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Future<void> _startScan() async {
    // ── Range mode ──────────────────────────────────────────────────────────
    if (_mode == 3) {
      if (_selectedRangeCidr == null) {
        _showSnack('Please select a CIDR range first.');
        return;
      }
      final requestedCount =
          int.tryParse(_randomCountController.text.trim()) ?? 5000;
      if (requestedCount < 1 || requestedCount > 500000) {
        _showSnack('Enter a number between 1 and 500,000.');
        return;
      }

      // Lock the scan button immediately — awaits below would leave it
      // unlocked for the duration of IP sampling, allowing double-taps.
      if (_scanning) return;
      setState(() {
        _scanning = true;
        _cancelled = false;
        _statusText = 'Building random IP sample...';
      });

      try {
        final alreadyScanned = await RangeScanStorage().loadScannedIps();

        final sampledIps = await RangeIpSampler.sample(
          allCidrs: [_selectedRangeCidr!],
          requestedCount: requestedCount,
          alreadyScanned: alreadyScanned,
        );

        if (sampledIps.isEmpty) {
          setState(() {
            _scanning = false;
            _statusText = 'All IPs in this range already scanned.';
          });
          _showSnack('No new IPs to scan. Go to History → Reset to start fresh.');
          return;
        }

        final bool isCf = _rangeCdnProfile == 'cloudflare';
        _runScan(
          sampledIps,
          null,
          isRangeScan: true,
          rangeCfMode: isCf,
          rangeCidr: _selectedRangeCidr,
          rangeRequestedCount: requestedCount,
        );
      } catch (e) {
        setState(() {
          _scanning = false;
          _statusText = 'Error preparing scan: $e';
        });
        _showSnack('Error: $e');
      }
      return;
    }

    // ── Normal / Deep mode (unchanged) ─────────────────────────────────────
    final ips = validateAndExtractIps(_ipController.text);
    if (ips.isEmpty) { _showSnack('No valid IPs found!'); return; }
    if (_mode == 2) {
      _showSniPickerDialog(ips);
      return;
    }
    _runScan(ips, null);
  }

  void _startBatchTimer() {
    _batchTimer?.cancel();
    _batchTimer = Timer.periodic(const Duration(milliseconds: 250), (_) {
      if (!mounted) { _batchTimer?.cancel(); return; }
      if (_pendingResults.isEmpty) return;
      setState(() {
        for (final r in _pendingResults) {
          _results.add(r);
          if (r.tier == IpTier.excellent || r.tier == IpTier.good) {
            _okCount++;
          } else if (r.tier == IpTier.usable || r.tier == IpTier.weak) {
            _thrCount++;
          } else {
            _failCount++;
          }
          // p36: count DPI kills
          if (r.phase == ScanPhase.dpiFail) _dpiKills++;
        }
        _pendingResults.clear();
        _displayDirty = true;
        final pct = _total > 0 ? (_done / _total * 100).round() : 0;
        _statusText = 'Scanning $pct% — ETA ${_calcEta()}';
      });
    });
  }

  void _stopBatchTimer() {
    _batchTimer?.cancel();
    _batchTimer = null;
    if (_pendingResults.isNotEmpty && mounted) {
      setState(() {
        _results.addAll(_pendingResults);
        _pendingResults.clear();
        _displayDirty = true;
      });
    }
  }

  void _runScan(List<String> ips, List<String>? deepSnis, {
    bool isRangeScan = false,
    bool rangeCfMode = false,
    String? rangeCidr,
    int? rangeRequestedCount,
  }) {
    _batchTimer?.cancel();
    _pendingResults.clear();
    _lastNotifPct = -1;
    _scanStartTime = DateTime.now(); // p43
    _dpiKills = 0; // p36 reset
    // BUG 6 FIX: resolve active profile and pass concurrency to engine
    // Range mode doesn't show SCAN PROFILE card → use fixed concurrency of 8
    final activeProfile = getProfile(_selectedProfile);
    final effectiveConcurrency = isRangeScan ? 8 : activeProfile.concurrency;
    setState(() {
      _scanning = true;
      _cancelled = false;
      _paused = false;
      _results = [];
      _done = 0;
      _total = ips.length;
      _okCount = 0;
      _thrCount = 0;
      _failCount = 0;
      _prefilterLive = 0;
      _prefilterTotal = ips.length;
      _prefiltering = true;
      _displayDirty   = true;
      _cachedDisplay  = [];
      _advancedFilter = 'all';   // reset filter on new scan
      _coloFilter     = '';      // reset colo search on new scan
      _statusText = 'Pre-filtering ${ips.length} IPs...';
    });

    _startBatchTimer();

    // CDN profile SNI override
    String? normalSniOverride;
    bool isCfScan;
    if (isRangeScan) {
      isCfScan = rangeCfMode;
      normalSniOverride = rangeCfMode ? 'speed.cloudflare.com' : null;
    } else {
      isCfScan = (_mode == 1 && _normalCdnProfile == 'cloudflare') || _mode == 2;
      if (_mode == 1 && _normalCdnProfile == 'cloudflare') {
        normalSniOverride = 'speed.cloudflare.com';
      }
    }
    // 'cdn_akamai' leaves normalSniOverride null → engine uses default kShiroSni
    // isCfScan=true when: normal+cloudflare profile OR deep mode (CF SNIs in preset)

    runScanningEngine(
      ips,
      mode: _mode == 2 ? ScanMode.deep : ScanMode.normal,
      concurrency: effectiveConcurrency,  // BUG 6 FIX + Range uses fixed 8
      deepSnis: deepSnis,
      normalSniOverride: normalSniOverride,
      isCfScan: isCfScan,
      onPrefilterDone: (liveCount, totalCount) {
        if (!mounted) return;
        setState(() {
          _prefilterLive  = liveCount;
          _prefilterTotal = totalCount;
          _prefiltering   = false;
          _total          = liveCount;
          _done           = 0;
          _statusText     = 'Scanning $liveCount live IPs...';
        });
      },
      onProgress: (done, total, result) {
        _pendingResults.add(result);
        _done = done;
        _total = total;
        final pct = total > 0 ? (done / total * 100).round() : 0;
        final milestone = (pct ~/ 25) * 25;
        if (milestone > _lastNotifPct && milestone > 0) {
          _lastNotifPct = milestone;
          if (pct >= 100) {
            sendNotification('✅ اسکن تموم شد!', 'نتایج آماده‌ست.');
          } else {
            sendNotification('در حال اسکن... $pct%', 'MidONe داره در پس‌زمینه کار می‌کنه');
          }
        }
      },
      isCancelled: () => _cancelled || _paused,
    ).then((results) {
      if (!mounted) return;
      _stopBatchTimer();
      setState(() {
        _results = results;
        _scanning = false;
        _prefiltering = false;
        _displayDirty = true;
        _statusText = 'Done! ${results.where((r) => r.isAlive).length} results';
      });
      if (results.isNotEmpty) {
        _showSnack('✓ Done! ${results.where((r) => r.isAlive).length} results found');
        Future.delayed(const Duration(milliseconds: 500), () {
          if (mounted) setState(() => _tab = 1);
        });
      }
      if (isRangeScan) {
        RangeScanStorage().addScannedIps(ips).then((_) {
          final alive = results.where((r) => r.isAlive).toList();
          final avgLatency = alive.isEmpty
              ? 0.0
              : alive.fold(0.0, (a, b) => a + b.latencyMs) / alive.length;
          final topIps = alive.take(10).map((r) => <String, dynamic>{
            'ip': r.ip,
            'grade': r.grade,
            'latencyMs': r.latencyMs,
            'tier': r.tier.name,
            if (r.colo != null) 'colo': r.colo,
            if (r.sniUsed != null) 'sniUsed': r.sniUsed,
          }).toList();

          RangeScanStorage().saveSession({
            'time': DateTime.now().toIso8601String(),
            'provider': rangeCfMode ? 'cloudflare' : 'akamai',
            'cidr': rangeCidr ?? '',
            'randomCount': rangeRequestedCount ?? ips.length,
            'totalScanned': results.length,
            'aliveCount': alive.length,
            'deadCount': results.where((r) => !r.isAlive).length,
            'excellentCount': results.where((r) => r.tier == IpTier.excellent).length,
            'goodCount': results.where((r) => r.tier == IpTier.good).length,
            'usableCount': results.where((r) => r.tier == IpTier.usable).length,
            'weakCount': results.where((r) => r.tier == IpTier.weak).length,
            'avgLatencyMs': double.parse(avgLatency.toStringAsFixed(1)),
            'topIps': topIps,
          }).then((_) {
            RangeScanStorage().scannedIpCount().then((count) {
              if (mounted) setState(() => _scannedIpMemoryCount = count);
            });
          });
        });
      }
    }).catchError((e) {
      if (!mounted) return;
      _stopBatchTimer();
      setState(() { _scanning = false; _prefiltering = false; });
    });
  }

  void _showSniPickerDialog(List<String> ips) {
    final localSelected = Set<String>.from(_selectedSnis);
    final allSnis = List<String>.from(kDeepSniPresets);

    showModalBottomSheet(
      context: context,
      backgroundColor: cardColor,
      isScrollControlled: true,
      shape: const RoundedRectangleBorder(
          borderRadius: BorderRadius.vertical(top: Radius.circular(24))),
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setModalState) {
          return Padding(
            padding: EdgeInsets.only(bottom: MediaQuery.of(ctx).viewInsets.bottom),
            child: Container(
              constraints: BoxConstraints(maxHeight: MediaQuery.of(ctx).size.height * 0.85),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Container(
                    margin: const EdgeInsets.only(top: 12, bottom: 4),
                    width: 40, height: 4,
                    decoration: BoxDecoration(color: borderColor, borderRadius: BorderRadius.circular(2)),
                  ),
                  Padding(
                    padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
                    child: Row(
                      children: [
                        const Icon(Icons.tune_rounded, color: accentLime, size: 20),
                        const SizedBox(width: 8),
                        Text('Deep Scan — SNI Selection',
                            style: GoogleFonts.inter(color: accentLime, fontWeight: FontWeight.w700, fontSize: 16)),
                        const Spacer(),
                        Text('${localSelected.length} selected',
                            style: GoogleFonts.inter(color: textSecond, fontSize: 12)),
                      ],
                    ),
                  ),
                  const Divider(color: borderColor, height: 1),
                  Flexible(
                    child: ListView.builder(
                      shrinkWrap: true,
                      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                      itemCount: allSnis.length,
                      itemBuilder: (ctx, i) {
                        final sni = allSnis[i];
                        final checked = localSelected.contains(sni);
                        return GestureDetector(
                          onTap: () {
                            setModalState(() {
                              if (checked) {
                                if (localSelected.length > 1) localSelected.remove(sni);
                              } else {
                                localSelected.add(sni);
                              }
                            });
                          },
                          child: Container(
                            margin: const EdgeInsets.only(bottom: 6),
                            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
                            decoration: BoxDecoration(
                              color: checked ? accentLime.withOpacity(0.08) : iconBg,
                              borderRadius: BorderRadius.circular(12),
                              border: Border.all(color: checked ? accentLime.withOpacity(0.4) : borderColor),
                            ),
                            child: Row(
                              children: [
                                Icon(
                                  checked ? Icons.check_box_rounded : Icons.check_box_outline_blank_rounded,
                                  color: checked ? accentLime : textSecond, size: 20,
                                ),
                                const SizedBox(width: 10),
                                Expanded(
                                  child: Text(sni,
                                      style: GoogleFonts.robotoMono(
                                          color: checked ? textPrimary : textSecond,
                                          fontSize: 13,
                                          fontWeight: checked ? FontWeight.w600 : FontWeight.normal)),
                                ),
                                if (sni == 'www.google.com')
                                  Container(
                                    padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                                    decoration: BoxDecoration(
                                        color: accentLime.withOpacity(0.15),
                                        borderRadius: BorderRadius.circular(6)),
                                    child: Text('ShirKhorshid',
                                        style: GoogleFonts.inter(color: accentLime, fontSize: 9, fontWeight: FontWeight.w700)),
                                  ),
                              ],
                            ),
                          ),
                        );
                      },
                    ),
                  ),
                  Padding(
                    padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                    child: Row(
                      children: [
                        Expanded(
                          child: TextField(
                            controller: _customSniController,
                            style: GoogleFonts.robotoMono(color: textPrimary, fontSize: 13),
                            decoration: InputDecoration(
                              hintText: 'Add custom SNI...',
                              hintStyle: GoogleFonts.robotoMono(color: textSecond, fontSize: 13),
                              filled: true, fillColor: iconBg,
                              contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
                              border: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: const BorderSide(color: borderColor)),
                              enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: const BorderSide(color: borderColor)),
                              focusedBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: const BorderSide(color: accentLime)),
                            ),
                          ),
                        ),
                        const SizedBox(width: 8),
                        GestureDetector(
                          onTap: () {
                            final custom = _customSniController.text.trim();
                            if (custom.isNotEmpty && !allSnis.contains(custom)) {
                              setModalState(() {
                                allSnis.add(custom);
                                localSelected.add(custom);
                                _customSniController.clear();
                              });
                            }
                          },
                          child: Container(
                            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 11),
                            decoration: BoxDecoration(color: accentLime, borderRadius: BorderRadius.circular(12)),
                            child: Text('Add', style: GoogleFonts.inter(color: bgColor, fontWeight: FontWeight.w700, fontSize: 13)),
                          ),
                        ),
                      ],
                    ),
                  ),
                  Padding(
                    padding: const EdgeInsets.fromLTRB(16, 4, 16, 20),
                    child: SizedBox(
                      width: double.infinity, height: 52,
                      child: ElevatedButton(
                        onPressed: () {
                          Navigator.pop(ctx);
                          setState(() { _selectedSnis = Set<String>.from(localSelected); });
                          _runScan(ips, localSelected.toList());
                        },
                        style: ElevatedButton.styleFrom(
                          backgroundColor: accentLime, foregroundColor: bgColor,
                          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
                          elevation: 0,
                        ),
                        child: Text('Start Deep Scan (${localSelected.length} SNIs)',
                            style: GoogleFonts.inter(fontWeight: FontWeight.w800, fontSize: 15)),
                      ),
                    ),
                  ),
                ],
              ),
            ),
          );
        },
      ),
    );
  }

  void _stopScan() {
    _cancelled = true;
    _paused = false;
    _stopBatchTimer();
    setState(() {
      _scanning = false;
      _prefiltering = false;
      _displayDirty = true;
      _statusText = 'Stopped (${_results.length} results so far)';
    });
  }

  // p44: pause scan
  void _pauseScan() {
    setState(() { _paused = true; _statusText = 'Paused...'; });
  }

  // p44: resume scan
  // BUG 7 FIX: only clear the _paused flag — do NOT restart the scan engine.
  // The existing Future.wait loop in runScanningEngine checks isCancelled which
  // reads _paused live, so clearing it here lets the loop continue automatically.
  void _resumeScan() {
    if (!_paused) return;
    setState(() {
      _paused = false;
      _statusText = 'Resumed...';
    });
  }

  // p43: ETA calculation
  String _calcEta() {
    if (_done == 0 || _total == 0 || _scanStartTime == null) return '--';
    final elapsed = DateTime.now().difference(_scanStartTime!).inSeconds;
    if (elapsed == 0) return '--';
    final rate = _done / elapsed;
    final remaining = _total - _done;
    if (rate == 0) return '--';
    final etaSec = (remaining / rate).round();
    if (etaSec < 60) return '~${etaSec}s';
    return '~${(etaSec / 60).round()}m';
  }

  // Cached sorted+filtered list
  List<ScanResult> get _displayResults {
    if (!_displayDirty) return _cachedDisplay;
    var list = [..._results];

    // p39: advanced filter
    switch (_advancedFilter) {
      case 'excellent':
        list = list.where((r) => r.tier == IpTier.excellent).toList();
        break;
      case 'low_rtt':
        list = list.where((r) => r.isAlive && r.latencyMs < 150).toList();
        break;
      case 'alive':
        list = list.where((r) => r.isAlive).toList();
        break;
      case 'ws_ok':
        list = list.where((r) => r.wsOk == true).toList();
        break;
      case 'ws_fail':
        list = list.where((r) => r.wsOk == false).toList();
        break;
      default:
        break;
    }

    // cf1: colo filter — filter by datacenter code (case-insensitive)
    if (_coloFilter.isNotEmpty) {
      final q = _coloFilter.trim().toUpperCase();
      list = list.where((r) => (r.colo ?? '').toUpperCase().contains(q)).toList();
    }

    switch (_sortBy) {
      case 'speed':
        list.sort((a, b) {
          final sc_a = a.score ?? -1;
          final sc_b = b.score ?? -1;
          return sc_b.compareTo(sc_a);
        });
        break;
      case 'reliability':
        list.sort((a, b) => b.reliability.compareTo(a.reliability));
        break;
      case 'colo':
        list.sort((a, b) {
          final ca = a.colo ?? 'ZZZ'; // null colos go last
          final cb = b.colo ?? 'ZZZ';
          final cmp = ca.compareTo(cb);
          if (cmp != 0) return cmp;
          return a.latencyMs.compareTo(b.latencyMs); // secondary: latency
        });
        break;
      default:
        list.sort((a, b) {
          if (a.isAlive != b.isAlive) return a.isAlive ? -1 : 1;
          return a.latencyMs.compareTo(b.latencyMs);
        });
    }
    _cachedDisplay = list;
    _displayDirty = false;
    return _cachedDisplay;
  }

  void _copyTop5() {
    final top5 = _displayResults.where((r) => r.isAlive).take(5).toList();
    if (top5.isEmpty) { _showSnack('No alive results!'); return; }
    Clipboard.setData(ClipboardData(text: top5.map((r) => r.ip).join('\n')));
    _showSnack('✓ Top 5 copied!');
  }

  void _copyAll() {
    final list = _displayResults.where((r) => r.isAlive).toList();
    if (list.isEmpty) { _showSnack('No alive results!'); return; }
    Clipboard.setData(ClipboardData(text: list.map((r) => r.ip).join('\n')));
    _showSnack('✓ All ${list.length} IPs copied!');
  }

  // p40: export JSON
  Future<void> _exportJson() async {
    if (_results.isEmpty) { _showSnack('No results!'); return; }
    try {
      final dir = await getExternalStorageDirectory() ?? await getApplicationDocumentsDirectory();
      final folder = Directory('${dir.path}/MidONeScanner');
      await folder.create(recursive: true);
      final ts = DateTime.now().toString().replaceAll(RegExp(r'[: ]'), '_').substring(0, 19);
      final file = File('${folder.path}/scan_$ts.json');
      final data = _results.map((r) => {
        'ip': r.ip, 'grade': r.grade, 'latencyMs': r.latencyMs,
        'jitterMs': r.jitterMs, 'isAlive': r.isAlive, 'country': r.country,
        'loss': r.loss, 'reliability': r.reliability, 'score': r.score,
        'survivalMs': r.survivalMs, 'tier': r.tier.name,
        'speedKBs': r.speedKBs, 'sniUsed': r.sniUsed,
        'dpiSuspicion': r.dpiSuspicion,
        'confidenceScore': r.confidenceScore,
      }).toList();
      await file.writeAsString(jsonEncode({
        'timestamp': DateTime.now().toIso8601String(),
        'results': data,
      }));
      _showSnack('✓ JSON saved: scan_$ts.json');
    } catch (e) { _showSnack('Export error: $e'); }
  }

  Future<void> _saveResults() async {
    if (_results.isEmpty) { _showSnack('No results!'); return; }
    try {
      final dir = await getExternalStorageDirectory() ?? await getApplicationDocumentsDirectory();
      final folder = Directory('${dir.path}/MidONeScanner');
      await folder.create(recursive: true);
      final ts = DateTime.now().toString().replaceAll(RegExp(r'[: ]'), '_').substring(0, 19);
      final file = File('${folder.path}/scan_$ts.txt');
      final alive = _results.where((r) => r.isAlive).toList();
      final top5 = alive.take(5).toList();
      final buf = StringBuffer();
      buf.writeln('MidONe Scanner SK v6.2 | t.me/mmdrlx | ${DateTime.now()}');
      buf.writeln('\n=== TOP 5 ===');
      for (int i = 0; i < top5.length; i++) {
        final r = top5[i];
        final speedStr = r.speedKBs != null ? '  Speed:${r.speedKBs!.toStringAsFixed(1)} KB/s' : '';
        final sniStr   = r.sniUsed  != null ? '  SNI:${r.sniUsed}'                             : '';
        buf.writeln('${i + 1}. IP:${r.ip}  ${r.latencyMs.toStringAsFixed(1)} ms  Loss:${r.loss}%  Grade:${r.grade}$speedStr$sniStr  ${r.flag} ${r.country}');
      }
      buf.writeln('\n=== ALL RESULTS ===');
      for (final r in _results) {
        buf.writeln('${r.ip.padRight(17)}${r.grade.padRight(4)}${r.latencyMs.toStringAsFixed(1).padLeft(8)} ms  Loss:${r.loss}%  Rel:${(r.reliability * 100).round()}%${r.isAlive ? '' : ' [DEAD]'}');
      }
      await file.writeAsString(buf.toString());
      _showSnack('✓ Saved: scan_$ts.txt');
    } catch (e) { _showSnack('Save error: $e'); }
  }

  // p41: retest all failed IPs
  // BUG 13 FIX: run retests in concurrent batches instead of sequentially
  Future<void> _retestFailed() async {
    final failed = _results.where((r) => !r.isAlive).toList();
    if (failed.isEmpty) { _showSnack('No failed IPs to retest!'); return; }
    _showSnack('Retesting ${failed.length} failed IPs...');

    const batchSize = 8;
    for (int i = 0; i < failed.length; i += batchSize) {
      if (!mounted) return;
      final batch = failed.skip(i).take(batchSize).toList();
      final results = await Future.wait(batch.map((r) => scanOneIp(r.ip)));
      if (!mounted) return;
      setState(() {
        for (int j = 0; j < batch.length; j++) {
          final idx = _results.indexWhere((x) => x.ip == batch[j].ip);
          if (idx >= 0) _results[idx] = results[j];
        }
        _displayDirty = true;
      });
    }
    if (mounted) _showSnack('✓ Retest done!');
  }

  void _showSnack(String msg) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(
      content: Text(msg, style: GoogleFonts.inter(color: bgColor, fontWeight: FontWeight.w600)),
      backgroundColor: accentLime,
      behavior: SnackBarBehavior.floating,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      duration: const Duration(seconds: 2),
    ));
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: bgColor,
      body: SafeArea(
        child: Stack(
          children: [
            Column(
              children: [
                _buildTopBar(),
                Expanded(child: _tab == 0 ? _buildScanTab() : _buildResultsTab()),
                _buildBottomNav(),
              ],
            ),
            // p52: debug overlay
            if (_devMode && kDebugMode) _buildDebugOverlay(),
          ],
        ),
      ),
    );
  }

  // ── Top Bar ───────────────────────────────────────────────────────────────
  Widget _buildTopBar() {
    return Container(
      color: card2Color,
      padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 10),
      child: Row(
        children: [
          Image.asset('assets/icons/app_icon.png', width: 36, height: 36),
          const SizedBox(width: 10),
          Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // p55: tap title 5x for dev mode
              // BUG 10 FIX: reset counter if > 2s between taps
              GestureDetector(
                onTap: () {
                  final now = DateTime.now();
                  if (_lastTitleTap != null &&
                      now.difference(_lastTitleTap!) > const Duration(seconds: 2)) {
                    _titleTapCount = 0;
                  }
                  _lastTitleTap = now;
                  _titleTapCount++;
                  if (_titleTapCount >= 5) {
                    _titleTapCount = 0;
                    setState(() { _devMode = !_devMode; });
                    _showSnack(_devMode ? '🔧 Dev Mode ON' : '🔧 Dev Mode OFF');
                  }
                },
                child: Text('MidONe Scanner',
                    style: GoogleFonts.inter(
                        color: accentLime, fontWeight: FontWeight.w800,
                        fontSize: 18, letterSpacing: -0.5)),
              ),
              Row(
                children: [
                  // BUG 11 FIX: explicit RTL direction for Persian text
                  Text(_ispName,
                      textDirection: TextDirection.rtl,
                      style: GoogleFonts.inter(color: textSecond, fontSize: 10)),
                  const SizedBox(width: 6),
                  Text('· $_pingText', style: GoogleFonts.inter(color: textSecond, fontSize: 10)),
                ],
              ),
            ],
          ),
          const Spacer(),
          GestureDetector(
            onTap: () async {
              final uri = Uri.parse('https://t.me/mmdrlx');
              if (await canLaunchUrl(uri)) {
                await launchUrl(uri, mode: LaunchMode.externalApplication);
              }
            },
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
              decoration: BoxDecoration(
                color: iconBg,
                borderRadius: BorderRadius.circular(10),
                border: Border.all(color: borderColor),
              ),
              child: Row(
                children: [
                  Image.asset('assets/icons/telegram_icon.png', width: 16, height: 16),
                  const SizedBox(width: 5),
                  Text('@mmdrlx',
                      style: GoogleFonts.inter(color: accentLime, fontSize: 12, fontWeight: FontWeight.w600)),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  // ── Scan Tab ──────────────────────────────────────────────────────────────
  Widget _buildScanTab() {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(16),
      child: Column(
        children: [
          _buildModeCard(),
          const SizedBox(height: 10),
          if (_mode == 1) _buildNormalCdnProfileCard(),
          if (_mode == 1) const SizedBox(height: 10),
          if (_mode != 3) _buildProfileCard(),   // p54 — hidden in Range mode
          if (_mode != 3) const SizedBox(height: 10),
          _buildInputCard(),
          const SizedBox(height: 10),
          _buildScanButton(),
          const SizedBox(height: 10),
          _buildProgressCard(),
          const SizedBox(height: 10),
          _buildRealtimeMetrics(),    // p36
          const SizedBox(height: 10),
          _buildStatsRow(),
          if (_results.isNotEmpty) ...[
            const SizedBox(height: 10),
            _buildViewResultsButton(),
          ],
        ],
      ),
    );
  }

  // CDN profile selector — Normal mode only
  Widget _buildNormalCdnProfileCard() {
    return _card(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('CDN PROFILE',
              style: GoogleFonts.inter(color: textSecond, fontWeight: FontWeight.w700, fontSize: 11, letterSpacing: 1.2)),
          const SizedBox(height: 10),
          Row(
            children: [
              _buildCdnProfileBtn('cdn_akamai', 'CDN Akamai'),
              const SizedBox(width: 4),
              _buildCdnProfileBtn('cloudflare', 'Cloudflare'),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildCdnProfileBtn(String value, String label) {
    final active = _normalCdnProfile == value;
    return Expanded(
      child: GestureDetector(
        onTap: () => setState(() => _normalCdnProfile = value),
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 180),
          margin: const EdgeInsets.symmetric(horizontal: 2),
          padding: const EdgeInsets.symmetric(vertical: 8),
          decoration: BoxDecoration(
            color: active ? accentLime.withOpacity(0.12) : iconBg,
            borderRadius: BorderRadius.circular(10),
            border: Border.all(color: active ? accentLime : borderColor, width: active ? 1.5 : 1),
          ),
          child: Text(label,
              style: GoogleFonts.inter(
                  color: active ? accentLime : textSecond,
                  fontSize: 10,
                  fontWeight: FontWeight.w700),
              textAlign: TextAlign.center),
        ),
      ),
    );
  }

  // p54: profile selector card
  Widget _buildProfileCard() {
    return _card(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('SCAN PROFILE',
              style: GoogleFonts.inter(color: textSecond, fontWeight: FontWeight.w700, fontSize: 11, letterSpacing: 1.2)),
          const SizedBox(height: 10),
          Row(
            children: kScanProfiles.map((p) {
              final active = _selectedProfile == p.name;
              return Expanded(
                child: GestureDetector(
                  onTap: () => setState(() => _selectedProfile = p.name),
                  child: AnimatedContainer(
                    duration: const Duration(milliseconds: 180),
                    margin: const EdgeInsets.symmetric(horizontal: 2),
                    padding: const EdgeInsets.symmetric(vertical: 8),
                    decoration: BoxDecoration(
                      color: active ? accentLime.withOpacity(0.12) : iconBg,
                      borderRadius: BorderRadius.circular(10),
                      border: Border.all(color: active ? accentLime : borderColor, width: active ? 1.5 : 1),
                    ),
                    child: Column(
                      children: [
                        Text(p.label, style: GoogleFonts.inter(color: active ? accentLime : textSecond, fontSize: 10, fontWeight: FontWeight.w700), textAlign: TextAlign.center),
                      ],
                    ),
                  ),
                ),
              );
            }).toList(),
          ),
        ],
      ),
    );
  }

  Widget _buildModeCard() {
    return _card(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('SCAN MODE',
              style: GoogleFonts.inter(color: textSecond, fontWeight: FontWeight.w700, fontSize: 11, letterSpacing: 1.2)),
          const SizedBox(height: 12),
          Row(
            children: [
              Expanded(child: _modeBtn(1, 'Normal', 'Fast · BW test')),
              const SizedBox(width: 8),
              Expanded(child: _modeBtn(2, 'Deep', 'Multi-SNI · 5 probes')),
              const SizedBox(width: 8),
              Expanded(child: _modeBtn(3, 'Range', 'CDN · CIDR')),
            ],
          ),
        ],
      ),
    );
  }

  Widget _modeBtn(int mode, String title, String sub) {
    final active = _mode == mode;
    return GestureDetector(
      onTap: () {
        setState(() {
          _mode = mode;
          if (mode != 3) {
            // Clear range state when leaving Range mode
            _rangeCidrs = [];
            _selectedRangeCidr = null;
            _loadingRangeCidrs = false;
          }
        });
        // Reload CIDRs when switching back to Range mode if list was cleared
        if (mode == 3 && _rangeCidrs.isEmpty) {
          _loadRangeCidrs();
        }
      },
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 200),
        padding: const EdgeInsets.symmetric(vertical: 14, horizontal: 10),
        decoration: BoxDecoration(
          color: active ? accentLime.withOpacity(0.12) : iconBg,
          borderRadius: BorderRadius.circular(14),
          border: Border.all(color: active ? accentLime : borderColor, width: active ? 1.5 : 1),
        ),
        child: Column(
          children: [
            Text(title, style: GoogleFonts.inter(color: active ? accentLime : textPrimary, fontWeight: FontWeight.w700, fontSize: 14)),
            const SizedBox(height: 4),
            Text(sub, style: GoogleFonts.inter(color: textSecond, fontSize: 10), textAlign: TextAlign.center),
          ],
        ),
      ),
    );
  }

  Widget _buildInputCard() {
    if (_mode == 3) return _buildRangeCard();
    return _card(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Text('IP ADDRESSES',
                  style: GoogleFonts.inter(color: textSecond, fontWeight: FontWeight.w700, fontSize: 11, letterSpacing: 1.2)),
              const Spacer(),
              _miniBtn('Paste', () async {
                final data = await Clipboard.getData('text/plain');
                if (data?.text != null) {
                  final cur = _ipController.text;
                  _ipController.text = cur.isEmpty ? data!.text! : '$cur\n${data!.text!}';
                }
              }),
              const SizedBox(width: 8),
              _miniBtn('Clear', () => _ipController.clear(), isDestructive: true),
            ],
          ),
          const SizedBox(height: 10),
          TextField(
            controller: _ipController,
            maxLines: 6,
            style: GoogleFonts.robotoMono(color: textPrimary, fontSize: 13),
            decoration: InputDecoration(
              hintText: '1.1.1.1\n8.8.8.8\n104.16.0.0\n...',
              hintStyle: GoogleFonts.robotoMono(color: textSecond, fontSize: 12),
              filled: true, fillColor: card2Color,
              border: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: BorderSide.none),
              focusedBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: const BorderSide(color: accentLime, width: 1.5)),
              enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: const BorderSide(color: borderColor, width: 1)),
              contentPadding: const EdgeInsets.all(14),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildRangeCard() {
    return _card(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // ── Header row with History button ──────────────────────────────
          Row(
            children: [
              Text('CDN PROFILE',
                  style: GoogleFonts.inter(
                      color: textSecond,
                      fontWeight: FontWeight.w700,
                      fontSize: 11,
                      letterSpacing: 1.2)),
              const Spacer(),
              GestureDetector(
                onTap: () => Navigator.push(
                  context,
                  MaterialPageRoute(
                      builder: (_) => const RangeHistoryPage()),
                ).then((_) {
                  RangeScanStorage().scannedIpCount().then((c) {
                    if (mounted) setState(() => _scannedIpMemoryCount = c);
                  });
                }),
                child: Container(
                  padding:
                      const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
                  decoration: BoxDecoration(
                    color: iconBg,
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: borderColor),
                  ),
                  child: Row(children: [
                    const Icon(Icons.history_rounded,
                        color: accentLime, size: 14),
                    const SizedBox(width: 4),
                    Text('History',
                        style: GoogleFonts.inter(
                            color: accentLime,
                            fontSize: 11,
                            fontWeight: FontWeight.w600)),
                  ]),
                ),
              ),
            ],
          ),
          const SizedBox(height: 10),

          // ── CDN Profile buttons ─────────────────────────────────────────
          Row(
            children: [
              _buildRangeProfileBtn('cloudflare', '☁️ Cloudflare'),
              const SizedBox(width: 8),
              _buildRangeProfileBtn('akamai', '🌐 Akamai'),
            ],
          ),
          const SizedBox(height: 16),

          // ── SELECT RANGE ────────────────────────────────────────────────
          Text('SELECT RANGE',
              style: GoogleFonts.inter(
                  color: textSecond,
                  fontWeight: FontWeight.w700,
                  fontSize: 11,
                  letterSpacing: 1.2)),
          const SizedBox(height: 8),

          if (_loadingRangeCidrs)
            const Center(
              child: Padding(
                padding: EdgeInsets.all(12),
                child: SizedBox(
                  width: 20,
                  height: 20,
                  child: CircularProgressIndicator(
                      strokeWidth: 2, color: accentLime),
                ),
              ),
            )
          else if (_rangeCidrs.isEmpty)
            Padding(
              padding: const EdgeInsets.symmetric(vertical: 8),
              child: Text('Tap a profile above to load ranges.',
                  style: GoogleFonts.inter(color: textSecond, fontSize: 12)),
            )
          else
            ConstrainedBox(
              constraints: const BoxConstraints(maxHeight: 260),
              child: ListView.builder(
                shrinkWrap: true,
                physics: const ClampingScrollPhysics(),
                itemCount: _rangeCidrs.length,
                itemBuilder: (ctx, i) {
                  final cidr = _rangeCidrs[i];
                  final sel = _selectedRangeCidr == cidr;
                  final count = cidrIpCount(cidr);
                  final countStr = count >= 1000000
                      ? '${(count / 1000000).toStringAsFixed(1)}M IPs'
                      : count >= 1000
                          ? '${(count / 1000).toStringAsFixed(0)}K IPs'
                          : '$count IPs';
                  return GestureDetector(
                    onTap: () => setState(() => _selectedRangeCidr = cidr),
                    child: AnimatedContainer(
                      duration: const Duration(milliseconds: 150),
                      margin: const EdgeInsets.only(bottom: 5),
                      padding: const EdgeInsets.symmetric(
                          horizontal: 12, vertical: 9),
                      decoration: BoxDecoration(
                        color: sel
                            ? accentLime.withOpacity(0.08)
                            : card2Color,
                        borderRadius: BorderRadius.circular(10),
                        border: Border.all(
                            color: sel ? accentLime : borderColor,
                            width: sel ? 1.5 : 1),
                      ),
                      child: Row(
                        children: [
                          Icon(
                            sel
                                ? Icons.radio_button_checked_rounded
                                : Icons.radio_button_off_rounded,
                            size: 15,
                            color: sel ? accentLime : textSecond,
                          ),
                          const SizedBox(width: 8),
                          Expanded(
                            child: Text(cidr,
                                style: GoogleFonts.robotoMono(
                                    color: sel ? accentLime : textPrimary,
                                    fontSize: 12,
                                    fontWeight: sel
                                        ? FontWeight.w600
                                        : FontWeight.w400)),
                          ),
                          Text('($countStr)',
                              style: GoogleFonts.inter(
                                  color: textSecond, fontSize: 11)),
                        ],
                      ),
                    ),
                  );
                },
              ),
            ),

          const SizedBox(height: 16),

          // ── Random sample count input ───────────────────────────────────
          Text('RANDOM SAMPLE',
              style: GoogleFonts.inter(
                  color: textSecond,
                  fontWeight: FontWeight.w700,
                  fontSize: 11,
                  letterSpacing: 1.2)),
          const SizedBox(height: 8),
          TextField(
            controller: _randomCountController,
            keyboardType: TextInputType.number,
            style: GoogleFonts.inter(color: textPrimary, fontSize: 14),
            decoration: InputDecoration(
              hintText: 'Number of IPs to scan randomly...',
              hintStyle:
                  GoogleFonts.inter(color: textSecond, fontSize: 12),
              filled: true,
              fillColor: card2Color,
              border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(10),
                  borderSide: BorderSide.none),
              focusedBorder: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(10),
                  borderSide:
                      const BorderSide(color: accentLime, width: 1.5)),
              enabledBorder: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(10),
                  borderSide:
                      const BorderSide(color: borderColor, width: 1)),
              contentPadding:
                  const EdgeInsets.symmetric(horizontal: 14, vertical: 11),
            ),
          ),
          const SizedBox(height: 8),
          Row(
            children: [
              const Icon(Icons.memory_rounded,
                  size: 13, color: textSecond),
              const SizedBox(width: 5),
              Text(
                'Scanned memory: ${_formatMemoryCount(_scannedIpMemoryCount)} IPs — will be skipped',
                style: GoogleFonts.inter(color: textSecond, fontSize: 11),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildRangeProfileBtn(String value, String label) {
    final active = _rangeCdnProfile == value;
    return Expanded(
      child: GestureDetector(
        onTap: _loadingRangeCidrs
            ? null
            : () {
                setState(() {
                  _rangeCdnProfile = value;
                  _rangeCidrs = [];
                  _selectedRangeCidr = null;
                });
                _loadRangeCidrs();
              },
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 180),
          padding: const EdgeInsets.symmetric(vertical: 10),
          decoration: BoxDecoration(
            color: active ? accentLime.withOpacity(0.12) : iconBg,
            borderRadius: BorderRadius.circular(12),
            border: Border.all(
                color: active ? accentLime : borderColor,
                width: active ? 1.5 : 1),
          ),
          child: Text(label,
              style: GoogleFonts.inter(
                  color: active ? accentLime : textPrimary,
                  fontWeight: FontWeight.w700,
                  fontSize: 13),
              textAlign: TextAlign.center),
        ),
      ),
    );
  }

  String _formatMemoryCount(int n) {
    if (n >= 1000000) return '${(n / 1000000).toStringAsFixed(1)}M';
    if (n >= 1000) return '${(n / 1000).toStringAsFixed(0)}K';
    return '$n';
  }

  void _loadRangeCidrs() {
    final meta = kCdnProviders.firstWhere(
      (m) => (_rangeCdnProfile == 'cloudflare'
          ? m.provider == CdnProvider.cloudflare
          : m.provider == CdnProvider.akamai),
    );
    setState(() => _loadingRangeCidrs = true);
    fetchAllCidrsForProvider(meta).then((cidrs) {
      if (!mounted) return;
      setState(() {
        _rangeCidrs = cidrs;
        _selectedRangeCidr = cidrs.isNotEmpty ? cidrs.first : null;
        _loadingRangeCidrs = false;
      });
    }).catchError((_) {
      if (!mounted) return;
      setState(() {
        _rangeCidrs = meta.fallback;
        _selectedRangeCidr =
            meta.fallback.isNotEmpty ? meta.fallback.first : null;
        _loadingRangeCidrs = false;
      });
    });
  }

  Widget _buildScanButton() {
    return Row(
      children: [
        Expanded(
          child: SizedBox(
            height: 54,
            child: ElevatedButton(
              onPressed: _scanning
                  ? _stopScan
                  : (_mode == 3 && _selectedRangeCidr == null ? null : _startScan),
              style: ElevatedButton.styleFrom(
                backgroundColor: _scanning ? const Color(0xFF3A1A1A) : accentLime,
                foregroundColor: _scanning ? const Color(0xFFFF5252) : bgColor,
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
                elevation: 0,
                side: BorderSide(
                    color: _scanning ? const Color(0xFFFF5252) : Colors.transparent,
                    width: 1.5),
              ),
              child: Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Icon(_scanning ? Icons.stop_rounded : Icons.radar_rounded, size: 20),
                  const SizedBox(width: 8),
                  Text(_scanning ? 'STOP SCAN' : 'START SCAN',
                      style: GoogleFonts.inter(fontWeight: FontWeight.w800, fontSize: 15, letterSpacing: 0.5)),
                ],
              ),
            ),
          ),
        ),
        // p44: pause/resume button
        if (_scanning) ...[
          const SizedBox(width: 8),
          SizedBox(
            height: 54, width: 54,
            child: ElevatedButton(
              onPressed: _paused ? _resumeScan : _pauseScan,
              style: ElevatedButton.styleFrom(
                backgroundColor: iconBg,
                foregroundColor: accentLime,
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16), side: const BorderSide(color: borderColor)),
                elevation: 0, padding: EdgeInsets.zero,
              ),
              child: Icon(_paused ? Icons.play_arrow_rounded : Icons.pause_rounded, size: 22),
            ),
          ),
        ],
      ],
    );
  }

  Widget _buildProgressCard() {
    final pct = _total > 0 ? _done / _total : 0.0;
    return _card(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(Icons.circle, size: 8, color: _scanning ? accentLime : textSecond),
              const SizedBox(width: 6),
              Expanded(
                child: Text(_statusText,
                    style: GoogleFonts.inter(
                        color: _scanning ? accentLime : textSecond,
                        fontSize: 13, fontWeight: FontWeight.w500)),
              ),
              if (_total > 0) ...[
                // p43: ETA
                if (_scanning)
                  Text('ETA ${_calcEta()}',
                      style: GoogleFonts.inter(color: textSecond, fontSize: 11)),
                const SizedBox(width: 8),
                Text('$_done / $_total',
                    style: GoogleFonts.inter(color: textPrimary, fontSize: 13, fontWeight: FontWeight.w700)),
              ],
            ],
          ),
          const SizedBox(height: 10),
          ClipRRect(
            borderRadius: BorderRadius.circular(6),
            child: LinearProgressIndicator(
              value: _prefiltering ? null : pct,
              backgroundColor: iconBg,
              valueColor: AlwaysStoppedAnimation(
                  _prefiltering ? const Color(0xFFFFAB40) : accentLime2),
              minHeight: 6,
            ),
          ),
          if (_prefilterTotal > 0 && !_prefiltering) ...[
            const SizedBox(height: 8),
            Row(
              children: [
                _chip(Icons.filter_alt_rounded, '$_prefilterLive live / $_prefilterTotal', accentLime),
                const SizedBox(width: 6),
                _chip(Icons.delete_sweep_rounded, '${_prefilterTotal - _prefilterLive} dead removed', const Color(0xFFFF5252)),
              ],
            ),
          ],
        ],
      ),
    );
  }

  // p36: live metrics panel
  Widget _buildRealtimeMetrics() {
    if (_results.isEmpty && !_scanning) return const SizedBox.shrink();
    final alive = _results.where((r) => r.isAlive).toList();
    final alivePercent = _results.isEmpty ? 0 : (alive.length / _results.length * 100).round();
    final avgRtt = alive.isEmpty ? 0.0 :
        alive.fold(0.0, (a, b) => a + b.latencyMs) / alive.length;
    // p34: top subnet from cache
    final topSubnet = SubnetMemoryCache().topSubnetLabel();

    return _card(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('LIVE METRICS',
              style: GoogleFonts.inter(color: textSecond, fontWeight: FontWeight.w700, fontSize: 11, letterSpacing: 1.2)),
          const SizedBox(height: 10),
          Row(
            children: [
              Expanded(child: _metricTile('Alive', '$alivePercent%', accentLime)),
              Expanded(child: _metricTile('Avg RTT', '${avgRtt.toStringAsFixed(0)}ms', const Color(0xFF60AAFF))),
              Expanded(child: _metricTile('DPI Kill', '$_dpiKills', const Color(0xFFFF6060))),
              Expanded(child: _metricTile('Scanned', '${_results.length}', textSecond)),
            ],
          ),
          if (topSubnet.isNotEmpty) ...[
            const SizedBox(height: 6),
            Row(
              children: [
                const Icon(Icons.lan_rounded, size: 12, color: textSecond),
                const SizedBox(width: 4),
                Text('Top subnet: $topSubnet',
                    style: GoogleFonts.robotoMono(color: textSecond, fontSize: 11)),
              ],
            ),
          ],
        ],
      ),
    );
  }

  Widget _metricTile(String label, String value, Color color) {
    return Column(
      children: [
        Text(value, style: GoogleFonts.inter(color: color, fontWeight: FontWeight.w800, fontSize: 18)),
        Text(label, style: GoogleFonts.inter(color: textSecond, fontSize: 10)),
      ],
    );
  }

  Widget _buildStatsRow() {
    return Row(
      children: [
        Expanded(child: _statCard('$_okCount', 'Excellent/Good', accentLime, statusGreen)),
        const SizedBox(width: 8),
        Expanded(child: _statCard('$_failCount', 'Dead', const Color(0xFFFF5252), statusRed)),
        const SizedBox(width: 8),
        Expanded(child: _statCard('$_thrCount', 'Usable/Weak', const Color(0xFFFFAB40), statusOrange)),
      ],
    );
  }

  Widget _statCard(String value, String label, Color accent, Color bg) {
    return Container(
      padding: const EdgeInsets.symmetric(vertical: 12),
      decoration: BoxDecoration(
          color: bg,
          borderRadius: BorderRadius.circular(14),
          border: Border.all(color: accent.withOpacity(0.25))),
      child: Column(
        children: [
          Text(value, style: GoogleFonts.inter(color: accent, fontWeight: FontWeight.w800, fontSize: 20)),
          const SizedBox(height: 2),
          Text(label, style: GoogleFonts.inter(color: textSecond, fontSize: 11)),
        ],
      ),
    );
  }

  Widget _buildViewResultsButton() {
    return SizedBox(
      width: double.infinity, height: 50,
      child: ElevatedButton(
        onPressed: () => setState(() => _tab = 1),
        style: ElevatedButton.styleFrom(
          backgroundColor: cardInner, foregroundColor: accentLime,
          shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(16),
              side: const BorderSide(color: borderColor)),
          elevation: 0,
        ),
        child: Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.bar_chart_rounded, size: 18),
            const SizedBox(width: 8),
            Text('View ${_results.length} Results',
                style: GoogleFonts.inter(fontWeight: FontWeight.w700, fontSize: 14)),
          ],
        ),
      ),
    );
  }

  // ── Results Tab ───────────────────────────────────────────────────────────
  Widget _buildResultsTab() {
    final list = _displayResults;
    return Column(
      children: [
        Container(
          color: card2Color,
          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
          child: Column(
            children: [
              // Sort & filter row
              SingleChildScrollView(
                scrollDirection: Axis.horizontal,
                child: Row(
                  children: [
                    Text('${list.length}', style: GoogleFonts.inter(color: textSecond, fontSize: 11)),
                    const SizedBox(width: 6),
                    _miniBtn('Latency', () => setState(() { _sortBy = 'latency'; _displayDirty = true; }), isActive: _sortBy == 'latency'),
                    const SizedBox(width: 5),
                    _miniBtn('Score', () => setState(() { _sortBy = 'speed'; _displayDirty = true; }), isActive: _sortBy == 'speed'),
                    const SizedBox(width: 5),
                    _miniBtn('Rel', () => setState(() { _sortBy = 'reliability'; _displayDirty = true; }), isActive: _sortBy == 'reliability'),
                    const SizedBox(width: 5),
                    // cf1: sort by datacenter
                    _miniBtn('Colo', () => setState(() { _sortBy = _sortBy == 'colo' ? 'latency' : 'colo'; _displayDirty = true; }), isActive: _sortBy == 'colo'),
                    const SizedBox(width: 5),
                    // p39: advanced filters
                    _miniBtn('All', () => setState(() { _advancedFilter = 'all'; _displayDirty = true; }), isActive: _advancedFilter == 'all'),
                    const SizedBox(width: 5),
                    _miniBtn('★★★', () => setState(() { _advancedFilter = 'excellent'; _displayDirty = true; }), isActive: _advancedFilter == 'excellent'),
                    const SizedBox(width: 5),
                    _miniBtn('<150ms', () => setState(() { _advancedFilter = 'low_rtt'; _displayDirty = true; }), isActive: _advancedFilter == 'low_rtt'),
                    const SizedBox(width: 5),
                    _miniBtn('Alive', () => setState(() { _advancedFilter = 'alive'; _displayDirty = true; }), isActive: _advancedFilter == 'alive'),
                    const SizedBox(width: 5),
                    // cf1/ws2: WS filter buttons
                    _miniBtn('WS ✓', () => setState(() { _advancedFilter = _advancedFilter == 'ws_ok' ? 'all' : 'ws_ok'; _displayDirty = true; }), isActive: _advancedFilter == 'ws_ok'),
                    const SizedBox(width: 5),
                    _miniBtn('WS ✗', () => setState(() { _advancedFilter = _advancedFilter == 'ws_fail' ? 'all' : 'ws_fail'; _displayDirty = true; }), isActive: _advancedFilter == 'ws_fail'),
                    const SizedBox(width: 5),
                    // p45: compact mode
                    _miniBtn(_compactMode ? 'Full' : 'Compact', () => setState(() => _compactMode = !_compactMode)),
                  ],
                ),
              ),
              // cf1: colo search field — only shown when results have colo data
              if (_results.any((r) => r.colo != null)) ...[
                const SizedBox(height: 6),
                SizedBox(
                  height: 30,
                  child: TextField(
                    onChanged: (v) => setState(() { _coloFilter = v; _displayDirty = true; }),
                    style: GoogleFonts.robotoMono(color: textPrimary, fontSize: 12),
                    decoration: InputDecoration(
                      hintText: 'Filter by datacenter (e.g. FRA)',
                      hintStyle: GoogleFonts.inter(color: textSecond, fontSize: 11),
                      contentPadding: const EdgeInsets.symmetric(horizontal: 10, vertical: 0),
                      filled: true,
                      fillColor: iconBg,
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(8),
                        borderSide: BorderSide(color: borderColor),
                      ),
                      enabledBorder: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(8),
                        borderSide: BorderSide(color: borderColor),
                      ),
                      focusedBorder: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(8),
                        borderSide: const BorderSide(color: Color(0xFF00E5FF)),
                      ),
                      prefixIcon: const Icon(Icons.cell_tower_rounded, size: 14, color: Color(0xFF00E5FF)),
                    ),
                  ),
                ),
              ],
              const SizedBox(height: 6),
              // Action row
              SingleChildScrollView(
                scrollDirection: Axis.horizontal,
                child: Row(
                  children: [
                    _buildCopyButton(),
                    const SizedBox(width: 5),
                    _miniBtn('Save TXT', _saveResults),
                    const SizedBox(width: 5),
                    _miniBtn('Export JSON', _exportJson),   // p40
                    const SizedBox(width: 5),
                    _miniBtn('Retest ❌', _retestFailed),   // p41
                  ],
                ),
              ),
            ],
          ),
        ),
        Expanded(
          child: list.isEmpty
              ? Center(
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Icon(Icons.radar_rounded, color: textSecond, size: 48),
                      const SizedBox(height: 12),
                      Text('No results yet.\nGo scan some IPs!',
                          textAlign: TextAlign.center,
                          style: GoogleFonts.inter(color: textSecond, fontSize: 15)),
                    ],
                  ))
              : ListView.builder(
                  padding: const EdgeInsets.all(12),
                  itemCount: list.length,
                  // p27: lazy rendering
                  itemBuilder: (ctx, i) => _compactMode
                      ? _compactResultCard(i + 1, list[i])
                      : _resultCard(i + 1, list[i]),
                ),
        ),
      ],
    );
  }

  Widget _buildCopyButton() {
    return PopupMenuButton<String>(
      color: cardColor,
      shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(12),
          side: const BorderSide(color: borderColor)),
      onSelected: (val) {
        if (val == 'top5') _copyTop5();
        if (val == 'all') _copyAll();
      },
      itemBuilder: (ctx) => [
        PopupMenuItem(
          value: 'top5',
          child: Row(children: [
            const Icon(Icons.filter_5_rounded, color: accentLime, size: 18),
            const SizedBox(width: 8),
            Text('Copy Top 5', style: GoogleFonts.inter(color: textPrimary, fontWeight: FontWeight.w600, fontSize: 13)),
          ]),
        ),
        PopupMenuItem(
          value: 'all',
          child: Row(children: [
            const Icon(Icons.copy_all_rounded, color: accentLime, size: 18),
            const SizedBox(width: 8),
            Text('Copy All', style: GoogleFonts.inter(color: textPrimary, fontWeight: FontWeight.w600, fontSize: 13)),
          ]),
        ),
      ],
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
        decoration: BoxDecoration(
            color: accentLime.withOpacity(0.12),
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: accentLime.withOpacity(0.5))),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text('Copy', style: GoogleFonts.inter(color: accentLime, fontSize: 11, fontWeight: FontWeight.w600)),
            const SizedBox(width: 3),
            const Icon(Icons.expand_more_rounded, color: accentLime, size: 14),
          ],
        ),
      ),
    );
  }

  // p45: compact card for 5000+ IPs
  Widget _compactResultCard(int rank, ScanResult r) {
    final gColor = gradeColor(r);
    return Container(
      margin: const EdgeInsets.only(bottom: 4),
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      decoration: BoxDecoration(
        color: cardColor,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: !r.isAlive ? const Color(0xFFFF5252).withOpacity(0.25) : borderColor),
      ),
      child: Row(
        children: [
          Text('#$rank', style: GoogleFonts.robotoMono(color: textSecond, fontSize: 10)),
          const SizedBox(width: 8),
          Expanded(child: Text(r.ip, style: GoogleFonts.robotoMono(color: textPrimary, fontSize: 13, fontWeight: FontWeight.w600))),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
            decoration: BoxDecoration(color: gColor.withOpacity(0.12), borderRadius: BorderRadius.circular(6), border: Border.all(color: gColor.withOpacity(0.3))),
            child: Text(r.grade, style: GoogleFonts.inter(color: gColor, fontSize: 10, fontWeight: FontWeight.w700)),
          ),
          const SizedBox(width: 8),
          Text('${r.latencyMs.toStringAsFixed(0)}ms', style: GoogleFonts.inter(color: accentLime, fontSize: 11)),
          const SizedBox(width: 6),
          Text(r.tierLabel.split(' ').last, style: GoogleFonts.inter(color: tierColor(r.tier), fontSize: 10)),
          // cf1: datacenter
          if (r.colo != null) ...[
            const SizedBox(width: 6),
            Text(r.colo!, style: GoogleFonts.inter(color: const Color(0xFF00E5FF), fontSize: 10, fontWeight: FontWeight.w600)),
          ],
          // ws2: WebSocket DPI result
          if (r.wsOk != null) ...[
            const SizedBox(width: 4),
            Icon(
              r.wsOk! ? Icons.check_circle_rounded : Icons.block_rounded,
              size: 12,
              color: r.wsOk! ? const Color(0xFF00E676) : const Color(0xFFFF5252),
            ),
          ],
        ],
      ),
    );
  }

  Widget _resultCard(int rank, ScanResult r) {
    final gColor = gradeColor(r);
    final relBars = (r.reliability * 5).round();
    return Container(
      margin: const EdgeInsets.only(bottom: 10),
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: cardColor,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
            color: !r.isAlive
                ? const Color(0xFFFF5252).withOpacity(0.3)
                : borderColor),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                decoration: BoxDecoration(color: iconBg, borderRadius: BorderRadius.circular(6)),
                child: Text('#$rank', style: GoogleFonts.robotoMono(color: textSecond, fontSize: 10)),
              ),
              const SizedBox(width: 8),
              Text(r.ip, style: GoogleFonts.robotoMono(color: textPrimary, fontWeight: FontWeight.w700, fontSize: 15)),
              if (!r.isAlive) ...[
                const SizedBox(width: 6),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                  decoration: BoxDecoration(color: const Color(0xFFFF5252).withOpacity(0.15), borderRadius: BorderRadius.circular(6)),
                  child: Text('DEAD', style: GoogleFonts.inter(color: const Color(0xFFFF5252), fontSize: 10, fontWeight: FontWeight.w700)),
                ),
              ] else if (r.loss > 30) ...[
                const SizedBox(width: 6),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                  decoration: BoxDecoration(color: const Color(0xFFFFAB40).withOpacity(0.15), borderRadius: BorderRadius.circular(6)),
                  child: Text('Loss ${r.loss}%', style: GoogleFonts.inter(color: const Color(0xFFFFAB40), fontSize: 10, fontWeight: FontWeight.w700)),
                ),
              ],
              // p16: DPI suspicion indicator
              if (r.dpiSuspicion > 0.5) ...[
                const SizedBox(width: 6),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                  decoration: BoxDecoration(color: const Color(0xFFFF3030).withOpacity(0.15), borderRadius: BorderRadius.circular(6)),
                  child: Text('DPI ${(r.dpiSuspicion * 100).round()}%', style: GoogleFonts.inter(color: const Color(0xFFFF3030), fontSize: 9, fontWeight: FontWeight.w700)),
                ),
              ],
              if (r.flag.isNotEmpty && r.flag != '🌐') ...[
                const SizedBox(width: 6),
                Text(r.flag, style: const TextStyle(fontSize: 14)),
              ],
              const Spacer(),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                decoration: BoxDecoration(
                    color: gColor.withOpacity(0.12),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: gColor.withOpacity(0.4))),
                child: Text(r.grade, style: GoogleFonts.inter(color: gColor, fontWeight: FontWeight.w700, fontSize: 11)),
              ),
            ],
          ),
          const SizedBox(height: 10),
          Row(
            children: [
              _chip(Icons.timer_outlined, '${r.latencyMs.toStringAsFixed(0)} ms', accentLime),
              const SizedBox(width: 8),
              _chip(Icons.show_chart_rounded, 'Jitter ${r.jitterMs.toStringAsFixed(0)} ms', const Color(0xFF60AAFF)),
              const SizedBox(width: 8),
              _chip(Icons.signal_cellular_alt_rounded, 'Loss ${r.loss}%', const Color(0xFFFFD060)),
            ],
          ),
          const SizedBox(height: 8),
          Wrap(
            spacing: 6,
            runSpacing: 4,
            children: [
              if (r.country.isNotEmpty)
                _chip(Icons.location_on_rounded, r.country.length > 12 ? r.country.substring(0, 12) : r.country, const Color(0xFFAA80FF)),
              _chip(Icons.percent_rounded, 'Rel ${(r.reliability * 100).round()}%', const Color(0xFFFFAB40)),
              if (r.score != null)
                _chip(Icons.stars_rounded, 'Score ${r.score!.toStringAsFixed(0)}', const Color(0xFF60AAFF)),
              _chip(Icons.signal_cellular_alt_rounded, r.tierLabel, tierColor(r.tier)),
              _chip(Icons.timeline_rounded, '${(r.survivalMs ?? 0) ~/ 1000}s',
                  r.isAlive ? const Color(0xFF60FF90) : const Color(0xFFFF6060)),
              // p20: confidence score
              if (r.confidenceScore != null)
                _chip(Icons.verified_rounded, 'Conf ${r.confidenceScore!.toStringAsFixed(0)}', const Color(0xFF80CFFF)),
              // cf1/ws2: Cloudflare datacenter + WebSocket DPI result
              if (r.colo != null)
                _chip(Icons.cell_tower_rounded, r.colo!, const Color(0xFF00E5FF)),
              if (r.wsOk != null)
                _chip(
                  r.wsOk! ? Icons.check_circle_rounded : Icons.block_rounded,
                  r.wsOk! ? 'WS ✓' : 'WS ✗',
                  r.wsOk! ? const Color(0xFF00E676) : const Color(0xFFFF5252),
                ),
            ],
          ),
          if (r.speedKBs != null || r.sniUsed != null) ...[
            const SizedBox(height: 6),
            Row(
              children: [
                if (r.speedKBs != null)
                  _chip(Icons.bolt_rounded, '${r.speedKBs!.toStringAsFixed(1)} KB/s', const Color(0xFFFFD700)),
                if (r.sniUsed != null) ...[
                  const SizedBox(width: 8),
                  Flexible(child: _chip(Icons.dns_rounded, r.sniUsed!, const Color(0xFF80CFFF))),
                ],
              ],
            ),
          ],
          // p55: dev mode — show raw TLS metrics
          if (_devMode && r.tcpLatencyMs != null) ...[
            const SizedBox(height: 6),
            Row(
              children: [
                _chip(Icons.settings_ethernet_rounded, 'TCP ${r.tcpLatencyMs!.toStringAsFixed(0)}ms', textSecond),
                const SizedBox(width: 6),
                _chip(Icons.lock_rounded, 'TLS ${r.tlsHandshakeMs?.toStringAsFixed(0) ?? '--'}ms', textSecond),
                if (r.realUsabilityIndex != null) ...[
                  const SizedBox(width: 6),
                  _chip(Icons.speed_rounded, 'RUI ${r.realUsabilityIndex!.toStringAsFixed(0)}', textSecond),
                ],
              ],
            ),
          ],
          const SizedBox(height: 8),
          Row(
            children: [
              ...List.generate(5, (i) => Padding(
                padding: const EdgeInsets.only(right: 3),
                child: Container(
                  width: 18, height: 5,
                  decoration: BoxDecoration(
                    color: i < relBars ? accentLime2 : iconBg,
                    borderRadius: BorderRadius.circular(3),
                  ),
                ),
              )),
              const Spacer(),
              GestureDetector(
                onTap: () => _retestCard(r),
                child: Container(
                  padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                  decoration: BoxDecoration(
                      color: iconBg,
                      borderRadius: BorderRadius.circular(8),
                      border: Border.all(color: borderColor)),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      const Icon(Icons.refresh_rounded, size: 12, color: accentLime),
                      const SizedBox(width: 4),
                      Text('Retest', style: GoogleFonts.inter(color: accentLime, fontSize: 10, fontWeight: FontWeight.w600)),
                    ],
                  ),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Future<void> _retestCard(ScanResult original) async {
    _showSnack('Retesting ${original.ip}...');
    final result = await scanOneIp(original.ip);
    if (!mounted) return;
    setState(() {
      final idx = _results.indexWhere((r) => r.ip == original.ip);
      if (idx >= 0) _results[idx] = result;
      _displayDirty = true;
    });
    if (result.isAlive) {
      _showSnack('✓ ${original.ip} — ${result.latencyMs.toStringAsFixed(0)} ms');
    } else {
      _showSnack('❌ ${original.ip} — Failed');
    }
  }

  // p52: debug overlay
  Widget _buildDebugOverlay() {
    return Positioned(
      bottom: 70, right: 8,
      child: Container(
        padding: const EdgeInsets.all(8),
        decoration: BoxDecoration(
          color: Colors.black87,
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: accentLime.withOpacity(0.3)),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          mainAxisSize: MainAxisSize.min,
          children: [
            Text('🔧 DEV', style: GoogleFonts.robotoMono(color: accentLime, fontSize: 9, fontWeight: FontWeight.w700)),
            Text('Results: ${_results.length}', style: const TextStyle(color: Colors.green, fontSize: 9)),
            Text('Done: $_done/$_total', style: const TextStyle(color: Colors.green, fontSize: 9)),
            Text('DPI: $_dpiKills', style: const TextStyle(color: Colors.orange, fontSize: 9)),
            Text('Logs: ${StructuredLogger().recentLogs.length}', style: const TextStyle(color: Colors.cyan, fontSize: 9)),
          ],
        ),
      ),
    );
  }

  // ── Shared Widgets ────────────────────────────────────────────────────────
  Widget _card({required Widget child}) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
          color: cardColor,
          borderRadius: BorderRadius.circular(18),
          border: Border.all(color: borderColor)),
      child: child,
    );
  }

  Widget _miniBtn(String label, VoidCallback onTap,
      {bool isDestructive = false, bool isActive = false, bool isAccent = false}) {
    Color color = textSecond;
    if (isDestructive) color = const Color(0xFFFF5252);
    if (isActive || isAccent) color = accentLime;
    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
        decoration: BoxDecoration(
            color: isAccent ? accentLime.withOpacity(0.12) : iconBg,
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: isActive || isAccent ? color.withOpacity(0.5) : borderColor)),
        child: Text(label, style: GoogleFonts.inter(color: color, fontSize: 11, fontWeight: FontWeight.w600)),
      ),
    );
  }

  Widget _chip(IconData icon, String label, Color color) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
          color: color.withOpacity(0.08),
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: color.withOpacity(0.2))),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 11, color: color),
          const SizedBox(width: 4),
          Text(label, style: GoogleFonts.inter(color: color, fontSize: 11)),
        ],
      ),
    );
  }

  Widget _buildBottomNav() {
    return Container(
      color: card2Color,
      padding: const EdgeInsets.only(top: 4, bottom: 4),
      child: Row(
        children: [
          Expanded(child: _navItem(0, Icons.radar_rounded, 'Scanner')),
          Expanded(child: _navItem(1, Icons.bar_chart_rounded, 'Results')),
        ],
      ),
    );
  }

  Widget _navItem(int idx, IconData icon, String label) {
    final active = _tab == idx;
    return GestureDetector(
      onTap: () => setState(() => _tab = idx),
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 200),
        margin: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
        padding: const EdgeInsets.symmetric(vertical: 10),
        decoration: BoxDecoration(
          color: active ? accentLime.withOpacity(0.12) : Colors.transparent,
          borderRadius: BorderRadius.circular(14),
          border: active ? Border.all(color: accentLime.withOpacity(0.3)) : null,
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, color: active ? accentLime : textSecond, size: 22),
            const SizedBox(height: 3),
            Text(label, style: GoogleFonts.inter(
                color: active ? accentLime : textSecond,
                fontSize: 11,
                fontWeight: active ? FontWeight.w700 : FontWeight.normal)),
          ],
        ),
      ),
    );
  }
}
