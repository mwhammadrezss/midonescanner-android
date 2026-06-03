import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math' as math;

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_local_notifications/flutter_local_notifications.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:path_provider/path_provider.dart';
import 'package:url_launcher/url_launcher.dart';
import 'package:file_picker/file_picker.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'engine/scanner_engine.dart';
import 'engine/concurrency_engine.dart';
import 'engine/probe_engine.dart' show kDeepSniPresets;
import 'models/scan_result.dart' show ScanPhase, IpTier;
import 'utils/ip_utils.dart' show validateAndExtractIps, isPrivateOrReserved;
import 'geoip.dart';
import 'utils/logger.dart';
import 'engine/subnet_cache.dart';
import 'models/cdn_provider.dart';
import 'engine/range_engine.dart';
import 'storage/range_scan_storage.dart';
import 'storage/custom_cidr_storage.dart';
import 'engine/range_ip_sampler.dart';
import 'ui/range/range_history_page.dart';
import 'dns_scanner/scanner.dart';
import 'dns_scanner/dns_servers.dart';
import 'engine/isolate_scan_engine.dart';
import 'engine/cf_ip_ranges.dart';
import 'engine/cf_xray_scan_engine.dart';
import 'xray/config_parser.dart';

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

// ─── Scan Tab Enums ──────────────────────────────────────────────────────────

enum ScanTab { cdn, cloudflare, range, dns }
enum CdnSubMode { normal, deep }

// ─── Cloudflare Result ────────────────────────────────────────────────────────

class CloudflareResult {
  final String ip;
  final bool tlsOk;
  final int httpStatus;
  final String colo;
  final bool? wsOk;
  final double latencyMs;

  const CloudflareResult({
    required this.ip,
    required this.tlsOk,
    required this.httpStatus,
    required this.colo,
    this.wsOk,
    required this.latencyMs,
  });

  bool get isEdge => tlsOk && httpStatus >= 200 && httpStatus < 400 && colo.isNotEmpty;
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

  if (Platform.isAndroid) {
    await initNotifications();
  }
  await GeoIPOffline().load();
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
  // ── Scan Tab (replaces _mode) ─────────────────────────────────────────────
  ScanTab _activeScanTab = ScanTab.cdn;
  CdnSubMode _cdnSubMode = CdnSubMode.normal;
  bool _scanning = false;
  bool _cancelled = false;
  bool _paused = false;         // p44: pause/resume
  int _done = 0, _total = 0, _okCount = 0, _thrCount = 0, _failCount = 0;
  int _prefilterLive = 0, _prefilterTotal = 0;
  bool _prefiltering = false;

  final _ipController = TextEditingController();
  List<ScanResult> _results = [];
  String _statusText = 'Ready to scan...';
  String _sortBy = 'speed';  // default: sort by score
  // BUG 9 FIX: removed _filterThrottled — dead code, no UI toggle existed.
  // The 'alive' advanced filter covers this use case.

  // p39: advanced filters
  String _advancedFilter = 'all'; // 'all', 'excellent', 'low_rtt', 'alive', 'ws_ok', 'ws_fail'
  String _coloFilter    = '';    // empty = all colos; e.g. 'FRA', 'AMS' — case-insensitive

  // p45: compact mode
  bool _compactMode = false;

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

  // ── Cloudflare tab state ─────────────────────────────────────────────────
  List<CloudflareResult> _cfResults = [];
  bool _cfScanning = false;
  bool _cfCancelled = false;
  int _cfDone = 0, _cfTotal = 0;
  String _cfStatus = 'Ready to scan Cloudflare IPs...';

  // ── CF Xray scanner state (SenPai-style two-phase) ────────────────────────
  // Config URL for Xray phase-2 validation
  final _cfConfigController = TextEditingController();
  String _cfConfigError = '';
  XrayConfig? _cfParsedConfig;

  // Scan options
  int _cfSampleCount = 500;           // random IPs from CF ranges (SenPai default)
  int _cfConcurrency = 50;            // parallel probes (SenPai default)
  int _cfTimeoutMs   = 5000;          // per-probe timeout ms (SenPai default)
  int _cfTopN        = 10;            // top-N phase-1 results for phase-2 (SenPai default)
  int _cfTries        = 4;             // tries per IP (SenPai default)
  CfSortMode _cfSortMode = CfSortMode.avg; // sort mode (SenPai default)
  String? _cfCidrFilter;              // null = all CF ranges

  // IP source mode: 0 = random from CF ranges, 1 = manual IPs from text field
  int _cfIpMode = 0;

  // Phase 1 results (all probed IPs)
  List<CfPhase1Result> _cfPhase1Results = [];
  bool _cfPhase1Done = false;
  int _cfPhase1Done_count = 0;
  int _cfPhase1Total = 0;

  // Phase 2 results (Xray validation)
  List<CfPhase2Result> _cfPhase2Results = [];
  bool _cfPhase2Done = false;
  int _cfPhase2Done_count = 0;
  int _cfPhase2Total = 0;

  // Show config section expanded
  bool _cfConfigExpanded = false;
  // Sample count presets
  static const _cfCountPresets = [100, 500, 1000, 5000, 20000, 50000, 100000];
  int _cfCountPresetIdx = 1; // default: 500 (SenPai default)
  // Timeout presets (ms)
  static const _cfTimeoutPresets = [3000, 5000, 8000, 12000];
  static const _cfTimeoutLabels = ['3s', '5s', '8s', '12s'];
  int _cfTimeoutPresetIdx = 1; // default: 5s (SenPai default)

  // ── DNS tab state ─────────────────────────────────────────────────────────
  final _dnsScanner = DNSScanner();
  StreamSubscription<ScanProgress>? _dnsScanSubscription;
  ScanProgress? _dnsLastProgress;
  final List<ScanProgress> _dnsStageLog = [];
  List<DNSServer>? _dnsResults;
  bool _dnsScanning = false;
  String? _dnsErrorMessage;
  List<String> _activeDnsServers = kAllDnsServers;
  bool _dnsUpdating = false;
  String? _dnsUpdateMessage;

  // ── DNS Apply (Windows) state ─────────────────────────────────────────────
  String? _appliedDnsIp;    // Primary DNS (DNS 1)
  String? _appliedDns2Ip;   // Secondary DNS (DNS 2)
  bool _applyingDns = false;
  bool _applyingDns2 = false;
  String? _applyDnsError;
  String? _applyDnsMessage;

  // ── DNS VPN (Android) state ───────────────────────────────────────────────
  static const _dnsVpnChannel = MethodChannel('org.mmdrlx.midone_scanner/dns_vpn');
  bool _dnsVpnRunning = false;
  String? _dnsVpnActiveDns1;
  String? _dnsVpnActiveDns2;
  bool _dnsVpnStarting = false;
  // Manual DNS input
  final _manualDns1Controller = TextEditingController();
  final _manualDns2Controller = TextEditingController();
  bool _showManualDnsInput = false;
  Timer? _dnsMonitorTimer;
  double? _dnsMonLat;
  double? _dnsMonJitter;
  double? _dnsMonLoss;
  int _dnsMonSamples = 0;
  int _dnsMonFails = 0;
  final List<double> _dnsMonLatHistory = [];

  // ── Range v2 state ────────────────────────────────────────────────────────
  String _rangeCdnProfile = 'cloudflare'; // 'cloudflare' or 'akamai'
  List<String> _rangeCidrs = [];
  Set<String> _selectedRangeCidrs = {}; // multi-select
  bool _loadingRangeCidrs = false;
  int _loadRangeCidrsGeneration = 0; // guards against stale fetch completions
  final _customCidrController  = TextEditingController();
  String? _customCidrError;
  // ── Imported IPs (from txt file) ─────────────────────────────────────────
  List<String> _importedIps = [];
  String _importedIpsProvider = 'cloudflare'; // 'cloudflare' or 'akamai'

  // ── Saved custom CIDRs (persistent) ─────────────────────────────────────
  List<String> _savedCidrs = [];
  bool _loadingSavedCidrs = false;
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
      if (mounted) _loadSavedCidrs();
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
    _cfConfigController.dispose();
    _customCidrController.dispose();
    _manualDns1Controller.dispose();
    _manualDns2Controller.dispose();
    _dnsScanSubscription?.cancel();
    _dnsMonitorTimer?.cancel();
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
    // FIX BUG#3: Guard against overlapping scans
    if (_scanning) return;

    // ── Range mode ──────────────────────────────────────────────────────────
    // Dispatch to correct handler
    if (_activeScanTab == ScanTab.cloudflare) { _startCfScan(); return; }
    if (_activeScanTab == ScanTab.dns) { _startDnsScan(); return; }
    if (_activeScanTab == ScanTab.range) {
      // ── Mode 1: Imported IPs from txt file ─────────────────────────────
      if (_importedIps.isNotEmpty) {
        if (_scanning) return;
        setState(() {
          _scanning = true;
          _cancelled = false;
          _statusText = 'Scanning ${_importedIps.length} imported IPs...';
        });
        _runScan(
          List<String>.from(_importedIps),
          null,
          isRangeScan: true,
          rangeCfMode: _importedIpsProvider == 'cloudflare',
        );
        return;
      }

      // ── Mode 2: Selected CIDRs (multi) + custom CIDR ───────────────────
      final customCidr = _customCidrController.text.trim();
      Set<String> activeCidrs = Set<String>.from(_selectedRangeCidrs);
      if (customCidr.isNotEmpty) {
        final err = _validateCidr(customCidr);
        if (err != null) { _showSnack('CIDR نامعتبر: $err'); return; }
        activeCidrs.add(customCidr.contains('/') ? customCidr : '$customCidr/32');
      }
      if (activeCidrs.isEmpty) {
        _showSnack('یک رنج انتخاب کن، CIDR وارد کن، یا فایل IP ایمپورت کن.');
        return;
      }

      if (_scanning) return;
      setState(() {
        _scanning = true;
        _cancelled = false;
        _statusText = 'Sampling IPs from ${activeCidrs.length} range(s)...';
      });

      try {
        final alreadyScanned = await RangeScanStorage().loadScannedIps();
        final sampledIps = await RangeIpSampler.sample(
          allCidrs: activeCidrs.toList(),
          requestedCount: 5000,
          alreadyScanned: alreadyScanned,
        );

        if (sampledIps.isEmpty) {
          if (mounted) setState(() { _scanning = false; _statusText = 'All IPs already scanned.'; });
          _showSnack('No new IPs. Go to History → Reset to start fresh.');
          return;
        }
        if (_cancelled) {
          if (mounted) setState(() { _scanning = false; _statusText = 'Cancelled.'; });
          return;
        }
        _runFastRangeScan(sampledIps);
      } catch (e) {
        if (mounted) setState(() { _scanning = false; _statusText = 'Error: $e'; });
        _showSnack('Error: $e');
      }
      return;
    }

    // ── CDN mode ─────────────────────────────────────────────────────────────
    // FIX: Support CIDR input (e.g. 104.16.0.0/24) — expand to individual IPs
    final ips = _expandCidrOrIps(_ipController.text);
    if (ips.isEmpty) { _showSnack('No valid IPs found! Check your input.'); return; }
    // Safety limit to prevent memory issues with huge CIDRs
    if (ips.length > 50000) { _showSnack('Too many IPs (${ips.length}). Max 50,000.'); return; }
    if (_cdnSubMode == CdnSubMode.deep) {
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
        _statusText = 'Scanning $pct%...';
      });
    });
  }

  void _stopBatchTimer() {
    _batchTimer?.cancel();
    _batchTimer = null;
    if (_pendingResults.isNotEmpty && mounted) {
      setState(() {
        // FIX(stop-stats): update stat counters when flushing pending results.
        // Previously only _results was updated but _okCount/_thrCount/_failCount
        // were not — causing incorrect counts during scanning.
        for (final r in _pendingResults) {
          _results.add(r);
          if (r.tier == IpTier.excellent || r.tier == IpTier.good) {
            _okCount++;
          } else if (r.tier == IpTier.usable || r.tier == IpTier.weak) {
            _thrCount++;
          } else {
            _failCount++;
          }
          if (r.phase == ScanPhase.dpiFail) _dpiKills++;
        }
        _pendingResults.clear();
        _displayDirty = true;
      });
    }
  }

  // Fast range scan — TCP-only probe (like cdn-ip-finder)
  // Processes 200 IPs at a time with 3s between batches.
  Future<void> _runFastRangeScan(List<String> ips) async {
    const batchSize  = 200;
    const batchDelay = Duration(seconds: 3);
    const timeoutMs  = 4000;

    _batchTimer?.cancel();
    _pendingResults.clear();
    _lastNotifPct = -1;
    _scanStartTime = DateTime.now();
    _dpiKills = 0;

    setState(() {
      _scanning   = true;
      _cancelled  = false;
      _paused     = false;
      _results    = [];
      _done       = 0;
      _total      = ips.length;
      _okCount    = 0;
      _thrCount   = 0;
      _failCount  = 0;
      _prefilterLive  = 0;
      _prefilterTotal = ips.length;
      _prefiltering   = false;
      _displayDirty   = true;
      _cachedDisplay  = [];
      _advancedFilter = 'alive';
      _coloFilter     = '';
      _statusText = 'Fast scan: ${ips.length} IPs\u2026';
    });

    _startBatchTimer();

    Future<ScanResult> probeOne(String ip) async {
      final (country, flag) = GeoIPOffline().lookupFull(ip);
      final start = DateTime.now();
      bool alive = false;
      double latency = 9999;
      try {
        final sock = await Socket.connect(ip, 443,
            timeout: Duration(milliseconds: timeoutMs));
        latency = DateTime.now().difference(start).inMilliseconds.toDouble();
        alive = true;
        await sock.close();
        sock.destroy();
      } catch (_) {}
      return ScanResult(
        ip:          ip,
        latencyMs:   alive ? latency : 9999,
        jitterMs:    0,
        isAlive:     alive,
        grade:       alive ? (latency < 100 ? 'A' : latency < 200 ? 'B' : latency < 400 ? 'C' : 'D') : 'F',
        country:     country,
        flag:        flag,
        loss:        alive ? 0 : 100,
        reliability: alive ? 1.0 : 0.0,
        score:       alive ? (100 - (latency / 10).clamp(0, 80)) : 0,
        survivalMs:  null,
        retransmits: 0,
        phase:       alive ? ScanPhase.passed : ScanPhase.tlsFail,
        tier:        alive
            ? (latency < 100 ? IpTier.excellent : latency < 200 ? IpTier.good : IpTier.usable)
            : IpTier.dead,
        dpiSuspicion: 0,
      );
    }

    int done = 0;
    try {
      for (int batchStart = 0; batchStart < ips.length; batchStart += batchSize) {
        if (_cancelled) break;
        final batch = ips.skip(batchStart).take(batchSize).toList();

        // Cap parallel TCP probes per batch (avoids socket exhaustion on large lists)
        const parallelCap = 40;
        final sem = Semaphore(parallelCap);
        final results = await Future.wait(
          batch.map((ip) async {
            await sem.acquire();
            try {
              return await probeOne(ip);
            } finally {
              sem.release();
            }
          }),
          eagerError: false,
        );

        for (final r in results) {
          _pendingResults.add(r);
          done++;
          if (r.isAlive) _okCount++;
          else _failCount++;
        }

        _done = done;
        final pct = (_done / _total * 100).round();
        setState(() {
          _statusText = 'Fast scan $pct% — batch ${batchStart ~/ batchSize + 1}/${(ips.length / batchSize).ceil()}';
        });

        if (!_cancelled && batchStart + batchSize < ips.length) {
          await Future.delayed(batchDelay);
        }
      }
    } catch (e) {
      if (mounted) {
        setState(() { _statusText = 'Scan error: $e'; });
        _showSnack('Scan error: $e');
      }
    } finally {
      _stopBatchTimer();
      if (mounted) {
        setState(() {
          _scanning = false;
          _displayDirty = true;
        });
      }
    }

    if (mounted && !_cancelled) {
      setState(() {
        _statusText = 'Done! ${_results.where((r) => r.isAlive).length} alive from ${ips.length}';
      });
      _showSnack('\u2713 Done! ${_results.where((r) => r.isAlive).length} alive IPs found');
      if (_results.isNotEmpty) {
        Future.delayed(const Duration(milliseconds: 500), () {
          if (mounted) setState(() => _tab = 1);
        });
      }
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
    // Platform-aware concurrency: Windows/desktop gets higher limits
    final effectiveConcurrency = (Platform.isWindows || Platform.isLinux || Platform.isMacOS) ? 32 : 8;
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

    // SNI override for range scan (profile-based); CDN uses engine default (kShiroSni)
    String? normalSniOverride;
    bool isCfScan;
    if (isRangeScan) {
      isCfScan = rangeCfMode;
      normalSniOverride = rangeCfMode ? 'speed.cloudflare.com' : null;
    } else {
      // CDN mode: speed.cloudflare.com SNI for CF/CDN edges; not CF-tab WS/HTTP gate.
      isCfScan = false;
      normalSniOverride = 'speed.cloudflare.com';
    }

    runIsolateScanEngine(
      ips,
      mode: _cdnSubMode == CdnSubMode.deep ? ScanMode.deep : ScanMode.normal,
      // concurrency auto-detected by runIsolateScanEngine (platform-aware)
      deepSnis: deepSnis,
      normalSniOverride: normalSniOverride,
      isCfScan: isCfScan,
      onPrefilterProgress: (checked, total) {
        if (!mounted) return;
        setState(() {
          _done = checked;
          _total = total;
          _statusText = 'Pre-filtering ${(checked / total * 100).round()}%...';
        });
      },
      onPrefilterDone: (liveCount, totalCount) {
        if (!mounted) return;
        setState(() {
          _prefilterLive  = liveCount;
          _prefilterTotal = totalCount;
          _prefiltering   = false;
          // FIX(prefilter-zero): never overwrite a valid _total with totalCount.
          // If liveCount==0 due to a race, keep whatever _total was already set to.
          _total = liveCount > 0 ? liveCount : _total;
          _statusText = liveCount > 0
              ? 'Scanning $liveCount live IPs...'
              : 'No live IPs on port 443 — try fewer IPs or Deep scan';
        });
      },
      onProgress: (done, total, result) {
        if (!mounted) return;
        _pendingResults.add(result);
        setState(() {
          _done = done;
          // FIX(total-overwrite): only let onProgress set _total while prefiltering.
          // After onPrefilterDone fires (_prefiltering=false), _total is the
          // authoritative live count — onProgress must not overwrite it.
          if (_prefiltering && total > 0) _total = total;
          if (_total > 0) {
            final pct = (done / _total * 100).round();
            _statusText = 'Scanning $pct%...';
          }
        });
        final pct = total > 0 ? (done / total * 100).round() : 0;
        final milestone = (pct ~/ 25) * 25;
        if (milestone > _lastNotifPct && milestone > 0) {
          _lastNotifPct = milestone;
          if (pct >= 100) {
            if (Platform.isAndroid) sendNotification('✅ اسکن تموم شد!', 'نتایج آماده‌ست.');
          } else {
            if (Platform.isAndroid) sendNotification('در حال اسکن... $pct%', 'MidONe داره در پس‌زمینه کار می‌کنه');
          }
        }
      },
      // FIX BUG#1: _paused must NOT kill isolates — only _cancelled should.
      // Pause is handled at the batch-timer/UI level; isolates keep scanning.
      isCancelled: () => _cancelled,
    ).then((results) {
      if (!mounted) return;
      _stopBatchTimer();
      final merged = results.isNotEmpty
          ? results
          : (_results.isNotEmpty ? _results : _pendingResults);
      setState(() {
        if (results.isNotEmpty) _results = results;
        _scanning = false;
        _prefiltering = false;
        _done = merged.length;
        _total = math.max(_total, merged.length);
        _displayDirty = true;
        _okCount   = merged.where((r) => r.tier == IpTier.excellent || r.tier == IpTier.good).length;
        _thrCount  = merged.where((r) => r.tier == IpTier.usable || r.tier == IpTier.weak).length;
        _failCount = merged.where((r) => r.tier == IpTier.dead).length;
        final alive = merged.where((r) => r.isAlive).length;
        _statusText = alive > 0
            ? 'Done! $alive usable / ${merged.length} scanned'
            : 'Done! 0 usable — ${merged.length} scanned (check IPs or try Deep)';
      });
      if (results.isNotEmpty) {
        _showSnack('✓ Done! ${results.where((r) => r.isAlive).length} results found');
        Future.delayed(const Duration(milliseconds: 500), () {
          if (mounted) setState(() => _tab = 1);
        });
      }
      if (isRangeScan) {
        RangeScanStorage().addScannedIps(ips).then((_) {
          final alive = results.where((r) => r.isAlive).toList()
            ..sort((a, b) => a.latencyMs.compareTo(b.latencyMs)); // best first
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
    if (_activeScanTab == ScanTab.cloudflare) { _stopCfScan(); return; }
    if (_activeScanTab == ScanTab.dns) { _cancelDnsScan(); return; }
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
    final top5 = _displayResults.where((r) => r.isAlive || r.tier == IpTier.usable || r.tier == IpTier.weak).take(5).toList();
    if (top5.isEmpty) { _showSnack('No results!'); return; }
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
      final dir = Platform.isAndroid ? (await getExternalStorageDirectory() ?? await getApplicationDocumentsDirectory()) : await getApplicationDocumentsDirectory();
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
      final dir = Platform.isAndroid ? (await getExternalStorageDirectory() ?? await getApplicationDocumentsDirectory()) : await getApplicationDocumentsDirectory();
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
          if (_activeScanTab == ScanTab.cdn) _buildCdnSubModeCard(),
          if (_activeScanTab == ScanTab.cdn) const SizedBox(height: 10),
          _buildInputCard(),
          const SizedBox(height: 10),
          if (_activeScanTab != ScanTab.dns) _buildScanButton(),
          if (_activeScanTab != ScanTab.dns) const SizedBox(height: 10),
          if (_activeScanTab == ScanTab.cdn) _buildProgressCard(),
          if (_activeScanTab == ScanTab.cdn) const SizedBox(height: 10),
          if (_activeScanTab == ScanTab.cdn) _buildRealtimeMetrics(),
          if (_activeScanTab == ScanTab.cdn) const SizedBox(height: 10),
          if (_activeScanTab == ScanTab.cdn) _buildStatsRow(),
          if (_activeScanTab == ScanTab.cdn && _results.isNotEmpty) ...[
            const SizedBox(height: 10),
            _buildViewResultsButton(),
          ],
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
              Expanded(child: _tabBtn(ScanTab.cdn, 'CDN', 'TLS · BW')),
              const SizedBox(width: 6),
              Expanded(child: _tabBtn(ScanTab.cloudflare, 'CF', 'کلودفلر')),
              const SizedBox(width: 6),
              Expanded(child: _tabBtn(ScanTab.range, 'Range', 'CIDR')),
              const SizedBox(width: 6),
              Expanded(child: _tabBtn(ScanTab.dns, 'DNS', 'Best DNS')),
            ],
          ),
        ],
      ),
    );
  }

  Widget _tabBtn(ScanTab tab, String title, String sub) {
    final active = _activeScanTab == tab;
    return GestureDetector(
      onTap: () {
        if (_activeScanTab == tab) return;
        _dnsScanSubscription?.cancel();
        _dnsScanSubscription = null;
        setState(() {
          _activeScanTab = tab;
          _scanning = false;
          _cfScanning = false;
          _dnsScanning = false;
          _dnsErrorMessage = null;
          _dnsLastProgress = null;
          _dnsStageLog.clear();
          _dnsResults = null;
          _cfResults = [];
          _results = [];
          _displayDirty = true;
          if (tab == ScanTab.range && _rangeCidrs.isEmpty) {
            WidgetsBinding.instance.addPostFrameCallback((_) => _loadRangeCidrs());
          }
        });
      },
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 200),
        padding: const EdgeInsets.symmetric(vertical: 12, horizontal: 4),
        decoration: BoxDecoration(
          color: active ? accentLime.withOpacity(0.12) : iconBg,
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: active ? accentLime : borderColor, width: active ? 1.5 : 1),
        ),
        child: Column(
          children: [
            Text(title, style: GoogleFonts.inter(color: active ? accentLime : textPrimary, fontWeight: FontWeight.w700, fontSize: 13)),
            const SizedBox(height: 3),
            Text(sub, style: GoogleFonts.inter(color: textSecond, fontSize: 9), textAlign: TextAlign.center),
          ],
        ),
      ),
    );
  }

  Widget _buildCdnSubModeCard() {
    return _card(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('CDN MODE',
              style: GoogleFonts.inter(color: textSecond, fontWeight: FontWeight.w700, fontSize: 11, letterSpacing: 1.2)),
          const SizedBox(height: 10),
          Row(
            children: [
              Expanded(child: _cdnSubBtn(CdnSubMode.normal, 'Normal', 'Fast · BW test')),
              const SizedBox(width: 8),
              Expanded(child: _cdnSubBtn(CdnSubMode.deep, 'Deep Scan', 'Multi-SNI · 5 probes')),
            ],
          ),
        ],
      ),
    );
  }

  Widget _cdnSubBtn(CdnSubMode mode, String title, String sub) {
    final active = _cdnSubMode == mode;
    return GestureDetector(
      onTap: () => setState(() => _cdnSubMode = mode),
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 180),
        padding: const EdgeInsets.symmetric(vertical: 10),
        decoration: BoxDecoration(
          color: active ? accentLime.withOpacity(0.12) : iconBg,
          borderRadius: BorderRadius.circular(10),
          border: Border.all(color: active ? accentLime : borderColor, width: active ? 1.5 : 1),
        ),
        child: Column(
          children: [
            Text(title, style: GoogleFonts.inter(color: active ? accentLime : textPrimary, fontWeight: FontWeight.w700, fontSize: 13)),
            const SizedBox(height: 3),
            Text(sub, style: GoogleFonts.inter(color: textSecond, fontSize: 10), textAlign: TextAlign.center),
          ],
        ),
      ),
    );
  }



  Widget _buildInputCard() {
    if (_activeScanTab == ScanTab.range) return _buildRangeCard();
    if (_activeScanTab == ScanTab.cloudflare) return _buildCfInputCard();
    if (_activeScanTab == ScanTab.dns) return _buildDnsCard();
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


  // ── Cloudflare Input Card ─────────────────────────────────────────────────
  Widget _buildCfInputCard() {
    return _card(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // ── Header ──────────────────────────────────────────────────────
          Row(
            children: [
              Text('CF IP ADDRESSES',
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

          // ── IP Source Mode toggle ────────────────────────────────────────
          Row(
            children: [
              _cfModeBtn(0, 'CF Ranges', 'Random from all CF IPs'),
              const SizedBox(width: 8),
              _cfModeBtn(1, 'Manual IPs', 'Paste your own IPs'),
            ],
          ),
          const SizedBox(height: 12),

          // ── Manual IP input (mode 1) ─────────────────────────────────────
          if (_cfIpMode == 1) ...[
            TextField(
              controller: _ipController,
              maxLines: 5,
              style: GoogleFonts.robotoMono(color: textPrimary, fontSize: 13),
              decoration: InputDecoration(
                hintText: '1.1.1.1\n104.16.0.0\n...',
                hintStyle: GoogleFonts.robotoMono(color: textSecond, fontSize: 12),
                filled: true, fillColor: card2Color,
                border: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: BorderSide.none),
                focusedBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: const BorderSide(color: Color(0xFF00E5FF), width: 1.5)),
                enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: const BorderSide(color: borderColor, width: 1)),
                contentPadding: const EdgeInsets.all(14),
              ),
            ),
            const SizedBox(height: 12),
          ],

          // ── CF Ranges mode (mode 0) ──────────────────────────────────────
          if (_cfIpMode == 0) ...[
            Container(
              padding: const EdgeInsets.all(10),
              decoration: BoxDecoration(
                color: card2Color,
                borderRadius: BorderRadius.circular(10),
                border: Border.all(color: borderColor),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('${kCfRangesV4.length} Cloudflare IPv4 Ranges',
                      style: GoogleFonts.inter(color: const Color(0xFF00E5FF), fontSize: 12, fontWeight: FontWeight.w700)),
                  const SizedBox(height: 6),
                  Wrap(
                    spacing: 4,
                    runSpacing: 4,
                    children: kCfRangesV4.map((cidr) => Container(
                      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                      decoration: BoxDecoration(
                        color: iconBg,
                        borderRadius: BorderRadius.circular(5),
                        border: Border.all(color: borderColor),
                      ),
                      child: Text(cidr, style: GoogleFonts.robotoMono(color: textSecond, fontSize: 10)),
                    )).toList(),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 12),

            // Sample count picker
            Text('HOW MANY IPs TO SCAN',
                style: GoogleFonts.inter(color: textSecond, fontWeight: FontWeight.w700, fontSize: 10, letterSpacing: 1.2)),
            const SizedBox(height: 6),
            SingleChildScrollView(
              scrollDirection: Axis.horizontal,
              child: Row(
                children: List.generate(_cfCountPresets.length, (i) {
                  final selected = _cfCountPresetIdx == i;
                  final count = _cfCountPresets[i];
                  final label = count >= 1000
                      ? '${(count / 1000).toStringAsFixed(count % 1000 == 0 ? 0 : 1)}K'
                      : '$count';
                  return Padding(
                    padding: const EdgeInsets.only(right: 6),
                    child: GestureDetector(
                      onTap: () => setState(() {
                        _cfCountPresetIdx = i;
                        _cfSampleCount = count;
                      }),
                      child: Container(
                        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
                        decoration: BoxDecoration(
                          color: selected ? accentLime : card2Color,
                          borderRadius: BorderRadius.circular(10),
                          border: Border.all(color: selected ? accentLime : borderColor),
                        ),
                        child: Text(label,
                            style: GoogleFonts.inter(
                                color: selected ? bgColor : textPrimary,
                                fontWeight: FontWeight.w700,
                                fontSize: 13)),
                      ),
                    ),
                  );
                }),
              ),
            ),
            const SizedBox(height: 12),
          ],

          // ── Timeout picker ───────────────────────────────────────────────
          Text('TIMEOUT PER IP',
              style: GoogleFonts.inter(color: textSecond, fontWeight: FontWeight.w700, fontSize: 10, letterSpacing: 1.2)),
          const SizedBox(height: 6),
          Row(
            children: List.generate(_cfTimeoutPresets.length, (i) {
              final selected = _cfTimeoutPresetIdx == i;
              return Expanded(
                child: Padding(
                  padding: EdgeInsets.only(right: i < _cfTimeoutPresets.length - 1 ? 6 : 0),
                  child: GestureDetector(
                    onTap: () => setState(() {
                      _cfTimeoutPresetIdx = i;
                      _cfTimeoutMs = _cfTimeoutPresets[i];
                    }),
                    child: Container(
                      padding: const EdgeInsets.symmetric(vertical: 8),
                      decoration: BoxDecoration(
                        color: selected ? accentLime : card2Color,
                        borderRadius: BorderRadius.circular(10),
                        border: Border.all(color: selected ? accentLime : borderColor),
                      ),
                      child: Text(_cfTimeoutLabels[i],
                          textAlign: TextAlign.center,
                          style: GoogleFonts.inter(
                              color: selected ? bgColor : textPrimary,
                              fontWeight: FontWeight.w700,
                              fontSize: 13)),
                    ),
                  ),
                ),
              );
            }),
          ),
          const SizedBox(height: 14),

          // ── Tries per IP picker (SENPAI-SYNC) ───────────────────────────
          Text('TRIES PER IP',
              style: GoogleFonts.inter(color: textSecond, fontWeight: FontWeight.w700, fontSize: 10, letterSpacing: 1.2)),
          const SizedBox(height: 6),
          Row(
            children: [1, 2, 4, 6].map((t) {
              final sel = _cfTries == t;
              return Expanded(
                child: Padding(
                  padding: EdgeInsets.only(right: t != 6 ? 6 : 0),
                  child: GestureDetector(
                    onTap: () => setState(() => _cfTries = t),
                    child: Container(
                      padding: const EdgeInsets.symmetric(vertical: 8),
                      decoration: BoxDecoration(
                        color: sel ? accentLime : card2Color,
                        borderRadius: BorderRadius.circular(10),
                        border: Border.all(color: sel ? accentLime : borderColor),
                      ),
                      child: Text('×$t',
                          textAlign: TextAlign.center,
                          style: GoogleFonts.inter(
                              color: sel ? bgColor : textPrimary,
                              fontWeight: FontWeight.w700,
                              fontSize: 13)),
                    ),
                  ),
                ),
              );
            }).toList(),
          ),
          const SizedBox(height: 14),

          // ── Sort mode picker (SENPAI-SYNC) ───────────────────────────────
          Text('SORT BY',
              style: GoogleFonts.inter(color: textSecond, fontWeight: FontWeight.w700, fontSize: 10, letterSpacing: 1.2)),
          const SizedBox(height: 6),
          SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: Row(
              children: [
                _cfSortBtn(CfSortMode.avg,    '⚡ Latency'),
                _cfSortBtn(CfSortMode.loss,   '📉 Loss %'),
                _cfSortBtn(CfSortMode.jitter, '〰 Jitter'),
                _cfSortBtn(CfSortMode.colo,   '🌍 Colo'),
                _cfSortBtn(CfSortMode.speed,  '🚀 Speed'),
              ],
            ),
          ),
          const SizedBox(height: 14),

          const SizedBox(height: 14),

          // ── Xray Config (SenPai-style Phase-2) ──────────────────────────
          GestureDetector(
            onTap: () => setState(() => _cfConfigExpanded = !_cfConfigExpanded),
            child: Row(
              children: [
                Text('CONFIG (VLESS/TROJAN) — optional',
                    style: GoogleFonts.inter(color: textSecond, fontWeight: FontWeight.w700, fontSize: 10, letterSpacing: 1.2)),
                const Spacer(),
                if (_cfParsedConfig != null)
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                    margin: const EdgeInsets.only(right: 6),
                    decoration: BoxDecoration(
                      color: const Color(0xFF69FF47).withOpacity(0.12),
                      borderRadius: BorderRadius.circular(5),
                      border: Border.all(color: const Color(0xFF69FF47).withOpacity(0.4)),
                    ),
                    child: Text('Config OK', style: GoogleFonts.inter(color: const Color(0xFF69FF47), fontSize: 10, fontWeight: FontWeight.w700)),
                  ),
                Icon(_cfConfigExpanded ? Icons.expand_less : Icons.expand_more,
                    color: textSecond, size: 18),
              ],
            ),
          ),
          if (_cfConfigExpanded) ...[
            const SizedBox(height: 8),
            TextField(
              controller: _cfConfigController,
              maxLines: 3,
              onChanged: (_) => _parseCfConfig(),
              style: GoogleFonts.robotoMono(color: textPrimary, fontSize: 12),
              decoration: InputDecoration(
                hintText: 'vless://uuid@host:port?type=ws&path=/ray&host=cdn.example.com&security=tls&sni=...\nor trojan://password@host:port?type=ws&path=/ray...',
                hintStyle: GoogleFonts.robotoMono(color: textSecond, fontSize: 11),
                filled: true, fillColor: card2Color,
                border: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: BorderSide.none),
                focusedBorder: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(12),
                    borderSide: BorderSide(
                        color: _cfConfigError.isNotEmpty ? const Color(0xFFFF5252) : const Color(0xFF00E5FF),
                        width: 1.5)),
                enabledBorder: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(12),
                    borderSide: BorderSide(
                        color: _cfParsedConfig != null
                            ? const Color(0xFF69FF47).withOpacity(0.5)
                            : borderColor,
                        width: 1)),
                contentPadding: const EdgeInsets.all(12),
              ),
            ),
            if (_cfConfigError.isNotEmpty) ...[
              const SizedBox(height: 4),
              Text(_cfConfigError,
                  style: GoogleFonts.inter(color: const Color(0xFFFF5252), fontSize: 11)),
            ],
            if (_cfParsedConfig != null) ...[
              const SizedBox(height: 8),
              Container(
                padding: const EdgeInsets.all(10),
                decoration: BoxDecoration(
                  color: const Color(0xFF69FF47).withOpacity(0.06),
                  borderRadius: BorderRadius.circular(10),
                  border: Border.all(color: const Color(0xFF69FF47).withOpacity(0.3)),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(children: [
                      const Icon(Icons.check_circle, color: Color(0xFF69FF47), size: 14),
                      const SizedBox(width: 6),
                      Expanded(
                        child: Text(
                          '${_cfParsedConfig!.protocol.toUpperCase()} | ${_cfParsedConfig!.network.toUpperCase()} | port ${_cfParsedConfig!.port}',
                          style: GoogleFonts.inter(color: const Color(0xFF69FF47), fontWeight: FontWeight.w700, fontSize: 12),
                        ),
                      ),
                    ]),
                    if (_cfParsedConfig!.effectiveSni.isNotEmpty) ...[
                      const SizedBox(height: 4),
                      Text('SNI: ${_cfParsedConfig!.effectiveSni}',
                          style: GoogleFonts.robotoMono(color: textSecond, fontSize: 11)),
                    ],
                    if (_cfParsedConfig!.remark.isNotEmpty) ...[
                      const SizedBox(height: 3),
                      Text('Remark: ${_cfParsedConfig!.remark}',
                          style: GoogleFonts.inter(color: textSecond, fontSize: 11)),
                    ],
                  ],
                ),
              ),
              const SizedBox(height: 10),
              // Top-N picker for phase 2
              Row(
                children: [
                  Text('Xray test top N IPs:',
                      style: GoogleFonts.inter(color: textSecond, fontSize: 12)),
                  const SizedBox(width: 8),
                  ...[10, 20, 50, 100].map((n) {
                    final sel = _cfTopN == n;
                    return Padding(
                      padding: const EdgeInsets.only(right: 6),
                      child: GestureDetector(
                        onTap: () => setState(() => _cfTopN = n),
                        child: Container(
                          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
                          decoration: BoxDecoration(
                            color: sel ? const Color(0xFF00E5FF) : card2Color,
                            borderRadius: BorderRadius.circular(8),
                            border: Border.all(color: sel ? const Color(0xFF00E5FF) : borderColor),
                          ),
                          child: Text('$n',
                              style: GoogleFonts.inter(
                                  color: sel ? bgColor : textPrimary,
                                  fontWeight: FontWeight.w700,
                                  fontSize: 12)),
                        ),
                      ),
                    );
                  }),
                ],
              ),
            ],
          ],
          const SizedBox(height: 12),

          // ── Progress ─────────────────────────────────────────────────────
          if (_cfScanning || _cfPhase1Total > 0) ...[
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Text(
                  _cfPhase2Total > 0
                      ? 'Phase 2: Config validation...'
                      : _cfPhase1Done
                          ? 'Phase 1 done — ${_cfPhase1Results.where((r) => r.isEdge).length} CF edges'
                          : 'Phase 1: CF edge detection...',
                  style: GoogleFonts.inter(
                      color: _cfPhase2Total > 0
                          ? const Color(0xFFFFD060)
                          : const Color(0xFF00E5FF),
                      fontSize: 12,
                      fontWeight: FontWeight.w600),
                ),
                Text(
                  _cfPhase2Total > 0
                      ? '$_cfPhase2Done_count / $_cfPhase2Total'
                      : '$_cfPhase1Done_count / $_cfPhase1Total',
                  style: GoogleFonts.inter(color: textPrimary, fontSize: 12, fontWeight: FontWeight.w700),
                ),
              ],
            ),
            const SizedBox(height: 6),
            LinearProgressIndicator(
              value: _cfPhase2Total > 0
                  ? (_cfPhase2Done_count / _cfPhase2Total)
                  : (_cfPhase1Total > 0 ? (_cfPhase1Done_count / _cfPhase1Total) : null),
              backgroundColor: iconBg,
              color: _cfPhase2Total > 0 ? const Color(0xFFFFD060) : const Color(0xFF00E5FF),
              minHeight: 5,
            ),
            const SizedBox(height: 12),
          ],

          // ── Phase 2 results ───────────────────────────────────────────────
          if (_cfPhase2Results.isNotEmpty) ...[
            Row(
              children: [
                Text('${_cfPhase2Results.where((r) => r.success).length} Config OK',
                    style: GoogleFonts.inter(color: const Color(0xFF69FF47), fontSize: 12, fontWeight: FontWeight.w700)),
                const SizedBox(width: 10),
                Text('${_cfPhase2Results.length} tested',
                    style: GoogleFonts.inter(color: textSecond, fontSize: 12)),
                const Spacer(),
                _miniBtn('Copy OK IPs', () {
                  final ips = _cfPhase2Results.where((r) => r.success).map((r) => r.ip).join('\n');
                  if (ips.isEmpty) { _showSnack('No working IPs!'); return; }
                  Clipboard.setData(ClipboardData(text: ips));
                  _showSnack('Copied ${_cfPhase2Results.where((r) => r.success).length} IPs');
                }, isAccent: true),
              ],
            ),
            const SizedBox(height: 8),
            ..._cfPhase2Results.map((r) => _cfPhase2ResultCard(r)),
          ],

          // ── Phase 1 results (no config / phase 1 only) ────────────────────
          if (_cfPhase2Results.isEmpty && _cfPhase1Results.isNotEmpty) ...[
            Row(
              children: [
                Text('${_cfPhase1Results.where((r) => r.isEdge).length} CF Edge',
                    style: GoogleFonts.inter(color: const Color(0xFF69FF47), fontSize: 12, fontWeight: FontWeight.w700)),
                const SizedBox(width: 10),
                Text('${_cfPhase1Results.length} total',
                    style: GoogleFonts.inter(color: textSecond, fontSize: 12)),
                const Spacer(),
                _miniBtn('Copy Edge IPs', () {
                  final ips = _cfPhase1Results.where((r) => r.isEdge).map((r) => r.ip).join('\n');
                  if (ips.isEmpty) { _showSnack('No CF edge IPs!'); return; }
                  Clipboard.setData(ClipboardData(text: ips));
                  _showSnack('Copied ${_cfPhase1Results.where((r) => r.isEdge).length} IPs');
                }, isAccent: true),
              ],
            ),
            const SizedBox(height: 8),
            ..._cfPhase1Results.where((r) => r.isEdge).map((r) => _cfPhase1ResultCard(r)),
          ],

          // ── Legacy cfResults (backward compat) ───────────────────────────
          if (_cfPhase1Results.isEmpty && _cfPhase2Results.isEmpty && _cfResults.isNotEmpty) ...[
            Row(
              children: [
                Text('${_cfResults.where((r) => r.isEdge).length} CF Edge',
                    style: GoogleFonts.inter(color: const Color(0xFF69FF47), fontSize: 12, fontWeight: FontWeight.w700)),
                const SizedBox(width: 10),
                Text('${_cfResults.length} total',
                    style: GoogleFonts.inter(color: textSecond, fontSize: 12)),
                const Spacer(),
                _miniBtn('Copy Edge IPs', () {
                  final edgeIps = _cfResults.where((r) => r.isEdge).map((r) => r.ip).join('\n');
                  if (edgeIps.isEmpty) { _showSnack('No CF edge IPs!'); return; }
                  Clipboard.setData(ClipboardData(text: edgeIps));
                  _showSnack('Copied ${_cfResults.where((r) => r.isEdge).length} IPs');
                }, isAccent: true),
              ],
            ),
            const SizedBox(height: 8),
            ..._cfResults.map((r) => _cfResultCard(r)),
          ],
        ],
      ),
    );
  }

  // ── CF mode toggle button ──────────────────────────────────────────────────
  Widget _cfModeBtn(int mode, String title, String subtitle) {
    final sel = _cfIpMode == mode;
    return Expanded(
      child: GestureDetector(
        onTap: () => setState(() => _cfIpMode = mode),
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 10),
          decoration: BoxDecoration(
            color: sel ? accentLime.withOpacity(0.12) : card2Color,
            borderRadius: BorderRadius.circular(10),
            border: Border.all(color: sel ? accentLime : borderColor, width: sel ? 1.5 : 1),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(title, style: GoogleFonts.inter(color: sel ? accentLime : textPrimary, fontWeight: FontWeight.w700, fontSize: 13)),
              const SizedBox(height: 2),
              Text(subtitle, style: GoogleFonts.inter(color: textSecond, fontSize: 10)),
            ],
          ),
        ),
      ),
    );
  }

  // ── Parse config from text field ───────────────────────────────────────────
  void _parseCfConfig() {
    final raw = _cfConfigController.text.trim();
    if (raw.isEmpty) {
      setState(() { _cfParsedConfig = null; _cfConfigError = ''; });
      return;
    }
    try {
      final cfg = parseProxyUrl(raw);
      setState(() { _cfParsedConfig = cfg; _cfConfigError = ''; });
    } catch (e) {
      setState(() {
        _cfParsedConfig = null;
        _cfConfigError = 'Parse error: ${e.toString().replaceAll('Invalid argument(s): ', '')}';
      });
    }
  }

  Future<void> _startCfScan() async {
    if (_cfScanning) return;

    List<String> manualIps = [];
    if (_cfIpMode == 1) {
      manualIps = _expandCidrOrIps(_ipController.text);
      if (manualIps.isEmpty) { _showSnack('No valid IPs found!'); return; }
    }

    _parseCfConfig();
    final config = _cfParsedConfig;

    setState(() {
      _cfScanning = true;
      _cfCancelled = false;
      _cfResults = [];
      _cfPhase1Results = [];
      _cfPhase2Results = [];
      _cfPhase1Done = false;
      _cfPhase2Done = false;
      _cfPhase1Done_count = 0;
      _cfPhase2Done_count = 0;
      _cfPhase1Total = _cfIpMode == 1 ? manualIps.length : _cfSampleCount;
      _cfPhase2Total = 0;
      _cfDone = 0;
      _cfTotal = _cfPhase1Total;
      _cfStatus = 'Scanning ${_cfPhase1Total} IPs...';
    });

    try {
      await runCfXrayScanner(
        ips: manualIps,
        sampleCount: _cfSampleCount,
        concurrency: _cfConcurrency,
        timeoutMs: _cfTimeoutMs,
        config: config,
        topN: _cfTopN,
        tries: _cfTries,
        sortMode: _cfSortMode,
        cidrFilter: null,
        validationMode: CfValidationMode.wsProbe,
        isCancelled: () => _cfCancelled,
        onPhase1Progress: (result, done, total) {
          if (!mounted) return;
          setState(() {
            _cfPhase1Results.add(result);
            _cfPhase1Done_count = done;
            _cfPhase1Total = total;
          });
        },
        onPhase2Progress: (result, done, total) {
          if (!mounted) return;
          setState(() {
            _cfPhase2Results.add(result);
            _cfPhase2Done_count = done;
            _cfPhase2Total = total;
          });
        },
      );
      if (mounted) {
        setState(() {
          _cfScanning = false;
          _cfPhase1Done = true;
          _cfPhase2Done = config != null;
          final edgeCount = _cfPhase1Results.where((r) => r.isEdge).length;
          final xrayCount = _cfPhase2Results.where((r) => r.success).length;
          _cfStatus = config != null
              ? 'Done! $xrayCount Config OK / $edgeCount CF edge'
              : 'Done! $edgeCount CF edge IPs found';
        });
      }
    } catch (e) {
      if (mounted) setState(() { _cfScanning = false; _cfStatus = 'Error: $e'; });
    }
  }

  void _stopCfScan() {
    setState(() { _cfCancelled = true; _cfScanning = false; });
  }

  // ── Sort button helper (SENPAI-SYNC) ───────────────────────────────────────
  Widget _cfSortBtn(CfSortMode mode, String label) {
    final sel = _cfSortMode == mode;
    return Padding(
      padding: const EdgeInsets.only(right: 6),
      child: GestureDetector(
        onTap: () => setState(() => _cfSortMode = mode),
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 7),
          decoration: BoxDecoration(
            color: sel ? const Color(0xFF00E5FF) : card2Color,
            borderRadius: BorderRadius.circular(10),
            border: Border.all(color: sel ? const Color(0xFF00E5FF) : borderColor),
          ),
          child: Text(label,
              style: GoogleFonts.inter(
                  color: sel ? bgColor : textPrimary,
                  fontWeight: FontWeight.w700,
                  fontSize: 12)),
        ),
      ),
    );
  }

  // ── Phase 1 result card ────────────────────────────────────────────────────
  Widget _cfPhase1ResultCard(CfPhase1Result r) {
    return Container(
      margin: const EdgeInsets.only(bottom: 6),
      padding: const EdgeInsets.all(10),
      decoration: BoxDecoration(
        color: r.isEdge ? const Color(0xFF00E5FF).withOpacity(0.05) : card2Color,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: r.isEdge ? const Color(0xFF00E5FF).withOpacity(0.4) : borderColor),
      ),
      child: Row(
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Wrap(
                  spacing: 6,
                  children: [
                    Text(r.ip, style: GoogleFonts.robotoMono(color: textPrimary, fontWeight: FontWeight.w700, fontSize: 13)),
                    if (r.isEdge) _cfBadge('CF Edge', const Color(0xFF69FF47)),
                    if (r.colo.isNotEmpty) _cfBadge(r.colo, const Color(0xFF00E5FF)),
                    if (r.wsOk == true) _cfBadge('WS OK', const Color(0xFF80E060)),
                    if (r.wsOk == false) _cfBadge('WS FAIL', const Color(0xFFFF5252)),
                  ],
                ),
                const SizedBox(height: 4),
                Wrap(
                  spacing: 8,
                  children: [
                    Text('avg ${r.avgMs.toStringAsFixed(0)}ms',
                        style: GoogleFonts.inter(color: textSecond, fontSize: 11)),
                    if (r.latencies.length > 1) ...[
                      Text('min ${r.minMs.toStringAsFixed(0)}ms',
                          style: GoogleFonts.inter(color: const Color(0xFF69FF47), fontSize: 11)),
                      Text('max ${r.maxMs.toStringAsFixed(0)}ms',
                          style: GoogleFonts.inter(color: textSecond, fontSize: 11)),
                      Text('jitter ${r.jitterMs.toStringAsFixed(0)}ms',
                          style: GoogleFonts.inter(color: const Color(0xFFFFD060), fontSize: 11)),
                      Text('loss ${r.lossPercent.toStringAsFixed(0)}%',
                          style: GoogleFonts.inter(
                              color: r.lossPercent > 0 ? const Color(0xFFFF9800) : textSecond,
                              fontSize: 11,
                              fontWeight: r.lossPercent > 0 ? FontWeight.w700 : FontWeight.w400)),
                    ],
                    Text('HTTP ${r.httpStatus}',
                        style: GoogleFonts.inter(color: textSecond, fontSize: 11)),
                  ],
                ),
              ],
            ),
          ),
          GestureDetector(
            onTap: () { Clipboard.setData(ClipboardData(text: r.ip)); _showSnack('Copied'); },
            child: const Icon(Icons.copy, color: Color(0xFF00E5FF), size: 16),
          ),
        ],
      ),
    );
  }

  // ── Phase 2 result card (Config validated) ──────────────────────────────────
  Widget _cfPhase2ResultCard(CfPhase2Result r) {
    final ok = r.success;
    final accent = ok ? const Color(0xFF69FF47) : const Color(0xFFFF5252);
    return Container(
      margin: const EdgeInsets.only(bottom: 6),
      padding: const EdgeInsets.all(10),
      decoration: BoxDecoration(
        color: ok ? accent.withOpacity(0.05) : card2Color,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: ok ? accent.withOpacity(0.4) : borderColor),
      ),
      child: Row(
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Wrap(
                  spacing: 6,
                  children: [
                    Text(r.ip, style: GoogleFonts.robotoMono(color: textPrimary, fontWeight: FontWeight.w700, fontSize: 13)),
                    _cfBadge(ok ? 'Config OK' : 'Config FAIL', accent),
                    if (r.phase1.colo.isNotEmpty) _cfBadge(r.phase1.colo, const Color(0xFF00E5FF)),
                    if (ok && r.validation.throughputKBs > 0)
                      _cfBadge('${r.validation.throughputKBs.toStringAsFixed(0)} KB/s', const Color(0xFFFFD060)),
                  ],
                ),
                const SizedBox(height: 4),
                if (ok)
                  Wrap(
                    spacing: 8,
                    children: [
                      Text('${r.validation.latencyMs.toStringAsFixed(0)} ms',
                          style: GoogleFonts.inter(color: const Color(0xFF69FF47), fontSize: 11, fontWeight: FontWeight.w600)),
                      if (r.validation.throughputKBs > 0)
                        Text('${r.validation.throughputKBs.toStringAsFixed(0)} KB/s',
                            style: GoogleFonts.inter(color: textSecond, fontSize: 11)),
                      Text('CF avg ${r.phase1.avgMs.toStringAsFixed(0)}ms',
                          style: GoogleFonts.inter(color: textSecond, fontSize: 11)),
                      if (r.phase1.latencies.length > 1) ...[
                        Text('loss ${r.phase1.lossPercent.toStringAsFixed(0)}%',
                            style: GoogleFonts.inter(
                                color: r.phase1.lossPercent > 0 ? const Color(0xFFFF9800) : textSecond,
                                fontSize: 11,
                                fontWeight: r.phase1.lossPercent > 0 ? FontWeight.w700 : FontWeight.w400)),
                        Text('jitter ${r.phase1.jitterMs.toStringAsFixed(0)}ms',
                            style: GoogleFonts.inter(color: const Color(0xFFFFD060), fontSize: 11)),
                      ],
                    ],
                  )
                else
                  GestureDetector(
                    onTap: () {
                      // Tap to copy full error to clipboard
                      final fullErr = r.validation.error.isNotEmpty
                          ? r.validation.error
                          : 'validation failed';
                      Clipboard.setData(ClipboardData(text: fullErr));
                      _showSnack('Error copied');
                    },
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          r.validation.error.isNotEmpty ? r.validation.error : 'validation failed',
                          style: GoogleFonts.robotoMono(color: const Color(0xFFFF5252), fontSize: 10),
                          maxLines: 6,
                          overflow: TextOverflow.ellipsis,
                        ),
                        const SizedBox(height: 2),
                        Text('tap to copy full log',
                            style: GoogleFonts.inter(color: const Color(0xFF888888), fontSize: 9)),
                      ],
                    ),
                  ),
              ],
            ),
          ),
          GestureDetector(
            onTap: () { Clipboard.setData(ClipboardData(text: r.ip)); _showSnack('Copied'); },
            child: Icon(Icons.copy, color: ok ? const Color(0xFF69FF47) : textSecond, size: 16),
          ),
        ],
      ),
    );
  }

  Widget _cfBadge(String label, Color color) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 2),
      decoration: BoxDecoration(
        color: color.withOpacity(0.12),
        borderRadius: BorderRadius.circular(5),
        border: Border.all(color: color.withOpacity(0.4)),
      ),
      child: Text(label, style: GoogleFonts.inter(color: color, fontSize: 10, fontWeight: FontWeight.w700)),
    );
  }

  Widget _cfResultCard(CloudflareResult r) {
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: r.isEdge ? const Color(0xFF00E5FF).withOpacity(0.05) : card2Color,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(
          color: r.isEdge ? const Color(0xFF00E5FF).withOpacity(0.4) : borderColor,
        ),
      ),
      child: Row(
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Text(r.ip, style: GoogleFonts.robotoMono(color: textPrimary, fontWeight: FontWeight.w700, fontSize: 14)),
                    if (r.isEdge) ...[
                      const SizedBox(width: 8),
                      Container(
                        padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                        decoration: BoxDecoration(
                          color: const Color(0xFF69FF47).withOpacity(0.12),
                          borderRadius: BorderRadius.circular(6),
                          border: Border.all(color: const Color(0xFF69FF47).withOpacity(0.4)),
                        ),
                        child: Text('CF Edge', style: GoogleFonts.inter(color: const Color(0xFF69FF47), fontSize: 10, fontWeight: FontWeight.w700)),
                      ),
                    ],
                  ],
                ),
                const SizedBox(height: 6),
                Wrap(
                  spacing: 6,
                  children: [
                    if (r.colo.isNotEmpty)
                      _chip(Icons.cell_tower_rounded, r.colo, const Color(0xFF00E5FF)),
                    _chip(
                      r.tlsOk ? Icons.lock_rounded : Icons.lock_open_rounded,
                      r.tlsOk ? 'TLS ✓' : 'TLS ✗',
                      r.tlsOk ? const Color(0xFF69FF47) : const Color(0xFFFF5252),
                    ),
                    if (r.wsOk != null)
                      _chip(
                        r.wsOk! ? Icons.check_circle_rounded : Icons.block_rounded,
                        r.wsOk! ? 'WS ✓' : 'WS ✗',
                        r.wsOk! ? const Color(0xFF69FF47) : const Color(0xFFFF5252),
                      ),
                    _chip(Icons.timer_outlined, '${r.latencyMs.toStringAsFixed(0)} ms', textSecond),
                    if (r.httpStatus > 0)
                      _chip(Icons.http_rounded, 'HTTP ${r.httpStatus}', r.httpStatus < 400 ? const Color(0xFF80E060) : const Color(0xFFFF5252)),
                  ],
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }


  // ═══════════════════════════════════════════════════════════════════════════
  // DNS Apply — Windows only
  // ═══════════════════════════════════════════════════════════════════════════

  Future<void> _applyDns(String ip, {bool secondary = false}) async {
    if (!Platform.isWindows) {
      _showSnack('Apply DNS is only supported on Windows.');
      return;
    }
    if (!mounted) return;
    setState(() {
      if (secondary) _applyingDns2 = true;
      else           _applyingDns  = true;
      _applyDnsError   = null;
      _applyDnsMessage = null;
    });
    try {
      final ifResult = await Process.run(
        'netsh', ['interface', 'show', 'interface'],
        runInShell: true,
      );
      if (!mounted) return;
      final activeIface = _parseActiveInterface(ifResult.stdout.toString());
      if (activeIface == null) {
        if (!mounted) return;
        setState(() {
          if (secondary) _applyingDns2 = false;
          else           _applyingDns  = false;
          _applyDnsError = 'No active network interface found. Check your connection.';
        });
        return;
      }

      ProcessResult r1;
      if (!secondary) {
        // Primary: set static → replaces existing primary
        r1 = await Process.run(
          'netsh', ['interface', 'ip', 'set', 'dns', activeIface, 'static', ip],
          runInShell: true,
        );
      } else {
        // Secondary: add at index 2
        r1 = await Process.run(
          'netsh', ['interface', 'ip', 'add', 'dns', activeIface, ip, 'index=2'],
          runInShell: true,
        );
      }

      if (!mounted) return;
      if (r1.exitCode == 0) {
        if (!secondary) _startDnsMonitor(ip);
        if (!mounted) return;
        setState(() {
          if (secondary) {
            _appliedDns2Ip  = ip;
            _applyingDns2   = false;
          } else {
            _appliedDnsIp   = ip;
            _applyingDns    = false;
          }
          _applyDnsMessage = secondary
              ? '✓ DNS 2 set on "$activeIface"'
              : '✓ DNS 1 set on "$activeIface"';
          _applyDnsError = null;
        });
      } else {
        if (!mounted) return;
        setState(() {
          if (secondary) _applyingDns2 = false;
          else           _applyingDns  = false;
          _applyDnsError = 'Failed (exit ${r1.exitCode}). Run as Administrator.';
        });
      }
    } catch (e) {
      if (!mounted) return;
      setState(() {
        if (secondary) _applyingDns2 = false;
        else           _applyingDns  = false;
        _applyDnsError = 'Error: $e';
      });
    }
  }

  String? _parseActiveInterface(String netshOutput) {
    final lines = netshOutput.split('\n');
    for (final line in lines) {
      final trimmed = line.trim();
      if (trimmed.contains('Connected') && trimmed.contains('Enabled')) {
        final parts = trimmed.split(RegExp(r'\s{2,}'));
        if (parts.length >= 4) return parts.last.trim();
      }
    }
    // Fallback: try common names
    for (final line in lines) {
      final t = line.trim();
      if (t.contains('Connected')) {
        final parts = t.split(RegExp(r'\s{2,}'));
        if (parts.length >= 4) return parts.last.trim();
      }
    }
    return null;
  }

  Future<void> _resetDns() async {
    if (!Platform.isWindows) return;
    if (mounted) setState(() { _applyingDns = true; _applyDnsError = null; });
    try {
      final ifResult = await Process.run(
        'netsh', ['interface', 'show', 'interface'], runInShell: true);
      final activeIface = _parseActiveInterface(ifResult.stdout.toString());
      if (activeIface == null) {
        if (mounted) setState(() { _applyingDns = false; });
        return;
      }
      await Process.run(
        'netsh', ['interface', 'ip', 'set', 'dns', activeIface, 'dhcp'],
        runInShell: true,
      );
      _stopDnsMonitor();
      if (mounted) setState(() {
        _appliedDnsIp  = null;
        _appliedDns2Ip = null;
        _applyingDns   = false;
        _applyingDns2  = false;
        _applyDnsMessage = '✓ DNS reset to Automatic (DHCP)';
        _applyDnsError = null;
        _dnsMonLat = null;
        _dnsMonJitter = null;
        _dnsMonLoss = null;
        _dnsMonSamples = 0;
        _dnsMonFails = 0;
        _dnsMonLatHistory.clear();
      });
    } catch (e) {
      if (mounted) setState(() { _applyingDns = false; _applyDnsError = 'Error: $e'; });
    }
  }

  void _startDnsMonitor(String ip) {
    _stopDnsMonitor();
    _dnsMonSamples = 0;
    _dnsMonFails = 0;
    _dnsMonLatHistory.clear();
    setState(() { _dnsMonLat = null; _dnsMonJitter = null; _dnsMonLoss = null; });
    _dnsMonitorTimer = Timer.periodic(const Duration(seconds: 2), (_) => _dnsMonitorTick(ip));
    _dnsMonitorTick(ip);
  }

  void _stopDnsMonitor() {
    _dnsMonitorTimer?.cancel();
    _dnsMonitorTimer = null;
  }

  Future<void> _dnsMonitorTick(String ip) async {
    if (!mounted) return;
    Socket? sock;
    double latency = 9999;
    bool alive = false;
    try {
      final t = DateTime.now();
      sock = await Socket.connect(ip, 53, timeout: const Duration(seconds: 2));
      latency = DateTime.now().difference(t).inMilliseconds.toDouble();
      alive = true;
      await sock.close();
      sock.destroy();
    } catch (_) {
      try { sock?.destroy(); } catch (_) {}
    }
    if (!mounted) return;
    setState(() {
      _dnsMonSamples++;
      if (!alive) {
        _dnsMonFails++;
      } else {
        _dnsMonLatHistory.add(latency);
        if (_dnsMonLatHistory.length > 20) _dnsMonLatHistory.removeAt(0);
        final n = _dnsMonLatHistory.length;
        _dnsMonLat = _dnsMonLatHistory.reduce((a, b) => a + b) / n;
        if (n >= 2) {
          final mean = _dnsMonLat!;
          final variance = _dnsMonLatHistory
              .map((v) => (v - mean) * (v - mean))
              .reduce((a, b) => a + b) / n;
          _dnsMonJitter = math.sqrt(variance);
        }
      }
      if (_dnsMonSamples > 0) {
        _dnsMonLoss = (_dnsMonFails / _dnsMonSamples) * 100;
      }
    });
  }

  String _dnsGamingGrade() {
    final lat = _dnsMonLat ?? 9999;
    final jit = _dnsMonJitter ?? 9999;
    final loss = _dnsMonLoss ?? 100;
    if (lat < 20 && jit < 5 && loss < 1) return '⚡ EXCELLENT — Pro Gaming';
    if (lat < 50 && jit < 15 && loss < 2) return '✅ GOOD — Gaming Ready';
    if (lat < 100 && jit < 30 && loss < 5) return '⚠️ FAIR — Playable';
    return '❌ POOR — Not Recommended';
  }

  Color _dnsGamingColor() {
    final lat = _dnsMonLat ?? 9999;
    final jit = _dnsMonJitter ?? 9999;
    final loss = _dnsMonLoss ?? 100;
    if (lat < 20 && jit < 5 && loss < 1) return const Color(0xFF00FF88);
    if (lat < 50 && jit < 15 && loss < 2) return const Color(0xFF69FF47);
    if (lat < 100 && jit < 30 && loss < 5) return const Color(0xFFFFD060);
    return Colors.redAccent;
  }

  Widget _buildDnsStatusPanel() {
    final lat = _dnsMonLat;
    final jit = _dnsMonJitter;
    final loss = _dnsMonLoss;
    final ready = lat != null;

    Color latColor(double v) =>
        v < 20 ? const Color(0xFF00FF88) : v < 50 ? const Color(0xFF69FF47) : v < 100 ? const Color(0xFFFFD060) : Colors.redAccent;
    Color jitColor(double v) =>
        v < 5 ? const Color(0xFF00FF88) : v < 15 ? const Color(0xFF69FF47) : v < 30 ? const Color(0xFFFFD060) : Colors.redAccent;
    Color lossColor(double v) =>
        v < 1 ? const Color(0xFF00FF88) : v < 5 ? const Color(0xFFFFD060) : Colors.redAccent;

    return Container(
      margin: const EdgeInsets.only(top: 14),
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: const Color(0xFF0D1F2D),
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: const Color(0xFF00E5FF).withOpacity(0.4), width: 1.5),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // Header
          Row(
            children: [
              Container(
                width: 8, height: 8,
                decoration: BoxDecoration(
                  color: ready ? const Color(0xFF00FF88) : const Color(0xFFFFD060),
                  shape: BoxShape.circle,
                  boxShadow: [BoxShadow(color: ready ? const Color(0xFF00FF88) : const Color(0xFFFFD060), blurRadius: 6)],
                ),
              ),
              const SizedBox(width: 8),
              Text(
                ready ? 'DNS Connected' : 'Connecting…',
                style: GoogleFonts.inter(
                  color: const Color(0xFF00E5FF),
                  fontWeight: FontWeight.w800,
                  fontSize: 13,
                ),
              ),
              const Spacer(),
              Text(
                _appliedDnsIp ?? '',
                style: GoogleFonts.robotoMono(
                  color: Colors.white70,
                  fontSize: 13,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ],
          ),
          if (ready) ...[
            const SizedBox(height: 12),
            // Gaming Grade Banner
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 7),
              decoration: BoxDecoration(
                color: _dnsGamingColor().withOpacity(0.1),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: _dnsGamingColor().withOpacity(0.5)),
              ),
              child: Text(
                _dnsGamingGrade(),
                style: GoogleFonts.inter(
                  color: _dnsGamingColor(),
                  fontWeight: FontWeight.w800,
                  fontSize: 12,
                ),
                textAlign: TextAlign.center,
              ),
            ),
            const SizedBox(height: 12),
            // Metrics row
            Row(
              children: [
                _dnsMetricBox('LATENCY', '${lat.toStringAsFixed(1)}ms', latColor(lat)),
                const SizedBox(width: 8),
                _dnsMetricBox('JITTER', jit != null ? '${jit.toStringAsFixed(1)}ms' : '--', jit != null ? jitColor(jit) : Colors.white38),
                const SizedBox(width: 8),
                _dnsMetricBox('LOSS', loss != null ? '${loss.toStringAsFixed(1)}%' : '--', loss != null ? lossColor(loss) : Colors.white38),
                const SizedBox(width: 8),
                _dnsMetricBox('SAMPLES', '$_dnsMonSamples', Colors.white38),
              ],
            ),
            const SizedBox(height: 10),
            // Mini latency bar chart (last 10 samples)
            if (_dnsMonLatHistory.length >= 2) _buildLatencySparkline(),
          ] else ...[
            const SizedBox(height: 8),
            const LinearProgressIndicator(
              backgroundColor: Colors.white12,
              color: Color(0xFF00E5FF),
              minHeight: 3,
            ),
          ],
          const SizedBox(height: 12),
          // Reset button
          OutlinedButton.icon(
            onPressed: _applyingDns ? null : _resetDns,
            icon: const Icon(Icons.dns_outlined, size: 15),
            label: Text('Reset to Auto DNS', style: GoogleFonts.inter(fontWeight: FontWeight.w600, fontSize: 12)),
            style: OutlinedButton.styleFrom(
              foregroundColor: Colors.white54,
              side: const BorderSide(color: Colors.white24),
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
              padding: const EdgeInsets.symmetric(vertical: 8),
            ),
          ),
        ],
      ),
    );
  }

  Widget _dnsMetricBox(String label, String value, Color color) {
    return Expanded(
      child: Container(
        padding: const EdgeInsets.symmetric(vertical: 8, horizontal: 6),
        decoration: BoxDecoration(
          color: color.withOpacity(0.07),
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: color.withOpacity(0.25)),
        ),
        child: Column(
          children: [
            Text(label, style: TextStyle(fontSize: 8, color: Colors.white38, fontWeight: FontWeight.w700, letterSpacing: 0.5)),
            const SizedBox(height: 3),
            Text(value, style: TextStyle(fontSize: 13, color: color, fontWeight: FontWeight.w800)),
          ],
        ),
      ),
    );
  }

  Widget _buildLatencySparkline() {
    final hist = _dnsMonLatHistory.length > 10 ? _dnsMonLatHistory.sublist(_dnsMonLatHistory.length - 10) : _dnsMonLatHistory;
    final maxVal = hist.reduce(math.max);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Text('LATENCY HISTORY', style: const TextStyle(fontSize: 8, color: Colors.white38, letterSpacing: 0.8, fontWeight: FontWeight.w700)),
        const SizedBox(height: 4),
        SizedBox(
          height: 28,
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.end,
            children: hist.map((v) {
              final h = maxVal > 0 ? (v / maxVal).clamp(0.1, 1.0) : 0.1;
              Color c = v < 20 ? const Color(0xFF00FF88) : v < 50 ? const Color(0xFF69FF47) : v < 100 ? const Color(0xFFFFD060) : Colors.redAccent;
              return Expanded(
                child: Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 1),
                  child: FractionallySizedBox(
                    heightFactor: h,
                    child: Container(
                      decoration: BoxDecoration(
                        color: c.withOpacity(0.7),
                        borderRadius: BorderRadius.circular(2),
                      ),
                    ),
                  ),
                ),
              );
            }).toList(),
          ),
        ),
      ],
    );
  }



  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // ── Android DNS VPN Apply Section ─────────────────────────────────────────
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Widget _buildAndroidApplyDnsSection() {
    final aliveSorted = (_dnsResults ?? []).where((s) => !s.eliminated).toList();
    final top5 = aliveSorted.take(5).toList();

    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: const Color(0xFF0A1A1F),
        borderRadius: BorderRadius.circular(14),
        border: Border.all(
          color: _dnsVpnRunning
              ? const Color(0xFF00FF88).withOpacity(0.6)
              : const Color(0xFF00E5FF).withOpacity(0.35),
          width: 1.5,
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // Header
          Row(
            children: [
              Icon(
                _dnsVpnRunning ? Icons.shield_rounded : Icons.dns_rounded,
                color: _dnsVpnRunning ? const Color(0xFF00FF88) : const Color(0xFF00E5FF),
                size: 16,
              ),
              const SizedBox(width: 8),
              Text(
                _dnsVpnRunning ? 'DNS VPN ACTIVE' : 'APPLY DNS',
                style: GoogleFonts.inter(
                  color: _dnsVpnRunning ? const Color(0xFF00FF88) : const Color(0xFF00E5FF),
                  fontWeight: FontWeight.w800,
                  fontSize: 13,
                  letterSpacing: 1.2,
                ),
              ),
              const Spacer(),
              if (_dnsVpnRunning) ...[
                Text(
                  _dnsVpnActiveDns1 ?? '',
                  style: GoogleFonts.robotoMono(
                      color: Colors.white54, fontSize: 11, fontWeight: FontWeight.w600),
                ),
                const SizedBox(width: 8),
                GestureDetector(
                  onTap: _stopDnsVpn,
                  child: Container(
                    padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                    decoration: BoxDecoration(
                      color: Colors.redAccent.withOpacity(0.15),
                      borderRadius: BorderRadius.circular(8),
                      border: Border.all(color: Colors.redAccent.withOpacity(0.5)),
                    ),
                    child: Text('Stop VPN',
                        style: GoogleFonts.inter(
                            color: Colors.redAccent,
                            fontWeight: FontWeight.w700,
                            fontSize: 11)),
                  ),
                ),
              ],
            ],
          ),
          if (!_dnsVpnRunning) ...[
            const SizedBox(height: 4),
            Text(
              'Tap Apply to route all DNS through a server via local VPN.',
              style: GoogleFonts.inter(color: Colors.white38, fontSize: 11, height: 1.4),
            ),
          ],
          const SizedBox(height: 12),

          // Top server rows (only when VPN not active)
          if (!_dnsVpnRunning)
            ...top5.asMap().entries.map((e) {
              final s = e.value;
              final rank = s.finalRank ?? (e.key + 1);
              final lat  = s.avgLatencyMs?.toStringAsFixed(0) ?? '?';
              final freedom = ((s.freedomScore ?? 0) * 100).toStringAsFixed(0);
              final Color rankColor = switch (rank) {
                1 => const Color(0xFFFFD700),
                2 => const Color(0xFFC0C0C0),
                3 => const Color(0xFFCD7F32),
                _ => Colors.white24,
              };

              return Padding(
                padding: const EdgeInsets.only(bottom: 7),
                child: Row(
                  children: [
                    Container(
                      width: 26, height: 26,
                      alignment: Alignment.center,
                      decoration: BoxDecoration(color: rankColor, shape: BoxShape.circle),
                      child: Text('#\$rank',
                          style: const TextStyle(
                              fontSize: 9, fontWeight: FontWeight.bold, color: Colors.black87)),
                    ),
                    const SizedBox(width: 10),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(s.ip,
                              style: GoogleFonts.robotoMono(
                                  color: Colors.white,
                                  fontWeight: FontWeight.w700,
                                  fontSize: 13)),
                          Row(children: [
                            _applyStatChip('\${lat}ms', Colors.white38),
                            const SizedBox(width: 6),
                            _applyStatChip('Free \${freedom}%', const Color(0xFF69FF47)),
                          ]),
                        ],
                      ),
                    ),
                    _dnsVpnStarting
                        ? const SizedBox(
                            width: 44, height: 28,
                            child: Center(
                              child: SizedBox(
                                width: 14, height: 14,
                                child: CircularProgressIndicator(
                                    strokeWidth: 2, color: Color(0xFF00E5FF)),
                              ),
                            ))
                        : GestureDetector(
                            onTap: () => _startDnsVpn(s.ip),
                            child: Container(
                              padding: const EdgeInsets.symmetric(
                                  horizontal: 12, vertical: 6),
                              decoration: BoxDecoration(
                                color: const Color(0xFF00E5FF).withOpacity(0.12),
                                borderRadius: BorderRadius.circular(8),
                                border: Border.all(
                                    color: const Color(0xFF00E5FF).withOpacity(0.5)),
                              ),
                              child: Text('Apply',
                                  style: GoogleFonts.inter(
                                      color: const Color(0xFF00E5FF),
                                      fontWeight: FontWeight.w700,
                                      fontSize: 11)),
                            ),
                          ),
                  ],
                ),
              );
            }),

          // Divider
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 10),
            child: Row(children: [
              const Expanded(child: Divider(color: Colors.white12)),
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 8),
                child: Text('or enter manually',
                    style: GoogleFonts.inter(color: Colors.white38, fontSize: 11)),
              ),
              const Expanded(child: Divider(color: Colors.white12)),
            ]),
          ),

          // Manual DNS toggle
          GestureDetector(
            onTap: () => setState(() => _showManualDnsInput = !_showManualDnsInput),
            child: Row(
              children: [
                const Icon(Icons.edit_rounded, color: Colors.white38, size: 14),
                const SizedBox(width: 6),
                Text('Manual DNS Entry',
                    style: GoogleFonts.inter(
                        color: Colors.white54,
                        fontWeight: FontWeight.w600,
                        fontSize: 12)),
                const Spacer(),
                Icon(
                  _showManualDnsInput
                      ? Icons.expand_less_rounded
                      : Icons.expand_more_rounded,
                  color: Colors.white38, size: 16,
                ),
              ],
            ),
          ),

          if (_showManualDnsInput) ...[
            const SizedBox(height: 10),
            _buildDnsTextField(_manualDns1Controller, 'DNS 1 (e.g. 8.8.8.8)'),
            const SizedBox(height: 8),
            _buildDnsTextField(_manualDns2Controller, 'DNS 2 (optional)'),
            const SizedBox(height: 10),
            SizedBox(
              width: double.infinity,
              child: FilledButton.icon(
                onPressed: _dnsVpnStarting ? null : () {
                  final d1 = _manualDns1Controller.text.trim();
                  final d2 = _manualDns2Controller.text.trim();
                  if (d1.isEmpty) { _showSnack('Enter at least DNS 1'); return; }
                  _startDnsVpn(d1, dns2: d2.isEmpty ? null : d2);
                },
                icon: _dnsVpnStarting
                    ? const SizedBox(
                        width: 14, height: 14,
                        child: CircularProgressIndicator(strokeWidth: 2))
                    : const Icon(Icons.play_arrow_rounded, size: 16),
                label: Text('Apply Manual DNS',
                    style: GoogleFonts.inter(
                        fontWeight: FontWeight.w700, fontSize: 13)),
                style: FilledButton.styleFrom(
                  backgroundColor: const Color(0xFF00E5FF),
                  foregroundColor: const Color(0xFF0D1117),
                  shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(10)),
                  padding: const EdgeInsets.symmetric(vertical: 10),
                ),
              ),
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildDnsTextField(TextEditingController ctrl, String hint) {
    return TextField(
      controller: ctrl,
      keyboardType: const TextInputType.numberWithOptions(decimal: true),
      style: GoogleFonts.robotoMono(color: Colors.white, fontSize: 13),
      decoration: InputDecoration(
        hintText: hint,
        hintStyle: GoogleFonts.robotoMono(color: Colors.white38, fontSize: 12),
        filled: true,
        fillColor: Colors.white.withOpacity(0.05),
        contentPadding:
            const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
        border: OutlineInputBorder(
            borderRadius: BorderRadius.circular(10),
            borderSide: const BorderSide(color: Colors.white12)),
        enabledBorder: OutlineInputBorder(
            borderRadius: BorderRadius.circular(10),
            borderSide: const BorderSide(color: Colors.white12)),
        focusedBorder: OutlineInputBorder(
            borderRadius: BorderRadius.circular(10),
            borderSide:
                const BorderSide(color: Color(0xFF00E5FF), width: 1.5)),
      ),
    );
  }

  // ── Android VPN methods ───────────────────────────────────────────────────

  Future<void> _startDnsVpn(String dns1, {String? dns2}) async {
    if (!Platform.isAndroid) return;
    if (!mounted) return;
    setState(() { _dnsVpnStarting = true; });
    try {
      await _dnsVpnChannel.invokeMethod<void>('startVpn', {
        'dns1': dns1,
        'dns2': dns2,
      });
      if (mounted) {
        setState(() {
          _dnsVpnRunning     = true;
          _dnsVpnActiveDns1  = dns1;
          _dnsVpnActiveDns2  = dns2;
          _dnsVpnStarting    = false;
        });
        _showSnack('✓ DNS VPN active — routing through \$dns1');
      }
    } on PlatformException catch (e) {
      if (mounted) {
        setState(() { _dnsVpnStarting = false; });
        if (e.code == 'VPN_DENIED') {
          _showSnack('VPN permission denied. Please allow it and try again.');
        } else {
          _showSnack('Failed to start DNS VPN: \${e.message}');
        }
      }
    } catch (e) {
      if (mounted) {
        setState(() { _dnsVpnStarting = false; });
        _showSnack('Error: \$e');
      }
    }
  }

  Future<void> _stopDnsVpn() async {
    if (!Platform.isAndroid) return;
    try {
      await _dnsVpnChannel.invokeMethod<void>('stopVpn');
      if (mounted) {
        setState(() {
          _dnsVpnRunning    = false;
          _dnsVpnActiveDns1 = null;
          _dnsVpnActiveDns2 = null;
        });
        _showSnack('DNS VPN stopped.');
      }
    } catch (e) {
      _showSnack('Error stopping VPN: \$e');
    }
  }

  Widget _buildApplyDnsSection() {
    final topServers = (_dnsResults ?? []).take(5).toList();
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: const Color(0xFF0A1A1F),
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: const Color(0xFF00E5FF).withOpacity(0.35), width: 1.5),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Row(
            children: [
              const Icon(Icons.dns_rounded, color: Color(0xFF00E5FF), size: 16),
              const SizedBox(width: 8),
              Text(
                'APPLY DNS',
                style: GoogleFonts.inter(
                  color: const Color(0xFF00E5FF),
                  fontWeight: FontWeight.w800,
                  fontSize: 13,
                  letterSpacing: 1.2,
                ),
              ),
              const Spacer(),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 3),
                decoration: BoxDecoration(
                  color: const Color(0xFF1A2A1A),
                  borderRadius: BorderRadius.circular(6),
                  border: Border.all(color: Colors.white12),
                ),
                child: Text(
                  '🎮 Game Optimizer',
                  style: GoogleFonts.inter(color: Colors.white38, fontSize: 10, fontWeight: FontWeight.w600),
                ),
              ),
            ],
          ),
          const SizedBox(height: 4),
          Text(
            'Select a DNS to apply system-wide. Run as Administrator for full access.',
            style: GoogleFonts.inter(color: Colors.white38, fontSize: 11, height: 1.4),
          ),
          const SizedBox(height: 12),
          // Top DNS server buttons
          ...topServers.asMap().entries.map((e) {
            final s = e.value;
            final rank = s.finalRank ?? (e.key + 1);
            final lat = s.avgLatencyMs?.toStringAsFixed(0) ?? '?';
            final freedom = ((s.freedomScore ?? 0) * 100).toStringAsFixed(0);
            final score = s.finalScore?.toStringAsFixed(1) ?? '?';
            Color rankColor = switch (rank) {
              1 => const Color(0xFFFFD700),
              2 => const Color(0xFFC0C0C0),
              3 => const Color(0xFFCD7F32),
              _ => Colors.white24,
            };

            return GestureDetector(
              onTap: null, // tap handled by DNS1/DNS2 buttons
              child: AnimatedContainer(
                duration: const Duration(milliseconds: 200),
                margin: const EdgeInsets.only(bottom: 7),
                padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                decoration: BoxDecoration(
                  color: (_appliedDnsIp == s.ip || _appliedDns2Ip == s.ip)
                      ? const Color(0xFF00E5FF).withOpacity(0.07)
                      : Colors.white.withOpacity(0.03),
                  borderRadius: BorderRadius.circular(10),
                  border: Border.all(
                    color: (_appliedDnsIp == s.ip || _appliedDns2Ip == s.ip)
                        ? const Color(0xFF00E5FF).withOpacity(0.4)
                        : Colors.white12,
                    width: (_appliedDnsIp == s.ip || _appliedDns2Ip == s.ip) ? 1.5 : 1,
                  ),
                ),
                child: Row(
                  children: [
                    // Rank badge
                    Container(
                      width: 26,
                      height: 26,
                      alignment: Alignment.center,
                      decoration: BoxDecoration(color: rankColor, shape: BoxShape.circle),
                      child: Text('#$rank',
                          style: const TextStyle(fontSize: 9, fontWeight: FontWeight.bold, color: Colors.black87)),
                    ),
                    const SizedBox(width: 10),
                    // IP
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            s.ip,
                            style: GoogleFonts.robotoMono(
                              color: (_appliedDnsIp == s.ip || _appliedDns2Ip == s.ip)
                                  ? const Color(0xFF00E5FF) : Colors.white,
                              fontWeight: FontWeight.w700,
                              fontSize: 13,
                            ),
                          ),
                          const SizedBox(height: 2),
                          Row(
                            children: [
                              _applyStatChip('${lat}ms', Colors.white38),
                              const SizedBox(width: 6),
                              _applyStatChip('Free ${freedom}%', const Color(0xFF69FF47)),
                              const SizedBox(width: 6),
                              _applyStatChip('Score $score', const Color(0xFF00E5FF)),
                            ],
                          ),
                        ],
                      ),
                    ),
                    // DNS 1 + DNS 2 buttons
                    Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        // ── DNS 1 ────────────────────────────────────────────
                        _dnsApplyBtn(
                          label: 'DNS 1',
                          ip: s.ip,
                          isSet: _appliedDnsIp == s.ip,
                          isLoading: _applyingDns && _appliedDnsIp == null,
                          onTap: (_applyingDns || _appliedDnsIp == s.ip)
                              ? null
                              : () => _applyDns(s.ip),
                          accent: const Color(0xFF00E5FF),
                        ),
                        const SizedBox(width: 6),
                        // ── DNS 2 ────────────────────────────────────────────
                        _dnsApplyBtn(
                          label: 'DNS 2',
                          ip: s.ip,
                          isSet: _appliedDns2Ip == s.ip,
                          isLoading: _applyingDns2 && _appliedDns2Ip == null,
                          onTap: (_applyingDns2 || _appliedDns2Ip == s.ip || _appliedDnsIp == null)
                              ? null
                              : () => _applyDns(s.ip, secondary: true),
                          accent: const Color(0xFF69FF47),
                          disabled: _appliedDnsIp == null,
                        ),
                      ],
                    ),
                  ],
                ),
              ),
            );
          }),
        ],
      ),
    );
  }

  Widget _dnsApplyBtn({
    required String label,
    required String ip,
    required bool isSet,
    required bool isLoading,
    required VoidCallback? onTap,
    required Color accent,
    bool disabled = false,
  }) {
    if (isLoading) {
      return SizedBox(
        width: 42, height: 28,
        child: Center(
          child: SizedBox(
            width: 14, height: 14,
            child: CircularProgressIndicator(strokeWidth: 2, color: accent),
          ),
        ),
      );
    }
    if (isSet) {
      return Container(
        padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 4),
        decoration: BoxDecoration(
          color: accent.withOpacity(0.15),
          borderRadius: BorderRadius.circular(7),
          border: Border.all(color: accent.withOpacity(0.6)),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.check_rounded, color: accent, size: 11),
            const SizedBox(width: 3),
            Text(label,
                style: TextStyle(color: accent, fontSize: 10, fontWeight: FontWeight.w800)),
          ],
        ),
      );
    }
    // Normal / disabled button
    final active = onTap != null && !disabled;
    return GestureDetector(
      onTap: active ? onTap : null,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 5),
        decoration: BoxDecoration(
          color: active ? accent.withOpacity(0.1) : Colors.white.withOpacity(0.03),
          borderRadius: BorderRadius.circular(7),
          border: Border.all(
            color: active ? accent.withOpacity(0.45) : Colors.white12,
          ),
        ),
        child: Text(
          label,
          style: TextStyle(
            color: active ? accent : Colors.white24,
            fontSize: 11,
            fontWeight: FontWeight.w700,
          ),
        ),
      ),
    );
  }

  Widget _applyStatChip(String text, Color color) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 2),
    decoration: BoxDecoration(
      color: color.withOpacity(0.08),
      borderRadius: BorderRadius.circular(4),
    ),
    child: Text(text, style: TextStyle(fontSize: 9, color: color, fontWeight: FontWeight.w600)),
  );

  // ── DNS Card ──────────────────────────────────────────────────────────────
  Widget _buildDnsCard() {
    return _card(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // Buttons
          Row(
            children: [
              Expanded(
                child: FilledButton.icon(
                  onPressed: _dnsScanning ? null : _startDnsScan,
                  icon: _dnsScanning
                      ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2))
                      : const Icon(Icons.radar_rounded, size: 18),
                  label: Text(_dnsScanning ? 'Scanning…' : 'Start DNS Scan',
                      style: GoogleFonts.inter(fontWeight: FontWeight.w700, fontSize: 14)),
                  style: FilledButton.styleFrom(
                    backgroundColor: const Color(0xFF00E5FF),
                    foregroundColor: const Color(0xFF0D1117),
                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                  ),
                ),
              ),
              if (_dnsScanning) ...[
                const SizedBox(width: 8),
                OutlinedButton.icon(
                  onPressed: _cancelDnsScan,
                  icon: const Icon(Icons.stop_rounded, size: 16),
                  label: Text('Cancel', style: GoogleFonts.inter(fontWeight: FontWeight.w600)),
                  style: OutlinedButton.styleFrom(
                    foregroundColor: Colors.redAccent,
                    side: const BorderSide(color: Colors.redAccent),
                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                  ),
                ),
              ],
            ],
          ),
          // DNS action buttons: Copy Top 5 + Update Online
          const SizedBox(height: 8),
          Row(
            children: [
              if (_dnsResults != null && _dnsResults!.isNotEmpty) ...[
                _miniBtn('Copy Top 5 DNS', _copyTop5Dns, isAccent: true),
                const SizedBox(width: 8),
              ],
              _miniBtn(
                _dnsUpdating
                    ? 'Updating…'
                    : 'Update Online (${_activeDnsServers.length})',
                _dnsUpdating ? () {} : _updateDnsOnline,
              ),
            ],
          ),
          if (_dnsUpdateMessage != null)
            Padding(
              padding: const EdgeInsets.only(top: 4),
              child: Text(
                _dnsUpdateMessage!,
                style: TextStyle(
                  fontSize: 11,
                  color: _dnsUpdateMessage!.startsWith('✓')
                      ? const Color(0xFF69FF47)
                      : Colors.white54,
                ),
                maxLines: 2,
                overflow: TextOverflow.ellipsis,
              ),
            ),
          // Error
          if (_dnsErrorMessage != null)
            Padding(
              padding: const EdgeInsets.only(top: 8),
              child: Text(_dnsErrorMessage!,
                  style: const TextStyle(color: Colors.redAccent, fontSize: 12)),
            ),
          // Progress
          if (_dnsLastProgress != null) ...[
            const SizedBox(height: 14),
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Text(
                  _dnsStageName(_dnsLastProgress!.stage),
                  style: const TextStyle(color: Color(0xFF00E5FF), fontWeight: FontWeight.bold, fontSize: 13),
                ),
                Text(
                  '${(_dnsLastProgress!.percentage * 100).toStringAsFixed(0)}%',
                  style: const TextStyle(color: Colors.white54, fontSize: 12),
                ),
              ],
            ),
            const SizedBox(height: 6),
            LinearProgressIndicator(
              value: _dnsLastProgress!.percentage,
              backgroundColor: Colors.white12,
              color: const Color(0xFF00E5FF),
              minHeight: 5,
            ),
            const SizedBox(height: 6),
            Text(
              _dnsLastProgress!.message.split('\n').first,
              style: const TextStyle(color: Colors.white54, fontSize: 12),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
            ),
            const SizedBox(height: 8),
            // Stage log (newest first)
            if (_dnsStageLog.length > 1)
              SizedBox(
                height: 80,
                child: ListView.builder(
                  reverse: true,
                  itemCount: _dnsStageLog.length,
                  itemBuilder: (ctx, i) {
                    final entry = _dnsStageLog[_dnsStageLog.length - 1 - i];
                    return Padding(
                      padding: const EdgeInsets.symmetric(vertical: 1),
                      child: Text(
                        '• ${entry.message.split('\n').first}',
                        style: TextStyle(
                          fontSize: 11,
                          color: i == 0 ? Colors.white70 : Colors.white30,
                        ),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                    );
                  },
                ),
              ),
          ],
          // Results
          if (_dnsResults != null) ...[
            const SizedBox(height: 14),
            Text('Top DNS Servers',
                style: GoogleFonts.inter(fontSize: 15, fontWeight: FontWeight.bold, color: textPrimary)),
            const SizedBox(height: 8),
            if (_dnsResults!.isEmpty)
              Padding(
                padding: const EdgeInsets.symmetric(vertical: 12),
                child: Center(
                  child: Text('No results found.',
                      style: GoogleFonts.inter(color: textSecond, fontSize: 13)),
                ),
              )
            else
              // ── Android: only show alive servers (eliminated == false) ──
              ..._dnsResults!
                  .where((s) => !s.eliminated)
                  .toList()
                  .asMap()
                  .entries
                  .map((e) => _DnsResultCard(server: e.value)),
            // ── Apply DNS — Windows ───────────────────────────────────────
            if (Platform.isWindows && _dnsResults!.isNotEmpty) ...[
              const SizedBox(height: 16),
              _buildApplyDnsSection(),
            ],
            // DNS Status Monitor panel (shows after Windows Apply)
            if (_appliedDnsIp != null) ...[
              _buildDnsStatusPanel(),
            ],
            if (_applyDnsMessage != null && _appliedDnsIp == null)
              Padding(
                padding: const EdgeInsets.only(top: 6),
                child: Text(_applyDnsMessage!,
                    style: const TextStyle(color: Color(0xFF69FF47), fontSize: 12)),
              ),
            if (_applyDnsError != null)
              Padding(
                padding: const EdgeInsets.only(top: 6),
                child: Text(_applyDnsError!,
                    style: const TextStyle(color: Colors.redAccent, fontSize: 12)),
              ),
            // ── Apply DNS — Android (VPN) ─────────────────────────────────
            if (Platform.isAndroid && _dnsResults != null && _dnsResults!.isNotEmpty) ...[
              const SizedBox(height: 16),
              _buildAndroidApplyDnsSection(),
            ],
          ] else if (!_dnsScanning) ...[
            const SizedBox(height: 16),
            Center(
              child: Text(
                'Tap "Start DNS Scan" to find\nthe best DNS servers on your network.',
                textAlign: TextAlign.center,
                style: GoogleFonts.inter(color: textSecond, fontSize: 13, height: 1.5),
              ),
            ),
          ],
        ],
      ),
    );
  }

  Future<void> _startDnsScan() async {
    if (_dnsScanning) return;
    setState(() {
      _dnsScanning = true;
      _dnsResults = null;
      _dnsStageLog.clear();
      _dnsLastProgress = null;
      _dnsErrorMessage = null;
    });
    try {
      _dnsScanSubscription = _dnsScanner.scan(_activeDnsServers).listen(
        (progress) {
          if (!mounted) return;
          setState(() {
            _dnsLastProgress = progress;
            _dnsStageLog.add(progress);
            if (progress.stage == ScanStage.complete) {
              _dnsResults = List<DNSServer>.from(_dnsScanner.results);
              _dnsScanning = false;
            }
          });
        },
        onError: (Object e) {
          if (!mounted) return;
          setState(() { _dnsErrorMessage = 'Error: $e'; _dnsScanning = false; });
        },
        onDone: () {
          if (!mounted) return;
          setState(() => _dnsScanning = false);
        },
        cancelOnError: true,
      );
    } catch (e) {
      if (mounted) setState(() { _dnsErrorMessage = 'Error starting scan: $e'; _dnsScanning = false; });
    }
  }

  void _cancelDnsScan() {
    _dnsScanSubscription?.cancel();
    _dnsScanSubscription = null;
    if (mounted) setState(() { _dnsScanning = false; _dnsLastProgress = null; });
  }

  void _copyTop5Dns() {
    if (_dnsResults == null || _dnsResults!.isEmpty) {
      _showSnack('No DNS results yet!');
      return;
    }
    final top5 = _dnsResults!.take(5).toList();
    final text = top5.map((s) {
      final rank = s.finalRank ?? 99;
      final latency = s.avgLatencyMs?.toStringAsFixed(0) ?? '?';
      return '#$rank  ${s.ip}  (${latency}ms)';
    }).join('\n');
    Clipboard.setData(ClipboardData(text: text));
    _showSnack('\u2713 Top ${top5.length} DNS copied!');
  }

  Future<void> _updateDnsOnline() async {
    if (_dnsUpdating || _dnsScanning) return;
    setState(() {
      _dnsUpdating = true;
      _dnsUpdateMessage = 'Fetching DNS list online\u2026';
    });
    try {
      final client = HttpClient();
      client.connectionTimeout = const Duration(seconds: 15);
      final request = await client.getUrl(Uri.parse('https://public-dns.info/nameservers.csv'));
      request.headers.set('User-Agent', 'MidOneScanner/1.0');
      final response = await request.close().timeout(const Duration(seconds: 45));
      if (response.statusCode == 200) {
        final body = await response.transform(const Utf8Decoder(allowMalformed: true)).join();
        final csvLines = body.split('\n');
        final fetched = <String>[
          // Always include premium Iranian DNS
          '178.22.122.100', '185.51.200.2', // Shecan
          '78.157.42.100',  '78.157.42.101', // Electro
          '185.55.226.26',  '185.55.225.25', // Begzar
          '91.99.101.12',   '91.99.101.13',  // Pars Online
          '217.218.127.127','217.218.155.155',// TCI
          '185.143.234.1',  '185.143.235.1', // Arvancloud
          // Top global DNS
          '1.1.1.1', '1.0.0.1',   // Cloudflare
          '8.8.8.8', '8.8.4.4',   // Google
          '9.9.9.9', '149.112.112.112', // Quad9
          '94.140.14.14', '94.140.15.15', // AdGuard
          '208.67.222.222', '208.67.220.220', // OpenDNS
        ];
        bool isHeader = true;
        for (final line in csvLines) {
          if (isHeader) { isHeader = false; continue; }
          final parts = line.split(',');
          if (parts.length < 10) continue;
          final ip = parts[0].trim();
          final reliabilityStr = parts[9].trim();
          final error = parts.length > 7 ? parts[7].trim() : '';
          if (ip.isEmpty || error.isNotEmpty || !ip.contains('.')) continue;
          double reliability = 0;
          try { reliability = double.parse(reliabilityStr); } catch (_) { continue; }
          if (reliability < 0.98) continue;
          if (!fetched.contains(ip)) fetched.add(ip);
          if (fetched.length >= 2500) break;
        }
        client.close();
        if (mounted) setState(() {
          _activeDnsServers = fetched;
          _dnsUpdating = false;
          _dnsUpdateMessage = '\u2713 Updated: ${fetched.length} DNS servers loaded';
        });
      } else {
        client.close();
        if (mounted) setState(() {
          _dnsUpdating = false;
          _dnsUpdateMessage = 'HTTP ${response.statusCode} — using built-in list';
        });
      }
    } catch (e) {
      if (mounted) setState(() {
        _dnsUpdating = false;
        _dnsUpdateMessage = 'Error: $e';
      });
    }
  }

  String _dnsStageName(ScanStage s) => switch (s) {
    ScanStage.pending           => '⏳ Preparing',
    ScanStage.stage1Latency     => '⚡ Stage 1: Latency',
    ScanStage.stage2aNxdomain   => '🔍 Stage 2A: NXDOMAIN',
    ScanStage.stage2bHijack     => '🛡 Stage 2B: Hijack',
    ScanStage.stage3BurstJitter => '💨 Stage 3: Burst',
    ScanStage.stage4Freedom     => '🗽 Stage 4: Freedom',
    ScanStage.stage5Doh         => '🔒 Stage 5: DoH + Rank',
    ScanStage.complete          => '✅ Complete',
    _                           => '',
  };


  Widget _buildRangeCard() {
    return _card(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // ── Header ──────────────────────────────────────────────────────
          Row(
            children: [
              Text('CDN PROFILE',
                  style: GoogleFonts.inter(color: textSecond, fontWeight: FontWeight.w700, fontSize: 11, letterSpacing: 1.2)),
              const Spacer(),
              GestureDetector(
                onTap: () => Navigator.push(context,
                  MaterialPageRoute(builder: (_) => const RangeHistoryPage()),
                ).then((_) {
                  RangeScanStorage().scannedIpCount().then((c) {
                    if (mounted) setState(() => _scannedIpMemoryCount = c);
                  });
                }),
                child: Container(
                  padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
                  decoration: BoxDecoration(color: iconBg, borderRadius: BorderRadius.circular(8), border: Border.all(color: borderColor)),
                  child: Row(children: [
                    const Icon(Icons.history_rounded, color: accentLime, size: 14),
                    const SizedBox(width: 4),
                    Text('History', style: GoogleFonts.inter(color: accentLime, fontSize: 11, fontWeight: FontWeight.w600)),
                  ]),
                ),
              ),
            ],
          ),
          const SizedBox(height: 10),

          // ── CDN Profile ──────────────────────────────────────────────────
          Row(children: [
            _buildRangeProfileBtn('cloudflare', '☁️ Cloudflare'),
            const SizedBox(width: 8),
            _buildRangeProfileBtn('akamai', '🌐 Akamai'),
          ]),
          const SizedBox(height: 16),

          // ── SELECT RANGE (multi-select) ───────────────────────────────────
          Row(
            children: [
              Text('SELECT RANGE',
                  style: GoogleFonts.inter(color: textSecond, fontWeight: FontWeight.w700, fontSize: 11, letterSpacing: 1.2)),
              const Spacer(),
              if (_selectedRangeCidrs.isNotEmpty)
                GestureDetector(
                  onTap: () => setState(() => _selectedRangeCidrs.clear()),
                  child: Text('Clear all',
                      style: GoogleFonts.inter(color: const Color(0xFFFF5252), fontSize: 10, fontWeight: FontWeight.w600)),
                ),
            ],
          ),
          const SizedBox(height: 4),
          Text('چند تا رو با هم انتخاب کن',
              style: GoogleFonts.inter(color: textSecond, fontSize: 10)),
          const SizedBox(height: 8),

          if (_loadingRangeCidrs)
            const Center(child: Padding(padding: EdgeInsets.all(12),
                child: SizedBox(width: 20, height: 20,
                    child: CircularProgressIndicator(strokeWidth: 2, color: accentLime))))
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
                  final sel = _selectedRangeCidrs.contains(cidr);
                  final count = cidrIpCount(cidr);
                  final countStr = count >= 1000000
                      ? '${(count / 1000000).toStringAsFixed(1)}M IPs'
                      : count >= 1000
                          ? '${(count / 1000).toStringAsFixed(0)}K IPs'
                          : '$count IPs';
                  return GestureDetector(
                    onTap: () => setState(() {
                      if (sel) _selectedRangeCidrs.remove(cidr);
                      else _selectedRangeCidrs.add(cidr);
                    }),
                    child: AnimatedContainer(
                      duration: const Duration(milliseconds: 150),
                      margin: const EdgeInsets.only(bottom: 5),
                      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 9),
                      decoration: BoxDecoration(
                        color: sel ? accentLime.withOpacity(0.08) : card2Color,
                        borderRadius: BorderRadius.circular(10),
                        border: Border.all(color: sel ? accentLime : borderColor, width: sel ? 1.5 : 1),
                      ),
                      child: Row(
                        children: [
                          Icon(
                            sel ? Icons.check_box_rounded : Icons.check_box_outline_blank_rounded,
                            size: 15,
                            color: sel ? accentLime : textSecond,
                          ),
                          const SizedBox(width: 8),
                          Expanded(
                            child: Text(cidr,
                                style: GoogleFonts.robotoMono(
                                    color: sel ? accentLime : textPrimary,
                                    fontSize: 12,
                                    fontWeight: sel ? FontWeight.w600 : FontWeight.w400)),
                          ),
                          Text('($countStr)',
                              style: GoogleFonts.inter(color: textSecond, fontSize: 11)),
                        ],
                      ),
                    ),
                  );
                },
              ),
            ),

          if (_selectedRangeCidrs.isNotEmpty) ...[
            const SizedBox(height: 6),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
              decoration: BoxDecoration(
                color: accentLime.withOpacity(0.06),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: accentLime.withOpacity(0.3)),
              ),
              child: Row(
                children: [
                  const Icon(Icons.playlist_add_check_rounded, color: accentLime, size: 14),
                  const SizedBox(width: 6),
                  Text('${_selectedRangeCidrs.length} range انتخاب شده',
                      style: GoogleFonts.inter(color: accentLime, fontSize: 11, fontWeight: FontWeight.w600)),
                ],
              ),
            ),
          ],

          const SizedBox(height: 16),

          // ── CUSTOM CIDR ───────────────────────────────────────────────────
          Text('CUSTOM RANGE (CIDR)',
              style: GoogleFonts.inter(color: textSecond, fontWeight: FontWeight.w700, fontSize: 11, letterSpacing: 1.2)),
          const SizedBox(height: 4),
          Text('مثلاً: 2.16.0.0/24 یا فقط 2.16.0.0 برای یک IP',
              style: GoogleFonts.inter(color: textSecond, fontSize: 10)),
          const SizedBox(height: 8),
          TextField(
            controller: _customCidrController,
            keyboardType: TextInputType.text,
            style: GoogleFonts.robotoMono(color: textPrimary, fontSize: 13),
            decoration: InputDecoration(
              hintText: '192.168.1.0/24',
              hintStyle: GoogleFonts.robotoMono(color: textSecond, fontSize: 12),
              filled: true, fillColor: card2Color,
              border: OutlineInputBorder(borderRadius: BorderRadius.circular(10), borderSide: BorderSide.none),
              focusedBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(10), borderSide: const BorderSide(color: accentLime, width: 1.5)),
              enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(10), borderSide: const BorderSide(color: borderColor, width: 1)),
              errorText: _customCidrError,
              contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 11),
              suffixIcon: _customCidrController.text.isNotEmpty
                  ? IconButton(
                      icon: const Icon(Icons.clear_rounded, size: 16, color: textSecond),
                      onPressed: () => setState(() { _customCidrController.clear(); _customCidrError = null; }),
                    )
                  : null,
            ),
            onChanged: (val) {
              setState(() {
                _customCidrError = _validateCidr(val.trim());
                if (_customCidrError == null && val.trim().isNotEmpty) {
                  // custom CIDR به عنوان override عمل میکنه در startScan
                }
              });
            },
          ),

          if (_customCidrController.text.isNotEmpty && _customCidrError == null)
            Padding(
              padding: const EdgeInsets.only(top: 8),
              child: SizedBox(
                width: double.infinity, height: 40,
                child: OutlinedButton.icon(
                  onPressed: () {
                    final cidr = _customCidrController.text.trim();
                    if (cidr.isNotEmpty) _saveCidr(cidr.contains('/') ? cidr : '$cidr/32');
                  },
                  icon: const Icon(Icons.bookmark_add_rounded, size: 16, color: accentLime),
                  label: Text('ذخیره این رنج', textDirection: TextDirection.rtl,
                      style: GoogleFonts.inter(color: accentLime, fontSize: 12, fontWeight: FontWeight.w600)),
                  style: OutlinedButton.styleFrom(
                    side: const BorderSide(color: accentLime, width: 1),
                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                    backgroundColor: accentLime.withOpacity(0.06),
                  ),
                ),
              ),
            ),

          const SizedBox(height: 20),

          // ── SAVED RANGES + Import/Export ──────────────────────────────────
          Row(
            children: [
              Text('SAVED RANGES',
                  style: GoogleFonts.inter(color: textSecond, fontWeight: FontWeight.w700, fontSize: 11, letterSpacing: 1.2)),
              const Spacer(),
              GestureDetector(
                onTap: _importIpsFromFile,
                child: Container(
                  padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                  decoration: BoxDecoration(color: iconBg, borderRadius: BorderRadius.circular(7), border: Border.all(color: borderColor)),
                  child: Row(children: [
                    const Icon(Icons.upload_file_rounded, color: accentLime, size: 13),
                    const SizedBox(width: 3),
                    Text('Import', style: GoogleFonts.inter(color: accentLime, fontSize: 10, fontWeight: FontWeight.w600)),
                  ]),
                ),
              ),
              const SizedBox(width: 6),
              GestureDetector(
                onTap: _savedCidrs.isEmpty ? null : _exportCidrs,
                child: Container(
                  padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                  decoration: BoxDecoration(
                    color: _savedCidrs.isEmpty ? card2Color : iconBg,
                    borderRadius: BorderRadius.circular(7),
                    border: Border.all(color: _savedCidrs.isEmpty ? borderColor.withOpacity(0.4) : borderColor),
                  ),
                  child: Row(children: [
                    Icon(Icons.download_rounded, color: _savedCidrs.isEmpty ? textSecond.withOpacity(0.4) : accentLime, size: 13),
                    const SizedBox(width: 3),
                    Text('Export',
                        style: GoogleFonts.inter(
                            color: _savedCidrs.isEmpty ? textSecond.withOpacity(0.4) : accentLime,
                            fontSize: 10, fontWeight: FontWeight.w600)),
                  ]),
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),

          // ── Imported IPs preview ──────────────────────────────────────────
          if (_importedIps.isNotEmpty) ...[
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
              decoration: BoxDecoration(
                color: const Color(0xFF00E5FF).withOpacity(0.06),
                borderRadius: BorderRadius.circular(10),
                border: Border.all(color: const Color(0xFF00E5FF).withOpacity(0.3)),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      const Icon(Icons.list_alt_rounded, color: Color(0xFF00E5FF), size: 14),
                      const SizedBox(width: 6),
                      Text('${_importedIps.length} IP آماده اسکن',
                          style: GoogleFonts.inter(color: const Color(0xFF00E5FF), fontSize: 12, fontWeight: FontWeight.w700)),
                      const SizedBox(width: 8),
                      GestureDetector(
                        onTap: _showImportedIpsProviderSheet,
                        child: Container(
                          padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 3),
                          decoration: BoxDecoration(
                            color: const Color(0xFFC6F135).withOpacity(0.12),
                            borderRadius: BorderRadius.circular(6),
                            border: Border.all(
                              color: const Color(0xFFC6F135).withOpacity(0.45),
                            ),
                          ),
                          child: Row(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              Text(
                                _importedIpsProvider == 'cloudflare' ? '☁️ Cloudflare' : '🌐 Akamai',
                                style: GoogleFonts.inter(
                                  color: const Color(0xFFC6F135),
                                  fontSize: 10,
                                  fontWeight: FontWeight.w600,
                                ),
                              ),
                              const SizedBox(width: 3),
                              const Icon(Icons.edit_rounded, color: Color(0xFFC6F135), size: 10),
                            ],
                          ),
                        ),
                      ),
                      const Spacer(),
                      GestureDetector(
                        onTap: () => setState(() => _importedIps.clear()),
                        child: const Icon(Icons.close_rounded, color: Color(0xFFFF5252), size: 16),
                      ),
                    ],
                  ),
                  const SizedBox(height: 6),
                  ConstrainedBox(
                    constraints: const BoxConstraints(maxHeight: 120),
                    child: ListView.builder(
                      shrinkWrap: true,
                      physics: const ClampingScrollPhysics(),
                      itemCount: _importedIps.length > 50 ? 50 : _importedIps.length,
                      itemBuilder: (ctx, i) => Padding(
                        padding: const EdgeInsets.symmetric(vertical: 1),
                        child: Text(
                          i < 49 || _importedIps.length <= 50
                              ? _importedIps[i]
                              : '... و ${_importedIps.length - 49} IP دیگه',
                          style: GoogleFonts.robotoMono(color: textPrimary, fontSize: 11),
                        ),
                      ),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 8),
          ],

          if (_loadingSavedCidrs)
            const Padding(padding: EdgeInsets.symmetric(vertical: 8),
                child: Center(child: SizedBox(width: 16, height: 16,
                    child: CircularProgressIndicator(strokeWidth: 2, color: accentLime))))
          else if (_savedCidrs.isEmpty)
            Padding(
              padding: const EdgeInsets.symmetric(vertical: 8),
              child: Text('هنوز رنجی ذخیره نشده. یک CIDR وارد کن و دکمه «ذخیره» رو بزن.',
                  textDirection: TextDirection.rtl,
                  style: GoogleFonts.inter(color: textSecond, fontSize: 11)),
            )
          else
            ConstrainedBox(
              constraints: const BoxConstraints(maxHeight: 200),
              child: ListView.builder(
                shrinkWrap: true,
                physics: const ClampingScrollPhysics(),
                itemCount: _savedCidrs.length,
                itemBuilder: (ctx, i) {
                  final cidr = _savedCidrs[i];
                  final sel = _selectedRangeCidrs.contains(cidr);
                  return GestureDetector(
                    onTap: () => setState(() {
                      if (sel) _selectedRangeCidrs.remove(cidr);
                      else _selectedRangeCidrs.add(cidr);
                      _customCidrController.text = cidr;
                    }),
                    child: AnimatedContainer(
                      duration: const Duration(milliseconds: 150),
                      margin: const EdgeInsets.only(bottom: 5),
                      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 9),
                      decoration: BoxDecoration(
                        color: sel ? accentLime.withOpacity(0.08) : card2Color,
                        borderRadius: BorderRadius.circular(10),
                        border: Border.all(color: sel ? accentLime : borderColor, width: sel ? 1.5 : 1),
                      ),
                      child: Row(
                        children: [
                          Icon(sel ? Icons.check_box_rounded : Icons.bookmark_border_rounded,
                              size: 14, color: sel ? accentLime : textSecond),
                          const SizedBox(width: 8),
                          Expanded(
                            child: Text(cidr,
                                style: GoogleFonts.robotoMono(
                                    color: sel ? accentLime : textPrimary,
                                    fontSize: 12,
                                    fontWeight: sel ? FontWeight.w600 : FontWeight.w400)),
                          ),
                          GestureDetector(
                            onTap: () => _deleteSavedCidr(cidr),
                            child: const Padding(padding: EdgeInsets.all(4),
                                child: Icon(Icons.close_rounded, size: 14, color: Color(0xFFFF5252))),
                          ),
                        ],
                      ),
                    ),
                  );
                },
              ),
            ),

          // ── CDN scan progress (live) ───────────────────────────────────────
          if (_scanning && _activeScanTab == ScanTab.range || (_total > 0 && !_scanning && _activeScanTab == ScanTab.range)) ...[
            const SizedBox(height: 16),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
              decoration: BoxDecoration(
                color: cardInner,
                borderRadius: BorderRadius.circular(10),
                border: Border.all(color: borderColor),
              ),
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
                                fontSize: 12, fontWeight: FontWeight.w500)),
                      ),
                      if (_total > 0) ...[
                        if (_scanning)
                          Text('ETA ${_calcEta()}',
                              style: GoogleFonts.inter(color: textSecond, fontSize: 10)),
                        const SizedBox(width: 6),
                        Text('$_done / $_total',
                            style: GoogleFonts.inter(color: textPrimary, fontSize: 12, fontWeight: FontWeight.w700)),
                      ],
                    ],
                  ),
                  const SizedBox(height: 8),
                  ClipRRect(
                    borderRadius: BorderRadius.circular(5),
                    child: LinearProgressIndicator(
                      value: _prefiltering ? null : (_total > 0 ? _done / _total : 0.0),
                      backgroundColor: iconBg,
                      valueColor: AlwaysStoppedAnimation(
                          _prefiltering ? const Color(0xFFFFAB40) : accentLime2),
                      minHeight: 5,
                    ),
                  ),
                  if (_okCount > 0 || _failCount > 0) ...[
                    const SizedBox(height: 6),
                    Row(
                      children: [
                        _chip(Icons.check_circle_outline_rounded, '$_okCount alive', accentLime),
                        const SizedBox(width: 6),
                        _chip(Icons.cancel_outlined, '$_failCount dead', const Color(0xFFFF5252)),
                        if (_thrCount > 0) ...[
                          const SizedBox(width: 6),
                          _chip(Icons.speed_rounded, '$_thrCount throttled', const Color(0xFFFFAB40)),
                        ],
                      ],
                    ),
                  ],
                ],
              ),
            ),
          ],
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
                  _selectedRangeCidrs.clear();
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

  // Validates a CIDR string. Returns null if valid, error message if invalid.
  String? _validateCidr(String val) {
    if (val.isEmpty) return null;
    if (!val.contains('/')) {
      // Single IP — must be a valid IPv4
      final parts = val.split('.');
      if (parts.length != 4) return 'فرمت IP اشتباه است';
      for (final p in parts) {
        final n = int.tryParse(p);
        if (n == null || n < 0 || n > 255) return 'فرمت IP اشتباه است';
      }
      return null; // valid single IP, will be treated as /32
    }
    final parts2 = val.split('/');
    if (parts2.length != 2) return 'فرمت CIDR اشتباه — مثال: 1.2.3.0/24';
    final ip   = parts2[0];
    final mask = int.tryParse(parts2[1]);
    if (mask == null || mask < 0 || mask > 32) return 'پیشوند باید بین 0 و 32 باشد';
    final ipParts = ip.split('.');
    if (ipParts.length != 4) return 'فرمت IP اشتباه است';
    for (final p in ipParts) {
      final n = int.tryParse(p);
      if (n == null || n < 0 || n > 255) return 'فرمت IP اشتباه است';
    }
    return null;
  }

  // Expands a text input that may contain IPs, CIDRs, or ranges into a flat IP list.
  // Used for CF scan and range custom CIDR.
  List<String> _expandCidrOrIps(String rawText) {
    final lines = rawText.split(RegExp(r'[\n,\s]+')).map((l) => l.trim()).where((l) => l.isNotEmpty).toList();
    final result = <String>{};
    final ipRegex = RegExp(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$');
    for (final line in lines) {
      if (line.contains('/')) {
        // CIDR expansion
        final parts = line.split('/');
        if (parts.length != 2) continue;
        final mask = int.tryParse(parts[1]);
        if (mask == null || mask < 16 || mask > 32) continue;
        final ipParts = parts[0].split('.');
        if (ipParts.length != 4) continue;
        final octets = ipParts.map(int.tryParse).toList();
        if (octets.any((o) => o == null || o < 0 || o > 255)) continue;
        final base = (octets[0]! << 24) | (octets[1]! << 16) | (octets[2]! << 8) | octets[3]!;
        final count = 1 << (32 - mask);
        final networkBase = base & (~((1 << (32 - mask)) - 1) & 0xFFFFFFFF);
        for (int i = (mask >= 31 ? 0 : 1); i < count - (mask >= 31 ? 0 : 1); i++) {
          final ipInt = (networkBase + i) & 0xFFFFFFFF;
          final ip = '${(ipInt >> 24) & 0xFF}.${(ipInt >> 16) & 0xFF}.${(ipInt >> 8) & 0xFF}.${ipInt & 0xFF}';
          result.add(ip);
          if (result.length >= 50000) break;
        }
      } else if (ipRegex.hasMatch(line)) {
        result.add(line);
      }
    }
    return result.where((ip) => !isPrivateOrReserved(ip)).toList();
  }

  // ── Saved CIDRs helpers ──────────────────────────────────────────────────

  Future<void> _loadSavedCidrs() async {
    if (!mounted) return;
    setState(() => _loadingSavedCidrs = true);
    final cidrs = await CustomCidrStorage().load();
    if (!mounted) return;
    setState(() {
      _savedCidrs = cidrs;
      _loadingSavedCidrs = false;
    });
  }

  Future<void> _saveCidr(String cidr) async {
    final added = await CustomCidrStorage().add(cidr);
    if (!mounted) return;
    if (added) {
      await _loadSavedCidrs();
      _showSnack('✅ رنج ذخیره شد: $cidr');
    } else {
      _showSnack('⚠️ این رنج قبلاً ذخیره شده یا لیست پر است (max 50)');
    }
  }

  Future<void> _deleteSavedCidr(String cidr) async {
    await CustomCidrStorage().remove(cidr);
    if (!mounted) return;
    await _loadSavedCidrs();
    _showSnack('🗑 حذف شد: $cidr');
  }

  Future<void> _exportCidrs() async {
    try {
      final path = await CustomCidrStorage().exportToFile();
      if (!mounted) return;
      _showSnack('✅ اکسپورت شد:\n$path');
    } catch (e) {
      if (!mounted) return;
      _showSnack('❌ خطا: ${e.toString()}');
    }
  }

  Future<void> _importCidrs() async {
    final count = await CustomCidrStorage().importFromFile();
    if (!mounted) return;
    if (count == -1) {
      // user cancelled
    } else if (count == 0) {
      _showSnack('⚠️ هیچ CIDR معتبری در فایل پیدا نشد.');
    } else {
      await _loadSavedCidrs();
      _showSnack('✅ $count رنج ایمپورت شد.');
    }
  }

  /// Import IPs from a plain-text file — one IP per line.
  /// Shows them in a preview card inside the Range tab; starts scan directly.
  Future<void> _importIpsFromFile() async {
    try {
      final result = await FilePicker.platform.pickFiles(
        type: FileType.custom,
        allowedExtensions: ['txt', 'csv'],
        withData: true,
      );
      if (result == null || result.files.isEmpty) return;
      final bytes = result.files.first.bytes;
      final String text;
      if (bytes != null) {
        text = String.fromCharCodes(bytes);
      } else {
        final filePath = result.files.first.path;
        if (filePath == null) {
          _showSnack('\u274c فایل قابل خواندن نیست.');
          return;
        }
        text = await File(filePath).readAsString();
      }
      final ips = text
          .split(RegExp(r'[\r\n,;\s]+'))
          .map((s) => s.trim())
          .where((s) {
            if (s.isEmpty) return false;
            // basic IPv4 check
            final parts = s.split('.');
            if (parts.length != 4) return false;
            return parts.every((p) {
              final n = int.tryParse(p);
              return n != null && n >= 0 && n <= 255;
            });
          })
          .toList();
      if (ips.isEmpty) {
        _showSnack('⚠️ هیچ IP معتبری در فایل پیدا نشد.');
        return;
      }
      if (!mounted) return;
      setState(() => _importedIps = ips);
      _showImportedIpsProviderSheet();
    } catch (e) {
      if (!mounted) return;
      _showSnack('❌ خطا: ${e.toString()}');
    }
  }

  void _showImportedIpsProviderSheet() {
    String selected = _importedIpsProvider;
    showModalBottomSheet(
      context: context,
      backgroundColor: const Color(0xFF112216),
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (ctx) {
        return StatefulBuilder(
          builder: (ctx, setSheetState) {
            return Directionality(
              textDirection: TextDirection.rtl,
              child: Padding(
                padding: const EdgeInsets.fromLTRB(24, 24, 24, 32),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    Text(
                      'انتخاب CDN Provider',
                      textAlign: TextAlign.center,
                      style: GoogleFonts.inter(
                        color: const Color(0xFFFFFFFF),
                        fontSize: 16,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                    const SizedBox(height: 6),
                    Text(
                      'برای اسکن IPهای ایمپورت‌شده یک پروایدر انتخاب کن',
                      textAlign: TextAlign.center,
                      style: GoogleFonts.inter(
                        color: const Color(0xFF8A9E8E),
                        fontSize: 12,
                      ),
                    ),
                    const SizedBox(height: 20),
                    Row(
                      children: [
                        Expanded(
                          child: GestureDetector(
                            onTap: () => setSheetState(() => selected = 'cloudflare'),
                            child: AnimatedContainer(
                              duration: const Duration(milliseconds: 180),
                              padding: const EdgeInsets.symmetric(vertical: 18),
                              decoration: BoxDecoration(
                                color: selected == 'cloudflare'
                                    ? const Color(0xFFC6F135).withOpacity(0.10)
                                    : const Color(0xFF0D1A11),
                                borderRadius: BorderRadius.circular(12),
                                border: Border.all(
                                  color: selected == 'cloudflare'
                                      ? const Color(0xFFC6F135)
                                      : const Color(0xFF2A4A30),
                                  width: selected == 'cloudflare' ? 2 : 1,
                                ),
                              ),
                              child: Column(
                                children: [
                                  const Text('☁️', style: TextStyle(fontSize: 28)),
                                  const SizedBox(height: 8),
                                  Text(
                                    'Cloudflare',
                                    style: GoogleFonts.inter(
                                      color: selected == 'cloudflare'
                                          ? const Color(0xFFC6F135)
                                          : const Color(0xFFFFFFFF),
                                      fontSize: 14,
                                      fontWeight: FontWeight.w600,
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          ),
                        ),
                        const SizedBox(width: 12),
                        Expanded(
                          child: GestureDetector(
                            onTap: () => setSheetState(() => selected = 'akamai'),
                            child: AnimatedContainer(
                              duration: const Duration(milliseconds: 180),
                              padding: const EdgeInsets.symmetric(vertical: 18),
                              decoration: BoxDecoration(
                                color: selected == 'akamai'
                                    ? const Color(0xFFC6F135).withOpacity(0.10)
                                    : const Color(0xFF0D1A11),
                                borderRadius: BorderRadius.circular(12),
                                border: Border.all(
                                  color: selected == 'akamai'
                                      ? const Color(0xFFC6F135)
                                      : const Color(0xFF2A4A30),
                                  width: selected == 'akamai' ? 2 : 1,
                                ),
                              ),
                              child: Column(
                                children: [
                                  const Text('🌐', style: TextStyle(fontSize: 28)),
                                  const SizedBox(height: 8),
                                  Text(
                                    'Akamai',
                                    style: GoogleFonts.inter(
                                      color: selected == 'akamai'
                                          ? const Color(0xFFC6F135)
                                          : const Color(0xFFFFFFFF),
                                      fontSize: 14,
                                      fontWeight: FontWeight.w600,
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 20),
                    GestureDetector(
                      onTap: () {
                        setState(() => _importedIpsProvider = selected);
                        Navigator.pop(ctx);
                        _showSnack(
                          '✅ ${_importedIps.length} IP ایمپورت شد — پروایدر: ${selected == "cloudflare" ? "Cloudflare" : "Akamai"} — استارت بزن.',
                        );
                      },
                      child: Container(
                        padding: const EdgeInsets.symmetric(vertical: 14),
                        decoration: BoxDecoration(
                          color: const Color(0xFFC6F135),
                          borderRadius: BorderRadius.circular(12),
                        ),
                        child: Text(
                          'تأیید',
                          textAlign: TextAlign.center,
                          style: GoogleFonts.inter(
                            color: const Color(0xFF0A1A0F),
                            fontSize: 15,
                            fontWeight: FontWeight.w700,
                          ),
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            );
          },
        );
      },
    );
  }

  void _loadRangeCidrs() {
    final meta = kCdnProviders.firstWhere(
      (m) => (_rangeCdnProfile == 'cloudflare'
          ? m.provider == CdnProvider.cloudflare
          : m.provider == CdnProvider.akamai),
    );
    // Increment generation counter — any in-flight fetch with an older
    // generation will discard its result, preventing stale data overwriting
    // the current profile's list (race condition when switching profiles quickly).
    _loadRangeCidrsGeneration++;
    final myGeneration = _loadRangeCidrsGeneration;
    setState(() => _loadingRangeCidrs = true);
    fetchAllCidrsForProvider(meta).then((cidrs) {
      if (!mounted) return;
      if (_loadRangeCidrsGeneration != myGeneration) return; // stale, discard
      setState(() {
        _rangeCidrs = cidrs;
        if (_selectedRangeCidrs.isEmpty && cidrs.isNotEmpty) _selectedRangeCidrs = {cidrs.first};
        _loadingRangeCidrs = false;
      });
    }).catchError((_) {
      if (!mounted) return;
      if (_loadRangeCidrsGeneration != myGeneration) return; // stale, discard
      setState(() {
        _rangeCidrs = meta.fallback;
        if (_selectedRangeCidrs.isEmpty && meta.fallback.isNotEmpty) _selectedRangeCidrs = {meta.fallback.first};
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
                  : (_activeScanTab == ScanTab.range &&
                      _selectedRangeCidrs.isEmpty &&
                      _customCidrController.text.trim().isEmpty &&
                      _importedIps.isEmpty
                        ? null : _startScan),
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

// ─── DNS Result Card ─────────────────────────────────────────────────────────

class _DnsResultCard extends StatelessWidget {
  final DNSServer server;

  const _DnsResultCard({required this.server});

  @override
  Widget build(BuildContext context) {
    final score   = server.finalScore ?? 0;
    final freedom = (server.freedomScore ?? 0) * 100;
    final latency = server.avgLatencyMs ?? 0;
    final rank    = server.finalRank ?? 99;

    Color rankColor() => switch (rank) {
      1 => const Color(0xFFFFD700),
      2 => const Color(0xFFC0C0C0),
      3 => const Color(0xFFCD7F32),
      _ => Colors.white24,
    };

    Color scoreColor() => score > 75
        ? const Color(0xFF69FF47)
        : score > 50
            ? const Color(0xFFFFE500)
            : Colors.redAccent;

    Color freedomColor() => freedom >= 90
        ? const Color(0xFF69FF47)
        : freedom >= 60
            ? const Color(0xFFFFE500)
            : Colors.redAccent;

    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: Colors.white.withOpacity(0.04),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(
          color: rank == 1
              ? const Color(0xFF00E5FF).withOpacity(0.6)
              : Colors.white12,
        ),
      ),
      child: Row(
        children: [
          // Rank badge
          Container(
            width: 32,
            height: 32,
            alignment: Alignment.center,
            decoration: BoxDecoration(color: rankColor(), shape: BoxShape.circle),
            child: Text(
              '#$rank',
              style: const TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: Colors.black87),
            ),
          ),
          const SizedBox(width: 12),
          // IP + stats
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    GestureDetector(
                      onTap: () {
                        Clipboard.setData(ClipboardData(text: server.ip));
                        ScaffoldMessenger.of(context).showSnackBar(
                          SnackBar(
                            content: Text(
                              '✓ ${server.ip} copied!',
                              style: const TextStyle(fontWeight: FontWeight.w600),
                            ),
                            duration: const Duration(seconds: 2),
                            behavior: SnackBarBehavior.floating,
                            backgroundColor: const Color(0xFF1E3525),
                          ),
                        );
                      },
                      child: Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Text(
                            server.ip,
                            style: const TextStyle(
                              fontWeight: FontWeight.bold,
                              color: Colors.white,
                              fontSize: 14,
                            ),
                          ),
                          const SizedBox(width: 5),
                          const Icon(
                            Icons.copy_rounded,
                            size: 13,
                            color: Colors.white38,
                          ),
                        ],
                      ),
                    ),
                    if (server.supportsDoH == true) ...[
                      const SizedBox(width: 6),
                      _DnsChip('DoH', const Color(0xFF00E5FF)),
                    ],
                    if (server.supportsIPv6 == true) ...[
                      const SizedBox(width: 4),
                      _DnsChip('IPv6', const Color(0xFF69FF47)),
                    ],
                  ],
                ),
                const SizedBox(height: 4),
                Wrap(
                  spacing: 8,
                  children: [
                    _DnsStat('Freedom', '${freedom.toStringAsFixed(0)}%', freedomColor()),
                    _DnsStat('Latency', '${latency.toStringAsFixed(0)}ms', Colors.white54),
                    _DnsStat('Jitter', '${server.jitterMs?.toStringAsFixed(0) ?? "?"}ms', Colors.white54),
                    if (server.packetLossRate != null && server.packetLossRate! > 0)
                      _DnsStat('Loss', '${(server.packetLossRate! * 100).toStringAsFixed(0)}%', Colors.orange),
                  ],
                ),
              ],
            ),
          ),
          // Final score
          Column(
            crossAxisAlignment: CrossAxisAlignment.end,
            children: [
              Text(
                score.toStringAsFixed(1),
                style: TextStyle(
                  fontSize: 20,
                  fontWeight: FontWeight.bold,
                  color: scoreColor(),
                ),
              ),
              const Text('score', style: TextStyle(fontSize: 9, color: Colors.white38)),
            ],
          ),
        ],
      ),
    );
  }
}

class _DnsChip extends StatelessWidget {
  final String label;
  final Color color;
  const _DnsChip(this.label, this.color);

  @override
  Widget build(BuildContext context) => Container(
        padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1),
        decoration: BoxDecoration(
          color: color.withOpacity(0.15),
          borderRadius: BorderRadius.circular(4),
          border: Border.all(color: color.withOpacity(0.5)),
        ),
        child: Text(label,
            style: TextStyle(fontSize: 9, color: color, fontWeight: FontWeight.bold)),
      );
}

class _DnsStat extends StatelessWidget {
  final String label;
  final String value;
  final Color color;
  const _DnsStat(this.label, this.value, this.color);

  @override
  Widget build(BuildContext context) => Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(label, style: const TextStyle(fontSize: 9, color: Colors.white38)),
          Text(value, style: TextStyle(fontSize: 11, color: color, fontWeight: FontWeight.w600)),
        ],
      );
}


