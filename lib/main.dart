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
import 'core/settings/app_settings.dart';
import 'core/l10n/strings.dart';
import 'features/cf/cf_scan_panel.dart';
import 'ui/settings/settings_page.dart';

// â”€â”€â”€ Notifications â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

// â”€â”€â”€ Scan Tab Enums â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

enum ScanTab { cdn, cloudflare, range, dns }
enum CdnSubMode { normal, deep }

// â”€â”€â”€ Forest Green Theme â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

// â”€â”€â”€ App â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
  await AppSettings.instance.load();
  await GeoIPOffline().load();
  runApp(const MidOneScannerApp());
}

class MidOneScannerApp extends StatelessWidget {
  const MidOneScannerApp({super.key});
  @override
  Widget build(BuildContext context) {
    return ValueListenableBuilder<AppLanguage>(
      valueListenable: AppSettings.languageNotifier,
      builder: (context, language, _) {
        final isFa = language == AppLanguage.fa;
        return MaterialApp(
          title: 'MidONe Scanner',
          debugShowCheckedModeBanner: false,
          locale: isFa ? const Locale('fa', 'IR') : const Locale('en', 'US'),
          supportedLocales: const [Locale('fa', 'IR'), Locale('en', 'US')],
          builder: (context, child) => Directionality(
            textDirection: isFa ? TextDirection.rtl : TextDirection.ltr,
            child: child!,
          ),
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
      },
    );
  }
}

// â”€â”€â”€ Home Screen â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});
  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

// p50: AppLifecycleObserver mixin
class _HomeScreenState extends State<HomeScreen> with WidgetsBindingObserver {
  int _tab = 0;
  // â”€â”€ Scan Tab (replaces _mode) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
  String _statusText = S.t.readyToScan;
  String _sortBy = 'speed';  // default: sort by score
  // BUG 9 FIX: removed _filterThrottled â€” dead code, no UI toggle existed.
  // The 'alive' advanced filter covers this use case.

  // p39: advanced filters
  String _advancedFilter = 'all'; // 'all', 'excellent', 'low_rtt', 'alive', 'ws_ok', 'ws_fail'
  String _coloFilter    = '';    // empty = all colos; e.g. 'FRA', 'AMS' â€” case-insensitive

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

  // â”€â”€ DNS tab state â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  final _dnsScanner = DNSScanner(config: ScanConfig.gamingIran());
  StreamSubscription<ScanProgress>? _dnsScanSubscription;
  ScanProgress? _dnsLastProgress;
  final List<ScanProgress> _dnsStageLog = [];
  List<DNSServer>? _dnsResults;
  bool _dnsScanning = false;
  String? _dnsErrorMessage;
  List<String> _activeDnsServers = kAllDnsServers;
  bool _dnsUpdating = false;
  String? _dnsUpdateMessage;

  // â”€â”€ DNS Apply (Windows) state â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  String? _appliedDnsIp;    // Primary DNS (DNS 1)
  String? _appliedDns2Ip;   // Secondary DNS (DNS 2)
  bool _applyingDns = false;
  bool _applyingDns2 = false;
  String? _applyDnsError;
  String? _applyDnsMessage;

  // â”€â”€ DNS VPN (Android) state â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

  // â”€â”€ Range v2 state â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  String _rangeCdnProfile = 'akamai';
  List<String> _rangeCidrs = [];
  Set<String> _selectedRangeCidrs = {}; // multi-select
  bool _loadingRangeCidrs = false;
  int _loadRangeCidrsGeneration = 0; // guards against stale fetch completions
  final _customCidrController  = TextEditingController();
  String? _customCidrError;
  // â”€â”€ Imported IPs (from txt file) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  List<String> _importedIps = [];
  String _importedIpsProvider = 'akamai';

  // â”€â”€ Saved custom CIDRs (persistent) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
  String _ispName = 'Ø¯Ø± Ø­Ø§Ù„ Ø¨Ø±Ø±Ø³ÛŒ...';
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
    // runs after the first build frame â€” avoids setState-in-initState warning.
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
    setState(() { _ispName = 'Ø§Ù¾Ø±Ø§ØªÙˆØ±: $isp'; });
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
              Text(S.t.appTitle,
                  style: GoogleFonts.inter(
                      color: accentLime, fontWeight: FontWeight.w800, fontSize: 20)),
              const SizedBox(height: 8),
              // BUG 11 FIX: explicit RTL for Persian strings in welcome dialog
              Text('Ø¨Ù‡ Ú©Ø§Ù†Ø§Ù„ ØªÙ„Ú¯Ø±Ø§Ù… Ù…Ø§ Ø¨Ù¾ÛŒÙˆÙ†Ø¯ÛŒØ¯!',
                  textDirection: TextDirection.rtl,
                  style: GoogleFonts.inter(
                      color: textPrimary, fontWeight: FontWeight.w700, fontSize: 15)),
              const SizedBox(height: 10),
              Text(
                'Ø¨Ø±Ø§ÛŒ Ø¯Ø±ÛŒØ§ÙØª Ø¢Ø®Ø±ÛŒÙ† Ø¨Ø±ÙˆØ²Ø±Ø³Ø§Ù†ÛŒ Ùˆ Ø¢ÛŒâ€ŒÙ¾ÛŒâ€ŒÙ‡Ø§ÛŒ Ø¬Ø¯ÛŒØ¯ Ø¨Ù‡ Ú©Ø§Ù†Ø§Ù„ ØªÙ„Ú¯Ø±Ø§Ù… Ù…Ø§ Ø¬ÙˆÛŒÙ† Ø¨Ø´ÛŒØ¯.',
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
                      Text('Ø¬ÙˆÛŒÙ† Ø¨Ù‡ @mmdrlx',
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
                // BUG 11 FIX: RTL for Persian 'Ø¨Ø¹Ø¯Ø§Ù‹'
                child: Text('Ø¨Ø¹Ø¯Ø§Ù‹',
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

    // â”€â”€ Range mode â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Dispatch to correct handler
    if (_activeScanTab == ScanTab.cloudflare) return;
    if (_activeScanTab == ScanTab.dns) { _startDnsScan(); return; }
    if (_activeScanTab == ScanTab.range) {
      // â”€â”€ Mode 1: Imported IPs from txt file â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
          rangeCfMode: false,
        );
        return;
      }

      // â”€â”€ Mode 2: Selected CIDRs (multi) + custom CIDR â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
      final customCidr = _customCidrController.text.trim();
      Set<String> activeCidrs = Set<String>.from(_selectedRangeCidrs);
      if (customCidr.isNotEmpty) {
        final err = _validateCidr(customCidr);
        if (err != null) { _showSnack('CIDR Ù†Ø§Ù…Ø¹ØªØ¨Ø±: $err'); return; }
        activeCidrs.add(customCidr.contains('/') ? customCidr : '$customCidr/32');
      }
      if (activeCidrs.isEmpty) {
        _showSnack('ÛŒÚ© Ø±Ù†Ø¬ Ø§Ù†ØªØ®Ø§Ø¨ Ú©Ù†ØŒ CIDR ÙˆØ§Ø±Ø¯ Ú©Ù†ØŒ ÛŒØ§ ÙØ§ÛŒÙ„ IP Ø§ÛŒÙ…Ù¾ÙˆØ±Øª Ú©Ù†.');
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
          requestedCount: _rangeCdnProfile == 'akamai' ? 999999 : 5000,
          alreadyScanned: _rangeCdnProfile == 'akamai' ? const {} : alreadyScanned,
        );

        if (sampledIps.isEmpty) {
          if (mounted) setState(() { _scanning = false; _statusText = 'All IPs already scanned.'; });
          _showSnack('No new IPs. Go to History â†’ Reset to start fresh.');
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

    // â”€â”€ CDN mode â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // FIX: Support CIDR input (e.g. 104.16.0.0/24) â€” expand to individual IPs
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
        _results.addAll(_pendingResults);
        _pendingResults.clear();
        _displayDirty = true;
      });
    }
  }

  // Fast range scan â€” TCP-only probe (like cdn-ip-finder)
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
          _statusText = 'Fast scan $pct% â€” batch ${batchStart ~/ batchSize + 1}/${(ips.length / batchSize).ceil()}';
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
      normalSniOverride = AppSettings.instance.cdnNormalSni;
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
          _done = 0; // reset for TLS scan phase (prefilter used same counter)
          _total = liveCount > 0 ? liveCount : totalCount;
          _statusText = liveCount > 0
              ? 'Scanning $liveCount live IPs...'
              : 'No live IPs on port 443 â€” check list or network';
        });
      },
      onProgress: (done, total, result) {
        if (!mounted) return;
        _pendingResults.add(result);
        setState(() {
          _done = done;
          if (total > 0) _total = total;
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
            if (Platform.isAndroid) sendNotification('âœ… Ø§Ø³Ú©Ù† ØªÙ…ÙˆÙ… Ø´Ø¯!', 'Ù†ØªØ§ÛŒØ¬ Ø¢Ù…Ø§Ø¯Ù‡â€ŒØ³Øª.');
          } else {
            if (Platform.isAndroid) sendNotification('Ø¯Ø± Ø­Ø§Ù„ Ø§Ø³Ú©Ù†... $pct%', 'MidONe Ø¯Ø§Ø±Ù‡ Ø¯Ø± Ù¾Ø³â€ŒØ²Ù…ÛŒÙ†Ù‡ Ú©Ø§Ø± Ù…ÛŒâ€ŒÚ©Ù†Ù‡');
          }
        }
      },
      // FIX BUG#1: _paused must NOT kill isolates â€” only _cancelled should.
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
            : 'Done! 0 usable â€” ${merged.length} scanned (check IPs or try Deep)';
      });
      if (results.isNotEmpty) {
        _showSnack('âœ“ Done! ${results.where((r) => r.isAlive).length} results found');
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
    final allSnis = {
      ...kDeepSniPresets,
      ...AppSettings.instance.cdnCustomSnis,
    }.toList();

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
                        Text('Deep Scan â€” SNI Selection',
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
    if (_activeScanTab == ScanTab.cloudflare) return;
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
    setState(() { _paused = true; _statusText = S.t.paused; });
  }

  // p44: resume scan
  // BUG 7 FIX: only clear the _paused flag â€” do NOT restart the scan engine.
  // The existing Future.wait loop in runScanningEngine checks isCancelled which
  // reads _paused live, so clearing it here lets the loop continue automatically.
  void _resumeScan() {
    if (!_paused) return;
    setState(() {
      _paused = false;
      _statusText = S.t.resumed;
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

    // cf1: colo filter â€” filter by datacenter code (case-insensitive)
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
    _showSnack('âœ“ Top 5 copied!');
  }

  void _copyAll() {
    final list = _displayResults.where((r) => r.isAlive).toList();
    if (list.isEmpty) { _showSnack('No alive results!'); return; }
    Clipboard.setData(ClipboardData(text: list.map((r) => r.ip).join('\n')));
    _showSnack('âœ“ All ${list.length} IPs copied!');
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
      _showSnack('âœ“ JSON saved: scan_$ts.json');
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
      _showSnack('âœ“ Saved: scan_$ts.txt');
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
    if (mounted) _showSnack('âœ“ Retest done!');
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

  // â”€â”€ Top Bar â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
                    _showSnack(_devMode ? 'ðŸ”§ Dev Mode ON' : 'ðŸ”§ Dev Mode OFF');
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
                  Text('Â· $_pingText', style: GoogleFonts.inter(color: textSecond, fontSize: 10)),
                ],
              ),
            ],
          ),
          const Spacer(),
          IconButton(
            icon: const Icon(Icons.settings_outlined, color: textSecond, size: 22),
            tooltip: S.t.settings,
            onPressed: () => Navigator.of(context).push(
              MaterialPageRoute(builder: (_) => const SettingsPage()),
            ),
          ),
          TextButton(
            onPressed: () async {
              final uri = Uri.parse('https://t.me/mmdrlx');
              if (await canLaunchUrl(uri)) {
                await launchUrl(uri, mode: LaunchMode.externalApplication);
              }
            },
            child: Text(S.t.telegramChannel,
                style: GoogleFonts.inter(color: const Color(0xFF29B6F6), fontSize: 12, fontWeight: FontWeight.w600)),
          ),
        ],
      ),
    );
  }

  // â”€â”€ Scan Tab â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
          if (_activeScanTab != ScanTab.dns && _activeScanTab != ScanTab.cloudflare) _buildScanButton(),
          if (_activeScanTab != ScanTab.dns && _activeScanTab != ScanTab.cloudflare) const SizedBox(height: 10),
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
          Text(S.t.scanMode.toUpperCase(),
              style: GoogleFonts.inter(color: textSecond, fontWeight: FontWeight.w700, fontSize: 11, letterSpacing: 1.2)),
          const SizedBox(height: 12),
          Row(
            children: [
              Expanded(child: _tabBtn(ScanTab.cdn, S.t.cdn, S.t.cdnModeSub)),
              const SizedBox(width: 6),
              Expanded(child: _tabBtn(ScanTab.cloudflare, 'CF', S.t.cf)),
              const SizedBox(width: 6),
              Expanded(child: _tabBtn(ScanTab.range, S.t.range, S.t.rangeModeSub)),
              const SizedBox(width: 6),
              Expanded(child: _tabBtn(ScanTab.dns, S.t.dns, S.t.dnsModeSub)),
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
          _dnsScanning = false;
          _dnsErrorMessage = null;
          _dnsLastProgress = null;
          _dnsStageLog.clear();
          _dnsResults = null;
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
          Text(S.t.cdnMode,
              style: GoogleFonts.inter(color: textSecond, fontWeight: FontWeight.w700, fontSize: 11, letterSpacing: 1.2)),
          const SizedBox(height: 10),
          Row(
            children: [
              Expanded(child: _cdnSubBtn(CdnSubMode.normal, 'Normal', 'Fast Â· BW test')),
              const SizedBox(width: 8),
              Expanded(child: _cdnSubBtn(CdnSubMode.deep, 'Deep Scan', 'Multi-SNI Â· 5 probes')),
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
    if (_activeScanTab == ScanTab.cloudflare) return const CfScanPanel();
    if (_activeScanTab == ScanTab.dns) return _buildDnsCard();
    return _card(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Text(S.t.ipAddresses,
                  style: GoogleFonts.inter(color: textSecond, fontWeight: FontWeight.w700, fontSize: 11, letterSpacing: 1.2)),
              const Spacer(),
              _miniBtn(S.t.paste, () async {
                final data = await Clipboard.getData('text/plain');
                if (data?.text != null) {
                  final cur = _ipController.text;
                  _ipController.text = cur.isEmpty ? data!.text! : '$cur\n${data!.text!}';
                }
              }),
              const SizedBox(width: 8),
              _miniBtn(S.t.clear, () => _ipController.clear(), isDestructive: true),
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

  // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
  // DNS Apply â€” Windows only
  // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

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
        // Primary: set static â†’ replaces existing primary
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
              ? 'âœ“ DNS 2 set on "$activeIface"'
              : 'âœ“ DNS 1 set on "$activeIface"';
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
        _applyDnsMessage = 'âœ“ DNS reset to Automatic (DHCP)';
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
    if (lat < 20 && jit < 5 && loss < 1) return 'âš¡ EXCELLENT â€” Pro Gaming';
    if (lat < 50 && jit < 15 && loss < 2) return 'âœ… GOOD â€” Gaming Ready';
    if (lat < 100 && jit < 30 && loss < 5) return 'âš ï¸ FAIR â€” Playable';
    return 'âŒ POOR â€” Not Recommended';
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
                ready ? 'DNS Connected' : 'Connectingâ€¦',
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



  // â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”
  // â”€â”€ Android DNS VPN Apply Section â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  // â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”

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

  // â”€â”€ Android VPN methods â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
        _showSnack('âœ“ DNS VPN active â€” routing through \$dns1');
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
                  'ðŸŽ® Game Optimizer',
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
                        // â”€â”€ DNS 1 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
                        // â”€â”€ DNS 2 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

  // â”€â”€ DNS Card â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
                  label: Text(_dnsScanning ? 'Scanningâ€¦' : 'Start DNS Scan',
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
                    ? 'Updatingâ€¦'
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
                  color: _dnsUpdateMessage!.startsWith('âœ“')
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
                        'â€¢ ${entry.message.split('\n').first}',
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
            Text(S.t.topDnsServers,
                style: GoogleFonts.inter(fontSize: 15, fontWeight: FontWeight.bold, color: textPrimary)),
            const SizedBox(height: 8),
            if (_dnsResults!.isEmpty)
              Padding(
                padding: const EdgeInsets.symmetric(vertical: 12),
                child: Center(
                  child: Text(S.t.noResultsFound,
                      style: GoogleFonts.inter(color: textSecond, fontSize: 13)),
                ),
              )
            else
              // â”€â”€ Android: only show alive servers (eliminated == false) â”€â”€
              ..._dnsResults!
                  .where((s) => !s.eliminated)
                  .toList()
                  .asMap()
                  .entries
                  .map((e) => _DnsResultCard(server: e.value)),
            // â”€â”€ Apply DNS â€” Windows â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
            // â”€â”€ Apply DNS â€” Android (VPN) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
          _dnsUpdateMessage = 'HTTP ${response.statusCode} â€” using built-in list';
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
    ScanStage.pending           => 'â³ Preparing',
    ScanStage.stage1Latency     => 'âš¡ Stage 1: Latency',
    ScanStage.stage2aNxdomain   => 'ðŸ” Stage 2A: NXDOMAIN',
    ScanStage.stage2bHijack     => 'ðŸ›¡ Stage 2B: Hijack',
    ScanStage.stage3BurstJitter => 'ðŸ’¨ Stage 3: Burst',
    ScanStage.stage4Freedom     => 'ðŸ—½ Stage 4: Freedom',
    ScanStage.stage5Doh         => 'ðŸ”’ Stage 5: DoH + Rank',
    ScanStage.complete          => 'âœ… Complete',
    _                           => '',
  };


  Widget _buildRangeCard() {
    return _card(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // â”€â”€ Header â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
          Row(
            children: [
              Text(S.t.akamaiRange,
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
                    Text(S.t.history, style: GoogleFonts.inter(color: accentLime, fontSize: 11, fontWeight: FontWeight.w600)),
                  ]),
                ),
              ),
            ],
          ),
          const SizedBox(height: 10),

          Text(S.t.akamaiSubtitle,
              style: GoogleFonts.inter(color: textSecond, fontSize: 11)),
          const SizedBox(height: 12),

          // â”€â”€ SELECT RANGE (multi-select) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
          Text('Ú†Ù†Ø¯ ØªØ§ Ø±Ùˆ Ø¨Ø§ Ù‡Ù… Ø§Ù†ØªØ®Ø§Ø¨ Ú©Ù†',
              style: GoogleFonts.inter(color: textSecond, fontSize: 10)),
          const SizedBox(height: 8),

          if (_loadingRangeCidrs)
            const Center(child: Padding(padding: EdgeInsets.all(12),
                child: SizedBox(width: 20, height: 20,
                    child: CircularProgressIndicator(strokeWidth: 2, color: accentLime))))
          else if (_rangeCidrs.isEmpty)
            Padding(
              padding: const EdgeInsets.symmetric(vertical: 8),
              child: Text('Loading Akamai ranges…',
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
                  Text('${_selectedRangeCidrs.length} range Ø§Ù†ØªØ®Ø§Ø¨ Ø´Ø¯Ù‡',
                      style: GoogleFonts.inter(color: accentLime, fontSize: 11, fontWeight: FontWeight.w600)),
                ],
              ),
            ),
          ],

          const SizedBox(height: 16),

          // â”€â”€ CUSTOM CIDR â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
          Text('CUSTOM RANGE (CIDR)',
              style: GoogleFonts.inter(color: textSecond, fontWeight: FontWeight.w700, fontSize: 11, letterSpacing: 1.2)),
          const SizedBox(height: 4),
          Text('Ù…Ø«Ù„Ø§Ù‹: 2.16.0.0/24 ÛŒØ§ ÙÙ‚Ø· 2.16.0.0 Ø¨Ø±Ø§ÛŒ ÛŒÚ© IP',
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
                  // custom CIDR Ø¨Ù‡ Ø¹Ù†ÙˆØ§Ù† override Ø¹Ù…Ù„ Ù…ÛŒÚ©Ù†Ù‡ Ø¯Ø± startScan
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
                  label: Text('Ø°Ø®ÛŒØ±Ù‡ Ø§ÛŒÙ† Ø±Ù†Ø¬', textDirection: TextDirection.rtl,
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

          // â”€â”€ SAVED RANGES + Import/Export â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
                    Text(S.t.importLabel, style: GoogleFonts.inter(color: accentLime, fontSize: 10, fontWeight: FontWeight.w600)),
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

          // â”€â”€ Imported IPs preview â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
                      Text('${_importedIps.length} IP Ø¢Ù…Ø§Ø¯Ù‡ Ø§Ø³Ú©Ù†',
                          style: GoogleFonts.inter(color: const Color(0xFF00E5FF), fontSize: 12, fontWeight: FontWeight.w700)),
                      const SizedBox(width: 8),
                      Container(
                        padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 3),
                        decoration: BoxDecoration(
                          color: const Color(0xFFC6F135).withOpacity(0.12),
                          borderRadius: BorderRadius.circular(6),
                          border: Border.all(
                            color: const Color(0xFFC6F135).withOpacity(0.45),
                          ),
                        ),
                        child: Text(
                          'Akamai',
                          style: GoogleFonts.inter(
                            color: const Color(0xFFC6F135),
                            fontSize: 10,
                            fontWeight: FontWeight.w600,
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
                              : '... Ùˆ ${_importedIps.length - 49} IP Ø¯ÛŒÚ¯Ù‡',
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
              child: Text('Ù‡Ù†ÙˆØ² Ø±Ù†Ø¬ÛŒ Ø°Ø®ÛŒØ±Ù‡ Ù†Ø´Ø¯Ù‡. ÛŒÚ© CIDR ÙˆØ§Ø±Ø¯ Ú©Ù† Ùˆ Ø¯Ú©Ù…Ù‡ Â«Ø°Ø®ÛŒØ±Ù‡Â» Ø±Ùˆ Ø¨Ø²Ù†.',
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

          // â”€â”€ CDN scan progress (live) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
  String _formatMemoryCount(int n) {
    if (n >= 1000000) return '${(n / 1000000).toStringAsFixed(1)}M';
    if (n >= 1000) return '${(n / 1000).toStringAsFixed(0)}K';
    return '$n';
  }

  // Validates a CIDR string. Returns null if valid, error message if invalid.
  String? _validateCidr(String val) {
    if (val.isEmpty) return null;
    if (!val.contains('/')) {
      // Single IP â€” must be a valid IPv4
      final parts = val.split('.');
      if (parts.length != 4) return 'ÙØ±Ù…Øª IP Ø§Ø´ØªØ¨Ø§Ù‡ Ø§Ø³Øª';
      for (final p in parts) {
        final n = int.tryParse(p);
        if (n == null || n < 0 || n > 255) return 'ÙØ±Ù…Øª IP Ø§Ø´ØªØ¨Ø§Ù‡ Ø§Ø³Øª';
      }
      return null; // valid single IP, will be treated as /32
    }
    final parts2 = val.split('/');
    if (parts2.length != 2) return 'ÙØ±Ù…Øª CIDR Ø§Ø´ØªØ¨Ø§Ù‡ â€” Ù…Ø«Ø§Ù„: 1.2.3.0/24';
    final ip   = parts2[0];
    final mask = int.tryParse(parts2[1]);
    if (mask == null || mask < 0 || mask > 32) return 'Ù¾ÛŒØ´ÙˆÙ†Ø¯ Ø¨Ø§ÛŒØ¯ Ø¨ÛŒÙ† 0 Ùˆ 32 Ø¨Ø§Ø´Ø¯';
    final ipParts = ip.split('.');
    if (ipParts.length != 4) return 'ÙØ±Ù…Øª IP Ø§Ø´ØªØ¨Ø§Ù‡ Ø§Ø³Øª';
    for (final p in ipParts) {
      final n = int.tryParse(p);
      if (n == null || n < 0 || n > 255) return 'ÙØ±Ù…Øª IP Ø§Ø´ØªØ¨Ø§Ù‡ Ø§Ø³Øª';
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

  // â”€â”€ Saved CIDRs helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
      _showSnack('âœ… Ø±Ù†Ø¬ Ø°Ø®ÛŒØ±Ù‡ Ø´Ø¯: $cidr');
    } else {
      _showSnack('âš ï¸ Ø§ÛŒÙ† Ø±Ù†Ø¬ Ù‚Ø¨Ù„Ø§Ù‹ Ø°Ø®ÛŒØ±Ù‡ Ø´Ø¯Ù‡ ÛŒØ§ Ù„ÛŒØ³Øª Ù¾Ø± Ø§Ø³Øª (max 50)');
    }
  }

  Future<void> _deleteSavedCidr(String cidr) async {
    await CustomCidrStorage().remove(cidr);
    if (!mounted) return;
    await _loadSavedCidrs();
    _showSnack('ðŸ—‘ Ø­Ø°Ù Ø´Ø¯: $cidr');
  }

  Future<void> _exportCidrs() async {
    try {
      final path = await CustomCidrStorage().exportToFile();
      if (!mounted) return;
      _showSnack('âœ… Ø§Ú©Ø³Ù¾ÙˆØ±Øª Ø´Ø¯:\n$path');
    } catch (e) {
      if (!mounted) return;
      _showSnack('âŒ Ø®Ø·Ø§: ${e.toString()}');
    }
  }

  Future<void> _importCidrs() async {
    final count = await CustomCidrStorage().importFromFile();
    if (!mounted) return;
    if (count == -1) {
      // user cancelled
    } else if (count == 0) {
      _showSnack('âš ï¸ Ù‡ÛŒÚ† CIDR Ù…Ø¹ØªØ¨Ø±ÛŒ Ø¯Ø± ÙØ§ÛŒÙ„ Ù¾ÛŒØ¯Ø§ Ù†Ø´Ø¯.');
    } else {
      await _loadSavedCidrs();
      _showSnack('âœ… $count Ø±Ù†Ø¬ Ø§ÛŒÙ…Ù¾ÙˆØ±Øª Ø´Ø¯.');
    }
  }

  /// Import IPs from a plain-text file â€” one IP per line.
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
          _showSnack('\u274c ÙØ§ÛŒÙ„ Ù‚Ø§Ø¨Ù„ Ø®ÙˆØ§Ù†Ø¯Ù† Ù†ÛŒØ³Øª.');
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
        _showSnack('âš ï¸ Ù‡ÛŒÚ† IP Ù…Ø¹ØªØ¨Ø±ÛŒ Ø¯Ø± ÙØ§ÛŒÙ„ Ù¾ÛŒØ¯Ø§ Ù†Ø´Ø¯.');
        return;
      }
      if (!mounted) return;
      setState(() {
        _importedIps = ips;
        _importedIpsProvider = 'akamai';
      });
      _showSnack('Imported ${ips.length} IPs (Akamai fast scan)');
    } catch (e) {
      if (!mounted) return;
      _showSnack('âŒ Ø®Ø·Ø§: ${e.toString()}');
    }
  }

  void _loadRangeCidrs() {
    final meta = kCdnProviders.firstWhere(
      (m) => m.provider == CdnProvider.akamai,
    );
    // Increment generation counter â€” any in-flight fetch with an older
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
                  Text(_scanning ? S.t.stopScan.toUpperCase() : S.t.startScan.toUpperCase(),
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
          Text(S.t.liveMetrics,
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
            Text('${S.t.viewResults} (${_results.length})',
                style: GoogleFonts.inter(fontWeight: FontWeight.w700, fontSize: 14)),
          ],
        ),
      ),
    );
  }

  // â”€â”€ Results Tab â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
                    _miniBtn(S.t.sortLatency, () => setState(() { _sortBy = 'latency'; _displayDirty = true; }), isActive: _sortBy == 'latency'),
                    const SizedBox(width: 5),
                    _miniBtn(S.t.sortScore, () => setState(() { _sortBy = 'speed'; _displayDirty = true; }), isActive: _sortBy == 'speed'),
                    const SizedBox(width: 5),
                    _miniBtn(S.t.sortReliability, () => setState(() { _sortBy = 'reliability'; _displayDirty = true; }), isActive: _sortBy == 'reliability'),
                    const SizedBox(width: 5),
                    // cf1: sort by datacenter
                    _miniBtn('Colo', () => setState(() { _sortBy = _sortBy == 'colo' ? 'latency' : 'colo'; _displayDirty = true; }), isActive: _sortBy == 'colo'),
                    const SizedBox(width: 5),
                    // p39: advanced filters
                    _miniBtn(S.t.filterAll, () => setState(() { _advancedFilter = 'all'; _displayDirty = true; }), isActive: _advancedFilter == 'all'),
                    const SizedBox(width: 5),
                    _miniBtn('â˜…â˜…â˜…', () => setState(() { _advancedFilter = 'excellent'; _displayDirty = true; }), isActive: _advancedFilter == 'excellent'),
                    const SizedBox(width: 5),
                    _miniBtn('<150ms', () => setState(() { _advancedFilter = 'low_rtt'; _displayDirty = true; }), isActive: _advancedFilter == 'low_rtt'),
                    const SizedBox(width: 5),
                    _miniBtn(S.t.filterAlive, () => setState(() { _advancedFilter = 'alive'; _displayDirty = true; }), isActive: _advancedFilter == 'alive'),
                    const SizedBox(width: 5),
                    // cf1/ws2: WS filter buttons
                    _miniBtn('WS âœ“', () => setState(() { _advancedFilter = _advancedFilter == 'ws_ok' ? 'all' : 'ws_ok'; _displayDirty = true; }), isActive: _advancedFilter == 'ws_ok'),
                    const SizedBox(width: 5),
                    _miniBtn('WS âœ—', () => setState(() { _advancedFilter = _advancedFilter == 'ws_fail' ? 'all' : 'ws_fail'; _displayDirty = true; }), isActive: _advancedFilter == 'ws_fail'),
                    const SizedBox(width: 5),
                    // p45: compact mode
                    _miniBtn(_compactMode ? S.t.filterFull : S.t.filterCompact, () => setState(() => _compactMode = !_compactMode)),
                  ],
                ),
              ),
              // cf1: colo search field â€” only shown when results have colo data
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
                    _miniBtn(S.t.saveTxt, _saveResults),
                    const SizedBox(width: 5),
                    _miniBtn(S.t.exportJson, _exportJson),   // p40
                    const SizedBox(width: 5),
                    _miniBtn('Retest âŒ', _retestFailed),   // p41
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
            Text(S.t.copyTop5, style: GoogleFonts.inter(color: textPrimary, fontWeight: FontWeight.w600, fontSize: 13)),
          ]),
        ),
        PopupMenuItem(
          value: 'all',
          child: Row(children: [
            const Icon(Icons.copy_all_rounded, color: accentLime, size: 18),
            const SizedBox(width: 8),
            Text(S.t.copyAll, style: GoogleFonts.inter(color: textPrimary, fontWeight: FontWeight.w600, fontSize: 13)),
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
              if (r.flag.isNotEmpty && r.flag != 'ðŸŒ') ...[
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
                  r.wsOk! ? 'WS âœ“' : 'WS âœ—',
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
          // p55: dev mode â€” show raw TLS metrics
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
      _showSnack('âœ“ ${original.ip} â€” ${result.latencyMs.toStringAsFixed(0)} ms');
    } else {
      _showSnack('âŒ ${original.ip} â€” Failed');
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
            Text('ðŸ”§ DEV', style: GoogleFonts.robotoMono(color: accentLime, fontSize: 9, fontWeight: FontWeight.w700)),
            Text('Results: ${_results.length}', style: const TextStyle(color: Colors.green, fontSize: 9)),
            Text('Done: $_done/$_total', style: const TextStyle(color: Colors.green, fontSize: 9)),
            Text('DPI: $_dpiKills', style: const TextStyle(color: Colors.orange, fontSize: 9)),
            Text('Logs: ${StructuredLogger().recentLogs.length}', style: const TextStyle(color: Colors.cyan, fontSize: 9)),
          ],
        ),
      ),
    );
  }

  // â”€â”€ Shared Widgets â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
          Expanded(child: _navItem(0, Icons.radar_rounded, S.t.scanner)),
          Expanded(child: _navItem(1, Icons.bar_chart_rounded, S.t.results)),
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

// â”€â”€â”€ DNS Result Card â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
                              'âœ“ ${server.ip} copied!',
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


