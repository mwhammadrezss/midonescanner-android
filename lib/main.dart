import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_local_notifications/flutter_local_notifications.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:path_provider/path_provider.dart';
import 'package:url_launcher/url_launcher.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'scanner_engine.dart';
import 'geoip.dart';

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

// ─── App ────────────────────────────────────────────────────────────────────

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
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

class _HomeScreenState extends State<HomeScreen> {
  int _tab = 0;
  int _mode = 1;
  bool _scanning = false;
  bool _cancelled = false;
  int _done = 0, _total = 0, _okCount = 0, _thrCount = 0, _failCount = 0;

  final _ipController = TextEditingController();
  List<ScanResult> _results = [];
  String _statusText = 'Ready to scan...';
  String _sortBy = 'latency'; // latency | speed | reliability
  bool _filterThrottled = false;

  // ISP & ping
  String _ispName = 'در حال بررسی...';
  String _pingText = 'Ping: -- ms';
  Timer? _ispTimer;

  @override
  void initState() {
    super.initState();
    _showWelcomePopupIfNeeded();
    _detectIsp();
    _ispTimer = Timer.periodic(const Duration(seconds: 30), (_) => _detectIsp());
  }

  @override
  void dispose() {
    _ispTimer?.cancel();
    super.dispose();
  }

  // ── ISP Detection واقعی (فیلتر-مقاوم) ──────────────────────────────────
  Future<void> _detectIsp() async {
    final isp = await detectIspName();
    if (!mounted) return;
    setState(() {
      _ispName = 'اپراتور: $isp';
    });
    _measurePing();
  }

  Future<void> _measurePing() async {
    try {
      final t = DateTime.now();
      final sock = await SecureSocket.connect(
        '8.8.8.8', 443,
        onBadCertificate: (_) => true,
        timeout: const Duration(seconds: 3),
      );
      final ms = DateTime.now().difference(t).inMilliseconds;
      await sock.close();
      if (mounted) setState(() => _pingText = 'Ping: $ms ms');
    } catch (_) {
      if (mounted) setState(() => _pingText = 'Ping: -- ms');
    }
  }

  // ── Welcome Popup ─────────────────────────────────────────────────────────
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
                      color: accentLime, fontWeight: FontWeight.w800,
                      fontSize: 20)),
              const SizedBox(height: 8),
              Text('به کانال تلگرام ما بپیوندید!',
                  style: GoogleFonts.inter(
                      color: textPrimary, fontWeight: FontWeight.w700,
                      fontSize: 15)),
              const SizedBox(height: 10),
              Text(
                'برای دریافت آخرین بروزرسانی و آی‌پی‌های جدید به کانال تلگرام ما جوین بشید.',
                textAlign: TextAlign.center,
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
                      Image.asset('assets/icons/telegram_icon.png',
                          width: 20, height: 20),
                      const SizedBox(width: 8),
                      Text('جوین به @mmdrlx',
                          style: GoogleFonts.inter(
                              fontWeight: FontWeight.w800, fontSize: 14)),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 10),
              TextButton(
                onPressed: () => Navigator.pop(ctx),
                child: Text('بعداً',
                    style: GoogleFonts.inter(
                        color: textSecond, fontSize: 13)),
              ),
            ],
          ),
        ),
      ),
    );
  }

  void _startScan() {
    final ips = validateAndExtractIps(_ipController.text);
    if (ips.isEmpty) { _showSnack('No valid IPs found!'); return; }
    setState(() {
      _scanning = true;
      _cancelled = false;
      _results = [];
      _done = 0;
      _total = ips.length;
      _okCount = 0;
      _thrCount = 0;
      _failCount = 0;
      _statusText = 'Scanning...';
    });

    runScanningEngine(
      ips,
      mode: _mode == 2 ? ScanMode.deep : ScanMode.normal,
      onProgress: (done, total, result) {
        if (!mounted) return;
        setState(() {
          _results.add(result);
          _done = done;
          _total = total;
          if (result.isAlive) {
            if (result.loss > 30) {
              _thrCount++;
            } else {
              _okCount++;
            }
          } else {
            _failCount++;
          }
          _statusText = 'Scanning ${(done / total * 100).round()}%';
        });
        final pct = (done / total * 100).round();
        if (pct % 25 == 0 || pct >= 100) {
          if (pct >= 100) {
            sendNotification('✅ اسکن تموم شد!', 'نتایج آماده‌ست. برگرد به برنامه.');
          } else {
            sendNotification('در حال اسکن... $pct%', 'MidONe داره در پس‌زمینه کار می‌کنه');
          }
        }
      },
      isCancelled: () => _cancelled,
    ).then((results) {
      if (!mounted) return;
      setState(() {
        _results = results;
        _scanning = false;
        _statusText = 'Done! ${results.where((r) => r.isAlive).length} results';
      });
      if (results.isNotEmpty) {
        _showSnack('✓ Done! ${results.where((r) => r.isAlive).length} results found');
        Future.delayed(const Duration(milliseconds: 500), () {
          if (mounted) setState(() => _tab = 1);
        });
      }
    }).catchError((e) {
      if (mounted) setState(() => _scanning = false);
    });
  }

  void _stopScan() {
    setState(() {
      _cancelled = true;
      _scanning = false;
      _statusText = 'Stopped';
    });
  }

  List<ScanResult> get _displayResults {
    var list = [..._results];
    if (_filterThrottled) list = list.where((r) => r.isAlive).toList();
    switch (_sortBy) {
      case 'speed':
        list.sort((a, b) {
          final bw_a = a.bandwidth ?? -1;
          final bw_b = b.bandwidth ?? -1;
          return bw_b.compareTo(bw_a); // بیشترین speed اول
        });
      case 'reliability':
        list.sort((a, b) => b.reliability.compareTo(a.reliability));
      default: // latency
        list.sort((a, b) {
          if (a.isAlive != b.isAlive) return a.isAlive ? -1 : 1;
          return a.latencyMs.compareTo(b.latencyMs);
        });
    }
    return list;
  }

  // ── Copy ─────────────────────────────────────────────────────────────────
  void _copyTop5() {
    final top5 = _displayResults.where((r) => r.isAlive).take(5).toList();
    if (top5.isEmpty) { _showSnack('No alive results!'); return; }
    final text = top5.map((r) => r.ip).join('\n');
    Clipboard.setData(ClipboardData(text: text));
    _showSnack('✓ Top 5 copied!');
  }

  void _copyAll() {
    final list = _displayResults.where((r) => r.isAlive).toList();
    if (list.isEmpty) { _showSnack('No alive results!'); return; }
    final text = list.map((r) => r.ip).join('\n');
    Clipboard.setData(ClipboardData(text: text));
    _showSnack('✓ All ${list.length} IPs copied!');
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
        buf.writeln('${i + 1}. IP:${r.ip}  ${r.latencyMs.toStringAsFixed(1)} ms  Loss:${r.loss}%  Grade:${r.grade}  ${r.flag} ${r.country}');
      }
      buf.writeln('\n=== ALL RESULTS ===');
      for (final r in _results) {
        buf.writeln('${r.ip.padRight(17)}${r.grade.padRight(4)}${r.latencyMs.toStringAsFixed(1).padLeft(8)} ms  Loss:${r.loss}%  Rel:${(r.reliability * 100).round()}%${r.isAlive ? '' : ' [DEAD]'}');
      }
      await file.writeAsString(buf.toString());
      _showSnack('✓ Saved: scan_$ts.txt');
    } catch (e) { _showSnack('Save error: $e'); }
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
        child: Column(
          children: [
            _buildTopBar(),
            Expanded(child: _tab == 0 ? _buildScanTab() : _buildResultsTab()),
            _buildBottomNav(),
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
              Text('MidONe Scanner',
                  style: GoogleFonts.inter(
                      color: accentLime, fontWeight: FontWeight.w800,
                      fontSize: 18, letterSpacing: -0.5)),
              Row(
                children: [
                  Text(_ispName,
                      style: GoogleFonts.inter(color: textSecond, fontSize: 10)),
                  const SizedBox(width: 6),
                  Text('· $_pingText',
                      style: GoogleFonts.inter(color: textSecond, fontSize: 10)),
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
                  Image.asset('assets/icons/telegram_icon.png',
                      width: 16, height: 16),
                  const SizedBox(width: 5),
                  Text('@mmdrlx',
                      style: GoogleFonts.inter(
                          color: accentLime, fontSize: 12,
                          fontWeight: FontWeight.w600)),
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
          const SizedBox(height: 12),
          _buildInputCard(),
          const SizedBox(height: 12),
          _buildScanButton(),
          const SizedBox(height: 12),
          _buildProgressCard(),
          const SizedBox(height: 12),
          _buildStatsRow(),
          if (_results.isNotEmpty) ...[
            const SizedBox(height: 12),
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
              style: GoogleFonts.inter(
                  color: textSecond, fontWeight: FontWeight.w700,
                  fontSize: 11, letterSpacing: 1.2)),
          const SizedBox(height: 12),
          Row(
            children: [
              Expanded(child: _modeBtn(1, 'Normal', 'Fast · 3 probes')),
              const SizedBox(width: 10),
              Expanded(child: _modeBtn(2, 'Deep', 'Accurate · 5 probes')),
            ],
          ),
        ],
      ),
    );
  }

  Widget _modeBtn(int mode, String title, String sub) {
    final active = _mode == mode;
    return GestureDetector(
      onTap: () => setState(() => _mode = mode),
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 200),
        padding: const EdgeInsets.symmetric(vertical: 14, horizontal: 10),
        decoration: BoxDecoration(
          color: active ? accentLime.withOpacity(0.12) : iconBg,
          borderRadius: BorderRadius.circular(14),
          border: Border.all(
              color: active ? accentLime : borderColor,
              width: active ? 1.5 : 1),
        ),
        child: Column(
          children: [
            Text(title,
                style: GoogleFonts.inter(
                    color: active ? accentLime : textPrimary,
                    fontWeight: FontWeight.w700, fontSize: 14)),
            const SizedBox(height: 4),
            Text(sub,
                style: GoogleFonts.inter(color: textSecond, fontSize: 10),
                textAlign: TextAlign.center),
          ],
        ),
      ),
    );
  }

  Widget _buildInputCard() {
    return _card(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Text('IP ADDRESSES',
                  style: GoogleFonts.inter(
                      color: textSecond, fontWeight: FontWeight.w700,
                      fontSize: 11, letterSpacing: 1.2)),
              const Spacer(),
              _miniBtn('Paste', () async {
                final data = await Clipboard.getData('text/plain');
                if (data?.text != null) {
                  final cur = _ipController.text;
                  _ipController.text =
                      cur.isEmpty ? data!.text! : '$cur\n${data!.text!}';
                }
              }),
              const SizedBox(width: 8),
              _miniBtn('Clear', () => _ipController.clear(),
                  isDestructive: true),
            ],
          ),
          const SizedBox(height: 10),
          TextField(
            controller: _ipController,
            maxLines: 6,
            style: GoogleFonts.robotoMono(color: textPrimary, fontSize: 13),
            decoration: InputDecoration(
              hintText: '1.1.1.1\n8.8.8.8\n104.16.0.0\n...',
              hintStyle:
                  GoogleFonts.robotoMono(color: textSecond, fontSize: 12),
              filled: true,
              fillColor: card2Color,
              border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(12),
                  borderSide: BorderSide.none),
              focusedBorder: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(12),
                  borderSide:
                      const BorderSide(color: accentLime, width: 1.5)),
              enabledBorder: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(12),
                  borderSide:
                      const BorderSide(color: borderColor, width: 1)),
              contentPadding: const EdgeInsets.all(14),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildScanButton() {
    return SizedBox(
      width: double.infinity, height: 54,
      child: ElevatedButton(
        onPressed: _scanning ? _stopScan : _startScan,
        style: ElevatedButton.styleFrom(
          backgroundColor:
              _scanning ? const Color(0xFF3A1A1A) : accentLime,
          foregroundColor:
              _scanning ? const Color(0xFFFF5252) : bgColor,
          shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(16)),
          elevation: 0,
          side: BorderSide(
              color: _scanning
                  ? const Color(0xFFFF5252)
                  : Colors.transparent,
              width: 1.5),
        ),
        child: Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
                _scanning
                    ? Icons.stop_rounded
                    : Icons.radar_rounded,
                size: 20),
            const SizedBox(width: 8),
            Text(_scanning ? 'STOP SCAN' : 'START SCAN',
                style: GoogleFonts.inter(
                    fontWeight: FontWeight.w800,
                    fontSize: 15,
                    letterSpacing: 0.5)),
          ],
        ),
      ),
    );
  }

  Widget _buildProgressCard() {
    final pct = _total > 0 ? _done / _total : 0.0;
    return _card(
      child: Column(
        children: [
          Row(
            children: [
              Icon(Icons.circle,
                  size: 8,
                  color: _scanning ? accentLime : textSecond),
              const SizedBox(width: 6),
              Text(_statusText,
                  style: GoogleFonts.inter(
                      color: _scanning ? accentLime : textSecond,
                      fontSize: 13, fontWeight: FontWeight.w500)),
              const Spacer(),
              if (_total > 0)
                Text('$_done / $_total',
                    style: GoogleFonts.inter(
                        color: textPrimary,
                        fontSize: 13,
                        fontWeight: FontWeight.w700)),
            ],
          ),
          const SizedBox(height: 10),
          ClipRRect(
            borderRadius: BorderRadius.circular(6),
            child: LinearProgressIndicator(
              value: pct,
              backgroundColor: iconBg,
              valueColor:
                  const AlwaysStoppedAnimation(accentLime2),
              minHeight: 6,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildStatsRow() {
    return Row(
      children: [
        Expanded(
            child: _statCard(
                '$_okCount', 'Passed', accentLime, statusGreen)),
        const SizedBox(width: 8),
        Expanded(
            child: _statCard(
                '$_failCount', 'Failed', const Color(0xFFFF5252), statusRed)),
        const SizedBox(width: 8),
        Expanded(
            child: _statCard('$_thrCount', 'High Loss',
                const Color(0xFFFFAB40), statusOrange)),
      ],
    );
  }

  Widget _statCard(
      String value, String label, Color accent, Color bg) {
    return Container(
      padding: const EdgeInsets.symmetric(vertical: 12),
      decoration: BoxDecoration(
          color: bg,
          borderRadius: BorderRadius.circular(14),
          border: Border.all(color: accent.withOpacity(0.25))),
      child: Column(
        children: [
          Text(value,
              style: GoogleFonts.inter(
                  color: accent,
                  fontWeight: FontWeight.w800,
                  fontSize: 20)),
          const SizedBox(height: 2),
          Text(label,
              style:
                  GoogleFonts.inter(color: textSecond, fontSize: 11)),
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
          backgroundColor: cardInner,
          foregroundColor: accentLime,
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
                style: GoogleFonts.inter(
                    fontWeight: FontWeight.w700, fontSize: 14)),
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
          padding: const EdgeInsets.symmetric(
              horizontal: 14, vertical: 8),
          child: Row(
            children: [
              Text('${list.length} results',
                  style: GoogleFonts.inter(
                      color: textSecond, fontSize: 12)),
              const Spacer(),
              _miniBtn('Latency', () => setState(() => _sortBy = 'latency'),
                  isActive: _sortBy == 'latency'),
              const SizedBox(width: 6),
              _miniBtn('Speed', () => setState(() => _sortBy = 'speed'),
                  isActive: _sortBy == 'speed'),
              const SizedBox(width: 6),
              _miniBtn('Rel', () => setState(() => _sortBy = 'reliability'),
                  isActive: _sortBy == 'reliability'),
              const SizedBox(width: 6),
              _miniBtn(_filterThrottled ? 'Alive ✓' : 'Alive', () {
                setState(() => _filterThrottled = !_filterThrottled);
              }, isActive: _filterThrottled),
              const SizedBox(width: 6),
              _buildCopyButton(),
              const SizedBox(width: 6),
              _miniBtn('Save', _saveResults),
            ],
          ),
        ),
        Expanded(
          child: list.isEmpty
              ? Center(
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Icon(Icons.radar_rounded,
                          color: textSecond, size: 48),
                      const SizedBox(height: 12),
                      Text('No results yet.\nGo scan some IPs!',
                          textAlign: TextAlign.center,
                          style: GoogleFonts.inter(
                              color: textSecond, fontSize: 15)),
                    ],
                  ))
              : ListView.builder(
                  padding: const EdgeInsets.all(12),
                  itemCount: list.length,
                  itemBuilder: (ctx, i) =>
                      _resultCard(i + 1, list[i]),
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
          child: Row(
            children: [
              const Icon(Icons.filter_5_rounded,
                  color: accentLime, size: 18),
              const SizedBox(width: 8),
              Text('Copy Top 5',
                  style: GoogleFonts.inter(
                      color: textPrimary,
                      fontWeight: FontWeight.w600,
                      fontSize: 13)),
            ],
          ),
        ),
        PopupMenuItem(
          value: 'all',
          child: Row(
            children: [
              const Icon(Icons.copy_all_rounded,
                  color: accentLime, size: 18),
              const SizedBox(width: 8),
              Text('Copy All',
                  style: GoogleFonts.inter(
                      color: textPrimary,
                      fontWeight: FontWeight.w600,
                      fontSize: 13)),
            ],
          ),
        ),
      ],
      child: Container(
        padding: const EdgeInsets.symmetric(
            horizontal: 10, vertical: 5),
        decoration: BoxDecoration(
            color: accentLime.withOpacity(0.12),
            borderRadius: BorderRadius.circular(8),
            border: Border.all(
                color: accentLime.withOpacity(0.5))),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text('Copy',
                style: GoogleFonts.inter(
                    color: accentLime,
                    fontSize: 11,
                    fontWeight: FontWeight.w600)),
            const SizedBox(width: 3),
            const Icon(Icons.expand_more_rounded,
                color: accentLime, size: 14),
          ],
        ),
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
                padding: const EdgeInsets.symmetric(
                    horizontal: 6, vertical: 2),
                decoration: BoxDecoration(
                    color: iconBg,
                    borderRadius: BorderRadius.circular(6)),
                child: Text('#$rank',
                    style: GoogleFonts.robotoMono(
                        color: textSecond, fontSize: 10)),
              ),
              const SizedBox(width: 8),
              Text(r.ip,
                  style: GoogleFonts.robotoMono(
                      color: textPrimary,
                      fontWeight: FontWeight.w700,
                      fontSize: 15)),
              if (!r.isAlive) ...[
                const SizedBox(width: 6),
                Container(
                  padding: const EdgeInsets.symmetric(
                      horizontal: 6, vertical: 2),
                  decoration: BoxDecoration(
                      color: const Color(0xFFFF5252)
                          .withOpacity(0.15),
                      borderRadius: BorderRadius.circular(6)),
                  child: Text('DEAD',
                      style: GoogleFonts.inter(
                          color: const Color(0xFFFF5252),
                          fontSize: 10,
                          fontWeight: FontWeight.w700)),
                ),
              ] else if (r.loss > 30) ...[
                const SizedBox(width: 6),
                Container(
                  padding: const EdgeInsets.symmetric(
                      horizontal: 6, vertical: 2),
                  decoration: BoxDecoration(
                      color: const Color(0xFFFFAB40)
                          .withOpacity(0.15),
                      borderRadius: BorderRadius.circular(6)),
                  child: Text('Loss ${r.loss}%',
                      style: GoogleFonts.inter(
                          color: const Color(0xFFFFAB40),
                          fontSize: 10,
                          fontWeight: FontWeight.w700)),
                ),
              ],
              if (r.flag.isNotEmpty && r.flag != '🌐') ...[
                const SizedBox(width: 6),
                Text(r.flag, style: const TextStyle(fontSize: 14)),
              ],
              const Spacer(),
              Container(
                padding: const EdgeInsets.symmetric(
                    horizontal: 8, vertical: 3),
                decoration: BoxDecoration(
                    color: gColor.withOpacity(0.12),
                    borderRadius: BorderRadius.circular(8),
                    border:
                        Border.all(color: gColor.withOpacity(0.4))),
                child: Text(r.grade,
                    style: GoogleFonts.inter(
                        color: gColor,
                        fontWeight: FontWeight.w700,
                        fontSize: 11)),
              ),
            ],
          ),
          const SizedBox(height: 10),
          Row(
            children: [
              _chip(Icons.timer_outlined,
                  '${r.latencyMs.toStringAsFixed(0)} ms', accentLime),
              const SizedBox(width: 8),
              _chip(Icons.show_chart_rounded,
                  'Jitter ${r.jitterMs.toStringAsFixed(0)} ms',
                  const Color(0xFF60AAFF)),
              const SizedBox(width: 8),
              _chip(Icons.signal_cellular_alt_rounded,
                  'Loss ${r.loss}%',
                  const Color(0xFFFFD060)),
            ],
          ),
          const SizedBox(height: 8),
          Row(
            children: [
              if (r.country.isNotEmpty)
                _chip(Icons.location_on_rounded,
                    r.country.length > 12
                        ? r.country.substring(0, 12)
                        : r.country,
                    const Color(0xFFAA80FF)),
              const SizedBox(width: 8),
              _chip(Icons.percent_rounded,
                  'Rel ${(r.reliability * 100).round()}%',
                  const Color(0xFFFFAB40)),
              if (r.bandwidth != null) ...[
                const SizedBox(width: 8),
                _chip(Icons.speed_rounded,
                    '${r.bandwidth!.toStringAsFixed(2)} Mbps',
                    const Color(0xFF60AAFF)),
              ],
            ],
          ),
          const SizedBox(height: 8),
          Row(
            children: [
              ...List.generate(
                  5,
                  (i) => Padding(
                        padding: const EdgeInsets.only(right: 3),
                        child: Container(
                          width: 18, height: 5,
                          decoration: BoxDecoration(
                            color: i < relBars
                                ? accentLime2
                                : iconBg,
                            borderRadius: BorderRadius.circular(3),
                          ),
                        ),
                      )),
              const Spacer(),
              GestureDetector(
                onTap: () => _retestCard(r),
                child: Container(
                  padding: const EdgeInsets.symmetric(
                      horizontal: 8, vertical: 4),
                  decoration: BoxDecoration(
                      color: iconBg,
                      borderRadius: BorderRadius.circular(8),
                      border: Border.all(color: borderColor)),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      const Icon(Icons.refresh_rounded,
                          size: 12, color: accentLime),
                      const SizedBox(width: 4),
                      Text('Retest',
                          style: GoogleFonts.inter(
                              color: accentLime,
                              fontSize: 10,
                              fontWeight: FontWeight.w600)),
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

  // ── Retest واقعی ─────────────────────────────────────────────────────────
  Future<void> _retestCard(ScanResult original) async {
    _showSnack('Retesting ${original.ip}...');
    final result = await scanOneIp(original.ip, repeats: 3);
    if (!mounted) return;
    setState(() {
      final idx = _results.indexWhere((r) => r.ip == original.ip);
      if (idx >= 0) _results[idx] = result;
    });
    if (result.isAlive) {
      _showSnack('✓ ${original.ip} — ${result.latencyMs.toStringAsFixed(0)} ms');
    } else {
      _showSnack('❌ ${original.ip} — Failed');
    }
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
      {bool isDestructive = false,
      bool isActive = false,
      bool isAccent = false}) {
    Color color = textSecond;
    if (isDestructive) color = const Color(0xFFFF5252);
    if (isActive || isAccent) color = accentLime;
    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(
            horizontal: 10, vertical: 5),
        decoration: BoxDecoration(
            color:
                isAccent ? accentLime.withOpacity(0.12) : iconBg,
            borderRadius: BorderRadius.circular(8),
            border: Border.all(
                color: isActive || isAccent
                    ? color.withOpacity(0.5)
                    : borderColor)),
        child: Text(label,
            style: GoogleFonts.inter(
                color: color,
                fontSize: 11,
                fontWeight: FontWeight.w600)),
      ),
    );
  }

  Widget _chip(IconData icon, String label, Color color) {
    return Container(
      padding:
          const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
          color: color.withOpacity(0.08),
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: color.withOpacity(0.2))),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 11, color: color),
          const SizedBox(width: 4),
          Text(label,
              style:
                  GoogleFonts.inter(color: color, fontSize: 11)),
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
          Expanded(
              child: _navItem(
                  0, Icons.radar_rounded, 'Scanner')),
          Expanded(
              child: _navItem(
                  1, Icons.bar_chart_rounded, 'Results')),
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
        margin: const EdgeInsets.symmetric(
            horizontal: 12, vertical: 6),
        padding: const EdgeInsets.symmetric(vertical: 10),
        decoration: BoxDecoration(
          color: active
              ? accentLime.withOpacity(0.12)
              : Colors.transparent,
          borderRadius: BorderRadius.circular(14),
          border: active
              ? Border.all(color: accentLime.withOpacity(0.3))
              : null,
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon,
                color: active ? accentLime : textSecond,
                size: 22),
            const SizedBox(height: 3),
            Text(label,
                style: GoogleFonts.inter(
                    color: active ? accentLime : textSecond,
                    fontSize: 11,
                    fontWeight: active
                        ? FontWeight.w700
                        : FontWeight.normal)),
          ],
        ),
      ),
    );
  }
}
