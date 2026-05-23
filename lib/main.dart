import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:path_provider/path_provider.dart';
import 'package:url_launcher/url_launcher.dart';

import 'scanner_engine.dart';

void main() {
  runApp(const MidOneScannerApp());
}

// ─── Forest Green Theme (INCY-inspired) ────────────────────────────────────

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

// همه SNI های موجود با نام نمایشی
const List<Map<String, String>> kAllSniOptions = [
  {'label': 'Cloudflare — speed.cloudflare.com', 'sni': 'speed.cloudflare.com'},
  {'label': 'Cloudflare — cloudflare.com',       'sni': 'cloudflare.com'},
  {'label': 'Akamai — a248.e.akamai.net',        'sni': 'a248.e.akamai.net'},
  {'label': 'Akamai — a77.net.akamai.net',       'sni': 'a77.net.akamai.net'},
  {'label': 'Akamai — a104.net.akamai.net',      'sni': 'a104.net.akamai.net'},
  {'label': 'Akamai — a184.net.akamai.net',      'sni': 'a184.net.akamai.net'},
  {'label': 'Google — google.com',               'sni': 'google.com'},
  {'label': 'Google — www.google.com',           'sni': 'www.google.com'},
  {'label': 'Google — fonts.googleapis.com',     'sni': 'fonts.googleapis.com'},
  {'label': 'Amazon — aws.amazon.com',           'sni': 'aws.amazon.com'},
  {'label': 'Amazon — d1.cloudfront.net',        'sni': 'd1.cloudfront.net'},
  {'label': 'Azure — ajax.aspnetcdn.com',        'sni': 'ajax.aspnetcdn.com'},
  {'label': 'Fastly — global.fastly.net',        'sni': 'global.fastly.net'},
  {'label': 'Iranian — aparat.com',              'sni': 'aparat.com'},
  {'label': 'Iranian — snapp.ir',                'sni': 'snapp.ir'},
  {'label': 'Iranian — digikala.com',            'sni': 'digikala.com'},
  {'label': 'Iranian — telewebion.com',          'sni': 'telewebion.com'},
  {'label': 'Iranian — varzesh3.com',            'sni': 'varzesh3.com'},
];

Color gradeColor(ScanResult r) {
  if (r.throttled) return const Color(0xFFFF5252);
  if (r.speed > 300) return accentLime;
  if (r.speed > 200) return const Color(0xFF80E060);
  if (r.speed > 100) return const Color(0xFFE0E060);
  if (r.speed > 50)  return const Color(0xFFE0A060);
  return const Color(0xFFFF5252);
}

// ─── App ───────────────────────────────────────────────────────────────────

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
          primary: accentLime,
          secondary: accentLime2,
          surface: cardColor,
        ),
        textTheme: GoogleFonts.interTextTheme(ThemeData.dark().textTheme),
      ),
      home: const HomeScreen(),
    );
  }
}

// ─── Home Screen ───────────────────────────────────────────────────────────

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});
  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  int _tab = 0;
  int _mode = 1;
  bool _scanning = false;
  int _done = 0;
  int _total = 0;
  int _okCount = 0;
  int _thrCount = 0;

  final _ipController = TextEditingController();
  final _engine = ScannerEngine();
  List<ScanResult> _results = [];
  String _statusText = 'Ready to scan...';
  String _sortBy = 'score';
  bool _filterThrottled = false;

  // SNI selector برای Auto-SNI
  Set<String> _selectedSnis = Set.from(kAllSniOptions.map((e) => e['sni']!));

  void _startScan() {
    final ips = ScannerEngine.parseIps(_ipController.text);
    if (ips.isEmpty) { _showSnack('No valid IPs found!'); return; }
    if (_mode == 2 && _selectedSnis.isEmpty) {
      _showSnack('Please select at least one SNI!'); return;
    }
    setState(() {
      _scanning = true;
      _results = [];
      _done = 0;
      _total = ips.length;
      _okCount = 0;
      _thrCount = 0;
      _statusText = 'Scanning...';
    });
    final scan = _mode == 1
        ? _engine.scanMode1(ips: ips, onProgress: _onProgress, onResult: _onResult, onDone: _onDone)
        : _engine.scanMode2(
            ips: ips,
            onProgress: _onProgress,
            onResult: _onResult,
            onDone: _onDone,
            customSnis: _selectedSnis.toList(),
          );
    scan.catchError((e) { if (mounted) setState(() => _scanning = false); });
  }

  void _stopScan() {
    _engine.stop();
    setState(() { _scanning = false; _statusText = 'Stopped'; });
  }

  void _onProgress(int done, int total) {
    if (!mounted) return;
    setState(() {
      _done = done; _total = total;
      _statusText = 'Scanning ${(done / total * 100).round()}%';
    });
  }

  void _onResult(ScanResult r) {
    if (!mounted) return;
    setState(() { if (r.throttled) _thrCount++; else _okCount++; });
  }

  void _onDone(List<ScanResult> results) {
    if (!mounted) return;
    setState(() {
      _results = results; _scanning = false;
      _statusText = 'Done! ${results.length} results';
    });
    if (results.isNotEmpty) {
      _showSnack('✓ Done! ${results.length} results found');
      Future.delayed(const Duration(milliseconds: 500), () {
        if (mounted) setState(() => _tab = 1);
      });
    }
  }

  List<ScanResult> get _displayResults {
    var list = [..._results];
    if (_filterThrottled) list = list.where((r) => !r.throttled).toList();
    list.sort((a, b) => _sortBy == 'score'
        ? b.score.compareTo(a.score) : b.speed.compareTo(a.speed));
    return list;
  }

  void _copyTop5() {
    final top5 = _results.where((r) => !r.throttled).take(5).toList();
    if (top5.isEmpty) { _showSnack('No clean results!'); return; }
    final text = _mode == 1
        ? top5.map((r) => r.ip).join('\n')
        : top5.map((r) => '${r.ip}  SNI:${r.sni}').join('\n');
    Clipboard.setData(ClipboardData(text: text));
    _showSnack('✓ Top 5 IPs copied!');
  }

  Future<void> _saveResults() async {
    if (_results.isEmpty) { _showSnack('No results!'); return; }
    try {
      final dir = await getExternalStorageDirectory() ?? await getApplicationDocumentsDirectory();
      final folder = Directory('${dir.path}/MidONeScanner');
      await folder.create(recursive: true);
      final ts = DateTime.now().toString().replaceAll(RegExp(r'[: ]'), '_').substring(0, 19);
      final file = File('${folder.path}/scan_$ts.txt');
      final top5 = _results.where((r) => !r.throttled).take(5).toList();
      final buf = StringBuffer();
      buf.writeln('MidONe Scanner SK v6.2 | t.me/mmdrlx | ${DateTime.now()}');
      buf.writeln('\n=== TOP 5 ===');
      for (int i = 0; i < top5.length; i++) {
        final r = top5[i];
        buf.writeln('${i + 1}. IP:${r.ip}  SNI:${r.sni}  CDN:${r.cdn}  ${r.speed} KB/s  Score:${r.score}');
      }
      buf.writeln('\n=== ALL RESULTS ===');
      for (final r in _results) {
        buf.writeln('${r.ip.padRight(17)}${r.cdn.padRight(12)}${r.sni.padRight(30)}${r.speed.toStringAsFixed(1).padLeft(8)} KB/s  ${r.reliability}/5  Score:${r.score}${r.throttled ? ' [THR]' : ''}');
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

  // ── Top Bar ──────────────────────────────────────────────────────────────

  Widget _buildTopBar() {
    return Container(
      color: card2Color,
      padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 12),
      child: Row(
        children: [
          // آیکون اپ در هدر
          Image.asset('assets/icons/app_icon.png', width: 36, height: 36),
          const SizedBox(width: 10),
          Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text('MidONe Scanner',
                  style: GoogleFonts.inter(
                      color: accentLime, fontWeight: FontWeight.w800,
                      fontSize: 18, letterSpacing: -0.5)),
              Text('v6.2',
                  style: GoogleFonts.inter(color: textSecond, fontSize: 11)),
            ],
          ),
          const Spacer(),
          // دکمه تلگرام با آیکون سبز
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

  // ── Scan Tab ─────────────────────────────────────────────────────────────

  Widget _buildScanTab() {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(16),
      child: Column(
        children: [
          _buildModeCard(),
          const SizedBox(height: 12),
          // SNI Selector فقط وقتی Auto-SNI انتخاب شده
          if (_mode == 2) ...[
            _buildSniSelector(),
            const SizedBox(height: 12),
          ],
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
              Expanded(child: _modeBtn(1, 'Simple', 'Fast · SNI: google.com')),
              const SizedBox(width: 10),
              Expanded(child: _modeBtn(2, 'Auto-SNI', 'CDN detect + custom SNIs')),
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
          border: Border.all(color: active ? accentLime : borderColor,
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

  // ── SNI Selector ─────────────────────────────────────────────────────────

  Widget _buildSniSelector() {
    final allSelected = _selectedSnis.length == kAllSniOptions.length;
    final noneSelected = _selectedSnis.isEmpty;

    return _card(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Text('SNI SELECTION',
                  style: GoogleFonts.inter(
                      color: textSecond, fontWeight: FontWeight.w700,
                      fontSize: 11, letterSpacing: 1.2)),
              const Spacer(),
              // دکمه ALL
              _miniBtn('ALL', () {
                setState(() {
                  _selectedSnis = Set.from(kAllSniOptions.map((e) => e['sni']!));
                });
              }, isAccent: allSelected),
              const SizedBox(width: 6),
              // دکمه NONE
              _miniBtn('NONE', () {
                setState(() => _selectedSnis = {});
              }, isDestructive: noneSelected),
            ],
          ),
          const SizedBox(height: 4),
          Text('${_selectedSnis.length} of ${kAllSniOptions.length} selected',
              style: GoogleFonts.inter(color: textSecond, fontSize: 11)),
          const SizedBox(height: 10),
          // لیست SNI ها
          ...kAllSniOptions.map((item) {
            final sni = item['sni']!;
            final label = item['label']!;
            final selected = _selectedSnis.contains(sni);
            return GestureDetector(
              onTap: () {
                setState(() {
                  if (selected) {
                    _selectedSnis.remove(sni);
                  } else {
                    _selectedSnis.add(sni);
                  }
                });
              },
              child: Container(
                margin: const EdgeInsets.only(bottom: 6),
                padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                decoration: BoxDecoration(
                  color: selected ? accentLime.withOpacity(0.08) : card2Color,
                  borderRadius: BorderRadius.circular(10),
                  border: Border.all(
                      color: selected ? accentLime.withOpacity(0.4) : borderColor),
                ),
                child: Row(
                  children: [
                    AnimatedContainer(
                      duration: const Duration(milliseconds: 150),
                      width: 18, height: 18,
                      decoration: BoxDecoration(
                        color: selected ? accentLime : Colors.transparent,
                        borderRadius: BorderRadius.circular(5),
                        border: Border.all(
                            color: selected ? accentLime : textSecond,
                            width: 1.5),
                      ),
                      child: selected
                          ? const Icon(Icons.check_rounded,
                              size: 12, color: Color(0xFF0A1A0F))
                          : null,
                    ),
                    const SizedBox(width: 10),
                    Expanded(
                      child: Text(label,
                          style: GoogleFonts.inter(
                              color: selected ? textPrimary : textSecond,
                              fontSize: 12,
                              fontWeight: selected
                                  ? FontWeight.w600
                                  : FontWeight.normal)),
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
              filled: true,
              fillColor: card2Color,
              border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(12),
                  borderSide: BorderSide.none),
              focusedBorder: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(12),
                  borderSide: const BorderSide(color: accentLime, width: 1.5)),
              enabledBorder: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(12),
                  borderSide: const BorderSide(color: borderColor, width: 1)),
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
                style: GoogleFonts.inter(
                    fontWeight: FontWeight.w800, fontSize: 15,
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
              Icon(Icons.circle, size: 8,
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
                        color: textPrimary, fontSize: 13,
                        fontWeight: FontWeight.w700)),
            ],
          ),
          const SizedBox(height: 10),
          ClipRRect(
            borderRadius: BorderRadius.circular(6),
            child: LinearProgressIndicator(
              value: pct,
              backgroundColor: iconBg,
              valueColor: const AlwaysStoppedAnimation(accentLime2),
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
        Expanded(child: _statCard('$_okCount', 'Passed', accentLime, statusGreen)),
        const SizedBox(width: 8),
        Expanded(child: _statCard('0', 'Failed', const Color(0xFFFF5252), statusRed)),
        const SizedBox(width: 8),
        Expanded(child: _statCard('$_thrCount', 'Throttled', const Color(0xFFFFAB40), statusOrange)),
      ],
    );
  }

  Widget _statCard(String value, String label, Color accent, Color bg) {
    return Container(
      padding: const EdgeInsets.symmetric(vertical: 12),
      decoration: BoxDecoration(
          color: bg, borderRadius: BorderRadius.circular(14),
          border: Border.all(color: accent.withOpacity(0.25))),
      child: Column(
        children: [
          Text(value,
              style: GoogleFonts.inter(
                  color: accent, fontWeight: FontWeight.w800, fontSize: 20)),
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
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
          child: Row(
            children: [
              Text('${list.length} results',
                  style: GoogleFonts.inter(color: textSecond, fontSize: 12)),
              const Spacer(),
              _miniBtn(_sortBy == 'score' ? 'Score ↓' : 'Speed ↓', () {
                setState(() => _sortBy = _sortBy == 'score' ? 'speed' : 'score');
              }),
              const SizedBox(width: 6),
              _miniBtn(_filterThrottled ? 'No THR ✓' : 'No THR', () {
                setState(() => _filterThrottled = !_filterThrottled);
              }, isActive: _filterThrottled),
              const SizedBox(width: 6),
              _miniBtn('Copy', _copyTop5, isAccent: true),
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
                      Icon(Icons.radar_rounded, color: textSecond, size: 48),
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
                  itemBuilder: (ctx, i) => _resultCard(i + 1, list[i]),
                ),
        ),
      ],
    );
  }

  Widget _resultCard(int rank, ScanResult r) {
    final gColor = gradeColor(r);
    return Container(
      margin: const EdgeInsets.only(bottom: 10),
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: cardColor,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
            color: r.throttled
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
                decoration: BoxDecoration(
                    color: iconBg, borderRadius: BorderRadius.circular(6)),
                child: Text('#$rank',
                    style: GoogleFonts.robotoMono(
                        color: textSecond, fontSize: 10)),
              ),
              const SizedBox(width: 8),
              Text(r.ip,
                  style: GoogleFonts.robotoMono(
                      color: textPrimary, fontWeight: FontWeight.w700,
                      fontSize: 15)),
              if (r.throttled) ...[
                const SizedBox(width: 6),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                  decoration: BoxDecoration(
                      color: const Color(0xFFFF5252).withOpacity(0.15),
                      borderRadius: BorderRadius.circular(6)),
                  child: Text('THR -${r.throttlePct}%',
                      style: GoogleFonts.inter(
                          color: const Color(0xFFFF5252),
                          fontSize: 10, fontWeight: FontWeight.w700)),
                ),
              ],
              const Spacer(),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                decoration: BoxDecoration(
                    color: gColor.withOpacity(0.12),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: gColor.withOpacity(0.4))),
                child: Text(r.grade,
                    style: GoogleFonts.inter(
                        color: gColor, fontWeight: FontWeight.w700,
                        fontSize: 11)),
              ),
            ],
          ),
          const SizedBox(height: 10),
          Row(
            children: [
              _chip(Icons.bolt_rounded, '${r.speed} KB/s', accentLime),
              const SizedBox(width: 8),
              _chip(Icons.timer_outlined, '${r.latency}ms',
                  const Color(0xFF60AAFF)),
              const SizedBox(width: 8),
              _chip(Icons.star_rounded, '${r.score}',
                  const Color(0xFFFFD060)),
            ],
          ),
          const SizedBox(height: 8),
          Row(
            children: [
              _chip(Icons.language_rounded, r.cdn,
                  const Color(0xFFFFAB40)),
              const SizedBox(width: 8),
              Expanded(
                child: Text('SNI: ${r.sni}',
                    style: GoogleFonts.robotoMono(
                        color: textSecond, fontSize: 10),
                    overflow: TextOverflow.ellipsis),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Row(
            children: List.generate(5, (i) => Padding(
              padding: const EdgeInsets.only(right: 3),
              child: Container(
                width: 18, height: 5,
                decoration: BoxDecoration(
                  color: i < r.reliability ? accentLime2 : iconBg,
                  borderRadius: BorderRadius.circular(3),
                ),
              ),
            )),
          ),
        ],
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
            border: Border.all(
                color: isActive || isAccent
                    ? color.withOpacity(0.5)
                    : borderColor)),
        child: Text(label,
            style: GoogleFonts.inter(
                color: color, fontSize: 11, fontWeight: FontWeight.w600)),
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
          border: active
              ? Border.all(color: accentLime.withOpacity(0.3))
              : null,
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, color: active ? accentLime : textSecond, size: 22),
            const SizedBox(height: 3),
            Text(label,
                style: GoogleFonts.inter(
                    color: active ? accentLime : textSecond,
                    fontSize: 11,
                    fontWeight:
                        active ? FontWeight.w700 : FontWeight.normal)),
          ],
        ),
      ),
    );
  }
}
