import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:path_provider/path_provider.dart';
import 'package:share_plus/share_plus.dart';
import 'scanner_engine.dart';

void main() {
  runApp(const MidOneScannerApp());
}

// ─── Theme ─────────────────────────────────────────────────────────────────

const bgColor      = Color(0xFF0A0A1A);
const cardColor    = Color(0xFF1A1A2E);
const card2Color   = Color(0xFF12122A);
const accentGold   = Color(0xFFFFD700);
const accentBlue   = Color(0xFF40C4FF);
const accentGreen  = Color(0xFF00E676);
const accentRed    = Color(0xFFFF1744);
const accentOrange = Color(0xFFFF6D00);

Color gradeColor(ScanResult r) {
  if (r.throttled) return accentRed;
  if (r.speed > 300) return const Color(0xFF00E676);
  if (r.speed > 200) return const Color(0xFF69F0AE);
  if (r.speed > 100) return const Color(0xFFFFFF00);
  if (r.speed > 50)  return const Color(0xFFFFAB40);
  return accentRed;
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
          primary: accentGold,
          secondary: accentBlue,
          surface: cardColor,
        ),
        textTheme: GoogleFonts.interTextTheme(
          ThemeData.dark().textTheme,
        ),
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
  int _tab = 0; // 0=scan, 1=results

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

  void _startScan() {
    final ips = ScannerEngine.parseIps(_ipController.text);
    if (ips.isEmpty) {
      _showSnack('No valid IPs found!');
      return;
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
        ? _engine.scanMode1(
            ips: ips,
            onProgress: _onProgress,
            onResult: _onResult,
            onDone: _onDone,
          )
        : _engine.scanMode2(
            ips: ips,
            onProgress: _onProgress,
            onResult: _onResult,
            onDone: _onDone,
          );

    scan.catchError((e) {
      if (mounted) setState(() => _scanning = false);
    });
  }

  void _stopScan() {
    _engine.stop();
    setState(() {
      _scanning = false;
      _statusText = 'Stopped';
    });
  }

  void _onProgress(int done, int total) {
    if (!mounted) return;
    setState(() {
      _done = done;
      _total = total;
      final pct = (done / total * 100).round();
      _statusText = 'Scanning $pct%';
    });
  }

  void _onResult(ScanResult r) {
    if (!mounted) return;
    setState(() {
      if (r.throttled) _thrCount++; else _okCount++;
    });
  }

  void _onDone(List<ScanResult> results) {
    if (!mounted) return;
    setState(() {
      _results = results;
      _scanning = false;
      _statusText = 'Done! ${results.length} results';
    });
    if (results.isNotEmpty) {
      _showSnack('✅ Done! ${results.length} results found');
      Future.delayed(const Duration(milliseconds: 500), () {
        if (mounted) setState(() => _tab = 1);
      });
    }
  }

  List<ScanResult> get _displayResults {
    var list = [..._results];
    if (_filterThrottled) list = list.where((r) => !r.throttled).toList();
    list.sort((a, b) => _sortBy == 'score'
        ? b.score.compareTo(a.score)
        : b.speed.compareTo(a.speed));
    return list;
  }

  void _copyTop5() {
    final top5 = _results.where((r) => !r.throttled).take(5).toList();
    if (top5.isEmpty) { _showSnack('No clean results!'); return; }
    final text = top5.map((r) => '${r.ip}  SNI:${r.sni}').join('\n');
    Clipboard.setData(ClipboardData(text: text));
    _showSnack('✅ Top 5 IPs copied!');
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
      buf.writeln('MidONe Scanner SK v6.1 | t.me/mmdrlx | ${DateTime.now()}');
      buf.writeln('\n=== TOP 5 ===');
      for (int i = 0; i < top5.length; i++) {
        final r = top5[i];
        buf.writeln('${i + 1}. IP:${r.ip}  SNI:${r.sni}  CDN:${r.cdn}  ${r.speed} KB/s  Score:${r.score}');
      }
      buf.writeln('\n=== ALL RESULTS ===');
      for (final r in _results) {
        final thr = r.throttled ? ' [THR]' : '';
        buf.writeln('${r.ip.padRight(17)}${r.cdn.padRight(12)}${r.sni.padRight(30)}${r.speed.toStringAsFixed(1).padLeft(8)} KB/s  ${r.reliability}/5  Score:${r.score}$thr');
      }
      await file.writeAsString(buf.toString());
      _showSnack('✅ Saved: scan_$ts.txt');
    } catch (e) {
      _showSnack('Save error: $e');
    }
  }

  void _showSnack(String msg) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(msg, style: const TextStyle(color: Colors.white)),
        backgroundColor: card2Color,
        behavior: SnackBarBehavior.floating,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
        duration: const Duration(seconds: 2),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: bgColor,
      body: SafeArea(
        child: Column(
          children: [
            _buildTopBar(),
            Expanded(
              child: _tab == 0 ? _buildScanTab() : _buildResultsTab(),
            ),
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
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
      child: Row(
        children: [
          Text('🦁', style: const TextStyle(fontSize: 22)),
          const SizedBox(width: 8),
          Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text('MidONe Scanner SK',
                  style: GoogleFonts.inter(
                      color: accentGold,
                      fontWeight: FontWeight.bold,
                      fontSize: 16)),
              Text('Shir Khorshid CDN Scanner',
                  style: GoogleFonts.inter(color: Colors.grey, fontSize: 11)),
            ],
          ),
          const Spacer(),
          Text('@mmdrlx',
              style: GoogleFonts.inter(color: accentBlue, fontSize: 12)),
        ],
      ),
    );
  }

  // ── Scan Tab ─────────────────────────────────────────────────────────────

  Widget _buildScanTab() {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(14),
      child: Column(
        children: [
          _buildModeCard(),
          const SizedBox(height: 10),
          _buildInputCard(),
          const SizedBox(height: 10),
          _buildScanButton(),
          const SizedBox(height: 10),
          _buildProgressCard(),
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

  Widget _buildModeCard() {
    return _card(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('Scan Mode',
              style: GoogleFonts.inter(
                  color: accentGold, fontWeight: FontWeight.bold, fontSize: 14)),
          const SizedBox(height: 10),
          Row(
            children: [
              Expanded(child: _modeBtn(1, '⚡ Simple', 'Fast, SNI: google.com')),
              const SizedBox(width: 10),
              Expanded(child: _modeBtn(2, '🧠 Auto-SNI', 'CDN detect + all SNIs')),
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
        padding: const EdgeInsets.symmetric(vertical: 12, horizontal: 8),
        decoration: BoxDecoration(
          color: active ? const Color(0xFF1565C0) : const Color(0xFF263238),
          borderRadius: BorderRadius.circular(12),
          border: active
              ? Border.all(color: accentBlue, width: 1.5)
              : Border.all(color: Colors.transparent),
        ),
        child: Column(
          children: [
            Text(title,
                style: GoogleFonts.inter(
                    color: Colors.white,
                    fontWeight: FontWeight.bold,
                    fontSize: 14)),
            const SizedBox(height: 3),
            Text(sub,
                style: GoogleFonts.inter(
                    color: Colors.grey, fontSize: 10),
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
              Text('IP Addresses',
                  style: GoogleFonts.inter(
                      color: accentGold,
                      fontWeight: FontWeight.bold,
                      fontSize: 14)),
              const Spacer(),
              _miniBtn('PASTE', accentBlue, () async {
                final data = await Clipboard.getData('text/plain');
                if (data?.text != null) {
                  final cur = _ipController.text;
                  _ipController.text = cur.isEmpty
                      ? data!.text!
                      : '$cur\n${data!.text!}';
                }
              }),
              const SizedBox(width: 6),
              _miniBtn('CLEAR', accentRed, () => _ipController.clear()),
            ],
          ),
          const SizedBox(height: 8),
          TextField(
            controller: _ipController,
            maxLines: 6,
            style: GoogleFonts.robotoMono(
                color: const Color(0xFFE0E0FF), fontSize: 13),
            decoration: InputDecoration(
              hintText: '1.1.1.1\n8.8.8.8\n104.16.0.0\n...',
              hintStyle: GoogleFonts.robotoMono(
                  color: const Color(0xFF546E7A), fontSize: 12),
              filled: true,
              fillColor: const Color(0xFF0D1117),
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(10),
                borderSide: BorderSide.none,
              ),
              focusedBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(10),
                borderSide: const BorderSide(color: accentBlue, width: 1.5),
              ),
              contentPadding: const EdgeInsets.all(12),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildScanButton() {
    return SizedBox(
      width: double.infinity,
      height: 52,
      child: ElevatedButton(
        onPressed: _scanning ? _stopScan : _startScan,
        style: ElevatedButton.styleFrom(
          backgroundColor: _scanning ? accentRed : accentGreen,
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
          elevation: 4,
        ),
        child: Text(
          _scanning ? '⛔  STOP SCAN' : '🚀  START SCAN',
          style: GoogleFonts.inter(
              color: Colors.black,
              fontWeight: FontWeight.bold,
              fontSize: 16),
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
              Text(_statusText,
                  style: GoogleFonts.inter(
                      color: _scanning ? accentBlue : Colors.grey,
                      fontSize: 13)),
              const Spacer(),
              if (_total > 0)
                Text('$_done / $_total',
                    style: GoogleFonts.inter(
                        color: accentGold, fontSize: 13,
                        fontWeight: FontWeight.bold)),
            ],
          ),
          const SizedBox(height: 8),
          ClipRRect(
            borderRadius: BorderRadius.circular(4),
            child: LinearProgressIndicator(
              value: pct,
              backgroundColor: const Color(0xFF263238),
              valueColor: const AlwaysStoppedAnimation(accentGreen),
              minHeight: 8,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildStatsRow() {
    return Row(
      children: [
        Expanded(child: _statCard('✅ $_okCount', 'Passed', const Color(0xFF1B5E20))),
        const SizedBox(width: 8),
        Expanded(child: _statCard('❌ 0', 'Failed', const Color(0xFFB71C1C))),
        const SizedBox(width: 8),
        Expanded(child: _statCard('⚠️ $_thrCount', 'Throttled', const Color(0xFFE65100))),
      ],
    );
  }

  Widget _statCard(String value, String label, Color bg) {
    return Container(
      padding: const EdgeInsets.symmetric(vertical: 10),
      decoration: BoxDecoration(
          color: bg, borderRadius: BorderRadius.circular(10)),
      child: Column(
        children: [
          Text(value,
              style: GoogleFonts.inter(
                  color: Colors.white,
                  fontWeight: FontWeight.bold,
                  fontSize: 16)),
          Text(label,
              style: GoogleFonts.inter(
                  color: Colors.white70, fontSize: 11)),
        ],
      ),
    );
  }

  Widget _buildViewResultsButton() {
    return SizedBox(
      width: double.infinity,
      height: 48,
      child: ElevatedButton(
        onPressed: () => setState(() => _tab = 1),
        style: ElevatedButton.styleFrom(
          backgroundColor: const Color(0xFF1565C0),
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
        ),
        child: Text('📊  View ${_results.length} Results',
            style: GoogleFonts.inter(
                color: Colors.white,
                fontWeight: FontWeight.bold,
                fontSize: 15)),
      ),
    );
  }

  // ── Results Tab ───────────────────────────────────────────────────────────

  Widget _buildResultsTab() {
    final list = _displayResults;
    return Column(
      children: [
        // Filter bar
        Container(
          color: card2Color,
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
          child: Row(
            children: [
              Text('${list.length} results',
                  style: GoogleFonts.inter(color: Colors.grey, fontSize: 12)),
              const Spacer(),
              _miniBtn(
                  _sortBy == 'score' ? 'SORT:SCORE' : 'SORT:SPEED',
                  accentBlue, () {
                setState(() =>
                    _sortBy = _sortBy == 'score' ? 'speed' : 'score');
              }),
              const SizedBox(width: 6),
              _miniBtn(
                  _filterThrottled ? 'NO THR ✓' : 'NO THR',
                  _filterThrottled ? accentGreen : Colors.grey, () {
                setState(() => _filterThrottled = !_filterThrottled);
              }),
              const SizedBox(width: 6),
              _miniBtn('COPY', accentGreen, _copyTop5),
              const SizedBox(width: 6),
              _miniBtn('SAVE', accentGold, _saveResults),
            ],
          ),
        ),
        // List
        Expanded(
          child: list.isEmpty
              ? Center(
                  child: Text('No results yet.\nGo scan some IPs!',
                      textAlign: TextAlign.center,
                      style: GoogleFonts.inter(
                          color: Colors.grey, fontSize: 16)))
              : ListView.builder(
                  padding: const EdgeInsets.all(10),
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
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: cardColor,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(
            color: r.throttled
                ? accentRed.withOpacity(0.3)
                : Colors.transparent),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Row 1: rank + IP + grade
          Row(
            children: [
              Text('#$rank',
                  style: GoogleFonts.robotoMono(
                      color: Colors.grey, fontSize: 11)),
              const SizedBox(width: 6),
              Text(r.ip,
                  style: GoogleFonts.robotoMono(
                      color: Colors.white,
                      fontWeight: FontWeight.bold,
                      fontSize: 15)),
              if (r.throttled)
                Container(
                  margin: const EdgeInsets.only(left: 6),
                  padding: const EdgeInsets.symmetric(
                      horizontal: 6, vertical: 2),
                  decoration: BoxDecoration(
                      color: accentRed.withOpacity(0.2),
                      borderRadius: BorderRadius.circular(4)),
                  child: Text('THR -${r.throttlePct}%',
                      style: GoogleFonts.inter(
                          color: accentRed,
                          fontSize: 10,
                          fontWeight: FontWeight.bold)),
                ),
              const Spacer(),
              Text(r.grade,
                  style: GoogleFonts.inter(
                      color: gColor,
                      fontWeight: FontWeight.bold,
                      fontSize: 14)),
            ],
          ),
          const SizedBox(height: 6),
          // Row 2: speed / latency / score
          Row(
            children: [
              _chip('⚡ ${r.speed} KB/s', accentGreen),
              const SizedBox(width: 8),
              _chip('🕐 ${r.latency}ms', accentBlue),
              const SizedBox(width: 8),
              _chip('★ ${r.score}', accentGold),
            ],
          ),
          const SizedBox(height: 6),
          // Row 3: CDN + reliability + SNI
          Row(
            children: [
              Text('CDN:${r.cdn}  [${r.relBar}]',
                  style: GoogleFonts.robotoMono(
                      color: Colors.grey, fontSize: 10)),
              const Spacer(),
              Flexible(
                child: Text('SNI:${r.sni}',
                    style: GoogleFonts.robotoMono(
                        color: Colors.grey, fontSize: 10),
                    overflow: TextOverflow.ellipsis),
              ),
            ],
          ),
        ],
      ),
    );
  }

  // ── Bottom Nav ────────────────────────────────────────────────────────────

  Widget _buildBottomNav() {
    return Container(
      color: card2Color,
      child: Row(
        children: [
          Expanded(child: _navBtn(0, Icons.radar, 'Scanner')),
          Expanded(child: _navBtn(1, Icons.bar_chart, 'Results')),
        ],
      ),
    );
  }

  Widget _navBtn(int tab, IconData icon, String label) {
    final active = _tab == tab;
    return InkWell(
      onTap: () => setState(() => _tab = tab),
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 10),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon,
                color: active ? accentGold : Colors.grey,
                size: 22),
            Text(label,
                style: GoogleFonts.inter(
                    color: active ? accentGold : Colors.grey,
                    fontSize: 11)),
          ],
        ),
      ),
    );
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  Widget _card({required Widget child}) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
          color: cardColor, borderRadius: BorderRadius.circular(14)),
      child: child,
    );
  }

  Widget _miniBtn(String label, Color color, VoidCallback onTap) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
        decoration: BoxDecoration(
          color: color.withOpacity(0.15),
          borderRadius: BorderRadius.circular(6),
          border: Border.all(color: color.withOpacity(0.4)),
        ),
        child: Text(label,
            style: GoogleFonts.inter(
                color: color, fontSize: 11, fontWeight: FontWeight.bold)),
      ),
    );
  }

  Widget _chip(String text, Color color) {
    return Text(text,
        style: GoogleFonts.robotoMono(color: color, fontSize: 12));
  }

  @override
  void dispose() {
    _ipController.dispose();
    super.dispose();
  }
}
