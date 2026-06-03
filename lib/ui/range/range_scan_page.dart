// lib/ui/range/range_scan_page.dart
// Full Range Scan page — ultra-fast CDN IP discovery

import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';

import '../../engine/range/range_scan_engine.dart';
import '../../engine/range/cidr_provider_service.dart';
import '../../engine/range/live_result_store.dart';
import '../../utils/scan_profiles.dart';
import 'provider_selector.dart';
import 'concurrency_slider.dart';
import 'statistics_panel.dart';
import 'live_results_panel.dart';
import 'top_ips_panel.dart';

// ── Theme constants ──────────────────────────────────────────────────────────
const _bgColor     = Color(0xFF0A1A0F);
const _cardColor   = Color(0xFF112216);
const _card2Color  = Color(0xFF0D1A11);
const _accentLime  = Color(0xFFC6F135);
const _textPrimary = Color(0xFFFFFFFF);
const _textSecond  = Color(0xFF8A9E8E);
const _iconBg      = Color(0xFF1E3525);
const _borderColor = Color(0xFF2A4A30);

class RangeScanPage extends StatefulWidget {
  const RangeScanPage({super.key});

  @override
  State<RangeScanPage> createState() => _RangeScanPageState();
}

class _RangeScanPageState extends State<RangeScanPage> {
  // ── Engine ───────────────────────────────────────────────────────────────
  final RangeScanEngine _engine = RangeScanEngine();
  final CidrProviderService _cidrService = CidrProviderService();

  // ── State ────────────────────────────────────────────────────────────────
  RangeCdnProvider? _selectedProvider;
  RangeCdnMeta? _selectedMeta;
  List<String> _cidrs = [];
  String? _selectedCidr;
  bool _loadingCidrs = false;

  int _concurrency = 200;
  RangeScanMode _mode = RangeScanMode.normalScan;
  ScanProfile? _selectedProfile = getProfile('balanced');

  bool _scanning = false;
  bool _paused = false;

  RangeScanStats _stats = RangeScanStats();

  // Batch UI updates
  Timer? _statsTimer;

  // Tab
  int _tab = 0; // 0 = config, 1 = live results

  // Stream key to rebuild LiveResultsPanel on new scan
  Key _panelKey = UniqueKey();

  @override
  void initState() {
    super.initState();
  }

  @override
  void dispose() {
    _engine.dispose();
    _statsTimer?.cancel();
    super.dispose();
  }

  // ── Provider selection ───────────────────────────────────────────────────
  void _selectProvider(RangeCdnMeta meta) {
    setState(() {
      _selectedMeta = meta;
      _selectedProvider = meta.provider;
      _cidrs = [];
      _selectedCidr = null;
      _loadingCidrs = true;
    });

    _cidrService.fetchCidrs(meta).then((allCidrs) {
      if (!mounted) return;
      final best = _cidrService.selectBestCidrs(allCidrs);
      setState(() {
        _cidrs = best;
        _selectedCidr = best.isNotEmpty ? best.first : null;
        _loadingCidrs = false;
      });
    }).catchError((_) {
      if (!mounted) return;
      setState(() {
        _cidrs = meta.fallbackCidrs.take(12).toList();
        _selectedCidr = _cidrs.isNotEmpty ? _cidrs.first : null;
        _loadingCidrs = false;
      });
    });
  }

  // ── Scan control ─────────────────────────────────────────────────────────
  void _startScan() {
    if (_selectedCidr == null) {
      _snack('Select a CIDR range first');
      return;
    }

    setState(() {
      _scanning = true;
      _paused = false;
      _panelKey = UniqueKey();
      _stats = RangeScanStats();
      _tab = 1;
    });

    _engine.reset();

    _statsTimer?.cancel();
    _statsTimer = Timer.periodic(const Duration(milliseconds: 400), (_) {
      if (!mounted) return;
      setState(() => _stats = _engine.stats);
    });

    _engine.scan(
      cidr: _selectedCidr!,
      mode: _mode,
      concurrencyOverride: _selectedProfile?.concurrency ?? _concurrency,
      provider: _selectedProvider,
      onStatsUpdate: (s) {
        if (!mounted) return;
        setState(() => _stats = s);
      },
    ).then((_) {
      _statsTimer?.cancel();
      if (!mounted) return;
      setState(() {
        _scanning = false;
        _paused = false;
        _stats = _engine.stats;
      });
      _snack('✓ Scan complete — ${_engine.results.length} results');
    }).catchError((e) {
      _statsTimer?.cancel();
      if (!mounted) return;
      setState(() { _scanning = false; _paused = false; });
      _snack('Scan error: $e');
    });
  }

  void _stopScan() {
    _engine.cancel();
    _statsTimer?.cancel();
    setState(() { _scanning = false; _paused = false; });
  }

  void _pauseScan() {
    _engine.pause();
    setState(() => _paused = true);
  }

  void _resumeScan() {
    _engine.resume();
    setState(() => _paused = false);
  }

  void _snack(String msg) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(
      content: Text(msg,
          style: GoogleFonts.inter(
              color: _bgColor, fontWeight: FontWeight.w600)),
      backgroundColor: _accentLime,
      behavior: SnackBarBehavior.floating,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
      duration: const Duration(seconds: 2),
    ));
  }

  // ── Build ─────────────────────────────────────────────────────────────────
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: _bgColor,
      appBar: AppBar(
        backgroundColor: _card2Color,
        elevation: 0,
        title: Row(
          children: [
            const Icon(Icons.radar_rounded, color: _accentLime, size: 20),
            const SizedBox(width: 8),
            Text('Range Scan',
                style: GoogleFonts.inter(
                    color: _accentLime,
                    fontWeight: FontWeight.w800,
                    fontSize: 17)),
            if (_scanning) ...[
              const SizedBox(width: 10),
              SizedBox(
                width: 14,
                height: 14,
                child: CircularProgressIndicator(
                  strokeWidth: 2,
                  color: _accentLime.withOpacity(0.7),
                ),
              ),
            ],
          ],
        ),
        bottom: PreferredSize(
          preferredSize: const Size.fromHeight(40),
          child: _buildTabBar(),
        ),
      ),
      body: IndexedStack(
        index: _tab,
        children: [
          _buildConfigTab(),
          _buildResultsTab(),
        ],
      ),
      bottomNavigationBar: _buildBottomBar(),
    );
  }

  // ── Tab bar ───────────────────────────────────────────────────────────────
  Widget _buildTabBar() {
    return Container(
      color: _card2Color,
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 6),
      child: Row(
        children: [
          _tabBtn(0, Icons.settings_rounded, 'Config'),
          const SizedBox(width: 8),
          _tabBtn(1, Icons.bar_chart_rounded,
              'Results${_engine.results.isNotEmpty ? " (${_engine.results.length})" : ""}'),
        ],
      ),
    );
  }

  Widget _tabBtn(int idx, IconData icon, String label) {
    final active = _tab == idx;
    return GestureDetector(
      onTap: () => setState(() => _tab = idx),
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 180),
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 6),
        decoration: BoxDecoration(
          color: active ? _accentLime.withOpacity(0.12) : Colors.transparent,
          borderRadius: BorderRadius.circular(10),
          border: Border.all(
              color: active ? _accentLime.withOpacity(0.4) : Colors.transparent),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon,
                size: 14,
                color: active ? _accentLime : _textSecond),
            const SizedBox(width: 5),
            Text(label,
                style: GoogleFonts.inter(
                    color: active ? _accentLime : _textSecond,
                    fontSize: 12,
                    fontWeight:
                        active ? FontWeight.w700 : FontWeight.normal)),
          ],
        ),
      ),
    );
  }

  // ── Config tab ────────────────────────────────────────────────────────────
  Widget _buildConfigTab() {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(14),
      child: Column(
        children: [
          _card(
            child: RangeProviderSelector(
              selected: _selectedProvider,
              onSelect: _selectProvider,
            ),
          ),
          const SizedBox(height: 10),
          if (_loadingCidrs)
            const Padding(
              padding: EdgeInsets.all(16),
              child: Center(
                child: SizedBox(
                  width: 20,
                  height: 20,
                  child: CircularProgressIndicator(
                      strokeWidth: 2, color: _accentLime),
                ),
              ),
            )
          else if (_cidrs.isNotEmpty)
            _card(child: _buildCidrSelector()),
          const SizedBox(height: 10),
          _card(child: _buildModeSelector()),
          const SizedBox(height: 10),
          if (_mode != RangeScanMode.fastProbeOnly)
            _card(child: _buildProfileSelector()),
          if (_mode != RangeScanMode.fastProbeOnly)
            const SizedBox(height: 10),
          _card(
            child: ConcurrencySlider(
              value: _concurrency,
              onChanged: (v) => setState(() => _concurrency = v),
            ),
          ),
          const SizedBox(height: 10),
          if (_scanning || _engine.results.isNotEmpty)
            Padding(
              padding: const EdgeInsets.only(bottom: 10),
              child: StatisticsPanel(stats: _stats),
            ),
        ],
      ),
    );
  }

  Widget _buildCidrSelector() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text('SELECT CIDR',
            style: GoogleFonts.inter(
                color: _textSecond,
                fontWeight: FontWeight.w700,
                fontSize: 11,
                letterSpacing: 1.2)),
        const SizedBox(height: 10),
        ..._cidrs.map((cidr) {
          final sel = _selectedCidr == cidr;
          return GestureDetector(
            onTap: () => setState(() => _selectedCidr = cidr),
            child: AnimatedContainer(
              duration: const Duration(milliseconds: 150),
              margin: const EdgeInsets.only(bottom: 6),
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
              decoration: BoxDecoration(
                color: sel ? _accentLime.withOpacity(0.08) : _card2Color,
                borderRadius: BorderRadius.circular(10),
                border: Border.all(
                    color: sel ? _accentLime : _borderColor,
                    width: sel ? 1.5 : 1),
              ),
              child: Row(
                children: [
                  Icon(
                      sel
                          ? Icons.radio_button_checked_rounded
                          : Icons.radio_button_off_rounded,
                      size: 15,
                      color: sel ? _accentLime : _textSecond),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(cidr,
                        style: GoogleFonts.robotoMono(
                            color: sel ? _accentLime : _textPrimary,
                            fontSize: 12,
                            fontWeight:
                                sel ? FontWeight.w600 : FontWeight.w400)),
                  ),
                ],
              ),
            ),
          );
        }),
      ],
    );
  }

  Widget _buildModeSelector() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text('SCAN MODE',
            style: GoogleFonts.inter(
                color: _textSecond,
                fontWeight: FontWeight.w700,
                fontSize: 11,
                letterSpacing: 1.2)),
        const SizedBox(height: 10),
        Row(
          children: [
            _modeBtn(RangeScanMode.fastProbeOnly, 'Fast',
                'TCP only · Ultra fast'),
            const SizedBox(width: 8),
            _modeBtn(RangeScanMode.normalScan, 'Normal',
                'TLS + Tunnel'),
            const SizedBox(width: 8),
            _modeBtn(RangeScanMode.deepScan, 'Deep',
                'Full analysis'),
          ],
        ),
      ],
    );
  }

  Widget _buildProfileSelector() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text('SCAN PROFILE',
            style: GoogleFonts.inter(
                color: _textSecond,
                fontWeight: FontWeight.w700,
                fontSize: 11,
                letterSpacing: 1.2)),
        const SizedBox(height: 10),
        ...kScanProfiles.map((profile) {
          final sel = _selectedProfile?.name == profile.name;
          return GestureDetector(
            onTap: () => setState(() => _selectedProfile = profile),
            child: AnimatedContainer(
              duration: const Duration(milliseconds: 150),
              margin: const EdgeInsets.only(bottom: 6),
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
              decoration: BoxDecoration(
                color: sel ? _accentLime.withOpacity(0.08) : _card2Color,
                borderRadius: BorderRadius.circular(10),
                border: Border.all(
                    color: sel ? _accentLime : _borderColor,
                    width: sel ? 1.5 : 1),
              ),
              child: Row(
                children: [
                  Icon(
                      sel
                          ? Icons.radio_button_checked_rounded
                          : Icons.radio_button_off_rounded,
                      size: 15,
                      color: sel ? _accentLime : _textSecond),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(profile.label,
                            style: GoogleFonts.inter(
                                color: sel ? _accentLime : _textPrimary,
                                fontSize: 13,
                                fontWeight: FontWeight.w600)),
                        const SizedBox(height: 2),
                        Text(profile.description,
                            style: GoogleFonts.inter(
                                color: _textSecond,
                                fontSize: 11)),
                      ],
                    ),
                  ),
                ],
              ),
            ),
          );
        }),
      ],
    );
  }

  Widget _modeBtn(RangeScanMode m, String title, String sub) {
    final active = _mode == m;
    return Expanded(
      child: GestureDetector(
        onTap: () => setState(() => _mode = m),
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 180),
          padding: const EdgeInsets.symmetric(vertical: 12, horizontal: 8),
          decoration: BoxDecoration(
            color: active ? _accentLime.withOpacity(0.12) : _iconBg,
            borderRadius: BorderRadius.circular(12),
            border: Border.all(
                color: active ? _accentLime : _borderColor,
                width: active ? 1.5 : 1),
          ),
          child: Column(
            children: [
              Text(title,
                  style: GoogleFonts.inter(
                      color: active ? _accentLime : _textPrimary,
                      fontWeight: FontWeight.w700,
                      fontSize: 13)),
              const SizedBox(height: 3),
              Text(sub,
                  style: GoogleFonts.inter(
                      color: _textSecond, fontSize: 9),
                  textAlign: TextAlign.center),
            ],
          ),
        ),
      ),
    );
  }

  // ── Results tab ───────────────────────────────────────────────────────────
  Widget _buildResultsTab() {
    final top = _engine.results.isEmpty
        ? <RangeScanResult>[]
        : LiveResultStore().results; // fallback

    final topSorted = List<RangeScanResult>.from(_engine.results)
      ..sort((a, b) => b.score.compareTo(a.score));
    final topN = topSorted.take(10).toList();

    return Column(
      children: [
        if (_scanning || _engine.results.isNotEmpty)
          Padding(
            padding: const EdgeInsets.fromLTRB(12, 10, 12, 0),
            child: StatisticsPanel(stats: _stats),
          ),
        if (topN.isNotEmpty)
          Padding(
            padding: const EdgeInsets.fromLTRB(12, 8, 12, 0),
            child: TopIpsPanel(
              topResults: topN,
              onCopyAll: () => _snack('✓ ${topN.length} IPs copied!'),
            ),
          ),
        const SizedBox(height: 4),
        Expanded(
          child: LiveResultsPanel(
            key: _panelKey,
            stream: _engine.resultStream,
            initialResults: _engine.results,
          ),
        ),
      ],
    );
  }

  // ── Bottom control bar ────────────────────────────────────────────────────
  Widget _buildBottomBar() {
    return Container(
      color: _card2Color,
      padding: const EdgeInsets.fromLTRB(14, 10, 14, 14),
      child: Row(
        children: [
          // Start / Stop
          Expanded(
            child: SizedBox(
              height: 50,
              child: ElevatedButton(
                onPressed: _scanning ? _stopScan : _startScan,
                style: ElevatedButton.styleFrom(
                  backgroundColor:
                      _scanning ? const Color(0xFF3A1A1A) : _accentLime,
                  foregroundColor:
                      _scanning ? const Color(0xFFFF5252) : _bgColor,
                  elevation: 0,
                  shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(14),
                      side: BorderSide(
                          color: _scanning
                              ? const Color(0xFFFF5252)
                              : Colors.transparent,
                          width: 1.5)),
                ),
                child: Row(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    Icon(_scanning
                        ? Icons.stop_rounded
                        : Icons.radar_rounded,
                        size: 20),
                    const SizedBox(width: 6),
                    Text(_scanning ? 'STOP' : 'START SCAN',
                        style: GoogleFonts.inter(
                            fontWeight: FontWeight.w800, fontSize: 14)),
                  ],
                ),
              ),
            ),
          ),
          // Pause / Resume
          if (_scanning) ...[
            const SizedBox(width: 8),
            SizedBox(
              height: 50,
              width: 50,
              child: ElevatedButton(
                onPressed: _paused ? _resumeScan : _pauseScan,
                style: ElevatedButton.styleFrom(
                  backgroundColor: _iconBg,
                  foregroundColor: _accentLime,
                  elevation: 0,
                  padding: EdgeInsets.zero,
                  shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(14),
                      side: const BorderSide(color: _borderColor)),
                ),
                child: Icon(
                    _paused
                        ? Icons.play_arrow_rounded
                        : Icons.pause_rounded,
                    size: 22),
              ),
            ),
          ],
        ],
      ),
    );
  }

  // ── Shared widgets ────────────────────────────────────────────────────────
  Widget _card({required Widget child}) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
          color: _cardColor,
          borderRadius: BorderRadius.circular(16),
          border: Border.all(color: _borderColor)),
      child: child,
    );
  }

  // ── Unused but kept for reference ──────────────────────────────────────
  Widget get _card2Color_widget => Container(color: _card2Color);
}

// Convenience extension for building page outside of main.dart
extension RangeScanPageRoute on RangeScanPage {
  MaterialPageRoute<void> get route =>
      MaterialPageRoute<void>(builder: (_) => this);
}
