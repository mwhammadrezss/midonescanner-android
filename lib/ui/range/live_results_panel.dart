// lib/ui/range/live_results_panel.dart
// Real-time streaming results list — auto-scrolls as new results arrive

import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import '../../engine/range/live_result_store.dart';

const _accentLime  = Color(0xFFC6F135);
const _textPrimary = Color(0xFFFFFFFF);
const _textSecond  = Color(0xFF8A9E8E);
const _iconBg      = Color(0xFF1E3525);
const _borderColor = Color(0xFF2A4A30);
const _cardColor   = Color(0xFF112216);
const _bgColor     = Color(0xFF0A1A0F);

Color _gradeColor(String grade) {
  switch (grade) {
    case 'S':  return const Color(0xFFFFD700);
    case 'A':  return const Color(0xFFC6F135);
    case 'B':  return const Color(0xFF80E060);
    case 'C':  return const Color(0xFFE0E060);
    case 'D':  return const Color(0xFFE0A060);
    default:   return const Color(0xFFFF5252);
  }
}

class LiveResultsPanel extends StatefulWidget {
  final Stream<RangeScanResult> stream;
  final List<RangeScanResult> initialResults;

  const LiveResultsPanel({
    super.key,
    required this.stream,
    required this.initialResults,
  });

  @override
  State<LiveResultsPanel> createState() => _LiveResultsPanelState();
}

class _LiveResultsPanelState extends State<LiveResultsPanel> {
  final List<RangeScanResult> _results = [];
  StreamSubscription<RangeScanResult>? _sub;
  final ScrollController _scroll = ScrollController();
  bool _autoScroll = true;

  @override
  void initState() {
    super.initState();
    _results.addAll(widget.initialResults);
    _sub = widget.stream.listen((r) {
      if (!mounted) return;
      setState(() => _results.add(r));
      if (_autoScroll) {
        WidgetsBinding.instance.addPostFrameCallback((_) {
          if (_scroll.hasClients) {
            _scroll.animateTo(
              _scroll.position.maxScrollExtent,
              duration: const Duration(milliseconds: 200),
              curve: Curves.easeOut,
            );
          }
        });
      }
    });
    _scroll.addListener(() {
      if (!_scroll.hasClients) return;
      final atBottom =
          _scroll.offset >= _scroll.position.maxScrollExtent - 80;
      if (_autoScroll != atBottom) {
        setState(() => _autoScroll = atBottom);
      }
    });
  }

  @override
  void dispose() {
    _sub?.cancel();
    _scroll.dispose();
    super.dispose();
  }

  void _copyIp(String ip) {
    Clipboard.setData(ClipboardData(text: ip));
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(
      content: Text('Copied $ip',
          style: GoogleFonts.inter(
              color: _bgColor, fontWeight: FontWeight.w600)),
      backgroundColor: _accentLime,
      behavior: SnackBarBehavior.floating,
      duration: const Duration(seconds: 1),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
    ));
  }

  @override
  Widget build(BuildContext context) {
    if (_results.isEmpty) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(Icons.search_rounded, color: _textSecond, size: 40),
            const SizedBox(height: 10),
            Text(
              'No results yet.\nStart scanning to discover IPs.',
              textAlign: TextAlign.center,
              style: GoogleFonts.inter(color: _textSecond, fontSize: 13),
            ),
          ],
        ),
      );
    }

    return Stack(
      children: [
        ListView.builder(
          controller: _scroll,
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
          itemCount: _results.length,
          itemBuilder: (ctx, i) => _resultCard(_results[i], i + 1),
        ),
        if (!_autoScroll)
          Positioned(
            bottom: 12,
            right: 12,
            child: GestureDetector(
              onTap: () {
                setState(() => _autoScroll = true);
                _scroll.animateTo(
                  _scroll.position.maxScrollExtent,
                  duration: const Duration(milliseconds: 300),
                  curve: Curves.easeOut,
                );
              },
              child: Container(
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: _accentLime,
                  borderRadius: BorderRadius.circular(20),
                ),
                child: const Icon(Icons.arrow_downward_rounded,
                    color: _bgColor, size: 18),
              ),
            ),
          ),
      ],
    );
  }

  Widget _resultCard(RangeScanResult r, int rank) {
    final gc = _gradeColor(r.grade);
    final latMs = r.latencyMs ?? r.tcpMs;
    return GestureDetector(
      onLongPress: () => _copyIp(r.ip),
      child: Container(
        margin: const EdgeInsets.only(bottom: 6),
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
        decoration: BoxDecoration(
          color: _cardColor,
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: _borderColor),
        ),
        child: Row(
          children: [
            // Rank
            SizedBox(
              width: 28,
              child: Text(
                '#$rank',
                style: GoogleFonts.robotoMono(
                    color: _textSecond, fontSize: 10),
              ),
            ),
            // Grade badge
            Container(
              width: 28,
              padding: const EdgeInsets.symmetric(vertical: 3),
              decoration: BoxDecoration(
                color: gc.withOpacity(0.12),
                borderRadius: BorderRadius.circular(6),
                border: Border.all(color: gc.withOpacity(0.4)),
              ),
              alignment: Alignment.center,
              child: Text(r.grade,
                  style: GoogleFonts.inter(
                      color: gc, fontSize: 10, fontWeight: FontWeight.w800)),
            ),
            const SizedBox(width: 8),
            // IP
            Expanded(
              child: Text(
                r.ip,
                style: GoogleFonts.robotoMono(
                    color: _textPrimary, fontSize: 13, fontWeight: FontWeight.w600),
              ),
            ),
            // Latency
            Text(
              '${latMs.toStringAsFixed(0)}ms',
              style: GoogleFonts.inter(color: _accentLime, fontSize: 11),
            ),
            const SizedBox(width: 8),
            // Country flag
            if (r.flag.isNotEmpty && r.flag != '🌐')
              Text(r.flag, style: const TextStyle(fontSize: 13)),
            const SizedBox(width: 4),
            // Deep scan badge
            if (r.deepScanned)
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 2),
                decoration: BoxDecoration(
                  color: const Color(0xFF60AAFF).withOpacity(0.12),
                  borderRadius: BorderRadius.circular(4),
                ),
                child: Text('D',
                    style: GoogleFonts.inter(
                        color: const Color(0xFF60AAFF),
                        fontSize: 9,
                        fontWeight: FontWeight.w700)),
              ),
          ],
        ),
      ),
    );
  }
}
