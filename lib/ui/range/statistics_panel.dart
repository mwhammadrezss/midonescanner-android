// lib/ui/range/statistics_panel.dart
// Live scan statistics panel

import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import '../../engine/range/range_scan_engine.dart';

const _accentLime  = Color(0xFFC6F135);
const _textPrimary = Color(0xFFFFFFFF);
const _textSecond  = Color(0xFF8A9E8E);
const _iconBg      = Color(0xFF1E3525);
const _borderColor = Color(0xFF2A4A30);
const _cardColor   = Color(0xFF112216);

class StatisticsPanel extends StatelessWidget {
  final RangeScanStats stats;

  const StatisticsPanel({super.key, required this.stats});

  String _fmt(Duration d) {
    final m = d.inMinutes;
    final s = d.inSeconds % 60;
    return m > 0 ? '${m}m ${s}s' : '${s}s';
  }

  @override
  Widget build(BuildContext context) {
    final rate = stats.probeRate;
    final rateStr = rate >= 10
        ? '${rate.toStringAsFixed(0)}/s'
        : '${rate.toStringAsFixed(1)}/s';

    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: _cardColor,
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: _borderColor),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'LIVE STATS',
            style: GoogleFonts.inter(
              color: _textSecond,
              fontWeight: FontWeight.w700,
              fontSize: 11,
              letterSpacing: 1.2,
            ),
          ),
          const SizedBox(height: 10),
          Row(
            children: [
              _tile('Probed', '${stats.totalProbed}', _textPrimary),
              _tile('Alive', '${stats.totalAlive}', _accentLime),
              _tile('Filtered', '${stats.totalFiltered}',
                  const Color(0xFF60AAFF)),
              _tile('Deep', '${stats.totalDeepScanned}',
                  const Color(0xFFFFD060)),
            ],
          ),
          const SizedBox(height: 8),
          Row(
            children: [
              _tile('Rate', rateStr, const Color(0xFF80E060)),
              _tile('Concurrency', '${stats.currentConcurrency}',
                  const Color(0xFFFFAB40)),
              _tile('Avg TCP',
                  '${stats.avgTcpMs.toStringAsFixed(0)}ms', _textSecond),
              _tile('Elapsed', _fmt(stats.elapsed), _textSecond),
            ],
          ),
        ],
      ),
    );
  }

  Widget _tile(String label, String value, Color color) {
    return Expanded(
      child: Column(
        children: [
          Text(
            value,
            style: GoogleFonts.inter(
              color: color,
              fontWeight: FontWeight.w800,
              fontSize: 15,
            ),
          ),
          Text(
            label,
            style: GoogleFonts.inter(color: _textSecond, fontSize: 9),
            textAlign: TextAlign.center,
          ),
        ],
      ),
    );
  }
}
