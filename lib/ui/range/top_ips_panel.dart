// lib/ui/range/top_ips_panel.dart
// Top IPs panel with scores and copy button

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import '../../engine/range/live_result_store.dart';

const _accentLime  = Color(0xFFC6F135);
const _accentLime2 = Color(0xFFA8D400);
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

class TopIpsPanel extends StatelessWidget {
  final List<RangeScanResult> topResults;
  final VoidCallback? onCopyAll;

  const TopIpsPanel({
    super.key,
    required this.topResults,
    this.onCopyAll,
  });

  @override
  Widget build(BuildContext context) {
    if (topResults.isEmpty) return const SizedBox.shrink();

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
          Row(
            children: [
              const Icon(Icons.star_rounded, color: Color(0xFFFFD700), size: 14),
              const SizedBox(width: 6),
              Text(
                'TOP IPs',
                style: GoogleFonts.inter(
                  color: _textSecond,
                  fontWeight: FontWeight.w700,
                  fontSize: 11,
                  letterSpacing: 1.2,
                ),
              ),
              const Spacer(),
              GestureDetector(
                onTap: () {
                  final text = topResults.map((r) => r.ip).join('\n');
                  Clipboard.setData(ClipboardData(text: text));
                  onCopyAll?.call();
                },
                child: Container(
                  padding:
                      const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
                  decoration: BoxDecoration(
                    color: _accentLime.withOpacity(0.12),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: _accentLime.withOpacity(0.4)),
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      const Icon(Icons.copy_rounded,
                          size: 12, color: _accentLime),
                      const SizedBox(width: 4),
                      Text('Copy All',
                          style: GoogleFonts.inter(
                              color: _accentLime,
                              fontSize: 11,
                              fontWeight: FontWeight.w600)),
                    ],
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 10),
          ...topResults.asMap().entries.map((e) {
            final i = e.key;
            final r = e.value;
            final gc = _gradeColor(r.grade);
            final latMs = r.latencyMs ?? r.tcpMs;
            return Container(
              margin: const EdgeInsets.only(bottom: 6),
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
              decoration: BoxDecoration(
                color: i == 0
                    ? _accentLime.withOpacity(0.06)
                    : _iconBg,
                borderRadius: BorderRadius.circular(10),
                border: Border.all(
                  color: i == 0 ? _accentLime.withOpacity(0.3) : _borderColor,
                ),
              ),
              child: Row(
                children: [
                  // Rank medal
                  SizedBox(
                    width: 22,
                    child: Text(
                      i == 0 ? '🥇' : i == 1 ? '🥈' : i == 2 ? '🥉' : '${i + 1}.',
                      style: const TextStyle(fontSize: 13),
                      textAlign: TextAlign.center,
                    ),
                  ),
                  const SizedBox(width: 8),
                  // Grade
                  Container(
                    width: 26,
                    padding: const EdgeInsets.symmetric(vertical: 2),
                    decoration: BoxDecoration(
                      color: gc.withOpacity(0.12),
                      borderRadius: BorderRadius.circular(5),
                      border: Border.all(color: gc.withOpacity(0.4)),
                    ),
                    alignment: Alignment.center,
                    child: Text(r.grade,
                        style: GoogleFonts.inter(
                            color: gc,
                            fontSize: 9,
                            fontWeight: FontWeight.w800)),
                  ),
                  const SizedBox(width: 8),
                  // IP
                  Expanded(
                    child: Text(r.ip,
                        style: GoogleFonts.robotoMono(
                            color: _textPrimary,
                            fontSize: 13,
                            fontWeight: FontWeight.w600)),
                  ),
                  // Latency
                  Text('${latMs.toStringAsFixed(0)}ms',
                      style: GoogleFonts.inter(
                          color: _accentLime, fontSize: 11)),
                  const SizedBox(width: 6),
                  // Score
                  Text('${r.score.toStringAsFixed(0)}pts',
                      style: GoogleFonts.inter(
                          color: _textSecond, fontSize: 10)),
                  if (r.flag.isNotEmpty && r.flag != '🌐') ...[
                    const SizedBox(width: 4),
                    Text(r.flag, style: const TextStyle(fontSize: 12)),
                  ],
                ],
              ),
            );
          }),
        ],
      ),
    );
  }
}
