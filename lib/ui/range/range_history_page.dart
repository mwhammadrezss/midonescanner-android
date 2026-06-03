// lib/ui/range/range_history_page.dart
// History page for Range scan sessions

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';

import '../../storage/range_scan_storage.dart';

// Theme constants (copied from main.dart — private there)
const _bgColor     = Color(0xFF0A1A0F);
const _cardColor   = Color(0xFF112216);
const _card2Color  = Color(0xFF0D1A11);
const _accentLime  = Color(0xFFC6F135);
const _textPrimary = Color(0xFFFFFFFF);
const _textSecond  = Color(0xFF8A9E8E);
const _iconBg      = Color(0xFF1E3525);
const _borderColor = Color(0xFF2A4A30);

class RangeHistoryPage extends StatefulWidget {
  const RangeHistoryPage({super.key});

  @override
  State<RangeHistoryPage> createState() => _RangeHistoryPageState();
}

class _RangeHistoryPageState extends State<RangeHistoryPage> {
  List<Map<String, dynamic>> _sessions = [];
  bool _loading = true;
  final Set<int> _expanded = {};

  @override
  void initState() {
    super.initState();
    _loadSessions();
  }

  Future<void> _loadSessions() async {
    if (!mounted) return;
    setState(() => _loading = true);
    final sessions = await RangeScanStorage().loadAllSessions();
    if (mounted) {
      setState(() {
        _sessions = sessions;
        _loading = false;
      });
    }
  }

  void _showResetDialog() {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: _cardColor,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(16),
          side: const BorderSide(color: _borderColor),
        ),
        title: Text(
          'Reset History?',
          style: GoogleFonts.inter(
              color: _accentLime, fontWeight: FontWeight.w700, fontSize: 16),
        ),
        content: Text(
          'This will clear all session records AND the scanned IP memory.\nNext scan will start fresh from the full IP pool.',
          style: GoogleFonts.inter(color: _textSecond, fontSize: 13, height: 1.5),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: Text('Cancel',
                style: GoogleFonts.inter(color: _textSecond, fontWeight: FontWeight.w600)),
          ),
          TextButton(
            onPressed: () async {
              Navigator.pop(ctx);
              await RangeScanStorage().resetAll();
              if (mounted) _loadSessions();
            },
            child: Text('Reset',
                style: GoogleFonts.inter(
                    color: const Color(0xFFFF5252), fontWeight: FontWeight.w700)),
          ),
        ],
      ),
    );
  }

  String _formatDate(String isoDate) {
    try {
      final dt = DateTime.parse(isoDate).toLocal();
      final months = [
        'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
        'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'
      ];
      final d = dt.day.toString().padLeft(2, '0');
      final m = months[dt.month - 1];
      final y = dt.year;
      final h = dt.hour.toString().padLeft(2, '0');
      final min = dt.minute.toString().padLeft(2, '0');
      return '$d $m $y $h:$min';
    } catch (_) {
      return isoDate.length >= 16 ? isoDate.substring(0, 16) : isoDate;
    }
  }

  String _fmtNum(dynamic n) {
    final v = (n as num?)?.toInt() ?? 0;
    if (v >= 1000000) return '${(v / 1000000).toStringAsFixed(1)}M';
    if (v >= 1000) return '${(v / 1000).toStringAsFixed(0)}K';
    return '$v';
  }

  String _tierEmoji(String tier) {
    switch (tier) {
      case 'excellent': return '⭐';
      case 'good':      return '✅';
      case 'usable':    return '🟡';
      case 'weak':      return '🔻';
      default:          return '❌';
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: _bgColor,
      appBar: AppBar(
        backgroundColor: _card2Color,
        elevation: 0,
        title: Text(
          'Range History',
          style: GoogleFonts.inter(
              color: _accentLime, fontWeight: FontWeight.w700, fontSize: 17),
        ),
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_rounded, color: _accentLime),
          onPressed: () => Navigator.pop(context),
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.delete_sweep_rounded,
                color: Color(0xFFFF5252)),
            tooltip: 'Reset History',
            onPressed: _showResetDialog,
          ),
        ],
      ),
      body: _loading
          ? const Center(
              child: CircularProgressIndicator(color: _accentLime, strokeWidth: 2))
          : _sessions.isEmpty
              ? Center(
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      const Icon(Icons.history_rounded,
                          color: _textSecond, size: 48),
                      const SizedBox(height: 12),
                      Text(
                        'No range scan history yet.',
                        style: GoogleFonts.inter(
                            color: _textSecond, fontSize: 15),
                      ),
                    ],
                  ),
                )
              : ListView.builder(
                  padding: const EdgeInsets.all(12),
                  itemCount: _sessions.length,
                  itemBuilder: (ctx, i) => _sessionCard(i, _sessions[i]),
                ),
    );
  }

  Widget _sessionCard(int index, Map<String, dynamic> session) {
    final isExpanded = _expanded.contains(index);
    final provider = session['provider'] as String? ?? 'cloudflare';
    final providerLabel =
        provider == 'akamai' ? '🌐 Akamai' : '☁️ Cloudflare';
    final cidr = session['cidr'] as String? ?? '';
    final time = _formatDate(session['time'] as String? ?? '');
    final topIps = (session['topIps'] as List?)
            ?.map((e) => Map<String, dynamic>.from(e as Map))
            .toList() ??
        [];
    final avgRtt = (session['avgLatencyMs'] as num?)?.toDouble() ?? 0.0;
    final aliveCount = (session['aliveCount'] as num?)?.toInt() ?? 0;
    final deadCount = (session['deadCount'] as num?)?.toInt() ?? 0;
    final randomCount = (session['randomCount'] as num?)?.toInt() ?? 0;
    final totalScanned = (session['totalScanned'] as num?)?.toInt() ?? 0;
    final excellentCount = (session['excellentCount'] as num?)?.toInt() ?? 0;
    final goodCount = (session['goodCount'] as num?)?.toInt() ?? 0;
    final usableCount = (session['usableCount'] as num?)?.toInt() ?? 0;
    final weakCount = (session['weakCount'] as num?)?.toInt() ?? 0;

    final displayIps = isExpanded ? topIps : topIps.take(3).toList();

    return Container(
      margin: const EdgeInsets.only(bottom: 12),
      decoration: BoxDecoration(
        color: _cardColor,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: _borderColor),
      ),
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // ── Header ────────────────────────────────────────────────────
            Row(
              children: [
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(providerLabel,
                          style: GoogleFonts.inter(
                              color: _accentLime,
                              fontWeight: FontWeight.w700,
                              fontSize: 14)),
                      const SizedBox(height: 2),
                      Text(cidr,
                          style: GoogleFonts.robotoMono(
                              color: _textPrimary, fontSize: 12)),
                    ],
                  ),
                ),
                Text(time,
                    style: GoogleFonts.inter(
                        color: _textSecond, fontSize: 11)),
              ],
            ),
            const SizedBox(height: 12),

            // ── Stats ─────────────────────────────────────────────────────
            _statRow('Requested', _fmtNum(randomCount), 'Scanned', _fmtNum(totalScanned)),
            const SizedBox(height: 4),
            _statRow('✅ Alive', _fmtNum(aliveCount), '❌ Dead', _fmtNum(deadCount)),
            const SizedBox(height: 4),
            _statRow('⭐ Excellent', '$excellentCount', '✓ Good', '$goodCount'),
            const SizedBox(height: 4),
            _statRow('~ Usable', '$usableCount', '↓ Weak', '$weakCount'),
            if (avgRtt > 0) ...[
              const SizedBox(height: 4),
              Row(children: [
                Text('Avg RTT: ',
                    style: GoogleFonts.inter(
                        color: _textSecond, fontSize: 12)),
                Text('${avgRtt.toStringAsFixed(1)} ms',
                    style: GoogleFonts.inter(
                        color: _accentLime,
                        fontWeight: FontWeight.w700,
                        fontSize: 12)),
              ]),
            ],

            const SizedBox(height: 10),

            // ── Top IPs ───────────────────────────────────────────────────
            if (topIps.isEmpty)
              Text('No alive IPs found in this session.',
                  style: GoogleFonts.inter(
                      color: _textSecond, fontSize: 12))
            else ...[
              Text('TOP IPs',
                  style: GoogleFonts.inter(
                      color: _textSecond,
                      fontWeight: FontWeight.w700,
                      fontSize: 11,
                      letterSpacing: 1.2)),
              const SizedBox(height: 6),
              ...displayIps.asMap().entries.map((entry) {
                final rank = entry.key + 1;
                final ip = entry.value;
                final ipAddr = ip['ip'] as String? ?? '';
                final grade = ip['grade'] as String? ?? '-';
                final latency =
                    (ip['latencyMs'] as num?)?.toDouble() ?? 0.0;
                final tier = ip['tier'] as String? ?? 'dead';
                final colo = ip['colo'] as String?;

                return Padding(
                  padding: const EdgeInsets.only(bottom: 4),
                  child: Row(
                    children: [
                      Text('$rank. ',
                          style: GoogleFonts.inter(
                              color: _textSecond, fontSize: 11)),
                      Expanded(
                        child: Text(ipAddr,
                            style: GoogleFonts.robotoMono(
                                color: _textPrimary,
                                fontSize: 12,
                                fontWeight: FontWeight.w600)),
                      ),
                      Container(
                        padding: const EdgeInsets.symmetric(
                            horizontal: 5, vertical: 1),
                        decoration: BoxDecoration(
                          color: _accentLime.withOpacity(0.12),
                          borderRadius: BorderRadius.circular(5),
                          border: Border.all(
                              color: _accentLime.withOpacity(0.3)),
                        ),
                        child: Text(grade,
                            style: GoogleFonts.inter(
                                color: _accentLime,
                                fontSize: 10,
                                fontWeight: FontWeight.w700)),
                      ),
                      const SizedBox(width: 6),
                      Text('${latency.toStringAsFixed(0)}ms',
                          style: GoogleFonts.inter(
                              color: _accentLime, fontSize: 11)),
                      const SizedBox(width: 4),
                      Text(_tierEmoji(tier),
                          style: const TextStyle(fontSize: 11)),
                      if (colo != null) ...[
                        const SizedBox(width: 4),
                        Text(colo,
                            style: GoogleFonts.inter(
                                color: const Color(0xFF00E5FF),
                                fontSize: 10,
                                fontWeight: FontWeight.w600)),
                      ],
                    ],
                  ),
                );
              }),
            ],

            const SizedBox(height: 10),

            // ── Bottom row ────────────────────────────────────────────────
            Row(
              children: [
                // Copy Top 5 button
                if (topIps.isNotEmpty)
                  GestureDetector(
                    onTap: () {
                      final text = topIps
                          .take(5)
                          .map((e) => e['ip'] as String? ?? '')
                          .where((ip) => ip.isNotEmpty)
                          .join('\n');
                      Clipboard.setData(ClipboardData(text: text));
                      ScaffoldMessenger.of(context).showSnackBar(
                        SnackBar(
                          content: Text('✓ Top 5 copied!',
                              style: GoogleFonts.inter(
                                  color: _bgColor,
                                  fontWeight: FontWeight.w600)),
                          backgroundColor: _accentLime,
                          behavior: SnackBarBehavior.floating,
                          shape: RoundedRectangleBorder(
                              borderRadius: BorderRadius.circular(10)),
                          duration: const Duration(seconds: 2),
                        ),
                      );
                    },
                    child: Container(
                      padding: const EdgeInsets.symmetric(
                          horizontal: 10, vertical: 6),
                      decoration: BoxDecoration(
                        color: _iconBg,
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(color: _borderColor),
                      ),
                      child: Text('Copy Top 5',
                          style: GoogleFonts.inter(
                              color: _accentLime,
                              fontSize: 11,
                              fontWeight: FontWeight.w600)),
                    ),
                  ),
                const Spacer(),
                // Expand / Collapse
                if (topIps.length > 3)
                  GestureDetector(
                    onTap: () => setState(() {
                      if (isExpanded) {
                        _expanded.remove(index);
                      } else {
                        _expanded.add(index);
                      }
                    }),
                    child: Text(
                      isExpanded ? 'Collapse ▲' : 'Expand ▼',
                      style: GoogleFonts.inter(
                          color: _textSecond,
                          fontSize: 12,
                          fontWeight: FontWeight.w600),
                    ),
                  ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _statRow(String l1, String v1, String l2, String v2) {
    return Row(
      children: [
        Expanded(
          child: RichText(
            text: TextSpan(children: [
              TextSpan(
                  text: '$l1: ',
                  style: GoogleFonts.inter(
                      color: _textSecond, fontSize: 12)),
              TextSpan(
                  text: v1,
                  style: GoogleFonts.inter(
                      color: _textPrimary,
                      fontWeight: FontWeight.w600,
                      fontSize: 12)),
            ]),
          ),
        ),
        Expanded(
          child: RichText(
            text: TextSpan(children: [
              TextSpan(
                  text: '$l2: ',
                  style: GoogleFonts.inter(
                      color: _textSecond, fontSize: 12)),
              TextSpan(
                  text: v2,
                  style: GoogleFonts.inter(
                      color: _textPrimary,
                      fontWeight: FontWeight.w600,
                      fontSize: 12)),
            ]),
          ),
        ),
      ],
    );
  }
}
