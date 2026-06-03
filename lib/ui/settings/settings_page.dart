import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:url_launcher/url_launcher.dart';

import '../../core/l10n/strings.dart';
import '../../core/settings/app_settings.dart';
import '../../engine/probe_engine.dart' show kDeepSniPresets;

const _bg = Color(0xFF0D1510);
const _card = Color(0xFF152018);
const _border = Color(0xFF2A4030);
const _accent = Color(0xFF7CFC00);
const _textSecond = Color(0xFF8BAF9A);

class SettingsPage extends StatefulWidget {
  const SettingsPage({super.key});

  @override
  State<SettingsPage> createState() => _SettingsPageState();
}

class _SettingsPageState extends State<SettingsPage> {
  final _normalSniCtrl = TextEditingController();
  final _customSnisCtrl = TextEditingController();

  @override
  void initState() {
    super.initState();
    final s = AppSettings.instance;
    _normalSniCtrl.text = s.cdnNormalSni;
    _customSnisCtrl.text = s.cdnCustomSnis.join('\n');
    // Listen to language changes to rebuild this page too
    AppSettings.languageNotifier.addListener(_onLangChange);
  }

  void _onLangChange() {
    if (mounted) setState(() {});
  }

  @override
  void dispose() {
    AppSettings.languageNotifier.removeListener(_onLangChange);
    _normalSniCtrl.dispose();
    _customSnisCtrl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final st = AppSettings.instance;
    final l = S.t;
    return Scaffold(
      backgroundColor: _bg,
      appBar: AppBar(
        backgroundColor: _card,
        title: Text(l.settings, style: GoogleFonts.inter(fontWeight: FontWeight.w700)),
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          // ── Language ──────────────────────────────────────────
          _section(l.language),
          SegmentedButton<AppLanguage>(
            segments: [
              ButtonSegment(
                value: AppLanguage.fa,
                label: Text('فارسی',
                    style: GoogleFonts.inter(fontWeight: FontWeight.w600)),
              ),
              ButtonSegment(
                value: AppLanguage.en,
                label: Text('English',
                    style: GoogleFonts.inter(fontWeight: FontWeight.w600)),
              ),
            ],
            selected: {st.language},
            onSelectionChanged: (s) async {
              // setLanguage fires languageNotifier → entire app rebuilds
              await st.setLanguage(s.first);
              // setState for this page (notifier listener also does it)
              if (mounted) setState(() {});
            },
          ),
          const SizedBox(height: 20),

          // ── CDN Normal SNI ────────────────────────────────────
          _section('CDN Normal SNI'),
          TextField(
            controller: _normalSniCtrl,
            style: GoogleFonts.robotoMono(color: Colors.white, fontSize: 12),
            decoration: _inputDeco('speed.cloudflare.com or google.com'),
            onSubmitted: (_) => _saveCdn(),
          ),
          const SizedBox(height: 8),
          Text(
            l.isFa(context)
                ? 'اسکن عمیق از پیش‌تنظیم‌های داخلی + لیست شما در پایین استفاده می‌کنه.'
                : 'Deep scan uses built-in presets + your list below.',
            style: GoogleFonts.inter(color: _textSecond, fontSize: 11),
          ),
          const SizedBox(height: 12),

          // ── CDN Deep SNIs ─────────────────────────────────────
          _section(
            l.isFa(context)
                ? 'CDN عمیق — SNI سفارشی (هر خط یکی)'
                : 'CDN Deep — custom SNIs (one per line)',
          ),
          TextField(
            controller: _customSnisCtrl,
            maxLines: 5,
            style: GoogleFonts.robotoMono(color: Colors.white, fontSize: 11),
            decoration: _inputDeco(
              'Optional — merged with: ${kDeepSniPresets.take(3).join(", ")}...',
            ),
          ),
          const SizedBox(height: 16),
          ElevatedButton(
            onPressed: _saveCdn,
            style: ElevatedButton.styleFrom(
              backgroundColor: _accent,
              foregroundColor: Colors.black,
            ),
            child: Text(l.save),
          ),
          const SizedBox(height: 24),

          // ── Telegram ──────────────────────────────────────────
          _section(l.joinTelegram),
          ListTile(
            tileColor: _card,
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(12),
              side: const BorderSide(color: _border),
            ),
            leading: const Icon(Icons.telegram, color: Color(0xFF29B6F6)),
            title: Text('@mmdrlx', style: GoogleFonts.inter(color: _accent)),
            subtitle: Text(
              l.telegramSub,
              style: GoogleFonts.inter(color: _textSecond, fontSize: 11),
            ),
            onTap: () => launchUrl(
              Uri.parse('https://t.me/mmdrlx'),
              mode: LaunchMode.externalApplication,
            ),
          ),
        ],
      ),
    );
  }

  Future<void> _saveCdn() async {
    final st = AppSettings.instance;
    await st.setCdnNormalSni(_normalSniCtrl.text);
    final lines = _customSnisCtrl.text
        .split(RegExp(r'[\n,]+'))
        .map((s) => s.trim())
        .where((s) => s.isNotEmpty)
        .toList();
    await st.setCdnCustomSnis(lines);
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(S.t.saved)),
      );
    }
  }

  Widget _section(String t) => Padding(
        padding: const EdgeInsets.only(bottom: 8),
        child: Text(
          t,
          style: GoogleFonts.inter(
            color: _textSecond,
            fontWeight: FontWeight.w700,
            fontSize: 11,
            letterSpacing: 1,
          ),
        ),
      );

  InputDecoration _inputDeco(String hint) => InputDecoration(
        hintText: hint,
        hintStyle: GoogleFonts.inter(color: _textSecond, fontSize: 11),
        filled: true,
        fillColor: const Color(0xFF1A2A1F),
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(10),
          borderSide: const BorderSide(color: _border),
        ),
      );
}

// Helper extension to avoid passing S.t.fa everywhere
extension _SHelper on S {
  bool isFa(BuildContext context) => fa;
}
