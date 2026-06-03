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
  }

  @override
  void dispose() {
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
          _section(l.language),
          SegmentedButton<AppLanguage>(
            segments: [
              ButtonSegment(value: AppLanguage.fa, label: Text(l.fa ? 'فارسی' : 'FA')),
              ButtonSegment(value: AppLanguage.en, label: const Text('English')),
            ],
            selected: {st.language},
            onSelectionChanged: (s) async {
              await st.setLanguage(s.first);
              setState(() {});
            },
          ),
          const SizedBox(height: 20),
          _section('CDN Normal SNI'),
          TextField(
            controller: _normalSniCtrl,
            style: GoogleFonts.robotoMono(color: Colors.white, fontSize: 12),
            decoration: _inputDeco('speed.cloudflare.com or google.com'),
            onSubmitted: (_) => _saveCdn(),
          ),
          const SizedBox(height: 8),
          Text('Deep scan uses built-in presets + your list below.',
              style: GoogleFonts.inter(color: _textSecond, fontSize: 11)),
          const SizedBox(height: 12),
          _section('CDN Deep — custom SNIs (one per line)'),
          TextField(
            controller: _customSnisCtrl,
            maxLines: 5,
            style: GoogleFonts.robotoMono(color: Colors.white, fontSize: 11),
            decoration: _inputDeco('Optional — merged with: ${kDeepSniPresets.take(3).join(", ")}...'),
          ),
          const SizedBox(height: 16),
          ElevatedButton(
            onPressed: _saveCdn,
            style: ElevatedButton.styleFrom(
              backgroundColor: _accent,
              foregroundColor: Colors.black,
            ),
            child: Text(l.fa ? 'ذخیره' : 'Save'),
          ),
          const SizedBox(height: 24),
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
              l.fa ? 'بروزرسانی و IPهای تمیز' : 'Updates & clean IPs',
              style: GoogleFonts.inter(color: _textSecond, fontSize: 11),
            ),
            onTap: () => launchUrl(Uri.parse('https://t.me/mmdrlx'),
                mode: LaunchMode.externalApplication),
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
        SnackBar(content: Text(S.t.fa ? 'ذخیره شد' : 'Saved')),
      );
    }
  }

  Widget _section(String t) => Padding(
        padding: const EdgeInsets.only(bottom: 8),
        child: Text(t,
            style: GoogleFonts.inter(
                color: _textSecond, fontWeight: FontWeight.w700, fontSize: 11, letterSpacing: 1)),
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
