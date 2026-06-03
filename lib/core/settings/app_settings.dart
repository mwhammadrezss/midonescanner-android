import 'package:shared_preferences/shared_preferences.dart';

enum AppLanguage { fa, en }

class AppSettings {
  AppSettings._();
  static final instance = AppSettings._();

  static const _keyLang = 'app_lang';
  static const _keyNormalSni = 'cdn_normal_sni';
  static const _keyCustomSnis = 'cdn_custom_snis';

  AppLanguage language = AppLanguage.fa;
  String cdnNormalSni = 'speed.cloudflare.com';
  List<String> cdnCustomSnis = [];

  Future<void> load() async {
    final p = await SharedPreferences.getInstance();
    final lang = p.getString(_keyLang);
    if (lang == 'en') language = AppLanguage.en;
    cdnNormalSni = p.getString(_keyNormalSni) ?? 'speed.cloudflare.com';
    cdnCustomSnis = p.getStringList(_keyCustomSnis) ?? [];
  }

  Future<void> setLanguage(AppLanguage lang) async {
    language = lang;
    final p = await SharedPreferences.getInstance();
    await p.setString(_keyLang, lang == AppLanguage.en ? 'en' : 'fa');
  }

  Future<void> setCdnNormalSni(String sni) async {
    cdnNormalSni = sni.trim().isEmpty ? 'speed.cloudflare.com' : sni.trim();
    final p = await SharedPreferences.getInstance();
    await p.setString(_keyNormalSni, cdnNormalSni);
  }

  Future<void> setCdnCustomSnis(List<String> snis) async {
    cdnCustomSnis = snis.map((s) => s.trim()).where((s) => s.isNotEmpty).toList();
    final p = await SharedPreferences.getInstance();
    await p.setStringList(_keyCustomSnis, cdnCustomSnis);
  }

  bool get isFa => language == AppLanguage.fa;
}
