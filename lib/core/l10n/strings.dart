import '../settings/app_settings.dart';

class S {
  final bool fa;
  const S._(this.fa);

  static S get t => S._(AppSettings.instance.isFa);

  String get appTitle => fa ? 'میدوان اسکنر' : 'MidONe Scanner';
  String get scanMode => fa ? 'حالت اسکن' : 'Scan mode';
  String get cdn => 'CDN';
  String get cf => fa ? 'کلودفلر' : 'Cloudflare';
  String get range => 'Range';
  String get dns => 'DNS';
  String get settings => fa ? 'تنظیمات' : 'Settings';
  String get language => fa ? 'زبان' : 'Language';
  String get startScan => fa ? 'شروع اسکن' : 'Start scan';
  String get stopScan => fa ? 'توقف' : 'Stop';
  String get export => fa ? 'خروجی' : 'Export';
  String get copy => fa ? 'کپی' : 'Copy';
  String get telegramChannel => '@mmdrlx';
  String get joinTelegram => fa ? 'کانال تلگرام' : 'Telegram channel';

  // CF / SenPai
  String get cfSource => fa ? 'منبع IP' : 'Source';
  String get cfRandom => fa ? 'رندوم' : 'Random';
  String get cfFromFile => fa ? 'از فایل' : 'From file';
  String get cfCount => fa ? 'تعداد' : 'Count';
  String get cfWorkers => fa ? 'کارگر' : 'Workers';
  String get cfTimeout => fa ? 'تایم‌اوت' : 'Timeout';
  String get cfPorts => fa ? 'پورت‌ها' : 'Ports';
  String get cfConfigUrl => fa ? 'لینک کانفیگ (vless/trojan)' : 'Config URL';
  String get cfTopN => fa ? 'تعداد برتر Phase 2' : 'Top N (Phase 2)';
  String get cfPhase1 => fa ? 'فاز ۱ — اتصال' : 'Phase 1 — Connectivity';
  String get cfPhase2 => fa ? 'فاز ۲ — xray' : 'Phase 2 — xray';
  String get cfResults => fa ? 'نتایج' : 'Results';
  String get importIps => fa ? 'ایمپورت IP' : 'Import IPs';
}
