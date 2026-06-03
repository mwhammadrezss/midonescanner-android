// lib/app/l10n.dart
// UI strings — Persian (default) / English.

class L10n {
  final bool fa;
  const L10n(this.fa);

  String t(String en, String faStr) => fa ? faStr : en;

  // App
  String get appTitle => t('MidONe Scanner', 'میدوان اسکنر');
  String get settings => t('Settings', 'تنظیمات');
  String get language => t('Language', 'زبان');
  String get theme => t('Theme', 'تم');
  String get themeForest => t('Forest', 'سبز');
  String get themeDark => t('Dark', 'تیره');
  String get save => t('Save', 'ذخیره');
  String get settingsSaved => t('Settings saved', 'تنظیمات ذخیره شد');
  String get later => t('Later', 'بعداً');
  String get joinChannel => t('Join @mmdrlx', 'جوین به @mmdrlx');
  String get ispChecking => t('Checking operator...', 'در حال بررسی اپراتور...');
  String ispLabel(String name) => fa ? 'اپراتور: $name' : 'ISP: $name';
  String pingLabel(String ms) => fa ? 'پینگ: $ms' : 'Ping: $ms';

  // Tabs
  String get tabCdn => t('CDN', 'CDN');
  String get tabCf => t('CF', 'کلودفلر');
  String get tabRange => t('Range', 'رنج');
  String get tabDns => t('DNS', 'DNS');
  String get tabScan => t('Scan', 'اسکن');
  String get tabResults => t('Results', 'نتایج');

  // CDN
  String get cdnMode => t('CDN MODE', 'حالت CDN');
  String get cdnNormal => t('Normal', 'نورمال');
  String get cdnDeep => t('Deep Scan', 'دیپ اسکن');
  String get cdnNormalSub => t('Full TLS + tunnel test', 'تست کامل TLS و تونل');
  String get cdnDeepSub => t('Multi-SNI deep test', 'تست عمیق چند SNI');
  String get cdnNormalType => t('NORMAL TYPE', 'نوع نورمال');
  String get cdnFast => t('Fast', 'فست');
  String get cdnStandard => t('Thorough', 'عمیق');
  String get cdnFastSub => t('TCP only — very fast', 'فقط TCP — خیلی سریع');
  String get cdnStandardSub => t('Full TLS scan (current)', 'اسکن کامل TLS (فعلی)');
  String get scanMode => t('SCAN MODE', 'حالت اسکن');
  String get tabSubCdn => t('TLS · BW', 'TLS · پهنای باند');
  String get tabSubRange => t('CIDR', 'CIDR');
  String get tabSubDns => t('Best DNS', 'بهترین DNS');
  String get pauseScan => t('Paused...', 'متوقف موقت...');
  String stoppedSoFar(int n) => fa ? 'متوقف شد ($n نتیجه)' : 'Stopped ($n results so far)';
  String get sortLatency => t('Latency', 'تأخیر');
  String get sortScore => t('Score', 'امتیاز');
  String get sortRel => t('Rel', 'پایداری');
  String get sortColo => t('Colo', 'دیتاسنتر');
  String get compact => t('Compact', 'فشرده');
  String get fullView => t('Full', 'کامل');
  String get saveTxt => t('Save TXT', 'ذخیره TXT');
  String get exportJson => t('Export JSON', 'خروجی JSON');
  String get retestFailed => t('Retest ❌', 'تست مجدد ❌');
  String get coloFilterHint => t('Filter datacenter (e.g. FRA)', 'فیلتر دیتاسنتر (مثلاً FRA)');
  String get noResultsYet => t('No results yet.\nGo scan some IPs!', 'هنوز نتیجه‌ای نیست.\nبرو چند IP اسکن کن!');
  String get viewResults => t('View Results', 'مشاهده نتایج');
  String get liveMetrics => t('LIVE METRICS', 'آمار زنده');
  String get dpiKills => t('DPI kills', 'قطع DPI');
  String get okCount => t('OK', 'موفق');
  String get thrCount => t('Throttled', 'محدود');
  String get failCount => t('Failed', 'ناموفق');
  String get eta => t('ETA', 'زمان باقی');
  String get welcomeTitle => t('MidONe Scanner', 'میدوان اسکنر');
  String get welcomeJoin => t('Join our Telegram channel!', 'به کانال تلگرام ما بپیوندید!');
  String get welcomeBody => t(
      'Get the latest updates and fresh IPs on our Telegram channel.',
      'برای دریافت آخرین بروزرسانی و آی‌پی‌های جدید به کانال تلگرام ما جوین بشید.');
  String rangesSelected(int n) => fa ? '$n رنج انتخاب شده' : '$n ranges selected';
  String get customCidrTitle => t('CUSTOM RANGE (CIDR)', 'رنج دستی (CIDR)');
  String get customCidrHint => t('e.g. 2.16.0.0/24 or 2.16.0.0 for one IP', 'مثلاً: 2.16.0.0/24 یا فقط 2.16.0.0 برای یک IP');
  String get cfIpTitle => t('CF IP ADDRESSES', 'آدرس IP کلودفلر');
  String get cfReady => t('Ready to scan Cloudflare IPs...', 'آماده اسکن IP کلودفلر...');
  String get wsOk => t('WS OK', 'WS موفق');
  String get wsFail => t('WS FAIL', 'WS ناموفق');
  String get configOk => t('Config OK', 'تنظیمات OK');
  String get verifyConfig => t('Verify Config', 'بررسی تنظیمات');
  String get sniCfTag => t('Cloudflare', 'کلودفلر');
  String get testMultiplier => t('TEST MULTIPLIER (TLS tries)', 'ضریب تست (تلاش TLS)');
  String get ipAddresses => t('IP ADDRESSES', 'آدرس IP');
  String get paste => t('Paste', 'چسباندن');
  String get clear => t('Clear', 'پاک');
  String get ipHint => t('1.1.1.1\n8.8.8.8\n...', '1.1.1.1\n8.8.8.8\n...');

  // Scan control
  String get startScan => t('START SCAN', 'شروع اسکن');
  String get stopScan => t('STOP', 'توقف');
  String get readyScan => t('Ready to scan...', 'آماده اسکن...');
  String prefiltering(int n) => fa ? 'پیش‌فیلتر $n IP...' : 'Pre-filtering $n IPs...';
  String scanningLive(int n) => fa ? 'در حال اسکن $n IP زنده...' : 'Scanning $n live IPs...';
  String get noTcpLive => fa ? 'هیچ IP زنده‌ای پیدا نشد' : 'No TCP live IPs';
  String scanningPct(int pct) => fa ? 'اسکن $pct%...' : 'Scanning $pct%...';
  String doneUsable(int u, int s) =>
      fa ? 'تمام! $u قابل استفاده از $s اسکن‌شده' : 'Done! $u usable / $s scanned';
  String get doneZero =>
      fa ? 'تمام! 0 نتیجه (Deep یا IP دیگر امتحان کن)' : 'Done! 0 results (try Deep or other IPs)';
  String snackDone(int u, int s) =>
      fa ? 'تمام: $u قابل استفاده از $s اسکن' : 'Done: $u usable / $s scanned';
  String get scanError => fa ? 'خطای اسکن' : 'Scan error';
  String get noValidIps => fa ? 'IP معتبر پیدا نشد!' : 'No valid IPs found!';
  String get tooManyIps => fa ? 'تعداد IP زیاد است! حداکثر ۵۰٬۰۰۰' : 'Too many IPs! Max 50,000';

  // Deep SNI
  String get deepSniTitle => t('Deep Scan — SNI', 'دیپ اسکن — SNI');
  String get sniPresets => t('PRESETS', 'پیش‌فرض');
  String get sniGoogle => t('www.google.com', 'www.google.com');
  String get sniCfSpeed => t('speed.cloudflare.com', 'speed.cloudflare.com');
  String get sniShirTag => t('ShirKhorshid', 'شیرخورشید');
  String get sniCustom => t('CUSTOM SNI', 'SNI دستی');
  String get sniCustomHint => t('Enter SNI host...', 'نام SNI را وارد کن...');
  String get sniAdd => t('Add', 'افزودن');
  String selectedCount(int n) => fa ? '$n انتخاب' : '$n selected';
  String get startDeep => t('Start Deep Scan', 'شروع دیپ اسکن');

  // Range
  String get rangeTitle => t('AKAMAI RANGE', 'رنج Akamai');
  String get rangeFastHint =>
      fa ? 'اسکن TCP سریع — فقط IPهای زنده' : 'Fast TCP scan — live IPs only';
  String get selectRange => t('SELECT RANGE', 'انتخاب رنج');
  String get selectMulti => fa ? 'چند رنج را با هم انتخاب کن' : 'Select multiple ranges';
  String get clearAll => t('Clear all', 'پاک کردن همه');
  String get history => t('History', 'تاریخچه');
  String get loadRanges => fa ? 'در حال بارگذاری رنج‌ها...' : 'Loading ranges...';
  String get tapLoadRanges =>
      fa ? 'رنج‌های Akamai در حال بارگذاری است' : 'Loading Akamai ranges...';
  String get import => t('Import', 'ایمپورت');
  String get export => t('Export', 'اکسپورت');
  String get customCidr => t('CUSTOM CIDR', 'CIDR دستی');
  String get saveRange => t('Save range', 'ذخیره رنج');
  String fastRangeStatus(int n) => fa ? 'اسکن سریع: $n IP' : 'Fast scan: $n IPs';

  // Results
  String get copyTop5 => t('Copy Top 5', 'کپی ۵ تا برتر');
  String get copyAll => t('Copy All', 'کپی همه');
  String get exportFile => t('Export', 'خروجی فایل');
  String get filterAll => t('All', 'همه');
  String get filterExcellent => t('★★★', '★★★');
  String get filterLowRtt => t('<150ms', '<۱۵۰ms');
  String get filterAlive => t('Alive', 'زنده');
  String get noResults => t('No results!', 'نتیجه‌ای نیست!');

  // Misc
  String get devModeOn => t('Dev Mode ON', 'حالت توسعه روشن');
  String get devModeOff => t('Dev Mode OFF', 'حالت توسعه خاموش');
  String get cancelled => t('Cancelled.', 'لغو شد.');
}

/// Deep scan preset SNIs (always available).
const kDeepSniPresetsUi = ['www.google.com', 'speed.cloudflare.com'];
