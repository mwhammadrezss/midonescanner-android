import '../settings/app_settings.dart';

class S {
  final bool fa;
  const S._(this.fa);

  static S get t => S._(AppSettings.instance.isFa);

  // ── App ──────────────────────────────────────────────────────
  String get appTitle        => fa ? 'میدوان اسکنر'          : 'MidONe Scanner';
  String get settings        => fa ? 'تنظیمات'               : 'Settings';
  String get language        => fa ? 'زبان'                  : 'Language';
  String get save            => fa ? 'ذخیره'                 : 'Save';
  String get saved           => fa ? 'ذخیره شد'              : 'Saved';
  String get cancel          => fa ? 'لغو'                   : 'Cancel';
  String get close           => fa ? 'بستن'                  : 'Close';
  String get copy            => fa ? 'کپی'                   : 'Copy';
  String get copied          => fa ? 'کپی شد'                : 'Copied';
  String get export          => fa ? 'خروجی'                 : 'Export';
  String get retest          => fa ? 'بررسی مجدد'            : 'Retest';
  String get error           => fa ? 'خطا'                   : 'Error';

  // ── Navigation ───────────────────────────────────────────────
  String get scanner         => fa ? 'اسکنر'                 : 'Scanner';
  String get results         => fa ? 'نتایج'                 : 'Results';

  // ── Scan Modes ───────────────────────────────────────────────
  String get scanMode        => fa ? 'حالت اسکن'             : 'Scan mode';
  String get cdn             => 'CDN';
  String get cf              => fa ? 'کلودفلر'               : 'Cloudflare';
  String get range           => 'Range';
  String get dns             => 'DNS';

  String get cdnModeSub      => fa ? 'TLS · پهنای باند'       : 'TLS · BW';
  String get cfModeSub       => fa ? 'کلودفلر'               : 'Cloudflare';
  String get rangeModeSub    => 'CIDR';
  String get dnsModeSub      => fa ? 'بهترین DNS'            : 'Best DNS';

  // ── CDN Sub-modes ────────────────────────────────────────────
  String get cdnMode         => fa ? 'حالت CDN'              : 'CDN MODE';
  String get normalMode      => fa ? 'عادی'                  : 'Normal';
  String get normalModeSub   => fa ? 'سریع · آزمون BW'       : 'Fast · BW test';
  String get deepScan        => fa ? 'اسکن عمیق'             : 'Deep Scan';
  String get deepScanSub     => fa ? 'چند-SNI · ۵ بررسی'    : 'Multi-SNI · 5 probes';

  // ── IP Input ─────────────────────────────────────────────────
  String get ipAddresses     => fa ? 'آدرس‌های IP'           : 'IP ADDRESSES';
  String get paste           => fa ? 'چسباندن'               : 'Paste';
  String get clear           => fa ? 'پاک‌کردن'              : 'Clear';

  // ── Scan Controls ────────────────────────────────────────────
  String get startScan       => fa ? 'شروع اسکن'             : 'Start scan';
  String get stopScan        => fa ? 'توقف'                  : 'Stop';
  String get pauseScan       => fa ? 'مکث'                   : 'Pause';
  String get resumeScan      => fa ? 'ادامه'                 : 'Resume';

  // ── Progress / Status ────────────────────────────────────────
  String get readyToScan     => fa ? 'آماده برای اسکن...'   : 'Ready to scan...';
  String get preFiltering    => fa ? 'پیش‌فیلتر'             : 'Pre-filtering';
  String get scanning        => fa ? 'در حال اسکن'           : 'Scanning';
  String get paused          => fa ? 'متوقف...'              : 'Paused...';
  String get resumed         => fa ? 'ادامه یافت...'         : 'Resumed...';
  String get liveMetrics     => fa ? 'معیارهای زنده'         : 'LIVE METRICS';

  // ── Results ──────────────────────────────────────────────────
  String get noResults       => fa ? 'هنوز نتیجه‌ای نیست.\nبرو اسکن کن!'
                                   : 'No results yet.\nGo scan some IPs!';
  String get copyTop5        => fa ? 'کپی ۵ تا برتر'        : 'Copy Top 5';
  String get copyAll         => fa ? 'کپی همه'               : 'Copy All';
  String get saveTxt         => fa ? 'ذخیره TXT'             : 'Save TXT';
  String get exportJson      => fa ? 'خروجی JSON'            : 'Export JSON';
  String get retestFailed    => fa ? 'بررسی مجدد ❌'         : 'Retest ❌';
  String get viewResults     => fa ? 'مشاهده نتایج'          : 'View Results';
  String get filterByColo    => fa ? 'فیلتر بر اساس دیتاسنتر' : 'Filter by datacenter';

  // ── Range Tab ────────────────────────────────────────────────
  String get akamaiRange     => fa ? 'اسکن رنج آکامای'      : 'AKAMAI RANGE SCAN';
  String get selectRange     => fa ? 'انتخاب رنج'            : 'SELECT RANGE';
  String get customRange     => fa ? 'رنج سفارشی (CIDR)'    : 'CUSTOM RANGE (CIDR)';
  String get savedRanges     => fa ? 'رنج‌های ذخیره‌شده'      : 'SAVED RANGES';
  String get history         => fa ? 'تاریخچه'               : 'History';
  String get importLabel     => fa ? 'وارد کردن'             : 'Import';
  String get exportLabel     => fa ? 'خروج'                  : 'Export';
  String get saveRange       => fa ? 'ذخیره این رنج'         : 'Save this range';
  String get multiSelect     => fa ? 'چند تا رو با هم انتخاب کن' : 'Select multiple ranges';
  String get akamaiSubtitle  => fa ? 'TCP سریع :443 — نمونه‌گیری بی‌محدود آکامای'
                                   : 'Fast TCP :443 — unlimited Akamai sampling';

  // ── CF / SenPai ──────────────────────────────────────────────
  String get cfSource        => fa ? 'منبع IP'               : 'Source';
  String get cfRandom        => fa ? 'رندوم'                 : 'Random';
  String get cfFromFile      => fa ? 'از فایل'               : 'From file';
  String get cfCount         => fa ? 'تعداد'                 : 'Count';
  String get cfWorkers       => fa ? 'کارگر'                 : 'Workers';
  String get cfTimeout       => fa ? 'تایم‌اوت'              : 'Timeout';
  String get cfPorts         => fa ? 'پورت‌ها'               : 'Ports';
  String get cfConfigUrl     => fa ? 'لینک کانفیگ (vless/trojan)' : 'Config URL';
  String get cfTopN          => fa ? 'تعداد برتر Phase 2'    : 'Top N (Phase 2)';
  String get cfPhase1        => fa ? 'فاز ۱ — اتصال'        : 'Phase 1 — Connectivity';
  String get cfPhase2        => fa ? 'فاز ۲ — xray'         : 'Phase 2 — xray';
  String get cfResults       => fa ? 'نتایج'                 : 'Results';
  String get importIps       => fa ? 'ایمپورت IP'            : 'Import IPs';

  // ── DNS Tab ──────────────────────────────────────────────────
  String get startDnsScan    => fa ? 'شروع اسکن DNS'        : 'Start DNS Scan';
  String get topDnsServers   => fa ? 'بهترین سرورهای DNS'   : 'Top DNS Servers';
  String get noResultsFound  => fa ? 'نتیجه‌ای یافت نشد.'   : 'No results found.';
  String get startDnsHint    => fa ? 'روی «شروع اسکن DNS» بزن\nتا بهترین DNS شبکه‌ات پیدا بشه.'
                                   : 'Tap "Start DNS Scan" to find\nthe best DNS servers on your network.';
  String get applyDns        => fa ? 'اعمال DNS'             : 'APPLY DNS';

  // ── Settings ─────────────────────────────────────────────────
  String get joinTelegram    => fa ? 'کانال تلگرام'          : 'Telegram channel';
  String get telegramChannel => '@mmdrlx';
  String get telegramSub     => fa ? 'بروزرسانی و IPهای تمیز' : 'Updates & clean IPs';
  String get cdnNormalSniLabel => fa ? 'SNI عادی CDN'        : 'CDN Normal SNI';
  String get cdnDeepSniLabel => fa ? 'SNI عمیق CDN (هر خط یکی)' : 'CDN Deep — custom SNIs (one per line)';

  // ── Dev Mode ─────────────────────────────────────────────────
  String get devModeOn       => fa ? '🔧 حالت توسعه روشن'   : '🔧 Dev Mode ON';
  String get devModeOff      => fa ? '🔧 حالت توسعه خاموش'  : '🔧 Dev Mode OFF';

  // ── Welcome Dialog ───────────────────────────────────────────
  String get welcomeTitle    => fa ? 'به کانال تلگرام ما بپیوندید!' : 'Join our Telegram!';
  String get welcomeBody     => fa ? 'برای دریافت آخرین بروزرسانی و آی‌پی‌های جدید به کانال تلگرام ما جوین بشید.'
                                   : 'Join our Telegram channel for the latest updates and new IPs.';
  String get joinBtn         => fa ? 'جوین به @mmdrlx'       : 'Join @mmdrlx';
  String get later           => fa ? 'بعداً'                 : 'Later';

  // ── Snackbar messages ────────────────────────────────────────
  String get noAliveResults  => fa ? 'نتیجه زنده‌ای نیست!'  : 'No alive results!';
  String get noResults2      => fa ? 'نتیجه‌ای نیست!'        : 'No results!';
  String get top5Copied      => fa ? '✓ ۵ تا برتر کپی شد!' : '✓ Top 5 copied!';
  String get scanDone        => fa ? 'اسکن تمام شد'         : 'Done!';

  // ── Sort / Filter Labels ─────────────────────────────────────
  String get sortLatency     => fa ? 'تأخیر'                 : 'Latency';
  String get sortScore       => fa ? 'امتیاز'                : 'Score';
  String get sortReliability => fa ? 'پایداری'               : 'Rel';
  String get sortColo        => 'Colo';
  String get filterAll       => fa ? 'همه'                   : 'All';
  String get filterAlive     => fa ? 'زنده'                  : 'Alive';
  String get filterCompact   => fa ? 'فشرده'                 : 'Compact';
  String get filterFull      => fa ? 'کامل'                  : 'Full';

  // ── Persian Language Label ───────────────────────────────────
  String get faLabel         => 'فارسی';
  String get enLabel         => 'English';
}
