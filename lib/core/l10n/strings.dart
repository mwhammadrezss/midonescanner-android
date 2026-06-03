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

  // ── Range Scan Page ─────────────────────────────────────────────────
  String get selectCidr      => fa ? 'انتخاب رنج CIDR'      : 'SELECT CIDR';
  String get scanModeLabel   => fa ? 'حالت اسکن'             : 'SCAN MODE';
  String get scanProfile     => fa ? 'پروفایل اسکن'          : 'SCAN PROFILE';
  String get fastMode        => fa ? 'سریع'                  : 'Fast';
  String get fastModeSub     => fa ? 'TCP فقط · فوق سریع'   : 'TCP only · Ultra fast';
  String get normalScanMode  => fa ? 'عادی'                  : 'Normal';
  String get normalScanSub   => fa ? 'TLS + تونل'            : 'TLS + Tunnel';
  String get deepScanMode    => fa ? 'عمیق'                  : 'Deep';
  String get deepScanModeSub => fa ? 'آنالیز کامل'           : 'Full analysis';
  String get stopLabel       => fa ? 'توقف'                  : 'STOP';
  String get startScanBtn    => fa ? 'شروع اسکن'             : 'START SCAN';
  String get configTab       => fa ? 'تنظیم'                 : 'Config';
  String get resultsTab      => fa ? 'نتایج'                 : 'Results';
  String get cdnProvider     => fa ? 'ارائه‌دهنده CDN'        : 'CDN PROVIDER';
  String get concurrency     => fa ? 'همزمانی'               : 'CONCURRENCY';
  String get selectCidrFirst => fa ? 'ابتدا یک رنج CIDR انتخاب کن' : 'Select a CIDR range first';
  String get scanComplete    => fa ? 'اسکن تمام شد'          : 'Scan complete';
  String get scanErrorMsg    => fa ? 'خطای اسکن'             : 'Scan error';

  // ── Statistics Panel ─────────────────────────────────────────────────
  String get liveStats       => fa ? 'آمار زنده'             : 'LIVE STATS';
  String get probed          => fa ? 'بررسی‌شده'              : 'Probed';
  String get alive           => fa ? 'زنده'                  : 'Alive';
  String get filtered        => fa ? 'فیلتر‌شده'              : 'Filtered';
  String get deep            => fa ? 'عمیق'                  : 'Deep';
  String get rate            => fa ? 'نرخ'                   : 'Rate';
  String get avgTcp          => fa ? 'میانگین TCP'            : 'Avg TCP';
  String get elapsed         => fa ? 'گذشته'                 : 'Elapsed';

  // ── Top IPs Panel ────────────────────────────────────────────────────
  String get topIps          => fa ? 'برترین IP‌ها'           : 'TOP IPs';
  String get copyAll2        => fa ? 'کپی همه'               : 'Copy All';

  // ── Live Results Panel ───────────────────────────────────────────────
  String get noResultsRange  => fa ? 'هنوز نتیجه‌ای نیست.\nاسکن را شروع کن تا IP پیدا بشه.'
                                   : 'No results yet.\nStart scanning to discover IPs.';
  String get copiedIp        => fa ? 'کپی شد'               : 'Copied';

  // ── Range History Page ───────────────────────────────────────────────
  String get rangeHistory    => fa ? 'تاریخچه اسکن رنج'      : 'Range History';
  String get resetHistory    => fa ? 'پاک کردن تاریخچه'      : 'Reset History';
  String get resetHistoryQ   => fa ? 'پاک کردن تاریخچه؟'    : 'Reset History?';
  String get resetHistoryBody => fa
      ? 'همه سشن‌ها و حافظه IP اسکن‌شده پاک می‌شه.\nاسکن بعدی از اول شروع می‌شه.'
      : 'This will clear all session records AND the scanned IP memory.\nNext scan will start fresh from the full IP pool.';
  String get reset           => fa ? 'پاک کن'                : 'Reset';
  String get noHistoryYet    => fa ? 'هنوز تاریخچه‌ای نیست.' : 'No range scan history yet.';
  String get noAliveInSession => fa ? 'هیچ IP زنده‌ای در این سشن پیدا نشد.' : 'No alive IPs found in this session.';
  String get copyTop5Btn     => fa ? 'کپی ۵ تا برتر'        : 'Copy Top 5';
  String get top5CopiedMsg   => fa ? '✓ ۵ تا برتر کپی شد!' : '✓ Top 5 copied!';
  String get collapseBtn     => fa ? 'بستن ▲'               : 'Collapse ▲';
  String get expandBtn       => fa ? 'باز کردن ▼'            : 'Expand ▼';
  String get avgRtt          => fa ? 'میانگین RTT'           : 'Avg RTT';
  String get requested       => fa ? 'درخواست‌شده'            : 'Requested';
  String get scanned         => fa ? 'اسکن‌شده'               : 'Scanned';
  String get aliveLabel      => fa ? '✅ زنده'               : '✅ Alive';
  String get deadLabel       => fa ? '❌ مرده'               : '❌ Dead';
  String get excellentLabel  => fa ? '⭐ عالی'               : '⭐ Excellent';
  String get goodLabel       => fa ? '✓ خوب'                : '✓ Good';
  String get usableLabel     => fa ? '~ قابل استفاده'        : '~ Usable';
  String get weakLabel       => fa ? '↓ ضعیف'               : '↓ Weak';

  // ── main.dart snack messages ─────────────────────────────────────────
  String get noNewIps        => fa ? 'IP جدیدی نیست. به تاریخچه برو → ریست کن.' : 'No new IPs. Go to History → Reset to start fresh.';
  String get noValidIps      => fa ? 'IP معتبری پیدا نشد! ورودی رو بررسی کن.' : 'No valid IPs found! Check your input.';
  String get tooManyIps      => fa ? 'تعداد IP خیلی زیاده' : 'Too many IPs';
  String get retestDone      => fa ? '✓ بررسی مجدد تمام شد!' : '✓ Retest done!';
  String get noFailedIps     => fa ? 'هیچ IP ناموفقی برای بررسی مجدد نیست!' : 'No failed IPs to retest!';
  String get noResultsSnack  => fa ? 'نتیجه‌ای نیست!' : 'No results!';
  String get noAliveSnack    => fa ? 'نتیجه زنده‌ای نیست!' : 'No alive results!';
  String get allCopied       => fa ? '✓ همه IP‌ها کپی شد!' : '✓ All IPs copied!';
  String get noDnsResults    => fa ? 'هنوز نتیجه DNS نیست!' : 'No DNS results yet!';
  String get applyDnsWindows => fa ? 'اعمال DNS فقط روی ویندوز پشتیبانی می‌شه.' : 'Apply DNS is only supported on Windows.';
  String get dnsVpnStopped   => fa ? 'DNS VPN متوقف شد.' : 'DNS VPN stopped.';
  String get enterDns1       => fa ? 'حداقل DNS 1 رو وارد کن' : 'Enter at least DNS 1';
  String get importedIps     => fa ? 'IP وارد شد' : 'Imported';
  String get retestingIp     => fa ? 'بررسی مجدد' : 'Retesting';
  String get failed          => fa ? 'ناموفق' : 'Failed';
  String get configError     => fa ? 'خطای کانفیگ' : 'Config error';
  String get noIpsInFile     => fa ? 'فایل IP خالی است' : 'No IPs in file';
  String get noWorkingEp     => fa ? 'endpoint سالم نیست' : 'No working endpoints';
  String get doneEndpoints   => fa ? 'تمام' : 'Done';
  String get cfSaved         => fa ? 'ذخیره شد' : 'Saved';

}
