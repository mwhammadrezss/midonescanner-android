import threading, socket, ssl, time, re, statistics, os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
sys.path.insert(0, '.')
from MidONeScanner import (CDN_MAP, CFG, is_private, detect_cdn,
    stage_tls, stage_reliability, stage_bandwidth, calc_score)

from kivy.app import App
from kivy.uix.screenmanager import ScreenManager, Screen, FadeTransition
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.scrollview import ScrollView
from kivy.uix.gridlayout import GridLayout
from kivy.uix.modalview import ModalView
from kivy.clock import Clock
from kivy.core.clipboard import Clipboard
from kivy.core.window import Window
from kivy.graphics import Color, RoundedRectangle, Line, Rectangle, Ellipse
from kivy.metrics import dp

# ═══ THEME (INCY dark green) ═══
BG    = (0.03, 0.08, 0.03, 1)
CARD  = (0.06, 0.14, 0.06, 1)
GREEN = (0.20, 0.72, 0.20, 1)
LGREE = (0.65, 0.90, 0.65, 1)
DIM   = (0.28, 0.50, 0.28, 1)
TEXT  = (0.82, 0.95, 0.82, 1)
GOLD  = (0.80, 1.00, 0.40, 1)

FLAG  = '.midone_joined'

def mark_joined():
    try: open(FLAG, 'w').close()
    except: pass

def is_joined():
    return os.path.exists(FLAG)

def mk_btn(text, bg=None, fg=None, h=50):
    b = Button(
        text=text,
        background_normal='', background_color=(0,0,0,0),
        color=fg or TEXT, font_size=dp(15), bold=True,
        size_hint_y=None, height=dp(h),
    )
    _bg = bg or GREEN
    with b.canvas.before:
        Color(*_bg)
        b._rr = RoundedRectangle(pos=b.pos, size=b.size, radius=[dp(14)])
    def upd(i,v): i._rr.pos=i.pos; i._rr.size=i.size
    b.bind(pos=upd, size=upd)
    return b

def set_bg(widget, color):
    with widget.canvas.before:
        Color(*color)
        r = Rectangle(pos=widget.pos, size=widget.size)
    widget.bind(pos=lambda i,v: setattr(r,'pos',v),
                size=lambda i,v: setattr(r,'size',v))


# ══════════════════════════════════════
#  TELEGRAM POPUP
# ══════════════════════════════════════
class TelegramPopup(ModalView):
    def __init__(self, **kw):
        super().__init__(
            size_hint=(0.88, None), height=dp(260),
            background_color=(0,0,0,0.75), auto_dismiss=False, **kw
        )
        with self.canvas.before:
            Color(*CARD)
            self._r = RoundedRectangle(pos=self.pos, size=self.size, radius=[dp(20)])
        self.bind(pos=lambda i,v: setattr(self._r,'pos',v),
                  size=lambda i,v: setattr(self._r,'size',v))

        root = BoxLayout(orientation='vertical', padding=dp(22), spacing=dp(12))

        root.add_widget(Label(
            text='[b][color=33cc33]✈  کانال سازنده[/color][/b]',
            markup=True, font_size=dp(19), size_hint_y=None, height=dp(38),
        ))
        root.add_widget(Label(
            text='برای دریافت آخرین آپدیت برنامه\nو IP‌های بروز و زنده، به کانال\nتلگرامی سازنده بپیوندید 🦁',
            font_size=dp(14), color=TEXT, halign='center',
            size_hint_y=None, height=dp(80),
        ))

        btn_join = mk_btn('✈   Join @mmdrlx', bg=GREEN, fg=BG, h=48)
        btn_join.bind(on_press=self._join)
        root.add_widget(btn_join)

        btn_skip = Button(
            text='بعداً',
            background_normal='', background_color=(0,0,0,0),
            color=DIM, font_size=dp(13),
            size_hint_y=None, height=dp(34),
        )
        btn_skip.bind(on_press=lambda x: self.dismiss())
        root.add_widget(btn_skip)
        self.add_widget(root)

    def _join(self, *a):
        mark_joined()
        try:
            import webbrowser
            webbrowser.open('https://t.me/mmdrlx')
        except: pass
        self.dismiss()


# ══════════════════════════════════════
#  HOME SCREEN
# ══════════════════════════════════════
class HomeScreen(Screen):
    def __init__(self, **kw):
        super().__init__(**kw)
        self.ips = []
        self._build()

    def _build(self):
        set_bg(self, BG)
        root = BoxLayout(orientation='vertical', padding=[dp(16), dp(10), dp(16), dp(12)], spacing=dp(10))

        # ── Header ──────────────────────────────
        hdr = BoxLayout(size_hint_y=None, height=dp(50))
        title_lbl = Label(
            text='[b]MidONe[/b]',
            markup=True, font_size=dp(22), color=LGREE,
            halign='left', valign='center', size_hint_x=0.45,
        )
        title_lbl.bind(size=title_lbl.setter('text_size'))
        ver_lbl = Label(
            text='[color=33cc33]v1.0.2[/color]',
            markup=True, font_size=dp(13), color=DIM,
            halign='left', valign='center', size_hint_x=0.35,
        )
        ver_lbl.bind(size=ver_lbl.setter('text_size'))
        tg_btn = Button(
            text='✈', font_size=dp(24),
            size_hint=(None, None), size=(dp(46), dp(46)),
            background_normal='', background_color=(0,0,0,0),
            color=GREEN,
        )
        tg_btn.bind(on_press=self._open_tg)
        hdr.add_widget(title_lbl)
        hdr.add_widget(ver_lbl)
        hdr.add_widget(tg_btn)
        root.add_widget(hdr)

        # ── Circle IP area ───────────────────────
        circle_wrap = FloatLayout(size_hint_y=None, height=dp(270))
        with circle_wrap.canvas.before:
            Color(0.05, 0.12, 0.05, 1)
            Ellipse(pos=(dp(28), dp(5)), size=(dp(260), dp(258)))
            Color(*GREEN)
            Line(ellipse=(dp(28), dp(5), dp(260), dp(258)), width=dp(1.8))

        lbl_enter = Label(
            text='[color=33cc33]Enter IPs[/color]',
            markup=True, font_size=dp(11), color=DIM,
            size_hint=(None, None), size=(dp(180), dp(18)),
            pos_hint={'center_x': 0.5, 'top': 0.95},
        )
        self.ip_input = TextInput(
            hint_text='1.2.3.4\n5.6.7.8\n...',
            hint_text_color=(*DIM[:3], 0.5),
            background_color=(0, 0, 0, 0),
            foreground_color=TEXT,
            cursor_color=GREEN,
            font_size=dp(13),
            size_hint=(None, None), size=(dp(228), dp(198)),
            pos_hint={'center_x': 0.5, 'center_y': 0.50},
            multiline=True,
        )
        self.count_lbl = Label(
            text='',
            markup=True, font_size=dp(12), color=GREEN,
            size_hint=(None, None), size=(dp(240), dp(22)),
            pos_hint={'center_x': 0.5, 'y': 0.03},
        )
        circle_wrap.add_widget(lbl_enter)
        circle_wrap.add_widget(self.ip_input)
        circle_wrap.add_widget(self.count_lbl)
        root.add_widget(circle_wrap)

        # ── Paste + Load ─────────────────────────
        row1 = BoxLayout(size_hint_y=None, height=dp(50), spacing=dp(10))
        btn_paste = mk_btn('📋  Paste', bg=(0.08, 0.20, 0.08, 1), fg=LGREE)
        btn_paste.bind(on_press=self._paste)
        btn_load = mk_btn('⬇  Load IPs', bg=GREEN, fg=BG)
        btn_load.bind(on_press=self._load)
        row1.add_widget(btn_paste)
        row1.add_widget(btn_load)
        root.add_widget(row1)

        # ── Mode row (hidden until load) ─────────
        self.mode_wrap = BoxLayout(orientation='vertical', spacing=dp(8), size_hint_y=None, height=0, opacity=0)

        row2 = BoxLayout(size_hint_y=None, height=dp(50), spacing=dp(10))
        btn_m1 = mk_btn('⚡  Normal Scan', bg=(0.10, 0.30, 0.10, 1), fg=LGREE)
        btn_m1.bind(on_press=lambda x: self._start(1))
        btn_m2 = mk_btn('🧠  Deep Scan', bg=(0.05, 0.18, 0.05, 1), fg=GREEN)
        btn_m2.bind(on_press=lambda x: self._start(2))
        row2.add_widget(btn_m1)
        row2.add_widget(btn_m2)
        self.mode_wrap.add_widget(row2)
        root.add_widget(self.mode_wrap)

        root.add_widget(Label())  # spacer
        self.add_widget(root)

        if not is_joined():
            Clock.schedule_once(lambda dt: TelegramPopup().open(), 0.9)

    def _open_tg(self, *a):
        try:
            import webbrowser
            webbrowser.open('https://t.me/mmdrlx')
        except: pass

    def _paste(self, *a):
        try:
            txt = Clipboard.paste()
            if txt:
                cur = self.ip_input.text
                self.ip_input.text = (cur + '\n' + txt) if cur else txt
        except: pass

    def _load(self, *a):
        raw = self.ip_input.text
        found = list(set(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', raw)))
        self.ips = [ip for ip in found if not is_private(ip)]
        if not self.ips:
            self.count_lbl.text = '[color=ff5555]❌ No valid IPs![/color]'
            return
        self.count_lbl.text = f'[color=33cc33][b]✓ {len(self.ips)} IPs loaded[/b][/color]'
        self.mode_wrap.opacity = 1
        self.mode_wrap.height = dp(58)

    def _start(self, mode):
        if not self.ips:
            self._load(None)
            if not self.ips: return
        self.manager.get_screen('scan').start(self.ips, mode)
        self.manager.current = 'scan'


# ══════════════════════════════════════
#  SCAN SCREEN
# ══════════════════════════════════════
class ScanScreen(Screen):
    def __init__(self, **kw):
        super().__init__(**kw)
        self._scanning = False
        self._results  = []
        self._build()

    def _build(self):
        set_bg(self, BG)
        root = BoxLayout(orientation='vertical', padding=[dp(16), dp(10), dp(16), dp(12)], spacing=dp(8))

        # Header
        hdr = BoxLayout(size_hint_y=None, height=dp(50))
        hdr.add_widget(Label(
            text='[b]MidONe[/b]  [size=13][color=33cc33]Scanning...[/color][/size]',
            markup=True, font_size=dp(20), color=LGREE,
            halign='left', valign='center',
        ))
        root.add_widget(hdr)

        # Status card
        status_card = BoxLayout(orientation='vertical',
            size_hint_y=None, height=dp(68),
            padding=[dp(14), dp(8)], spacing=dp(4))
        with status_card.canvas.before:
            Color(*CARD)
            self._sc = RoundedRectangle(pos=status_card.pos, size=status_card.size, radius=[dp(14)])
        status_card.bind(pos=lambda i,v: setattr(self._sc,'pos',v),
                         size=lambda i,v: setattr(self._sc,'size',v))

        self.status_lbl = Label(
            text='Initializing...', markup=True,
            font_size=dp(14), color=GREEN,
            size_hint_y=None, height=dp(28),
            halign='left', valign='center',
        )
        self.status_lbl.bind(size=self.status_lbl.setter('text_size'))
        self.prog_lbl = Label(
            text='', markup=True,
            font_size=dp(12), color=DIM,
            size_hint_y=None, height=dp(22),
            halign='left', valign='center',
        )
        self.prog_lbl.bind(size=self.prog_lbl.setter('text_size'))
        status_card.add_widget(self.status_lbl)
        status_card.add_widget(self.prog_lbl)
        root.add_widget(status_card)

        # Live output
        scroll = ScrollView()
        self.live = GridLayout(cols=1, size_hint_y=None, spacing=dp(2), padding=[0, dp(4)])
        self.live.bind(minimum_height=self.live.setter('height'))
        scroll.add_widget(self.live)
        root.add_widget(scroll)

        btn_stop = mk_btn('■  Stop Scan', bg=(0.22, 0.06, 0.06, 1), fg=(1, 0.55, 0.55, 1), h=48)
        btn_stop.bind(on_press=self._stop)
        root.add_widget(btn_stop)
        self.add_widget(root)

    def _upd_status(self, txt):
        def _d(dt): self.status_lbl.text = txt
        Clock.schedule_once(_d)

    def _upd_prog(self, txt):
        def _d(dt): self.prog_lbl.text = txt
        Clock.schedule_once(_d)

    def _add(self, txt):
        def _d(dt):
            lbl = Label(
                text=txt, markup=True,
                size_hint_y=None, height=dp(22),
                font_size=dp(11), color=TEXT,
                halign='left', valign='middle',
                text_size=(Window.width - dp(32), None),
            )
            self.live.add_widget(lbl)
        Clock.schedule_once(_d)

    def _stop(self, *a):
        self._scanning = False

    def start(self, ips, mode):
        self._scanning = True
        self._results  = []
        self.live.clear_widgets()
        label = 'Normal Scan' if mode == 1 else 'Deep Scan'
        self._upd_status(f'[b]{label}[/b] — {len(ips)} IPs')
        self._upd_prog('Starting...')
        threading.Thread(target=self._run, args=(ips, mode), daemon=True).start()

    def _run(self, ips, mode):
        if mode == 1: self._mode1(ips)
        else:         self._mode2(ips)
        self._finish()

    def _mode1(self, ips):
        sni, done = 'google.com', [0]
        def test(ip):
            if not self._scanning: return None
            ok, _ = stage_tls(ip, sni)
            if not ok: return None
            bw = stage_bandwidth(ip, sni, '/')
            if bw['ok']:
                sc  = calc_score(bw['speed'], bw['latency'], bw['jitter'], bw['throttled'])
                col = '33cc33' if bw['speed']>200 else ('a5d6a7' if bw['speed']>80 else '66bb6a')
                thr = '  [color=ff5555][THR][/color]' if bw['throttled'] else ''
                self._add(f"[color={col}]▸ {ip:<17}  {bw['speed']:>7.1f} KB/s  {bw['latency']}ms  ✦{sc}[/color]{thr}")
                return {'ip':ip,'sni':sni,'speed':bw['speed'],'latency':bw['latency'],
                        'jitter':bw['jitter'],'throttled':bw['throttled'],
                        'throttle_pct':bw.get('throttle_pct',0),'score':sc}
        with ThreadPoolExecutor(max_workers=CFG['threads']) as ex:
            for f in as_completed({ex.submit(test,ip): ip for ip in ips}):
                if not self._scanning: break
                r = f.result()
                if r: self._results.append(r)
                done[0] += 1
                self._upd_prog(f'[color=33cc33]{done[0]}/{len(ips)}[/color]  ·  [color=a5d6a7]{len(self._results)} passed[/color]')

    def _mode2(self, ips):
        done = [0]
        def pipeline(ip):
            if not self._scanning: return []
            res, cdn_name, ordered_snis = [], *detect_cdn(ip),
            cdn_ep = CDN_MAP.get(cdn_name,{}).get('endpoint','/')
            valid = []
            for sni in ordered_snis:
                if not self._scanning: break
                ok, _ = stage_tls(ip, sni)
                if not ok: continue
                reliable, rel_count, _ = stage_reliability(ip, sni)
                if reliable: valid.append((sni, rel_count))
            for sni, rel_count in valid:
                if not self._scanning: break
                bw = stage_bandwidth(ip, sni, cdn_ep)
                if bw['ok']:
                    sc  = calc_score(bw['speed'],bw['latency'],bw['jitter'],bw['throttled'],rel_count)
                    col = '33cc33' if bw['speed']>200 else ('a5d6a7' if bw['speed']>80 else '66bb6a')
                    thr = '  [color=ff5555][THR][/color]' if bw['throttled'] else ''
                    self._add(f"[color={col}]▸ {ip:<16} {sni:<22} {bw['speed']:>6.1f} KB/s ✦{sc}[/color]{thr}")
                    res.append({'ip':ip,'sni':sni,'cdn':cdn_name,'speed':bw['speed'],
                                'latency':bw['latency'],'jitter':bw['jitter'],
                                'throttled':bw['throttled'],'throttle_pct':bw.get('throttle_pct',0),
                                'reliability':rel_count,'score':sc})
            return res
        with ThreadPoolExecutor(max_workers=CFG['threads']) as ex:
            for f in as_completed({ex.submit(pipeline,ip): ip for ip in ips}):
                if not self._scanning: break
                self._results.extend(f.result())
                done[0] += 1
                self._upd_prog(f'[color=33cc33]{done[0]}/{len(ips)}[/color]  ·  [color=a5d6a7]{len(self._results)} passed[/color]')

    def _finish(self):
        self._scanning = False
        self._results.sort(key=lambda x: x['score'], reverse=True)
        rs = self.manager.get_screen('result')
        rs.show(self._results)
        Clock.schedule_once(lambda dt: setattr(self.manager,'current','result'), 0.4)


# ══════════════════════════════════════
#  RESULT SCREEN
# ══════════════════════════════════════
class ResultScreen(Screen):
    def __init__(self, **kw):
        super().__init__(**kw)
        self._results = []
        self._build()

    def _build(self):
        set_bg(self, BG)
        root = BoxLayout(orientation='vertical', padding=[dp(16),dp(10),dp(16),dp(12)], spacing=dp(8))

        # Header
        hdr = BoxLayout(size_hint_y=None, height=dp(50))
        back = Button(
            text='←', font_size=dp(22),
            size_hint=(None,None), size=(dp(44),dp(44)),
            background_normal='', background_color=(0,0,0,0),
            color=GREEN,
        )
        back.bind(on_press=lambda x: setattr(self.manager,'current','home'))
        self.hdr_lbl = Label(
            text='[b]Results[/b]',
            markup=True, font_size=dp(19), color=LGREE,
            halign='left', valign='center',
        )
        self.hdr_lbl.bind(size=self.hdr_lbl.setter('text_size'))
        hdr.add_widget(back)
        hdr.add_widget(self.hdr_lbl)
        root.add_widget(hdr)

        # Summary card
        summ = BoxLayout(size_hint_y=None, height=dp(36), padding=[dp(12),0])
        with summ.canvas.before:
            Color(*CARD)
            self._sc2 = RoundedRectangle(pos=summ.pos, size=summ.size, radius=[dp(10)])
        summ.bind(pos=lambda i,v: setattr(self._sc2,'pos',v),
                  size=lambda i,v: setattr(self._sc2,'size',v))
        self.sum_lbl = Label(text='', markup=True, font_size=dp(13), color=GREEN,
                             halign='left', valign='center')
        self.sum_lbl.bind(size=self.sum_lbl.setter('text_size'))
        summ.add_widget(self.sum_lbl)
        root.add_widget(summ)

        # Results list
        scroll = ScrollView()
        self.list_out = GridLayout(cols=1, size_hint_y=None, spacing=dp(3), padding=[0,dp(4)])
        self.list_out.bind(minimum_height=self.list_out.setter('height'))
        scroll.add_widget(self.list_out)
        root.add_widget(scroll)

        # Copy buttons row 1
        r1 = BoxLayout(size_hint_y=None, height=dp(48), spacing=dp(8))
        ba = mk_btn('Copy All', bg=(0.07,0.20,0.07,1), fg=GREEN, h=48)
        ba.bind(on_press=lambda x: self._copy(0))
        b10 = mk_btn('Copy 10 Best', bg=GREEN, fg=BG, h=48)
        b10.bind(on_press=lambda x: self._copy(10))
        r1.add_widget(ba); r1.add_widget(b10)
        root.add_widget(r1)

        # Copy buttons row 2
        r2 = BoxLayout(size_hint_y=None, height=dp(48), spacing=dp(8))
        b3 = mk_btn('Copy 3 Best', bg=(0.14,0.42,0.14,1), fg=BG, h=48)
        b3.bind(on_press=lambda x: self._copy(3))
        bsv = mk_btn('Save File', bg=(0.05,0.12,0.05,1), fg=DIM, h=48)
        bsv.bind(on_press=self._save)
        r2.add_widget(b3); r2.add_widget(bsv)
        root.add_widget(r2)

        self.toast = Label(text='', markup=True, font_size=dp(13), color=GOLD,
                           size_hint_y=None, height=dp(26))
        root.add_widget(self.toast)
        self.add_widget(root)

    def show(self, results):
        self._results = results
        def _do(dt):
            self.list_out.clear_widgets()
            clean = [r for r in results if not r['throttled']]
            self.sum_lbl.text = (
                f'[color=33cc33][b]{len(results)} passed[/b][/color]'
                f'  ·  [color=a5d6a7]{len(clean)} clean[/color]'
            )
            for i, r in enumerate(results, 1):
                col = '33cc33' if r['speed']>200 else ('a5d6a7' if r['speed']>80 else '66bb6a')
                thr = '  [color=ff5555][THR][/color]' if r['throttled'] else ''
                row = Label(
                    text=f"[color={col}][b]{i}.[/b]  {r['ip']:<17}  {r['speed']:>7.1f} KB/s  ✦{r['score']}[/color]{thr}",
                    markup=True,
                    size_hint_y=None, height=dp(26),
                    font_size=dp(12), color=TEXT,
                    halign='left', valign='middle',
                    text_size=(Window.width - dp(32), None),
                )
                self.list_out.add_widget(row)
        Clock.schedule_once(_do)

    def _copy(self, n):
        clean = [r for r in self._results if not r['throttled']]
        pool  = clean if clean else self._results
        target = pool[:n] if n > 0 else pool
        Clipboard.copy('\n'.join(r['ip'] for r in target))
        lbl = f'Copied {len(target)} IPs ✓'
        def _do(dt): self.toast.text = f'[color=a5d6a7]{lbl}[/color]'
        Clock.schedule_once(_do)
        Clock.schedule_once(lambda dt: setattr(self.toast,'text',''), 2.5)

    def _save(self, *a):
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        fn = f'scan_{ts}.txt'
        try:
            with open(fn,'w',encoding='utf-8') as f:
                f.write('MidONe Scanner SK | t.me/mmdrlx\n\n')
                for i,r in enumerate(self._results,1):
                    f.write(f"{i}. {r['ip']}  SNI:{r.get('sni','')}  {r['speed']} KB/s  Score:{r['score']}\n")
            def _do(dt): self.toast.text = f'[color=a5d6a7]✓ Saved: {fn}[/color]'
            Clock.schedule_once(_do)
        except:
            Clock.schedule_once(lambda dt: setattr(self.toast,'text','[color=ff5555]Save failed[/color]'), 0)


# ══════════════════════════════════════
#  APP
# ══════════════════════════════════════
class MidOneApp(App):
    def build(self):
        Window.clearcolor = BG
        sm = ScreenManager(transition=FadeTransition(duration=0.22))
        sm.add_widget(HomeScreen(name='home'))
        sm.add_widget(ScanScreen(name='scan'))
        sm.add_widget(ResultScreen(name='result'))
        return sm

if __name__ == '__main__':
    MidOneApp().run()
