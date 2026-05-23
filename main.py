# -*- coding: utf-8 -*-
import re
import json
import threading
import time
import socket
import ssl
import statistics
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from kivy.utils import platform
from kivy.app import App

if platform == 'android':
    try:
        from android.permissions import request_permissions, Permission
        request_permissions([
            Permission.INTERNET,
            Permission.ACCESS_NETWORK_STATE,
        ])
    except Exception:
        pass

from kivy.lang import Builder
from kivy.uix.screenmanager import ScreenManager, Screen, FadeTransition
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.behaviors import ButtonBehavior
from kivy.uix.label import Label
from kivy.properties import StringProperty, NumericProperty, ListProperty, BooleanProperty
from kivy.core.window import Window
from kivy.core.clipboard import Clipboard
from kivy.clock import Clock
from kivy.animation import Animation
from kivy.storage.jsonstore import JsonStore

Window.size = (400, 750)

# ═══ REAL SCANNER ENGINE ═══

CDN_MAP = {
    "Cloudflare": {
        "headers":  ["cf-ray","cf-cache-status","cf-request-id"],
        "server":   ["cloudflare"],
        "snis":     ["speed.cloudflare.com","cloudflare.com"],
        "endpoint": "/__down?bytes=8000000",
    },
    "Akamai": {
        "headers":  ["x-check-cacheable","x-serial","x-true-cache-key","akamai-origin-hop"],
        "server":   ["akamaighost","akamai"],
        "snis":     ["a248.e.akamai.net","a77.net.akamai.net","a104.net.akamai.net",
                     "a184.net.akamai.net","ds-aksb.akamaized.net","ak.net.akamaized.net"],
        "endpoint": "/",
    },
    "Google": {
        "headers":  ["x-goog-generation","x-guploader-uploadid","x-goog-hash"],
        "server":   ["gws","google frontend","esf","sffe"],
        "snis":     ["fonts.googleapis.com","google.com","www.google.com"],
        "endpoint": "/",
    },
    "Amazon": {
        "headers":  ["x-amz-cf-id","x-amz-cf-pop","x-amz-request-id"],
        "server":   ["amazons3","cloudfront"],
        "snis":     ["d1.cloudfront.net","aws.amazon.com"],
        "endpoint": "/",
    },
    "Azure": {
        "headers":  ["x-azure-ref","x-msedge-ref","x-ec-custom-error"],
        "server":   ["microsoft-azure","ecd"],
        "snis":     ["ajax.aspnetcdn.com"],
        "endpoint": "/",
    },
    "Fastly": {
        "headers":  ["x-served-by","x-fastly-request-id","x-cache-hits"],
        "server":   ["varnish"],
        "snis":     ["global.fastly.net"],
        "endpoint": "/",
    },
    "Iranian": {
        "headers":  [],
        "server":   [],
        "snis":     ["aparat.com","snapp.ir","digikala.com",
                     "telewebion.com","varzesh3.com","bmi.ir"],
        "endpoint": "/",
    },
}

ALL_SNIS = []
for _v in CDN_MAP.values():
    for _s in _v["snis"]:
        if _s not in ALL_SNIS:
            ALL_SNIS.append(_s)

CFG = {
    "threads":            20,
    "connect_timeout":    2.5,
    "tls_timeout":        3.0,
    "read_timeout":       5.0,
    "test_duration":      5.0,
    "min_bytes":          4096,
    "throttle_threshold": 0.40,
    "reliability_tries":  5,
    "reliability_min":    3,
}

PRIVATE = [r'^10\.', r'^192\.168\.', r'^172\.(1[6-9]|2\d|3[01])\.',
           r'^127\.', r'^0\.', r'^169\.254\.']

def is_private(ip):
    return any(re.match(p, ip) for p in PRIVATE)

def ssl_connect(ip, sni, timeout=3.0):
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, 443))
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ss = ctx.wrap_socket(sock, server_hostname=sni)
        return ss, sock
    except:
        if sock:
            try: sock.close()
            except: pass
        return None, None

def detect_cdn(ip):
    for probe in ["aparat.com","a248.e.akamai.net","speed.cloudflare.com"]:
        ss, sock = ssl_connect(ip, probe, CFG["connect_timeout"])
        if not ss: continue
        try:
            ss.sendall(
                f"HEAD / HTTP/1.1\r\nHost: {probe}\r\n"
                f"User-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n".encode()
            )
            buf = b""
            ss.settimeout(2.0)
            try:
                while len(buf) < 1024:
                    c = ss.recv(256)
                    if not c: break
                    buf += c
                    if b"\r\n\r\n" in buf: break
            except: pass
            hdrs = buf.decode(errors="ignore").lower()
            srv = ""
            for line in hdrs.split("\r\n"):
                if line.startswith("server:"):
                    srv = line.split(":",1)[1].strip(); break
            for name, info in CDN_MAP.items():
                if name == "Iranian": continue
                if any(h in hdrs for h in info["headers"]):
                    return name, info["snis"]+[s for s in ALL_SNIS if s not in info["snis"]]
                if any(sv in srv for sv in info["server"]):
                    return name, info["snis"]+[s for s in ALL_SNIS if s not in info["snis"]]
        except: pass
        finally:
            try: ss.close()
            except: pass
            try: sock.close()
            except: pass
    return "Unknown", ALL_SNIS

def stage_tls(ip, sni):
    ss = None; sock = None
    try:
        t = time.time()
        ss, sock = ssl_connect(ip, sni, CFG["tls_timeout"])
        if not ss: return False, 9999
        hs = round((time.time()-t)*1000)
        ss.sendall(
            f"HEAD / HTTP/1.1\r\nHost: {sni}\r\n"
            f"User-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n".encode()
        )
        buf = b""
        ss.settimeout(2.0)
        try:
            while len(buf) < 512:
                c = ss.recv(256)
                if not c: break
                buf += c
                if b"HTTP/" in buf: break
        except: pass
        if buf and b"HTTP/" in buf: return True, hs
        if hs < CFG["tls_timeout"]*900: return True, hs
    except: pass
    finally:
        try: ss.close()
        except: pass
        try: sock.close()
        except: pass
    return False, 9999

def stage_reliability(ip, sni):
    success, lats = 0, []
    for _ in range(CFG["reliability_tries"]):
        ok, ms = stage_tls(ip, sni)
        if ok:
            success += 1
            lats.append(ms)
        time.sleep(0.1)
    return success >= CFG["reliability_min"], success, \
           round(statistics.mean(lats)) if lats else 9999

def stage_bandwidth(ip, sni, endpoint="/"):
    ss = None; sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(CFG["connect_timeout"])
        sock.connect((ip, 443))
        sock.settimeout(CFG["read_timeout"])
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ss = ctx.wrap_socket(sock, server_hostname=sni)
        ss.sendall(
            f"GET {endpoint} HTTP/1.1\r\nHost: {sni}\r\n"
            f"User-Agent: Mozilla/5.0\r\nAccept: */*\r\n"
            f"Connection: close\r\n\r\n".encode()
        )
        start=time.time(); total=0; first_byte=None; samples=[]; last_t=start
        while True:
            try:
                chunk = ss.recv(65536)
                if not chunk: break
                now = time.time()
                if first_byte is None: first_byte = now-start
                total += len(chunk)
                if now-last_t >= 1.0:
                    samples.append((total/1024)/max(now-start,0.001))
                    last_t = now
                if now-start > CFG["test_duration"]: break
            except: break
        elapsed = time.time()-start
        if elapsed > 0 and total >= CFG["min_bytes"]:
            speed = (total/1024)/elapsed
            latency = round((first_byte or 0)*1000)
            jitter = round(statistics.stdev(samples),1) if len(samples)>1 else 0
            throttled=False; throttle_pct=0
            if len(samples) >= 3:
                mid = len(samples)//2
                f_avg = statistics.mean(samples[:mid])
                s_avg = statistics.mean(samples[mid:])
                if f_avg > 0:
                    drop = (f_avg-s_avg)/f_avg
                    throttle_pct = round(drop*100)
                    throttled = drop > CFG["throttle_threshold"]
            return {"speed":round(speed,1),"latency":latency,"jitter":jitter,
                    "throttled":throttled,"throttle_pct":throttle_pct,"ok":True}
    except: pass
    finally:
        if ss:
            try: ss.close()
            except: pass
        if sock:
            try: sock.close()
            except: pass
    return {"ok":False}

def calc_score(speed, latency, jitter, throttled, reliability=5):
    s   = min(speed/500,1.0)*55
    l   = max(0,1-latency/800)*20
    j   = max(0,1-jitter/max(speed,1))*10
    t   = 0 if throttled else 5
    rel = (reliability/CFG["reliability_tries"])*10
    return round(s+l+j+t+rel,1)

def scan_ip_normal(ip):
    """Normal scan: TLS + bandwidth with google.com SNI"""
    sni = "google.com"
    ok, latency = stage_tls(ip, sni)
    if not ok:
        return None
    bw = stage_bandwidth(ip, sni, "/")
    if bw["ok"]:
        sc = calc_score(bw["speed"], bw["latency"], bw["jitter"], bw["throttled"])
        thr = " [THR]" if bw["throttled"] else ""
        return {
            "ip": ip,
            "sni": sni,
            "speed": bw["speed"],
            "latency": bw["latency"],
            "score": sc,
            "throttled": bw["throttled"],
            "ping": f"{bw['latency']}ms | {bw['speed']:.0f} KB/s{thr}",
            "val": sc,
            "status": "THR" if bw["throttled"] else "Clean",
        }
    return None

def scan_ip_deep(ip):
    """Deep scan: CDN detection + reliability + bandwidth"""
    cdn_name, ordered_snis = detect_cdn(ip)
    cdn_ep = CDN_MAP.get(cdn_name, {}).get("endpoint", "/")
    best = None
    for sni in ordered_snis[:4]:
        ok, _ = stage_tls(ip, sni)
        if not ok: continue
        reliable, rel_count, _ = stage_reliability(ip, sni)
        if not reliable: continue
        bw = stage_bandwidth(ip, sni, cdn_ep)
        if bw["ok"]:
            sc = calc_score(bw["speed"], bw["latency"], bw["jitter"], bw["throttled"], rel_count)
            thr = " [THR]" if bw["throttled"] else ""
            r = {
                "ip": ip,
                "sni": sni,
                "cdn": cdn_name,
                "speed": bw["speed"],
                "latency": bw["latency"],
                "score": sc,
                "throttled": bw["throttled"],
                "ping": f"{bw['latency']}ms | {bw['speed']:.0f} KB/s{thr}",
                "val": sc,
                "status": "THR" if bw["throttled"] else "Clean",
            }
            if best is None or sc > best["score"]:
                best = r
    return best

def retest_ip(ip, sni="google.com"):
    """Quick retest for a single IP"""
    ok, latency = stage_tls(ip, sni)
    if not ok:
        return None, 9999
    bw = stage_bandwidth(ip, sni, "/")
    if bw["ok"]:
        return f"{bw['latency']}ms | {bw['speed']:.0f} KB/s", bw["latency"]
    return None, 9999


# ═══ KV DESIGN ═══

KV_DESIGN = '''
#:import Window kivy.core.window.Window

<IconButton@ButtonBehavior+BoxLayout>:
    padding: [dp(4), dp(4)]

<NeonButton@ButtonBehavior+Label>:
    text_color: [1, 1, 1, 1]
    bg_color: [0.62, 1.0, 0.0, 1]
    font_name: "Roboto"
    bold: True
    canvas.before:
        Color:
            rgba: self.bg_color if self.state == 'normal' else [0.5, 0.8, 0.0, 1]
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [22, ]

<DarkCard@BoxLayout>:
    orientation: 'vertical'
    padding: dp(16)
    spacing: dp(12)
    canvas.before:
        Color:
            rgba: [0.08, 0.08, 0.08, 1]
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [24, ]
        Color:
            rgba: [0.62, 1.0, 0.0, 0.3]
        Line:
            rounded_rectangle: (self.x, self.y, self.width, self.height, 24)
            width: dp(1)

<IPItem@BoxLayout>:
    ip_text: ''
    ping_text: ''
    status_text: 'Clean'
    on_retest: None
    orientation: 'horizontal'
    padding: [dp(12), dp(8)]
    spacing: dp(10)
    size_hint_y: None
    height: dp(60)
    canvas.before:
        Color:
            rgba: [0.08, 0.08, 0.08, 1]
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [14, ]
        Color:
            rgba: [0.62, 1.0, 0.0, 0.15]
        Line:
            rounded_rectangle: (self.x, self.y, self.width, self.height, 14)
            width: dp(1)

    Label:
        text: root.ip_text
        color: [1, 1, 1, 1]
        bold: True
        font_size: '14sp'
        halign: 'left'
        text_size: self.size
        valign: 'middle'
        padding_x: dp(5)

    Label:
        text: root.ping_text
        color: [0.62, 1.0, 0.0, 1]
        font_size: '12sp'
        size_hint_x: None
        width: dp(110)
        valign: 'middle'
        halign: 'right'

    BoxLayout:
        size_hint_x: None
        width: dp(55)
        padding: [dp(4), dp(6)]
        canvas.before:
            Color:
                rgba: [0, 0.4, 0, 0.2]
            RoundedRectangle:
                pos: self.pos
                size: self.size
                radius: [8, ]
        Label:
            text: root.status_text
            color: [0.4, 1, 0.4, 1]
            font_size: '10sp'
            bold: True

    IconButton:
        size_hint_x: None
        width: dp(36)
        on_release: if root.on_retest: root.on_retest(root.ip_text)
        canvas.before:
            Color:
                rgba: [0.15, 0.15, 0.15, 1]
            RoundedRectangle:
                pos: self.pos
                size: self.size
                radius: [10, ]
        Label:
            text: "↻"
            color: [0.62, 1.0, 0.0, 1]
            font_size: '18sp'
            bold: True


ScreenManager:
    transition: FadeTransition(duration=0.3)
    HomeScreen:
    ScanningScreen:
    ResultsScreen:

<HomeScreen>:
    name: 'home'
    canvas.before:
        Color:
            rgba: [0.046, 0.046, 0.046, 1]
        Rectangle:
            pos: self.pos
            size: self.size

    BoxLayout:
        orientation: 'vertical'
        padding: dp(20)
        spacing: dp(15)

        BoxLayout:
            size_hint_y: None
            height: dp(60)
            orientation: 'horizontal'
            valign: 'middle'

            BoxLayout:
                orientation: 'vertical'
                size_hint_x: 0.7
                Label:
                    text: "MidONe"
                    font_size: '22sp'
                    bold: True
                    color: [1, 1, 1, 1]
                    halign: 'left'
                    text_size: self.size
                Label:
                    text: "v1.0.2"
                    font_size: '13sp'
                    color: [0.62, 1.0, 0.0, 1]
                    halign: 'left'
                    text_size: self.size

            IconButton:
                size_hint: (None, None)
                size: (dp(40), dp(40))
                pos_hint: {'center_y': 0.5}
                on_release: root.show_history_popup()
                canvas.before:
                    Color:
                        rgba: [0.08, 0.08, 0.08, 1]
                    RoundedRectangle:
                        pos: self.pos
                        size: self.size
                        radius: [12, ]
                Label:
                    text: "🕒"
                    font_size: '18sp'

            Widget:
                size_hint_x: None
                width: dp(10)

            IconButton:
                size_hint: (None, None)
                size: (dp(40), dp(40))
                pos_hint: {'center_y': 0.5}
                on_release: root.open_telegram()
                canvas.before:
                    Color:
                        rgba: [0.08, 0.08, 0.08, 1]
                    RoundedRectangle:
                        pos: self.pos
                        size: self.size
                        radius: [12, ]
                Label:
                    text: "✈"
                    font_size: '18sp'
                    color: [0.62, 1.0, 0.0, 1]

        BoxLayout:
            size_hint_y: None
            height: dp(35)
            padding: [dp(12), 0]
            canvas.before:
                Color:
                    rgba: [0.08, 0.08, 0.08, 1]
                RoundedRectangle:
                    pos: self.pos
                    size: self.size
                    radius: [10, ]
            Label:
                text: root.connection_status
                color: [0.7, 0.7, 0.7, 1]
                font_size: '12sp'
                halign: 'left'
                text_size: self.size
                valign: 'middle'
            Label:
                text: root.ping_status
                color: [0.62, 1.0, 0.0, 1]
                font_size: '12sp'
                bold: True
                halign: 'right'
                text_size: self.size
                valign: 'middle'

        Widget:
            size_hint_y: None
            height: dp(10)

        DarkCard:
            Label:
                text: "Enter IPs Below:"
                font_size: '15sp'
                color: [1, 1, 1, 1]
                bold: True
                size_hint_y: None
                height: dp(20)
                halign: 'left'
                text_size: self.size

            TextInput:
                id: ip_input
                hint_text: "1.2.3.4\\n5.6.7.8\\n..."
                hint_text_color: [0.4, 0.4, 0.4, 1]
                background_color: [0.05, 0.05, 0.05, 1]
                foreground_color: [1, 1, 1, 1]
                cursor_color: [0.62, 1.0, 0.0, 1]
                font_size: '16sp'
                padding: dp(12)
                multiline: True
                size_hint_y: 1
                background_normal: ''
                background_active: ''
                canvas.after:
                    Color:
                        rgba: [0.62, 1.0, 0.0, 0.5] if self.focus else [0.2, 0.2, 0.2, 1]
                    Line:
                        rounded_rectangle: (self.x, self.y, self.width, self.height, 12)
                        width: dp(1.2)

            Label:
                text: root.loaded_count_text
                font_size: '13sp'
                color: [0.62, 1.0, 0.0, 1]
                bold: True
                size_hint_y: None
                height: dp(20)
                halign: 'center'

        BoxLayout:
            size_hint_y: None
            height: dp(50)
            spacing: dp(15)

            NeonButton:
                text: "Paste"
                bg_color: [0.08, 0.22, 0.05, 1]
                text_color: [0.62, 1.0, 0.0, 1]
                on_release: root.perform_smart_paste()
                canvas.after:
                    Color:
                        rgba: [0.62, 1.0, 0.0, 0.4]
                    Line:
                        rounded_rectangle: (self.x, self.y, self.width, self.height, 22)
                        width: dp(1)

            NeonButton:
                text: "Load IPs"
                bg_color: [0.62, 1.0, 0.0, 1]
                on_release: root.load_ips()

        Widget:
            size_hint_y: None
            height: dp(10)

        BoxLayout:
            size_hint_y: None
            height: dp(55)
            spacing: dp(15)

            NeonButton:
                text: "Normal Scan"
                bg_color: [0.1, 0.1, 0.1, 1]
                on_release: root.start_scan(mode="normal")
                canvas.after:
                    Color:
                        rgba: [0.62, 1.0, 0.0, 0.6]
                    Line:
                        rounded_rectangle: (self.x, self.y, self.width, self.height, 22)
                        width: dp(1.5)

            NeonButton:
                text: "Deep Scan"
                bg_color: [0.62, 1.0, 0.0, 1]
                on_release: root.start_scan(mode="deep")

        Widget:
            size_hint_y: 0.1

    BoxLayout:
        id: promo_popup
        orientation: 'vertical'
        pos_hint: {'x': 0, 'y': 0}
        size_hint: (1, 1)
        opacity: 0
        disabled: True
        canvas.before:
            Color:
                rgba: [0, 0, 0, 0.85]
            Rectangle:
                pos: self.pos
                size: self.size

        BoxLayout:
            orientation: 'vertical'
            size_hint: (0.85, None)
            height: dp(260)
            pos_hint: {'center_x': 0.5, 'center_y': 0.5}
            padding: dp(24)
            spacing: dp(20)
            canvas.before:
                Color:
                    rgba: [0.08, 0.08, 0.08, 1]
                RoundedRectangle:
                    pos: self.pos
                    size: self.size
                    radius: [24, ]
                Color:
                    rgba: [0.62, 1.0, 0.0, 1]
                Line:
                    rounded_rectangle: (self.x, self.y, self.width, self.height, 24)
                    width: dp(2)

            Label:
                text: "کانال تلگرام سازنده"
                font_size: '18sp'
                bold: True
                color: [0.62, 1.0, 0.0, 1]
                halign: 'center'

            Label:
                text: "برای دریافت آخرین آپدیت برنامه و IPهای به روزرسانی شده، سالم و زنده به کانال تلگرامی ما بپیوندید."
                font_size: '14sp'
                color: [1, 1, 1, 1]
                halign: 'center'
                valign: 'middle'
                text_size: (self.width - dp(10), None)

            NeonButton:
                text: "Join @mmdrlx"
                size_hint_y: None
                height: dp(45)
                on_release: root.close_promo_popup(join=True)

            NeonButton:
                text: "بعدا"
                size_hint_y: None
                height: dp(35)
                bg_color: [0.2, 0.2, 0.2, 1]
                on_release: root.close_promo_popup(join=False)

    BoxLayout:
        id: history_popup
        orientation: 'vertical'
        size_hint: (1, 1)
        opacity: 0
        disabled: True
        canvas.before:
            Color:
                rgba: [0, 0, 0, 0.7]
            Rectangle:
                pos: self.pos
                size: self.size
        IconButton:
            size_hint_y: 0.6
            on_release: root.hide_history_popup()
        BoxLayout:
            orientation: 'vertical'
            size_hint_y: 0.4
            padding: dp(20)
            spacing: dp(12)
            canvas.before:
                Color:
                    rgba: [0.08, 0.08, 0.08, 1]
                RoundedRectangle:
                    pos: self.pos
                    size: self.size
                    radius: [24, 24, 0, 0]
            Label:
                text: "Last Best IPs (History)"
                font_size: '15sp'
                bold: True
                color: [0.62, 1.0, 0.0, 1]
                size_hint_y: None
                height: dp(25)
            Label:
                id: history_content
                text: "No history found."
                color: [0.9, 0.9, 0.9, 1]
                font_size: '14sp'
                halign: 'center'
            NeonButton:
                text: "Close"
                size_hint_y: None
                height: dp(40)
                bg_color: [0.2, 0.2, 0.2, 1]
                on_release: root.hide_history_popup()


<ScanningScreen>:
    name: 'scanning'
    canvas.before:
        Color:
            rgba: [0.046, 0.046, 0.046, 1]
        Rectangle:
            pos: self.pos
            size: self.size

    BoxLayout:
        orientation: 'vertical'
        padding: dp(30)
        spacing: dp(20)

        Widget:
            size_hint_y: 0.1

        BoxLayout:
            id: radar_box
            size_hint: (None, None)
            size: (dp(180), dp(180))
            pos_hint: {'center_x': 0.5}
            canvas.before:
                Color:
                    rgba: [0.08, 0.08, 0.08, 1]
                Ellipse:
                    pos: self.pos
                    size: self.size
                Color:
                    rgba: [0.62, 1.0, 0.0, 0.2]
                Line:
                    circle: (self.center_x, self.center_y, dp(90))
                    width: dp(2)
                Line:
                    circle: (self.center_x, self.center_y, dp(50))
                    width: dp(1)
            canvas.after:
                Color:
                    rgba: [0.62, 1.0, 0.0, 0.8]
                Line:
                    points: [self.x, root.scan_line_y, self.right, root.scan_line_y] if root.scan_line_y > 0 else [self.x, self.y, self.x, self.y]
                    width: dp(2.5)

        Label:
            text: str(int(root.progress_percent)) + "%"
            font_size: '38sp'
            bold: True
            color: [0.62, 1.0, 0.0, 1]
            size_hint_y: None
            height: dp(45)

        Label:
            text: root.current_status_text
            font_size: '13sp'
            color: [1, 1, 1, 1]
            halign: 'center'
            size_hint_y: None
            height: dp(40)

        Label:
            text: root.found_count_text
            font_size: '14sp'
            bold: True
            color: [0.62, 1.0, 0.0, 1]
            size_hint_y: None
            height: dp(28)

        Widget:
            size_hint_y: 0.2

        NeonButton:
            text: "Stop Scan"
            size_hint_y: None
            height: dp(48)
            bg_color: [0.3, 0.06, 0.06, 1]
            on_release: root.stop_scan()


<ResultsScreen>:
    name: 'results'
    canvas.before:
        Color:
            rgba: [0.046, 0.046, 0.046, 1]
        Rectangle:
            pos: self.pos
            size: self.size

    BoxLayout:
        orientation: 'vertical'
        padding: dp(16)
        spacing: dp(12)

        BoxLayout:
            size_hint_y: None
            height: dp(50)
            orientation: 'horizontal'
            Label:
                text: "Scan Results"
                font_size: '18sp'
                bold: True
                color: [1, 1, 1, 1]
                halign: 'left'
                text_size: self.size
                valign: 'middle'
            Label:
                text: root.clean_summary_text
                font_size: '13sp'
                bold: True
                color: [0.4, 1, 0.4, 1]
                halign: 'right'
                text_size: self.size
                valign: 'middle'

        ScrollView:
            size_hint_y: 1
            BoxLayout:
                id: results_container
                orientation: 'vertical'
                spacing: dp(10)
                size_hint_y: None
                height: self.minimum_height

        BoxLayout:
            size_hint_y: None
            height: dp(45)
            spacing: dp(10)

            NeonButton:
                text: "Copy All"
                bg_color: [0.08, 0.08, 0.08, 1]
                on_release: root.copy_results("all")
                canvas.after:
                    Color:
                        rgba: [0.62, 1.0, 0.0, 0.5]
                    Line:
                        rounded_rectangle: (self.x, self.y, self.width, self.height, 22)
                        width: dp(1)

            NeonButton:
                text: "Copy 10 Best"
                bg_color: [0.62, 1.0, 0.0, 1]
                on_release: root.copy_results("10")

        BoxLayout:
            size_hint_y: None
            height: dp(45)
            spacing: dp(10)

            NeonButton:
                text: "Copy 3 Best"
                bg_color: [0.08, 0.22, 0.05, 1]
                text_color: [0.62, 1.0, 0.0, 1]
                on_release: root.copy_results("3")
                canvas.after:
                    Color:
                        rgba: [0.62, 1.0, 0.0, 0.4]
                    Line:
                        rounded_rectangle: (self.x, self.y, self.width, self.height, 22)
                        width: dp(1)

            NeonButton:
                text: "Share"
                bg_color: [0.1, 0.1, 0.1, 1]
                on_release: root.quick_share_results()
                canvas.after:
                    Color:
                        rgba: [1, 1, 1, 0.2]
                    Line:
                        rounded_rectangle: (self.x, self.y, self.width, self.height, 22)
                        width: dp(1)

        NeonButton:
            text: "Back"
            size_hint_y: None
            height: dp(48)
            bg_color: [0.2, 0.2, 0.2, 1]
            on_release: root.go_back_home()
'''


class HomeScreen(Screen):
    connection_status = StringProperty("Ready to scan")
    ping_status = StringProperty("")
    loaded_count_text = StringProperty("No IPs loaded yet")
    valid_ips = ListProperty([])

    def __init__(self, **kwargs):  # ✅ bug fixed: **kwargs
        super(HomeScreen, self).__init__(**kwargs)
        Clock.schedule_once(self.check_first_run, 0.5)

    def check_first_run(self, dt):
        try:
            store = JsonStore('midone_config.json')
            if not store.exists('settings') or not store.get('settings').get('promo_shown', False):
                self.show_promo_popup()
        except:
            self.show_promo_popup()

    def show_promo_popup(self):
        self.ids.promo_popup.disabled = False
        Animation(opacity=1, duration=0.4).start(self.ids.promo_popup)

    def close_promo_popup(self, join=False):
        if join:
            self.open_telegram()
        try:
            store = JsonStore('midone_config.json')
            store.put('settings', promo_shown=True)
        except: pass
        anim = Animation(opacity=0, duration=0.3)
        anim.bind(on_complete=lambda *a: setattr(self.ids.promo_popup, 'disabled', True))
        anim.start(self.ids.promo_popup)

    def open_telegram(self):
        try:
            import webbrowser
            webbrowser.open("https://t.me/mmdrlx")
        except: pass

    def perform_smart_paste(self):
        try:
            clipboard_text = Clipboard.paste()
            if clipboard_text:
                cleaned = self.validate_and_extract_ips(clipboard_text)
                if cleaned:
                    self.ids.ip_input.text = "\n".join(cleaned)
                    self.valid_ips = cleaned
                    self.loaded_count_text = f"{len(cleaned)} IPs loaded from clipboard"
                else:
                    self.loaded_count_text = "No valid IPs in clipboard"
            else:
                self.loaded_count_text = "Clipboard is empty"
        except Exception as e:
            self.loaded_count_text = "Paste failed"

    def load_ips(self):
        input_text = self.ids.ip_input.text
        cleaned = self.validate_and_extract_ips(input_text)
        self.valid_ips = cleaned
        if cleaned:
            self.loaded_count_text = f"{len(cleaned)} IPs loaded — choose scan mode"
        else:
            self.loaded_count_text = "No valid IPs found"

    def validate_and_extract_ips(self, text):
        ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        found = re.findall(ipv4_pattern, text)
        # Filter private IPs
        public = [ip for ip in found if not is_private(ip)]
        return list(set(public))

    def start_scan(self, mode="normal"):
        if not self.valid_ips:
            self.load_ips()
            if not self.valid_ips:
                return
        sm = self.manager
        scanning_scr = sm.get_screen('scanning')
        scanning_scr.prepare_and_launch_scan(self.valid_ips, mode)
        sm.current = 'scanning'

    def show_history_popup(self):
        try:
            store = JsonStore('midone_history.json')
            if store.exists('cache'):
                ips = store.get('cache').get('best_ips', [])
                if ips:
                    self.ids.history_content.text = "\n".join([f"  {ip}" for ip in ips])
                else:
                    self.ids.history_content.text = "No history yet."
            else:
                self.ids.history_content.text = "No previous scans."
        except:
            self.ids.history_content.text = "No history."
        self.ids.history_popup.disabled = False
        Animation(opacity=1, duration=0.3).start(self.ids.history_popup)

    def hide_history_popup(self):
        anim = Animation(opacity=0, duration=0.2)
        anim.bind(on_complete=lambda *a: setattr(self.ids.history_popup, 'disabled', True))
        anim.start(self.ids.history_popup)


class ScanningScreen(Screen):
    scan_line_y = NumericProperty(0)
    progress_percent = NumericProperty(0)
    current_status_text = StringProperty("Initializing...")
    found_count_text = StringProperty("")
    _stop_flag = False

    def prepare_and_launch_scan(self, ips, mode):
        self.ips_to_scan = ips
        self.scan_mode = mode
        self.progress_percent = 0
        self.scan_line_y = 0
        self.found_count_text = ""
        self._stop_flag = False
        self.start_radar_animation()
        threading.Thread(target=self.run_scanning_engine, daemon=True).start()

    def start_radar_animation(self):
        box = self.ids.radar_box
        self.scan_line_y = box.y
        anim = (Animation(scan_line_y=box.top, duration=1.2, t='in_out_quad') +
                Animation(scan_line_y=box.y, duration=1.2, t='in_out_quad'))
        anim.repeat = True
        self.active_radar_anim = anim
        anim.start(self)

    def stop_scan(self):
        self._stop_flag = True
        self.current_status_text = "Stopping..."

    def run_scanning_engine(self):
        total = len(self.ips_to_scan)
        results = []
        done = [0]

        def update_ui(ip, idx):
            self.progress_percent = ((idx + 1) / total) * 100
            mode_label = "Normal" if self.scan_mode == "normal" else "Deep"
            self.current_status_text = f"{mode_label}: {idx+1}/{total}\n{ip}"
            self.found_count_text = f"Found: {len(results)} IPs"

        if self.scan_mode == "normal":
            def test(ip):
                if self._stop_flag: return None
                return scan_ip_normal(ip)
            with ThreadPoolExecutor(max_workers=CFG["threads"]) as ex:
                futs = {ex.submit(test, ip): ip for ip in self.ips_to_scan}
                for f in as_completed(futs):
                    if self._stop_flag: break
                    r = f.result()
                    if r: results.append(r)
                    done[0] += 1
                    ip = futs[f]
                    Clock.schedule_once(lambda dt, i=ip, d=done[0]: update_ui(i, d-1))
        else:
            def test_deep(ip):
                if self._stop_flag: return None
                return scan_ip_deep(ip)
            with ThreadPoolExecutor(max_workers=max(1, CFG["threads"]//2)) as ex:
                futs = {ex.submit(test_deep, ip): ip for ip in self.ips_to_scan}
                for f in as_completed(futs):
                    if self._stop_flag: break
                    r = f.result()
                    if r: results.append(r)
                    done[0] += 1
                    ip = futs[f]
                    Clock.schedule_once(lambda dt, i=ip, d=done[0]: update_ui(i, d-1))

        results.sort(key=lambda x: x["score"], reverse=True)
        self.trigger_alert_vibration()
        Clock.schedule_once(lambda dt: self.finalize_scan_results(results), 0.2)

    def trigger_alert_vibration(self):
        try:
            from plyer import vibrator
            vibrator.vibrate(0.15)
        except: pass

    def finalize_scan_results(self, results):
        if hasattr(self, 'active_radar_anim'):
            self.active_radar_anim.cancel(self)
        sm = self.manager
        res_screen = sm.get_screen('results')
        res_screen.render_results_view(results)
        sm.current = 'results'


class ResultsScreen(Screen):
    clean_summary_text = StringProperty("0 Clean")
    raw_results_list = []

    def render_results_view(self, results):
        self.raw_results_list = results
        container = self.ids.results_container
        container.clear_widgets()

        clean = [r for r in results if not r.get("throttled", False)]
        self.clean_summary_text = f"{len(results)} Passed | {len(clean)} Clean"

        # Save top 5 to history
        try:
            top_5 = [item['ip'] for item in results[:5]]
            store = JsonStore('midone_history.json')
            store.put('cache', best_ips=top_5)
        except: pass

        for item in results:
            item_widget = Builder.load_string(f'''
IPItem:
    ip_text: "{item['ip']}"
    ping_text: "{item['ping']}"
    status_text: "{'THR' if item.get('throttled') else 'Clean'}"
    on_retest: app.root.get_screen('results').retest_single_row
''')
            container.add_widget(item_widget)

    def retest_single_row(self, ip_address):
        # Find the widget and retest with real scanner
        for widget in self.ids.results_container.children:
            if hasattr(widget, 'ip_text') and widget.ip_text == ip_address:
                widget.ping_text = "Testing..."

                def async_retest(w=widget, ip=ip_address):
                    # Find SNI from results
                    sni = "google.com"
                    for r in self.raw_results_list:
                        if r['ip'] == ip:
                            sni = r.get('sni', 'google.com')
                            break
                    result, _ = retest_ip(ip, sni)
                    def update_ui(dt):
                        if result:
                            w.ping_text = result
                            w.status_text = "OK"
                        else:
                            w.ping_text = "Failed"
                            w.status_text = "Fail"
                    Clock.schedule_once(update_ui)

                threading.Thread(target=async_retest, daemon=True).start()
                break

    def copy_results(self, mode):
        if not self.raw_results_list: return
        if mode == "all":
            selected = [item['ip'] for item in self.raw_results_list]
        elif mode == "10":
            selected = [item['ip'] for item in self.raw_results_list[:10]]
        elif mode == "3":
            selected = [item['ip'] for item in self.raw_results_list[:3]]
        else:
            selected = []
        Clipboard.copy("\n".join(selected))

    def quick_share_results(self):
        if not self.raw_results_list: return
        top_ips = "\n".join([item['ip'] for item in self.raw_results_list[:3]])
        share_msg = f"MidONe Scanner Best IPs:\n{top_ips}\nChannel: @mmdrlx"
        try:
            from plyer import share
            share.share(share_msg)
        except:
            Clipboard.copy(share_msg)

    def go_back_home(self):
        self.manager.current = 'home'


class MidONeScannerApp(App):
    def build(self):
        self.title = "MidONe Scanner"
        Window.bind(on_keyboard=self.handle_hardware_back_button)
        return Builder.load_string(KV_DESIGN)

    def handle_hardware_back_button(self, window, key, scancode, codepoint, modifiers):
        if key == 27:
            sm = self.root
            if sm.current != 'home':
                sm.current = 'home'
                return True
        return False


if __name__ == '__main__':
    MidONeScannerApp().run()