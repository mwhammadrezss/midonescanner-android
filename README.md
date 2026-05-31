<div align="center">

<img src="assets/icons/app_icon.png" width="140" />

# MidONe Scanner
### اسکنر حرفه‌ای آی‌پی تمیز
##### CDN &nbsp;·&nbsp; CLOUDFLARE &nbsp;·&nbsp; DNS
[![Release](https://img.shields.io/github/v/release/mwhammadrezss/midonescanner-android?label=آخرین%20نسخه&style=flat-square&color=brightgreen)](https://github.com/mwhammadrezss/midonescanner-android/releases/latest)
[![Platform](https://img.shields.io/badge/Platform-Android-green?style=flat-square&logo=android)](https://github.com/mwhammadrezss/midonescanner-android/releases/latest)
[![Telegram](https://img.shields.io/badge/Telegram-@mmdrlx-blue?style=flat-square&logo=telegram)](https://t.me/mmdrlx)

<br/>

[**⬇️ دانلود APK**](https://github.com/mwhammadrezss/midonescanner-android/releases/download/v7.0.1/MidONeScannerV7.0.1.apk) &nbsp;·&nbsp; [**📣 کانال تلگرام**](https://t.me/mmdrlx)

</div>

---

## 🔍 چرا MidONe Scanner؟

بیشتر ابزارهای اسکن IP فقط یک **ping** ساده می‌زنند — عددی که هیچ ربطی به سرعت واقعی اتصال ندارد. MidONe Scanner متفاوت است:

> **داده واقعی دانلود می‌کند.** سرعتی که اپ نشان می‌دهد، همان چیزی است که در واقعیت تجربه خواهید کرد.

---
how ? 
## 🔬 Under the Hood — Scan Engine Pipelines

> For technical and semi-technical users: here's exactly what happens behind the scenes in each scan mode.

---

### 1️⃣ CDN — Smart Scan

#### ⚡ Normal Engine
```text
TCP Connect
→ TLS Handshake
→ HTTP/2 Request
→ Response Validation
→ Latency Measurement
→ Candidate Scoring
→ Ranking
```

#### 🔍 Deep Scan Engine
```text
TCP Connect
→ TLS Handshake
→ HTTP/2 Keep-Alive
→ Long Connection Test (25s)
→ DPI Detection
→ Stability Analysis
→ Packet Loss Check
→ Final Score
→ Ranking
```

---

### 2️⃣ Cloudflare — Dedicated Cloudflare Scanner

```text
TCP Connect
→ TLS Handshake
→ Cloudflare Verification
→ Colo Detection (FRA, AMS, LHR, ...)
→ HTTP/2 Test
→ WebSocket Upgrade Test
→ WebSocket Stability Check
→ Latency Measurement
→ Final Score
→ Ranking
```

---

### 3️⃣ Range — High-Speed Range Scanner

```text
CIDR Range
→ IP Generation
→ Concurrent TCP Probe
→ Dead IP Removal
→ Candidate Filter
→ Deep Scan Queue
→ Stability Verification
→ Live Ranking Engine
→ Final Results
```

---

### 4️⃣ DNS — DNS Benchmark Engine

```text
DNS Resolve
→ Average Latency
→ NXDOMAIN Check
→ Burst Performance
→ Jitter Measurement
→ Freedom Verification
→ DoH Support Test
→ Reliability Score
→ Final Ranking
```

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **Simple Mode** | Fast scan with fixed SNI — ideal for quick tests |
| 🧠 **Auto-SNI Mode** | Automatic CDN detection + optimal SNI selection |
| 📋 **Copy Top 5** | Copy the top 5 IPs with a single tap |
| 💾 **Save to File** | Save full results to device storage |
| 🚨 **Throttle Badge** | Shows speed drop percentage per IP |
| ⭐ **Grade System** | S / A / B / C / D ranking per IP |
| 🌙 **Dark UI** | Dark interface with Forest Green theme |

---

## 📲 Installation

```
1. Tap the "Download APK" button
2. Open the app-release.apk file
3. Select Install
   (If "Unknown source" warning appears → Settings → Allow install from unknown sources)
```

---

## 🚀 Getting Started

**1. Enter your IPs**
```
1.1.1.1
104.16.0.1
8.8.8.8
```

**2. Choose your scan mode**
- `Simple` — fast, for quick tests
- `Auto-SNI` — precise, for finding the best IPs

**3. Tap Start Scan and watch the results**

---

## 📦 Technical Specs

| Spec | Value |
|------|-------|
| Platform | Android 5.0+ |
| Framework | Flutter / Dart |
| Protocol | TLS 1.2/1.3 over TCP:443 |
| Threads | 20 parallel threads |
| Reliability Tries | 5× per IP |
| Test Duration | Up to 5 seconds per IP |
| Throttle Threshold | 40%+ speed drop = Throttled |

---

<div align="center">

**📣 Join our Telegram channel for the latest updates and clean IPs**

[![Join Telegram](https://img.shields.io/badge/Join-@mmdrlx-blue?style=for-the-badge&logo=telegram)](https://t.me/mmdrlx)

<sub>Made with ❤️ by MidONe</sub>

---

### ❤️ Support the Project

If this tool has been useful to you, show your support and keep me motivated!

**USDT (TRC20)**
```
THPDqXuHkiAJeexrs8wjPQCTVLxje3JFYU
```

**USDT (ERC20)**
```
0x3C0248A058b83875ae994296ca40e7e00f70bfB4
```

**TON (TON)**
```
UQAGASqgVnidUt-0d03mi1Q2VZYFSUa4I8KoqrVpmQbZskdS
```

</div>

<!-- build trigger: 2026-05-31T22:39:35.493702 -->