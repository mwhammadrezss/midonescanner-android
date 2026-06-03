# Assets required for build

Place these files before `flutter build`:

- `icons/app_icon.png` — app logo
- `icons/telegram_icon.png` — optional (UI falls back if missing)
- `geo/ipcountry.bin` — offline GeoIP database
- `xray/xray-android-arm64` — xray-core binary for Android arm64-v8a (from Xray-core releases)
- `xray/xray-windows-amd64.exe` — xray-core for Windows (CI downloads automatically)

CI workflow downloads xray binaries when building releases.
