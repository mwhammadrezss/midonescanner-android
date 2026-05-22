[app]

title = MidONe Scanner
package.name = midonescanner
package.domain = org.midone
source.dir = .
source.include_exts = py,png,jpg,kv,json
version = 1.0.2

requirements = python3,kivy==2.3.0,plyer,requests

orientation = portrait
fullscreen = 0

android.api = 34
android.minapi = 21
android.ndk = 26b
android.accept_sdk_license = True
android.archs = arm64-v8a, armeabi-v7a
android.permissions = INTERNET, VIBRATE
android.allow_backup = True

log_level = 2
warn_on_root = 1

[buildozer]
log_level = 2
