[app]

title = MidONe Scanner
package.name = midonescanner
package.domain = org.midone
source.dir = .
source.include_exts = py,png,jpg,kv,json
source.main = main.py
version = 1.0.2
android.numeric_version = 1000200

requirements = python3,kivy==2.2.1,cython==0.29.37,plyer

orientation = portrait
fullscreen = 0

android.api = 31
android.minapi = 21
android.ndk = 25b
android.ndk_api = 21
android.accept_sdk_license = True
android.archs = arm64-v8a
android.permissions = INTERNET,ACCESS_NETWORK_STATE,VIBRATE
android.allow_backup = True

p4a.branch = master
p4a.commit = 957a3e5f8c270f7aa648ba185e5a68c1077a798d

log_level = 2
warn_on_root = 1

[buildozer]
log_level = 2
