[app]

title = MidONe Scanner SK
package.name = midonescanner
package.domain = org.mmdrlx
source.dir = .
source.include_exts = py,png,jpg,kv,json
source.main = main.py
version = 6.1
android.numeric_version = 610

requirements = python3,kivy==2.2.1,cython==0.29.37,plyer

orientation = portrait
fullscreen = 0

android.api = 31
android.minapi = 21
android.ndk = 25b
android.ndk_api = 21
android.accept_sdk_license = True
android.archs = arm64-v8a
android.permissions = INTERNET,WRITE_EXTERNAL_STORAGE,READ_EXTERNAL_STORAGE,ACCESS_NETWORK_STATE
android.allow_backup = True

p4a.branch = master
p4a.commit = 957a3e5f8c270f7aa648ba185e5a68c1077a798d

[buildozer]
log_level = 2
warn_on_root = 1
