[app]
title = MidONe Scanner
android.accept_sdk_license = True
package.name = midonescanner
package.domain = org.midone
source.dir = .
source.include_exts = py,png,jpg,kv,json
version = 1.0.2
requirements = kivy==2.3.0,plyer,requests
python = 3.10

# Android UI adjustments
orientation = portrait
fullscreen = 0

# Android SDK & Architecture configurations (Target 34 for fixing Unsafe prompt)
android.api = 34
android.minapi = 21
android.ndk = 26b
android.archs = arm64-v8a, armeabi-v7a
android.allow_backup = True

# Device System Integration Permissions
android.permissions = INTERNET, VIBRATE

# Build configurations setup
p4a.branch = master
release = 1
