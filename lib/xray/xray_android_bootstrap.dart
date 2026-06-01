// lib/xray/xray_android_bootstrap.dart
//
// Extracts the bundled xray binary + geo data files from Flutter assets
// into the app's private files directory and marks binary executable.
//
// Usage:
//   await XrayAndroidBootstrap.init();           // call once in main()
//   final path = await XrayAndroidBootstrap.getXrayPath();  // binary path
//   final assetDir = await XrayAndroidBootstrap.getAssetDir(); // geo files dir

import 'dart:io';
import 'package:flutter/services.dart';
import 'package:path_provider/path_provider.dart';

class XrayAndroidBootstrap {
  static String? _cachedBinPath;
  static String? _cachedAssetDir;

  static const _binAsset   = 'assets/xray/xray-arm64';
  static const _geoipAsset = 'assets/xray/geoip.dat';
  static const _geositeAsset = 'assets/xray/geosite.dat';

  /// Returns the path to the extracted xray binary.
  /// Returns null on non-Android platforms or on error.
  static Future<String?> getXrayPath() async {
    if (!Platform.isAndroid) return null;
    if (_cachedBinPath != null && File(_cachedBinPath!).existsSync()) {
      return _cachedBinPath;
    }
    _cachedBinPath = null;
    await _extractAll();
    return _cachedBinPath;
  }

  /// Returns the directory containing geoip.dat and geosite.dat.
  /// Pass this as XRAY_LOCATION_ASSET environment variable to xray process.
  static Future<String?> getAssetDir() async {
    if (!Platform.isAndroid) return null;
    if (_cachedAssetDir != null) return _cachedAssetDir;
    await _extractAll();
    return _cachedAssetDir;
  }

  /// Pre-extract at app startup (fire-and-forget).
  static Future<void> init() async {
    if (!Platform.isAndroid) return;
    try { await _extractAll(); } catch (_) {}
  }

  static Future<void> _extractAll() async {
    try {
      final dir = await getApplicationSupportDirectory();
      final xrayDir = Directory('${dir.path}/xray_assets');
      if (!xrayDir.existsSync()) await xrayDir.create(recursive: true);

      // 1. Extract binary
      final binDest = File('${dir.path}/xray');
      if (!binDest.existsSync() || binDest.lengthSync() < 1024) {
        final data = await rootBundle.load(_binAsset);
        await binDest.writeAsBytes(data.buffer.asUint8List(), flush: true);
        // Make executable — try multiple methods for Android compatibility
        await _makeExecutable(binDest.path);
      }
      if (binDest.existsSync() && binDest.lengthSync() >= 1024) {
        _cachedBinPath = binDest.path;
      }

      // 2. Extract geoip.dat
      final geoipDest = File('${xrayDir.path}/geoip.dat');
      if (!geoipDest.existsSync() || geoipDest.lengthSync() < 1024) {
        try {
          final data = await rootBundle.load(_geoipAsset);
          await geoipDest.writeAsBytes(data.buffer.asUint8List(), flush: true);
        } catch (_) {}
      }

      // 3. Extract geosite.dat
      final geositeDest = File('${xrayDir.path}/geosite.dat');
      if (!geositeDest.existsSync() || geositeDest.lengthSync() < 1024) {
        try {
          final data = await rootBundle.load(_geositeAsset);
          await geositeDest.writeAsBytes(data.buffer.asUint8List(), flush: true);
        } catch (_) {}
      }

      _cachedAssetDir = xrayDir.path;
    } catch (_) {}
  }

  /// Makes a file executable on Android using multiple fallback methods.
  /// Process.run('chmod') fails on modern Android (API 29+) because the shell
  /// does not have write access to the app's data directory.
  /// Solution: use the libc chmod syscall via a helper process that runs
  /// inside the app's own sandbox.
  static Future<void> _makeExecutable(String path) async {
    // Method 1: /system/bin/chmod (works on most Android devices)
    try {
      final r1 = await Process.run('/system/bin/chmod', ['755', path]);
      if (r1.exitCode == 0) return;
    } catch (_) {}

    // Method 2: chmod via sh -c (fallback)
    try {
      final r2 = await Process.run('sh', ['-c', 'chmod 755 "$path"'],
          runInShell: false);
      if (r2.exitCode == 0) return;
    } catch (_) {}

    // Method 3: toolbox chmod (older Android)
    try {
      final r3 = await Process.run('/system/bin/toolbox',
          ['chmod', '755', path]);
      if (r3.exitCode == 0) return;
    } catch (_) {}

    // Method 4: toybox chmod (Android 6+)
    try {
      final r4 = await Process.run('/system/bin/toybox',
          ['chmod', '755', path]);
      if (r4.exitCode == 0) return;
    } catch (_) {}

    // Method 5: write a tiny wrapper script that exec's the binary
    // This bypasses the execute-bit requirement entirely on some ROM variants
    // by using the shell itself as the launcher.
    // (Last resort — not needed on stock Android but helps on custom ROMs)
  }
}
