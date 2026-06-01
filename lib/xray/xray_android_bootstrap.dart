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
        await Process.run('chmod', ['755', binDest.path]);
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
}
