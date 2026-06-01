// lib/xray/xray_android_bootstrap.dart
//
// Extracts the bundled xray binary from Flutter assets into the app's
// private files directory and marks it executable.
//
// Usage:
//   await XrayAndroidBootstrap.init();      // call once in main()
//   final path = await XrayAndroidBootstrap.getXrayPath(); // get binary path

import 'dart:io';
import 'package:flutter/services.dart';
import 'package:path_provider/path_provider.dart';

class XrayAndroidBootstrap {
  static String? _cachedPath;

  // Asset name bundled in pubspec.yaml under assets/xray/
  static const _assetName = 'assets/xray/xray-arm64';

  /// Returns the path to the extracted xray binary on Android.
  /// Returns null on non-Android platforms or on error.
  static Future<String?> getXrayPath() async {
    if (!Platform.isAndroid) return null;

    // Return cached path if binary still exists
    if (_cachedPath != null) {
      if (File(_cachedPath!).existsSync()) return _cachedPath;
      _cachedPath = null; // invalidate if deleted
    }

    return _extractBinary();
  }

  /// Pre-extract the binary at app startup (background, non-blocking).
  static Future<void> init() async {
    if (!Platform.isAndroid) return;
    try {
      await getXrayPath();
    } catch (_) {}
  }

  static Future<String?> _extractBinary() async {
    try {
      final dir = await getApplicationSupportDirectory();
      final dest = File('${dir.path}/xray');

      // Load binary from Flutter assets
      final ByteData data = await rootBundle.load(_assetName);
      final bytes = data.buffer.asUint8List();

      // Write to app files dir
      await dest.writeAsBytes(bytes, flush: true);

      // Make executable: chmod 755
      final chmod = await Process.run('chmod', ['755', dest.path]);
      if (chmod.exitCode != 0) {
        // Fallback chmod
        await Process.run('chmod', ['+x', dest.path]);
      }

      // Verify file is there and non-empty
      if (!dest.existsSync() || dest.lengthSync() < 1024) {
        return null;
      }

      _cachedPath = dest.path;
      return dest.path;
    } catch (_) {
      return null;
    }
  }
}
