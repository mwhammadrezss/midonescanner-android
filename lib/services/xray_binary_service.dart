// Locates / extracts xray-core binary (APK assets or beside exe on Windows).

import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:path_provider/path_provider.dart';

class XrayBinaryService {
  XrayBinaryService._();
  static final instance = XrayBinaryService._();

  String? _cachedPath;
  bool? _available;

  static const _assetAndroid = 'assets/xray/xray-android-arm64';
  static const _assetWindows = 'assets/xray/xray-windows-amd64.exe';

  Future<bool> isAvailable() async {
    if (Platform.isAndroid || Platform.isIOS) return false;
    if (_available != null) return _available!;
    _available = (await getPath()) != null;
    return _available!;
  }

  Future<String?> getPath() async {
    if (Platform.isAndroid || Platform.isIOS) return null;
    if (_cachedPath != null && File(_cachedPath!).existsSync()) return _cachedPath;

    if (Platform.isWindows) {
      final exeDir = File(Platform.resolvedExecutable).parent.path;
      final sidecar = File('$exeDir${Platform.pathSeparator}xray.exe');
      if (sidecar.existsSync()) {
        _cachedPath = sidecar.path;
        return _cachedPath;
      }
    }

    try {
      final dir = await getApplicationSupportDirectory();
      final sub = Directory('${dir.path}${Platform.pathSeparator}xray');
      if (!sub.existsSync()) sub.createSync(recursive: true);

      final outName = Platform.isWindows ? 'xray.exe' : 'xray';
      final outFile = File('${sub.path}${Platform.pathSeparator}$outName');
      if (outFile.existsSync()) {
        if (!Platform.isWindows) {
          try {
            await Process.run('chmod', ['+x', outFile.path]);
          } catch (_) {}
        }
        _cachedPath = outFile.path;
        return _cachedPath;
      }

      final asset = Platform.isWindows ? _assetWindows : _assetAndroid;
      try {
        final data = await rootBundle.load(asset);
        await outFile.writeAsBytes(
          data.buffer.asUint8List(data.offsetInBytes, data.lengthInBytes),
          flush: true,
        );
        if (!Platform.isWindows) {
          try {
            await Process.run('chmod', ['+x', outFile.path]);
          } catch (_) {}
        }
        _cachedPath = outFile.path;
        _available = true;
        return _cachedPath;
      } catch (_) {
        if (kDebugMode) {
          debugPrint('[XrayBinary] asset missing: $asset');
        }
      }
    } catch (e) {
      if (kDebugMode) debugPrint('[XrayBinary] $e');
    }

    return null;
  }

  void reset() {
    _cachedPath = null;
    _available = null;
  }
}
