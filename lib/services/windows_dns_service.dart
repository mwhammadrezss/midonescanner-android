import 'dart:io';

/// Apply DNS on Windows via netsh (primary + secondary).
class WindowsDnsService {
  static Future<bool> setDns(String primary, {String? secondary}) async {
    if (!Platform.isWindows) return false;
    try {
      final r1 = await Process.run(
        'netsh',
        ['interface', 'ip', 'set', 'dns', 'name=Wi-Fi', 'static', primary, 'primary'],
        runInShell: true,
      );
      if (r1.exitCode != 0) {
        await Process.run(
          'netsh',
          ['interface', 'ip', 'set', 'dns', 'name=Ethernet', 'static', primary, 'primary'],
          runInShell: true,
        );
      }
      if (secondary != null && secondary.isNotEmpty) {
        await Process.run(
          'netsh',
          ['interface', 'ip', 'add', 'dns', 'name=Wi-Fi', secondary, 'index=2'],
          runInShell: true,
        );
      }
      return true;
    } catch (_) {
      return false;
    }
  }
}
