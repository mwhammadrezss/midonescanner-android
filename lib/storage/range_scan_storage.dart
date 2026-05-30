// lib/storage/range_scan_storage.dart
// Range scan storage: scanned IP memory + session history

import 'dart:convert';
import 'package:shared_preferences/shared_preferences.dart';

class RangeScanStorage {
  static final RangeScanStorage _i = RangeScanStorage._();
  factory RangeScanStorage() => _i;
  RangeScanStorage._();

  static const String _scannedIpsKey = 'range_scanned_ips_v1';
  static const String _sessionsKey   = 'range_sessions_v1';

  // ─── Scanned IP Memory ────────────────────────────────────────────────────

  Future<void> addScannedIps(List<String> ips) async {
    final prefs = await SharedPreferences.getInstance();
    final existing = prefs.getStringList(_scannedIpsKey) ?? [];
    final merged = {...existing, ...ips}.toList();
    await prefs.setStringList(_scannedIpsKey, merged);
  }

  Future<Set<String>> loadScannedIps() async {
    final prefs = await SharedPreferences.getInstance();
    return (prefs.getStringList(_scannedIpsKey) ?? []).toSet();
  }

  Future<void> clearScannedIps() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_scannedIpsKey);
  }

  Future<int> scannedIpCount() async {
    final prefs = await SharedPreferences.getInstance();
    return (prefs.getStringList(_scannedIpsKey) ?? []).length;
  }

  // ─── Session History ──────────────────────────────────────────────────────

  Future<void> saveSession(Map<String, dynamic> session) async {
    final prefs = await SharedPreferences.getInstance();
    final existing = prefs.getStringList(_sessionsKey) ?? [];
    existing.insert(0, jsonEncode(session));
    await prefs.setStringList(_sessionsKey, existing.take(50).toList());
  }

  Future<List<Map<String, dynamic>>> loadAllSessions() async {
    final prefs = await SharedPreferences.getInstance();
    final items = prefs.getStringList(_sessionsKey) ?? [];
    return items
        .map((s) {
          try {
            return jsonDecode(s) as Map<String, dynamic>;
          } catch (_) {
            return <String, dynamic>{};
          }
        })
        .where((m) => m.isNotEmpty)
        .toList();
  }

  Future<void> clearAllSessions() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_sessionsKey);
  }

  Future<void> resetAll() async {
    await clearScannedIps();
    await clearAllSessions();
  }
}
