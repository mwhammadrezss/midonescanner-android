// lib/storage/custom_cidr_storage.dart
// Persistent storage for user-defined custom CIDR ranges.
// Features:
//   - Save / load up to 50 CIDRs in SharedPreferences
//   - Export to a plain-text .txt file (one CIDR per line)
//   - Import from a plain-text .txt file
//
// Export location: app Documents directory (path_provider)
// Import: file_picker lets the user pick any .txt file

import 'dart:io';
import 'package:file_picker/file_picker.dart';
import 'package:path_provider/path_provider.dart';
import 'package:shared_preferences/shared_preferences.dart';

class CustomCidrStorage {
  static final CustomCidrStorage _i = CustomCidrStorage._();
  factory CustomCidrStorage() => _i;
  CustomCidrStorage._();

  static const String _key      = 'custom_cidrs_v1';
  static const int    _maxItems = 50;

  // ── Load ──────────────────────────────────────────────────────────────────

  Future<List<String>> load() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getStringList(_key) ?? [];
  }

  // ── Save (replace full list) ──────────────────────────────────────────────

  Future<void> saveAll(List<String> cidrs) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setStringList(_key, cidrs.take(_maxItems).toList());
  }

  // ── Add single CIDR (deduplicates, max 50) ────────────────────────────────

  Future<bool> add(String cidr) async {
    final list = await load();
    if (list.contains(cidr)) return false; // already exists
    if (list.length >= _maxItems) return false; // full
    list.add(cidr);
    await saveAll(list);
    return true;
  }

  // ── Remove single CIDR ────────────────────────────────────────────────────

  Future<void> remove(String cidr) async {
    final list = await load();
    list.remove(cidr);
    await saveAll(list);
  }

  // ── Clear all ─────────────────────────────────────────────────────────────

  Future<void> clear() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_key);
  }

  // ── Export to .txt ────────────────────────────────────────────────────────
  // Returns the exported file path, or throws on error.

  Future<String> exportToFile() async {
    final cidrs = await load();
    if (cidrs.isEmpty) throw Exception('No saved CIDRs to export.');

    Directory dir;
    try {
      dir = await getApplicationDocumentsDirectory();
    } catch (_) {
      dir = await getTemporaryDirectory();
    }

    final file = File('${dir.path}/midonescanner_cidrs.txt');
    await file.writeAsString(cidrs.join('\n') + '\n');
    return file.path;
  }

  // ── Import from .txt ──────────────────────────────────────────────────────
  // Opens a file picker, reads valid CIDRs (one per line), merges with existing.
  // Returns number of NEW CIDRs added, or -1 if user cancelled.

  Future<int> importFromFile() async {
    FilePickerResult? result;
    try {
      result = await FilePicker.platform.pickFiles(
        type: FileType.custom,
        allowedExtensions: ['txt'],
        allowMultiple: false,
      );
    } catch (_) {
      // FilePicker not available on this platform — shouldn't happen on Android/Windows
      return -1;
    }

    if (result == null || result.files.isEmpty) return -1;

    final path = result.files.single.path;
    if (path == null) return -1;

    final lines = await File(path).readAsLines();
    final validCidrs = lines
        .map((l) => l.trim())
        .where((l) => l.isNotEmpty && _isValidCidr(l))
        .toSet()
        .toList();

    if (validCidrs.isEmpty) return 0;

    final existing = await load();
    int added = 0;
    for (final cidr in validCidrs) {
      if (!existing.contains(cidr) && existing.length < _maxItems) {
        existing.add(cidr);
        added++;
      }
    }
    if (added > 0) await saveAll(existing);
    return added;
  }

  // ── Internal CIDR validator ───────────────────────────────────────────────

  static bool _isValidCidr(String s) {
    final parts = s.split('/');
    if (parts.length != 2) return false;
    final prefix = int.tryParse(parts[1]);
    if (prefix == null || prefix < 0 || prefix > 32) return false;
    final octets = parts[0].split('.');
    if (octets.length != 4) return false;
    for (final o in octets) {
      final b = int.tryParse(o);
      if (b == null || b < 0 || b > 255) return false;
    }
    return true;
  }
}
