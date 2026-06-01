// lib/utils/logger.dart
// p51: structuredJsonLogs — structured per-phase logging
// p53: replayableFailureLogs — failed sessions stored for replay

import 'dart:convert';
import 'dart:io';
import 'package:path_provider/path_provider.dart';

class StructuredLogger {
  static final StructuredLogger _i = StructuredLogger._();
  factory StructuredLogger() => _i;
  StructuredLogger._();

  final List<Map<String, dynamic>> _buffer = [];
  static const int _maxBuffer = 500;

  /// Log a structured event.
  void log({
    required String phase,
    required String ip,
    String? sni,
    String? event,
    String? error,
    Map<String, dynamic>? extra,
  }) {
    final entry = <String, dynamic>{
      'ts': DateTime.now().toIso8601String(),
      'phase': phase,
      'ip': ip,
      if (sni != null) 'sni': sni,
      if (event != null) 'event': event,
      if (error != null) 'error': error,
      if (extra != null) ...extra,
    };
    _buffer.add(entry);
    if (_buffer.length > _maxBuffer) _buffer.removeAt(0);
  }

  List<Map<String, dynamic>> get recentLogs => List.unmodifiable(_buffer);

  String exportJson() => const JsonEncoder.withIndent('  ').convert(_buffer);

  Future<void> saveToFile() async {
    try {
      final dir = await getApplicationDocumentsDirectory();
      final file = File('${dir.path}/midone_logs.json');
      await file.writeAsString(exportJson());
    } catch (_) {}
  }

  void clear() => _buffer.clear();
}
