import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/services.dart';
import 'package:path_provider/path_provider.dart';

class ExportService {
  static Future<String?> saveText(String content, {String? suggestedName}) async {
    final name = suggestedName ??
        'midone-export-${DateTime.now().millisecondsSinceEpoch}.txt';

    if (Platform.isWindows || Platform.isLinux || Platform.isMacOS) {
      final path = await FilePicker.platform.saveFile(
        dialogTitle: 'Save export',
        fileName: name,
        type: FileType.custom,
        allowedExtensions: ['txt'],
      );
      if (path == null) return null;
      final file = File(path.endsWith('.txt') ? path : '$path.txt');
      await file.writeAsString(content);
      return file.path;
    }

    final dir = await getApplicationDocumentsDirectory();
    final folder = Directory('${dir.path}/MidONeScanner');
    if (!folder.existsSync()) folder.createSync(recursive: true);
    final file = File('${folder.path}/$name');
    await file.writeAsString(content);
    return file.path;
  }

  static Future<void> copyToClipboard(String text) async {
    await Clipboard.setData(ClipboardData(text: text));
  }

  static String formatEndpoints(Iterable<String> endpoints) =>
      endpoints.join('\n');
}
