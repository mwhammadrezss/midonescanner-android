import 'dart:io';

import 'package:path_provider/path_provider.dart';

/// SenPai-style live result file: SenPaiScannerResult-YYYYMMDD-HHMMSS.txt
class LiveResultWriter {
  LiveResultWriter() {
    final now = DateTime.now();
    final stamp =
        '${now.year}${_2(now.month)}${_2(now.day)}-${_2(now.hour)}${_2(now.minute)}${_2(now.second)}';
    _fileName = 'SenPaiScannerResult-$stamp.txt';
  }

  late final String _fileName;
  File? _file;
  IOSink? _sink;

  static String _2(int n) => n.toString().padLeft(2, '0');

  Future<File> _ensureFile() async {
    if (_file != null) return _file!;
    Directory dir;
    if (Platform.isWindows) {
      dir = File(Platform.resolvedExecutable).parent;
    } else {
      dir = await getApplicationDocumentsDirectory();
      dir = Directory('${dir.path}${Platform.pathSeparator}MidONeScanner');
      if (!dir.existsSync()) dir.createSync(recursive: true);
    }
    _file = File('${dir.path}${Platform.pathSeparator}$_fileName');
    _sink = _file!.openWrite(mode: FileMode.append);
    await _sink!.writeln('# MidONe Scanner — live CF results');
    await _sink!.writeln('# $_fileName');
    return _file!;
  }

  Future<void> append(String line) async {
    await _ensureFile();
    _sink?.writeln(line);
    await _sink?.flush();
  }

  Future<void> appendEndpoint(String ip, int port, {String? note}) async {
    final ep = '$ip:$port';
    await append(note != null ? '$ep  $note' : ep);
  }

  Future<String?> finish() async {
    await _sink?.flush();
    await _sink?.close();
    _sink = null;
    return _file?.path;
  }

  String? get path => _file?.path;
}
