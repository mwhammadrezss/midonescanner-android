import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';

import '../../core/l10n/strings.dart';
import '../../core/services/export_service.dart';
import '../../engine/cf_xray_scan_engine.dart';

class CfResultsPage extends StatelessWidget {
  final List<CfPhase2Result> phase2;
  final List<CfPhase1Result> phase1;
  final String? liveFilePath;

  const CfResultsPage({
    super.key,
    required this.phase2,
    required this.phase1,
    this.liveFilePath,
  });

  @override
  Widget build(BuildContext context) {
    final working = phase2.where((r) => r.success).toList();
    return Scaffold(
      backgroundColor: const Color(0xFF0D1510),
      appBar: AppBar(
        backgroundColor: const Color(0xFF152018),
        title: Text(S.t.cfResults, style: GoogleFonts.inter(fontWeight: FontWeight.w700)),
        actions: [
          IconButton(
            icon: const Icon(Icons.copy),
            onPressed: () async {
              final text = working.map((r) => '${r.ip}:${r.phase1.port}').join('\n');
              await Clipboard.setData(ClipboardData(text: text));
              if (context.mounted) {
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(content: Text(S.t.fa ? 'کپی شد' : 'Copied')),
                );
              }
            },
          ),
          IconButton(
            icon: const Icon(Icons.save_alt),
            onPressed: () async {
              final buf = StringBuffer('# CF Results\n');
              for (final r in phase2) {
                buf.writeln(
                    '${r.success ? "OK" : "FAIL"} ${r.ip}:${r.phase1.port} '
                    '${r.validation.throughputMbps.toStringAsFixed(1)}Mbps');
              }
              await ExportService.saveText(buf.toString(), suggestedName: 'ips.txt');
            },
          ),
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          if (liveFilePath != null)
            Padding(
              padding: const EdgeInsets.only(bottom: 12),
              child: Text(
                Platform.isWindows
                    ? 'Live: $liveFilePath'
                    : 'Live log saved',
                style: GoogleFonts.robotoMono(color: const Color(0xFF8BAF9A), fontSize: 10),
              ),
            ),
          Text('${working.length} / ${phase2.length} working',
              style: GoogleFonts.inter(color: const Color(0xFF7CFC00), fontWeight: FontWeight.w700)),
          const SizedBox(height: 12),
          ...phase2.map((r) => _ResultTile(r: r)),
        ],
      ),
    );
  }
}

class _ResultTile extends StatelessWidget {
  final CfPhase2Result r;
  const _ResultTile({required this.r});

  @override
  Widget build(BuildContext context) {
    final ok = r.success;
    return Card(
      color: const Color(0xFF152018),
      margin: const EdgeInsets.only(bottom: 8),
      child: ListTile(
        leading: Icon(ok ? Icons.check_circle : Icons.cancel,
            color: ok ? const Color(0xFF7CFC00) : Colors.red),
        title: Text('${r.ip}:${r.phase1.port}',
            style: GoogleFonts.robotoMono(color: Colors.white, fontSize: 13)),
        subtitle: Text(
          '${r.phase1.colo} · ${r.validation.latencyMs.toStringAsFixed(0)}ms · '
          '${r.validation.throughputMbps.toStringAsFixed(1)} Mbps · ${r.validation.transport}',
          style: GoogleFonts.inter(color: const Color(0xFF8BAF9A), fontSize: 11),
        ),
      ),
    );
  }
}
