// SenPai-style Cloudflare scanner UI (Phase 1 + Phase 2 xray).

import 'dart:io' show Platform;

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';

import '../../core/l10n/strings.dart';
import '../../core/services/export_service.dart';
import '../../core/services/live_result_writer.dart';
import '../../engine/cf_xray_scan_engine.dart';
import '../../utils/ip_utils.dart';
import '../../xray/config_parser.dart';
import 'cf_results_page.dart';

// Theme (matches main.dart)
const _cardInner = Color(0xFF1A2A1F);
const _border = Color(0xFF2A4030);
const _textSecond = Color(0xFF8BAF9A);
const _accent = Color(0xFF7CFC00);
const _accent2 = Color(0xFF5CE600);

class CfScanPanel extends StatefulWidget {
  const CfScanPanel({super.key});

  @override
  State<CfScanPanel> createState() => _CfScanPanelState();
}

class _CfScanPanelState extends State<CfScanPanel> {
  final _configCtrl = TextEditingController();

  bool _scanning = false;
  bool _cancelled = false;
  String _status = '';
  int _p1Done = 0, _p1Total = 0;
  int _p2Done = 0, _p2Total = 0;

  int _sourceMode = 0; // 0 random 1 file
  List<String> _fileIps = [];
  int _countIdx = 1;
  static const _counts = [1000, 5000, 20000];
  int _workersIdx = 0;
  static const _workers = [50, 100, 200];
  int _timeoutIdx = 1;
  static const _timeouts = [2000, 3000, 5000];
  int _topNIdx = 0;
  static const _topNs = [10, 25, 50, 100];
  int _tries = 4;
  CfSortMode _sortMode = CfSortMode.avg;

  final Set<int> _selectedPorts = {443};
  static const _allPorts = [0, 443, 8443, 2053, 2083, 2087, 2096]; // 0 = config port

  List<CfPhase1Result> _phase1 = [];
  List<CfPhase2Result> _phase2 = [];
  LiveResultWriter? _liveWriter;

  @override
  void dispose() {
    _configCtrl.dispose();
    super.dispose();
  }

  int get _sampleCount => _counts[_countIdx.clamp(0, _counts.length - 1)];
  int get _concurrency => _workers[_workersIdx.clamp(0, _workers.length - 1)];
  int get _timeoutMs => _timeouts[_timeoutIdx.clamp(0, _timeouts.length - 1)];
  int get _topN {
    final i = _topNIdx.clamp(0, _topNs.length - 1);
    return _topNs[i];
  }

  List<int> _resolvePorts(XrayConfig? cfg) {
    final ports = <int>{};
    for (final p in _selectedPorts) {
      if (p == 0) {
        if (cfg != null) ports.add(cfg.port);
      } else {
        ports.add(p);
      }
    }
    if (ports.isEmpty) ports.add(443);
    return ports.toList();
  }

  Future<void> _importIps() async {
    final r = await FilePicker.platform.pickFiles(type: FileType.custom, allowedExtensions: ['txt']);
    if (r == null || r.files.isEmpty) return;
    final path = r.files.single.path;
    if (path == null) return;
    final text = await File(path).readAsString();
    final ips = validateAndExtractIps(text);
    setState(() {
      _fileIps = ips;
      _sourceMode = 1;
      _status = S.t.importIps + ': ${ips.length}';
    });
  }

  Future<void> _startScan() async {
    if (_scanning) return;
    XrayConfig? cfg;
    try {
      final raw = _configCtrl.text.trim();
      if (raw.isNotEmpty) cfg = parseProxyUrl(raw);
    } catch (e) {
      _snack('Config error: $e');
      return;
    }

    final ips = _sourceMode == 1 ? _fileIps : <String>[];
    if (_sourceMode == 1 && ips.isEmpty) {
      _snack(S.t.fa ? 'فایل IP خالی است' : 'No IPs in file');
      return;
    }

    _liveWriter = LiveResultWriter();
    setState(() {
      _scanning = true;
      _cancelled = false;
      _phase1 = [];
      _phase2 = [];
      _p1Done = _p2Done = 0;
      _p1Total = _sourceMode == 1
          ? ips.length * _resolvePorts(cfg).length
          : _sampleCount * _resolvePorts(cfg).length;
      _p2Total = 0;
      _status = S.t.cfPhase1;
    });

    try {
      final results = await runCfXrayScanner(
        ips: ips,
        sampleCount: _sampleCount,
        concurrency: _concurrency,
        timeoutMs: _timeoutMs,
        config: cfg,
        topN: cfg != null ? _topN : 0,
        tries: _tries,
        sortMode: _sortMode,
        ports: _resolvePorts(cfg),
        isCancelled: () => _cancelled,
        onLiveLog: (line) => _liveWriter?.append(line),
        onPhase1Progress: (_, done, total) {
          if (!mounted) return;
          setState(() {
            _p1Done = done;
            _p1Total = total;
            _status = '${S.t.cfPhase1} $done/$total';
          });
        },
        onPhase2Progress: (r, done, total) {
          if (!mounted) return;
          if (r.success) {
            _liveWriter?.appendEndpoint(
              r.ip,
              r.validation.port,
              note: '${r.validation.throughputMbps.toStringAsFixed(1)}Mbps',
            );
          }
          setState(() {
            _p2Done = done;
            _p2Total = total;
            _status = '${S.t.cfPhase2} $done/$total';
          });
        },
      );

      if (!mounted) return;
      setState(() {
        _phase1 = results.map((r) => r.phase1).toList();
        _phase2 = results;
        _scanning = false;
        final ok = results.where((r) => r.success).length;
        _status = S.t.fa
            ? 'تمام — $ok endpoint سالم'
            : 'Done — $ok working endpoints';
      });

      final livePath = await _liveWriter?.finish();
      if (livePath != null && Platform.isWindows) {
        _snack(S.t.fa ? 'ذخیره: $livePath' : 'Saved: $livePath');
      }

      if (mounted && results.isNotEmpty) {
        Navigator.of(context).push(
          MaterialPageRoute(
            builder: (_) => CfResultsPage(
              phase2: results,
              phase1: _phase1,
              liveFilePath: livePath,
            ),
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _scanning = false;
          _status = 'Error: $e';
        });
      }
    }
  }

  void _stopScan() => setState(() => _cancelled = true);

  Future<void> _copyWorking() async {
    final lines = _phase2
        .where((r) => r.success)
        .map((r) => '${r.ip}:${r.phase1.port}')
        .toList();
    if (lines.isEmpty) {
      _snack(S.t.fa ? 'endpoint سالم نیست' : 'No working endpoints');
      return;
    }
    await ExportService.copyToClipboard(lines.join('\n'));
    _snack(S.t.fa ? 'کپی شد' : 'Copied');
  }

  Future<void> _exportResults() async {
    final buf = StringBuffer();
    buf.writeln('# MidONe Scanner CF export');
    for (final r in _phase2) {
      final mark = r.success ? '✓' : '✗';
      buf.writeln(
          '$mark ${r.ip}:${r.phase1.port} '
          '${r.validation.throughputMbps.toStringAsFixed(1)}Mbps '
          'lat=${r.validation.latencyMs.toStringAsFixed(0)}ms');
    }
    final path = await ExportService.saveText(buf.toString(), suggestedName: 'cf-ips.txt');
    if (path != null) _snack(S.t.fa ? 'ذخیره: $path' : 'Saved: $path');
  }

  void _snack(String m) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(m)));
  }

  @override
  Widget build(BuildContext context) {
    final s = S.t;
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: const Color(0xFF152018),
        borderRadius: BorderRadius.circular(18),
        border: Border.all(color: _border),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(
                child: Text('CLOUDFLARE — SenPai',
                    style: GoogleFonts.inter(
                        color: _textSecond, fontWeight: FontWeight.w700, fontSize: 11, letterSpacing: 1.2)),
              ),
              Text(
                Platform.isWindows ? 'Phase2: xray' : 'Phase2: TLS/WS',
                style: GoogleFonts.inter(color: _accent, fontSize: 10, fontWeight: FontWeight.w600),
              ),
            ],
          ),
          const SizedBox(height: 12),
          _rowLabel(s.cfSource),
          Row(
            children: [
              _chip(s.cfRandom, _sourceMode == 0, () => setState(() => _sourceMode = 0)),
              const SizedBox(width: 8),
              _chip(s.cfFromFile, _sourceMode == 1, () => _importIps()),
            ],
          ),
          if (_sourceMode == 1)
            Padding(
              padding: const EdgeInsets.only(top: 6),
              child: Text('${_fileIps.length} IPs',
                  style: GoogleFonts.inter(color: _accent, fontSize: 12)),
            ),
          const SizedBox(height: 10),
          if (_sourceMode == 0) ...[
            _rowLabel(s.cfCount),
            _presetRow(_counts.map((e) => '$e').toList(), _countIdx, (i) => setState(() => _countIdx = i)),
          ],
          _rowLabel(s.cfWorkers),
          _presetRow(_workers.map((e) => '$e').toList(), _workersIdx, (i) => setState(() => _workersIdx = i)),
          _rowLabel(s.cfTimeout),
          _presetRow(_timeouts.map((e) => '${e ~/ 1000}s').toList(), _timeoutIdx,
              (i) => setState(() => _timeoutIdx = i)),
          _rowLabel(s.cfPorts),
          Wrap(
            spacing: 6,
            runSpacing: 6,
            children: _allPorts.map((p) {
              final label = p == 0 ? 'Config' : '$p';
              final on = _selectedPorts.contains(p);
              return FilterChip(
                label: Text(label, style: const TextStyle(fontSize: 11)),
                selected: on,
                onSelected: (v) => setState(() {
                  if (v) {
                    _selectedPorts.add(p);
                  } else {
                    _selectedPorts.remove(p);
                  }
                  if (_selectedPorts.isEmpty) _selectedPorts.add(443);
                }),
                selectedColor: _accent.withOpacity(0.25),
                checkmarkColor: _accent,
              );
            }).toList(),
          ),
          const SizedBox(height: 10),
          _rowLabel(s.cfConfigUrl),
          TextField(
            controller: _configCtrl,
            style: GoogleFonts.robotoMono(color: Colors.white, fontSize: 11),
            maxLines: 2,
            decoration: InputDecoration(
              hintText: 'vless://... or trojan://... (empty = Phase 1 only)',
              hintStyle: GoogleFonts.inter(color: _textSecond, fontSize: 11),
              filled: true,
              fillColor: _cardInner,
              border: OutlineInputBorder(borderRadius: BorderRadius.circular(10), borderSide: const BorderSide(color: _border)),
            ),
          ),
          if (_configCtrl.text.trim().isNotEmpty || true) ...[
            const SizedBox(height: 8),
            _rowLabel(s.cfTopN),
            _presetRow(_topNs.map((e) => '$e').toList(), _topNIdx, (i) => setState(() => _topNIdx = i)),
          ],
          const SizedBox(height: 12),
          if (_scanning) ...[
            LinearProgressIndicator(
              value: _p1Total > 0 ? _p1Done / _p1Total : null,
              backgroundColor: _cardInner,
              color: _accent2,
            ),
            const SizedBox(height: 6),
            Text(_status, style: GoogleFonts.inter(color: _accent, fontSize: 12)),
          ],
          const SizedBox(height: 12),
          Row(
            children: [
              Expanded(
                child: ElevatedButton.icon(
                  onPressed: _scanning ? _stopScan : _startScan,
                  icon: Icon(_scanning ? Icons.stop : Icons.radar),
                  label: Text(_scanning ? s.stopScan : s.startScan),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: _scanning ? const Color(0xFFFF5252) : _accent,
                    foregroundColor: Colors.black,
                    padding: const EdgeInsets.symmetric(vertical: 14),
                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
                  ),
                ),
              ),
              if (_phase2.isNotEmpty) ...[
                const SizedBox(width: 8),
                IconButton(
                  onPressed: _copyWorking,
                  icon: const Icon(Icons.copy, color: _accent),
                  tooltip: s.copy,
                ),
                IconButton(
                  onPressed: _exportResults,
                  icon: const Icon(Icons.save_alt, color: _accent),
                  tooltip: s.export,
                ),
              ],
            ],
          ),
        ],
      ),
    );
  }

  Widget _rowLabel(String t) => Padding(
        padding: const EdgeInsets.only(bottom: 6, top: 4),
        child: Text(t, style: GoogleFonts.inter(color: _textSecond, fontSize: 11, fontWeight: FontWeight.w600)),
      );

  Widget _chip(String label, bool on, VoidCallback tap) => GestureDetector(
        onTap: tap,
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
          decoration: BoxDecoration(
            color: on ? _accent.withOpacity(0.2) : _cardInner,
            borderRadius: BorderRadius.circular(10),
            border: Border.all(color: on ? _accent : _border),
          ),
          child: Text(label,
              style: GoogleFonts.inter(
                  color: on ? _accent : _textSecond, fontWeight: FontWeight.w600, fontSize: 12)),
        ),
      );

  Widget _presetRow(List<String> labels, int selected, ValueChanged<int> onSelect) {
    return Row(
      children: List.generate(labels.length, (i) {
        final on = i == selected;
        return Expanded(
          child: Padding(
            padding: EdgeInsets.only(right: i < labels.length - 1 ? 6 : 0),
            child: GestureDetector(
              onTap: () => onSelect(i),
              child: Container(
                padding: const EdgeInsets.symmetric(vertical: 8),
                alignment: Alignment.center,
                decoration: BoxDecoration(
                  color: on ? _accent.withOpacity(0.15) : _cardInner,
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: on ? _accent : _border),
                ),
                child: Text(labels[i],
                    style: GoogleFonts.inter(
                        fontSize: 10,
                        fontWeight: FontWeight.w700,
                        color: on ? _accent : _textSecond)),
              ),
            ),
          ),
        );
      }),
    );
  }
}
