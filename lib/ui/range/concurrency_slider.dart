// lib/ui/range/concurrency_slider.dart
// Concurrency slider widget

import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

const _accentLime  = Color(0xFFC6F135);
const _textPrimary = Color(0xFFFFFFFF);
const _textSecond  = Color(0xFF8A9E8E);
const _iconBg      = Color(0xFF1E3525);
const _borderColor = Color(0xFF2A4A30);

class ConcurrencySlider extends StatefulWidget {
  final int value;
  final ValueChanged<int> onChanged;
  final int min;
  final int max;

  const ConcurrencySlider({
    super.key,
    required this.value,
    required this.onChanged,
    this.min = 50,
    this.max = 1000,
  });

  @override
  State<ConcurrencySlider> createState() => _ConcurrencySliderState();
}

class _ConcurrencySliderState extends State<ConcurrencySlider> {
  late double _current;

  @override
  void initState() {
    super.initState();
    _current = widget.value.toDouble();
  }

  @override
  void didUpdateWidget(ConcurrencySlider old) {
    super.didUpdateWidget(old);
    _current = widget.value.toDouble();
  }

  String _label(double v) {
    final i = v.toInt();
    if (i >= 1000) return '${(i / 1000).toStringAsFixed(1)}K';
    return '$i';
  }

  @override
  Widget build(BuildContext context) {
    final steps = (widget.max - widget.min) ~/ 50;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Text(
              'CONCURRENCY',
              style: GoogleFonts.inter(
                color: _textSecond,
                fontWeight: FontWeight.w700,
                fontSize: 11,
                letterSpacing: 1.2,
              ),
            ),
            const Spacer(),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
              decoration: BoxDecoration(
                color: _accentLime.withOpacity(0.12),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: _accentLime.withOpacity(0.4)),
              ),
              child: Text(
                _label(_current),
                style: GoogleFonts.inter(
                  color: _accentLime,
                  fontWeight: FontWeight.w800,
                  fontSize: 13,
                ),
              ),
            ),
          ],
        ),
        const SizedBox(height: 4),
        SliderTheme(
          data: SliderTheme.of(context).copyWith(
            activeTrackColor: _accentLime,
            inactiveTrackColor: _iconBg,
            thumbColor: _accentLime,
            overlayColor: _accentLime.withOpacity(0.15),
            thumbShape: const RoundSliderThumbShape(enabledThumbRadius: 10),
            trackHeight: 4,
          ),
          child: Slider(
            value: _current.clamp(widget.min.toDouble(), widget.max.toDouble()),
            min: widget.min.toDouble(),
            max: widget.max.toDouble(),
            divisions: steps,
            onChanged: (v) {
              setState(() => _current = v);
              widget.onChanged(v.toInt());
            },
          ),
        ),
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Text('${widget.min}',
                style: GoogleFonts.inter(color: _textSecond, fontSize: 10)),
            Text('${widget.max}',
                style: GoogleFonts.inter(color: _textSecond, fontSize: 10)),
          ],
        ),
      ],
    );
  }
}
