// lib/ui/range/provider_selector.dart
// CDN provider grid selector widget

import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import '../../engine/range/cidr_provider_service.dart';
import '../../core/l10n/strings.dart';

const _bgColor     = Color(0xFF0A1A0F);
const _cardColor   = Color(0xFF112216);
const _accentLime  = Color(0xFFC6F135);
const _textPrimary = Color(0xFFFFFFFF);
const _textSecond  = Color(0xFF8A9E8E);
const _borderColor = Color(0xFF2A4A30);
const _iconBg      = Color(0xFF1E3525);

class RangeProviderSelector extends StatelessWidget {
  final RangeCdnProvider? selected;
  final ValueChanged<RangeCdnMeta> onSelect;

  const RangeProviderSelector({
    super.key,
    required this.selected,
    required this.onSelect,
  });

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          S.t.cdnProvider,
          style: GoogleFonts.inter(
            color: _textSecond,
            fontWeight: FontWeight.w700,
            fontSize: 11,
            letterSpacing: 1.2,
          ),
        ),
        const SizedBox(height: 10),
        GridView.builder(
          shrinkWrap: true,
          physics: const NeverScrollableScrollPhysics(),
          gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
            crossAxisCount: 3,
            crossAxisSpacing: 8,
            mainAxisSpacing: 8,
            childAspectRatio: 2.4,
          ),
          itemCount: kRangeCdnProviders.length,
          itemBuilder: (ctx, i) {
            final meta = kRangeCdnProviders[i];
            final isSelected = selected == meta.provider;
            return GestureDetector(
              onTap: () => onSelect(meta),
              child: AnimatedContainer(
                duration: const Duration(milliseconds: 180),
                decoration: BoxDecoration(
                  color: isSelected ? _accentLime.withOpacity(0.12) : _iconBg,
                  borderRadius: BorderRadius.circular(10),
                  border: Border.all(
                    color: isSelected ? _accentLime : _borderColor,
                    width: isSelected ? 1.5 : 1,
                  ),
                ),
                alignment: Alignment.center,
                child: Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    Text(meta.emoji, style: const TextStyle(fontSize: 16)),
                    const SizedBox(height: 2),
                    Text(
                      meta.name,
                      style: GoogleFonts.inter(
                        color: isSelected ? _accentLime : _textPrimary,
                        fontWeight: FontWeight.w600,
                        fontSize: 10,
                      ),
                      textAlign: TextAlign.center,
                    ),
                  ],
                ),
              ),
            );
          },
        ),
      ],
    );
  }
}
