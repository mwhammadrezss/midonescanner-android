// lib/app/app_palette.dart
// Mutable global palette — forest (default) or darker clean dark theme.

import 'package:flutter/material.dart';

late Color bgColor      = const Color(0xFF0A1A0F);
late Color cardColor    = const Color(0xFF112216);
late Color card2Color   = const Color(0xFF0D1A11);
late Color cardInner    = const Color(0xFF1A3020);
late Color accentLime   = const Color(0xFFC6F135);
late Color accentLime2  = const Color(0xFFA8D400);
late Color textPrimary  = const Color(0xFFFFFFFF);
late Color textSecond   = const Color(0xFF8A9E8E);
late Color iconBg       = const Color(0xFF1E3525);
late Color borderColor  = const Color(0xFF2A4A30);
late Color statusGreen  = const Color(0xFF1A3A1E);
late Color statusRed    = const Color(0xFF3A1A1A);
late Color statusOrange = const Color(0xFF3A2A1A);

void applyAppPalette(String themeId) {
  if (themeId == 'dark') {
    bgColor      = const Color(0xFF000000);
    cardColor    = const Color(0xFF080808);
    card2Color   = const Color(0xFF030303);
    cardInner    = const Color(0xFF0E0E0E);
    accentLime   = const Color(0xFFE6EE9C);
    accentLime2  = const Color(0xFFC0CA33);
    textPrimary  = const Color(0xFFFAFAFA);
    textSecond   = const Color(0xFF757575);
    iconBg       = const Color(0xFF101010);
    borderColor  = const Color(0xFF1F1F1F);
    statusGreen  = const Color(0xFF152015);
    statusRed    = const Color(0xFF1A1010);
    statusOrange = const Color(0xFF1A1610);
  } else {
    bgColor      = const Color(0xFF0A1A0F);
    cardColor    = const Color(0xFF112216);
    card2Color   = const Color(0xFF0D1A11);
    cardInner    = const Color(0xFF1A3020);
    accentLime   = const Color(0xFFC6F135);
    accentLime2  = const Color(0xFFA8D400);
    textPrimary  = const Color(0xFFFFFFFF);
    textSecond   = const Color(0xFF8A9E8E);
    iconBg       = const Color(0xFF1E3525);
    borderColor  = const Color(0xFF2A4A30);
    statusGreen  = const Color(0xFF1A3A1E);
    statusRed    = const Color(0xFF3A1A1A);
    statusOrange = const Color(0xFF3A2A1A);
  }
}
