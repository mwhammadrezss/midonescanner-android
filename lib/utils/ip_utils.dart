// lib/utils/ip_utils.dart

bool isPrivateOrReserved(String ip) {
  final parts = ip.split('.');
  if (parts.length != 4) return true;
  final o = parts.map((p) => int.tryParse(p) ?? -1).toList();
  if (o.any((x) => x < 0 || x > 255)) return true;

  if (o[0] == 0)   return true;
  if (o[0] == 10)  return true;
  if (o[0] == 100 && o[1] >= 64 && o[1] <= 127) return true;
  if (o[0] == 127) return true;
  if (o[0] == 169 && o[1] == 254) return true;
  if (o[0] == 172 && o[1] >= 16 && o[1] <= 31) return true;
  if (o[0] == 192 && o[1] == 168) return true;
  if (o[0] >= 224 && o[0] <= 239) return true;
  if (o[0] >= 240) return true;

  return false;
}

List<String> validateAndExtractIps(String rawText) {
  final ipRegex = RegExp(
    r'\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))\b',
  );
  return ipRegex
      .allMatches(rawText)
      .map((m) => m.group(1)!)
      .where((ip) => !isPrivateOrReserved(ip))
      .toSet()
      .toList();
}
