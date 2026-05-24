// lib/engine/tls_engine.dart
import 'dart:io';

bool validateCert(X509Certificate cert) {
  if (cert.pem.isEmpty) return false;

  final now = DateTime.now();

  if (now.isBefore(cert.startValidity)) return false;
  if (now.isAfter(cert.endValidity))    return false;

  return true;
}

bool isFrontingCompatible({
  required String sni,
  required String certCn,
}) {
  return !certCn.contains(sni);
}
