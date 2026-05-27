// lib/utils/stats_utils.dart
import 'dart:math';

double calcJitter(List<double> samples) {
  if (samples.length < 2) return 0;

  final avg = samples.reduce((a, b) => a + b) / samples.length;

  final variance = samples
      .map((x) => pow(x - avg, 2))
      .reduce((a, b) => a + b) /
      (samples.length - 1); // BUGFIX: sample variance (Bessel's correction), not population variance

  return sqrt(variance);
}

double calcDrift(List<double> samples) {
  if (samples.length < 2) return 0;

  return samples.last - samples.first;
}
