// lib/engine/adaptive_concurrency.dart
// p30: adaptiveConcurrencyController — dynamically adjusts concurrency based on network errors
// UPGRADED: min 2→4, max 24→50, initial 8→12 for Windows-level performance

class AdaptiveConcurrencyController {
  static final AdaptiveConcurrencyController _i =
      AdaptiveConcurrencyController._();
  factory AdaptiveConcurrencyController() => _i;
  AdaptiveConcurrencyController._();

  int _current = 12;
  int _errorCount = 0;
  int _successCount = 0;

  static const int _minConcurrency = 4;
  static const int _maxConcurrency = 50;
  static const int _scaleUpThreshold = 10;
  static const int _scaleDownThreshold = 5;
  static const int _scaleStep = 2;

  int get current => _current;

  /// Seed initial concurrency value.
  void seed(int value) {
    _current = value.clamp(_minConcurrency, _maxConcurrency);
    _errorCount = 0;
    _successCount = 0;
  }

  /// Call after a successful scan.
  void recordSuccess() {
    _successCount++;
    _errorCount = 0;
    if (_successCount >= _scaleUpThreshold && _current < _maxConcurrency) {
      _current = (_current + _scaleStep).clamp(_minConcurrency, _maxConcurrency);
      _successCount = 0;
    }
  }

  /// Call after a scan error (timeout, connection refused, etc.).
  void recordError() {
    _errorCount++;
    _successCount = 0;
    if (_errorCount >= _scaleDownThreshold && _current > _minConcurrency) {
      _current = (_current - _scaleStep).clamp(_minConcurrency, _maxConcurrency);
      _errorCount = 0;
    }
  }

  /// Reset to default concurrency.
  void reset() {
    _current = 12;
    _errorCount = 0;
    _successCount = 0;
  }

  /// Get concurrency capped by IP count and a hardcoded upper limit.
  int effectiveConcurrency({required int totalIps, int max = 50}) {
    if (totalIps < 20) return _current.clamp(_minConcurrency, 8);
    if (totalIps < 100) return _current.clamp(_minConcurrency, 16);
    return _current.clamp(_minConcurrency, max);
  }
}
