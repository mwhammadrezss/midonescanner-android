// lib/engine/concurrency_engine.dart
import 'dart:async';

class Semaphore {
  int _count;
  final _waiters = <Completer<void>>[];

  Semaphore(this._count);

  Future<void> acquire() async {
    if (_count > 0) {
      _count--;
      return;
    }
    final c = Completer<void>();
    _waiters.add(c);
    await c.future;
  }

  void release() {
    if (_waiters.isNotEmpty) {
      final c = _waiters.removeAt(0);
      c.complete();
    } else {
      _count++;
    }
  }

  /// Dynamically increase the semaphore capacity (e.g. when adaptive controller scales up).
  /// Wakes waiting tasks up to [extra] slots.
  void expand(int extra) {
    for (int i = 0; i < extra; i++) {
      if (_waiters.isNotEmpty) {
        _waiters.removeAt(0).complete();
      } else {
        _count++;
      }
    }
  }
}
