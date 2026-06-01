// lib/engine/range/worker_pool.dart
// Semaphore-based worker pool with dynamic concurrency

import 'dart:async';

class WorkerPool {
  int _concurrency;
  int _active = 0;
  final List<Completer<void>> _waiters = [];
  bool _disposed = false;

  WorkerPool({required int concurrency})
      : _concurrency = concurrency.clamp(1, 2000);

  int get concurrency => _concurrency;
  int get activeCount => _active;

  set concurrency(int v) {
    final newVal = v.clamp(1, 2000);
    final oldVal = _concurrency;
    _concurrency = newVal;
    // If we increased concurrency, wake up waiting tasks
    if (newVal > oldVal) {
      final extra = newVal - oldVal;
      for (int i = 0; i < extra && _waiters.isNotEmpty; i++) {
        _waiters.removeAt(0).complete();
      }
    }
  }

  /// Acquire a slot, run the task, release the slot
  Future<T> run<T>(Future<T> Function() task) async {
    await _acquire();
    try {
      return await task();
    } finally {
      _release();
    }
  }

  /// Run all items through [worker], respecting concurrency and cancellation
  Future<void> runBatch<T>(
    List<T> items,
    Future<void> Function(T item) worker, {
    bool Function()? isCancelled,
  }) async {
    final futures = items.map((item) async {
      if (_disposed) return;
      if (isCancelled != null && isCancelled()) return;
      await run(() => worker(item));
    }).toList();
    await Future.wait(futures);
  }

  Future<void> _acquire() async {
    while (_active >= _concurrency) {
      if (_disposed) return;
      final c = Completer<void>();
      _waiters.add(c);
      await c.future;
      // Re-check disposed after waking — dispose() may have woken us
      if (_disposed) return;
    }
    _active++;
  }

  void _release() {
    _active = (_active - 1).clamp(0, _concurrency + _waiters.length);
    if (_waiters.isNotEmpty) {
      _waiters.removeAt(0).complete();
    }
  }

  void dispose() {
    _disposed = true;
    // Wake all waiters so they can exit
    for (final c in _waiters) {
      if (!c.isCompleted) c.complete();
    }
    _waiters.clear();
  }
}
