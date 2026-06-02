// lib/services/ai_service.dart
// AI Service for MidONe Scanner — connects to xiaomimimo API
// Model: deepseek or compatible via OpenAI-compatible endpoint

import 'dart:async';
import 'dart:convert';
import 'package:http/http.dart' as http;

const _aiBaseUrl  = 'https://api.xiaomimimo.com/v1';
const _aiApiKey   = 'sk-s0rhqo9qoztwvr2q4louxbekli9y1v2n04ymq2bu2d2sbxjq';
const _aiModel    = 'deepseek-chat';
const _aiTimeout  = Duration(seconds: 30);

class AiMessage {
  final String role;
  final String content;
  const AiMessage({required this.role, required this.content});

  Map<String, dynamic> toJson() => {'role': role, 'content': content};
}

class AiResponse {
  final String content;
  final bool ok;
  final String? error;

  const AiResponse({required this.content, required this.ok, this.error});
}

class AiService {
  static final AiService _i = AiService._();
  factory AiService() => _i;
  AiService._();

  final _client = http.Client();

  /// Send a chat completion request
  Future<AiResponse> chat({
    required List<AiMessage> messages,
    double temperature = 0.7,
    int maxTokens = 1024,
  }) async {
    try {
      final body = jsonEncode({
        'model': _aiModel,
        'messages': messages.map((m) => m.toJson()).toList(),
        'temperature': temperature,
        'max_tokens': maxTokens,
      });

      final response = await _client.post(
        Uri.parse('$_aiBaseUrl/chat/completions'),
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer $_aiApiKey',
        },
        body: body,
      ).timeout(_aiTimeout);

      if (response.statusCode == 200) {
        final data = jsonDecode(response.body) as Map<String, dynamic>;
        final choices = data['choices'] as List<dynamic>?;
        if (choices != null && choices.isNotEmpty) {
          final msg = choices[0]['message'] as Map<String, dynamic>?;
          final content = msg?['content'] as String? ?? '';
          return AiResponse(content: content, ok: true);
        }
        return const AiResponse(content: '', ok: false, error: 'No choices in response');
      } else {
        return AiResponse(
          content: '',
          ok: false,
          error: 'HTTP ${response.statusCode}: ${response.body}',
        );
      }
    } on TimeoutException {
      return const AiResponse(content: '', ok: false, error: 'Request timed out');
    } catch (e) {
      return AiResponse(content: '', ok: false, error: e.toString());
    }
  }

  /// Simple one-shot question
  Future<AiResponse> ask(String question) {
    return chat(messages: [
      const AiMessage(role: 'system', content: 'You are a helpful assistant for MidONe Scanner, an Android CDN IP scanner app.'),
      AiMessage(role: 'user', content: question),
    ]);
  }

  /// Analyze scan results and give recommendations
  Future<AiResponse> analyzeScanResults({
    required int totalScanned,
    required int aliveCount,
    required int excellentCount,
    required int goodCount,
    required double avgLatencyMs,
    required List<String> topIps,
  }) {
    final summary = '''
Scan Results:
- Total scanned: $totalScanned
- Alive: $aliveCount (${totalScanned > 0 ? (aliveCount / totalScanned * 100).toStringAsFixed(1) : 0}%)
- Excellent: $excellentCount
- Good: $goodCount
- Average latency: ${avgLatencyMs.toStringAsFixed(1)}ms
- Top IPs: ${topIps.take(5).join(', ')}
''';
    return chat(messages: [
      const AiMessage(
        role: 'system',
        content: 'You are an expert CDN IP analyzer. Analyze scan results and give concise, actionable recommendations in Persian (Farsi).',
      ),
      AiMessage(
        role: 'user',
        content: 'نتایج اسکن زیر رو تحلیل کن و پیشنهاد بده:\n$summary',
      ),
    ], maxTokens: 512);
  }

  void dispose() {
    _client.close();
  }
}
