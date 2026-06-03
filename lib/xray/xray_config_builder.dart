// Builds minimal xray-core JSON (SenPai internal/xraytest/builder.go parity).

import 'dart:convert';
import 'config_parser.dart';

String buildXrayConfigJson(XrayConfig cfg, int socksPort) {
  final map = <String, dynamic>{
    'log': {'loglevel': 'none', 'access': '', 'error': ''},
    'dns': {
      'servers': ['1.1.1.1', '8.8.8.8'],
    },
    'inbounds': [
      {
        'tag': 'socks-in',
        'port': socksPort,
        'listen': '127.0.0.1',
        'protocol': 'socks',
        'sniffing': {
          'enabled': true,
          'destOverride': ['http', 'tls'],
        },
        'settings': {'udp': true},
      },
    ],
    'outbounds': [
      _buildOutbound(cfg),
      {
        'tag': 'direct',
        'protocol': 'freedom',
        'settings': <String, dynamic>{},
      },
    ],
  };
  return const JsonEncoder.withIndent('  ').convert(map);
}

Map<String, dynamic> _buildOutbound(XrayConfig cfg) {
  if (cfg.protocol == 'trojan') return _buildTrojanOutbound(cfg);
  return _buildVlessOutbound(cfg);
}

Map<String, dynamic> _buildVlessOutbound(XrayConfig cfg) {
  final user = <String, dynamic>{
    'id': cfg.uuid,
    'encryption': cfg.encryption,
  };
  if (cfg.flow.isNotEmpty) user['flow'] = cfg.flow;

  return {
    'tag': 'proxy',
    'protocol': 'vless',
    'settings': {
      'vnext': [
        {
          'address': cfg.address,
          'port': cfg.port,
          'users': [user],
        },
      ],
    },
    'streamSettings': _buildStreamSettings(cfg),
  };
}

Map<String, dynamic> _buildTrojanOutbound(XrayConfig cfg) {
  return {
    'tag': 'proxy',
    'protocol': 'trojan',
    'settings': {
      'servers': [
        {
          'address': cfg.address,
          'port': cfg.port,
          'password': cfg.password,
        },
      ],
    },
    'streamSettings': _buildStreamSettings(cfg),
  };
}

Map<String, dynamic> _buildStreamSettings(XrayConfig cfg) {
  final stream = <String, dynamic>{
    'network': cfg.network,
    'security': cfg.security,
  };

  if (cfg.security == 'tls') {
    final tls = <String, dynamic>{};
    if (cfg.sni.isNotEmpty) tls['serverName'] = cfg.sni;
    if (cfg.fingerprint.isNotEmpty) tls['fingerprint'] = cfg.fingerprint;
    if (cfg.insecure) tls['allowInsecure'] = true;
    if (cfg.alpn.isNotEmpty) tls['alpn'] = cfg.alpn;
    stream['tlsSettings'] = tls;
  }

  switch (cfg.network) {
    case 'ws':
      final ws = <String, dynamic>{'path': cfg.path};
      if (cfg.host.isNotEmpty) {
        ws['headers'] = {'Host': cfg.host};
      }
      stream['wsSettings'] = ws;
      break;
    case 'grpc':
      final grpc = <String, dynamic>{'serviceName': cfg.serviceName};
      if (cfg.authority.isNotEmpty) grpc['authority'] = cfg.authority;
      if (cfg.mode == 'multi') grpc['multiMode'] = true;
      stream['grpcSettings'] = grpc;
      break;
    case 'xhttp':
    case 'splithttp':
      final xhttp = <String, dynamic>{'path': cfg.path};
      if (cfg.host.isNotEmpty) {
        xhttp['headers'] = {'Host': cfg.host};
      }
      if (cfg.mode.isNotEmpty) xhttp['mode'] = cfg.mode;
      stream['xhttpSettings'] = xhttp;
      break;
  }

  return stream;
}
