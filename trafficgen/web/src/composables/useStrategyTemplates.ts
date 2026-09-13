import { ref } from 'vue'
import { useI18n } from 'vue-i18n'

const STORAGE_KEY = 'strategy-templates'

export interface StrategyTemplate {
  id: string
  name: string
  description: string
  protocol: string
  config: Record<string, any>
  flow_control?: { type: string; value: number }
  isBuiltin?: boolean
}

function getBuiltinTemplates(t: (key: string) => string): StrategyTemplate[] {
  return [
    {
      id: 'builtin-tcp-handshake',
      name: t('strategy.templateTcpHandshake'),
      description: t('strategy.templateTcpHandshakeDesc'),
      protocol: 'tcp',
      config: {
        src_ip: '192.168.1.100', dst_ip: '192.168.1.1',
        src_port: 12345, dst_port: 80,
        ttl: 64, tos: 0,
        tcp: { handshake: true, termination: true, mss: 1460, window_size: 65535 }
      },
      isBuiltin: true
    },
    {
      id: 'builtin-http-get',
      name: t('strategy.templateHttpGet'),
      description: t('strategy.templateHttpGetDesc'),
      protocol: 'http',
      config: {
        src_ip: '192.168.1.100', dst_ip: '192.168.1.1',
        src_port: 12345, dst_port: 80,
        ttl: 64, tos: 0,
        http: { method: 'GET', uri: '/', headers: {}, body: '', keep_alive: true, transactions: 10 }
      },
      isBuiltin: true
    },
    {
      id: 'builtin-http-post',
      name: t('strategy.templateHttpPost'),
      description: t('strategy.templateHttpPostDesc'),
      protocol: 'http',
      config: {
        src_ip: '192.168.1.100', dst_ip: '192.168.1.1',
        src_port: 12345, dst_port: 80,
        ttl: 64, tos: 0,
        http: { method: 'POST', uri: '/api/data', headers: { 'Content-Type': 'application/json' }, body: '{"key":"value"}', keep_alive: false, transactions: 1 }
      },
      isBuiltin: true
    },
    {
      id: 'builtin-udp-stream',
      name: t('strategy.templateUdpStream'),
      description: t('strategy.templateUdpStreamDesc'),
      protocol: 'udp',
      config: {
        src_ip: '192.168.1.100', dst_ip: '192.168.1.1',
        src_port: 12345, dst_port: 5000,
        ttl: 64, tos: 0,
        udp: { response: false }
      },
      isBuiltin: true
    },
    {
      id: 'builtin-dns-query',
      name: t('strategy.templateDnsQuery'),
      description: t('strategy.templateDnsQueryDesc'),
      protocol: 'dns',
      config: {
        src_ip: '192.168.1.100', dst_ip: '8.8.8.8',
        src_port: 12345, dst_port: 53,
        ttl: 64, tos: 0,
        dns: { domain: 'example.com', query_type: 1, response: false, response_ip: '' }
      },
      isBuiltin: true
    },
    {
      id: 'builtin-icmp-ping',
      name: t('strategy.templateIcmpPing'),
      description: t('strategy.templateIcmpPingDesc'),
      protocol: 'icmp',
      config: {
        src_ip: '192.168.1.100', dst_ip: '192.168.1.1',
        ttl: 64, tos: 0,
        icmp: { type: 8, code: 0, sequence: 1, data: 'ping' }
      },
      isBuiltin: true
    },
    {
      id: 'builtin-arp-request',
      name: t('strategy.templateArpRequest'),
      description: t('strategy.templateArpRequestDesc'),
      protocol: 'arp',
      config: {
        src_ip: '192.168.1.100', dst_ip: '192.168.1.1',
        arp: { operation: 1, target_mac: '', target_ip: '192.168.1.1' }
      },
      isBuiltin: true
    },
    {
      id: 'builtin-tcp-pressure',
      name: t('strategy.templateTcpPressure'),
      description: t('strategy.templateTcpPressureDesc'),
      protocol: 'tcp',
      config: {
        src_ip: '192.168.1.100', dst_ip: '192.168.1.1',
        src_port: 12345, dst_port: 80,
        ttl: 64, tos: 0,
        tcp: { handshake: true, termination: true, mss: 1460, window_size: 65535 }
      },
      flow_control: { type: 'bps', value: 1000 },
      isBuiltin: true
    }
  ]
}

function loadCustomTemplates(): StrategyTemplate[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (raw) return JSON.parse(raw)
  } catch {}
  return []
}

function saveCustomTemplates(templates: StrategyTemplate[]) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(templates))
}

export function useStrategyTemplates() {
  const { t } = useI18n()
  const customTemplates = ref<StrategyTemplate[]>(loadCustomTemplates())

  const allTemplates = ref<StrategyTemplate[]>([
    ...getBuiltinTemplates(t),
    ...customTemplates.value
  ])

  function addTemplate(template: Omit<StrategyTemplate, 'id' | 'isBuiltin'>) {
    const newTemplate: StrategyTemplate = {
      ...template,
      id: 'custom-' + Date.now().toString(36),
      isBuiltin: false
    }
    customTemplates.value.push(newTemplate)
    saveCustomTemplates(customTemplates.value)
    allTemplates.value = [...getBuiltinTemplates(t), ...customTemplates.value]
    return newTemplate
  }

  function deleteTemplate(id: string) {
    customTemplates.value = customTemplates.value.filter(t => t.id !== id)
    saveCustomTemplates(customTemplates.value)
    allTemplates.value = [...getBuiltinTemplates(t), ...customTemplates.value]
  }

  function getTemplate(id: string): StrategyTemplate | undefined {
    return allTemplates.value.find(t => t.id === id)
  }

  return {
    allTemplates,
    customTemplates,
    addTemplate,
    deleteTemplate,
    getTemplate
  }
}
