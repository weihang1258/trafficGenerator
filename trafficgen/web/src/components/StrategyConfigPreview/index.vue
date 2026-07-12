<template>
  <el-card shadow="never" class="strategy-preview">
    <template #header>
      <div class="preview-header">
        <span class="preview-name">{{ strategy.name }}</span>
        <el-tag size="small" effect="plain">{{ strategy.protocol.toUpperCase() }}</el-tag>
      </div>
    </template>

    <!-- Network Config -->
    <el-divider content-position="left">{{ t('strategy.sectionNetworkConfig') }}</el-divider>
    <el-descriptions :column="2" border size="small">
      <el-descriptions-item :label="t('strategy.srcIP')">{{ displayValue(config?.src_ip) }}</el-descriptions-item>
      <el-descriptions-item :label="t('strategy.dstIP')">{{ displayValue(config?.dst_ip) }}</el-descriptions-item>
      <el-descriptions-item :label="t('strategy.srcPort')">{{ displayValue(config?.src_port) }}</el-descriptions-item>
      <el-descriptions-item :label="t('strategy.dstPort')">{{ displayValue(config?.dst_port) }}</el-descriptions-item>
    </el-descriptions>

    <!-- L2/L3 Config -->
    <el-divider content-position="left">{{ t('strategy.sectionL2L3Config') }}</el-divider>
    <el-descriptions :column="2" border size="small">
      <el-descriptions-item :label="t('strategy.srcMAC')">{{ config?.src_mac || '-' }}</el-descriptions-item>
      <el-descriptions-item :label="t('strategy.dstMAC')">{{ config?.dst_mac || '-' }}</el-descriptions-item>
      <el-descriptions-item :label="t('strategy.vlan')">
        {{ config?.vlan_id ? `ID: ${config.vlan_id}` : t('strategy.vlanEnable') + ': No' }}
      </el-descriptions-item>
      <el-descriptions-item :label="t('strategy.ttl')">{{ config?.ttl ?? 64 }}</el-descriptions-item>
      <el-descriptions-item :label="t('strategy.tos')">{{ config?.tos ?? 0 }}</el-descriptions-item>
    </el-descriptions>

    <!-- Protocol-specific config -->
    <el-divider content-position="left">{{ t('strategy.sectionProtocolConfig') }}</el-divider>

    <!-- TCP -->
    <el-descriptions v-if="strategy.protocol === 'tcp'" :column="2" border size="small">
      <el-descriptions-item :label="t('strategy.handshake')">{{ config?.tcp?.handshake ? t('common.yes') : t('common.no') }}</el-descriptions-item>
      <el-descriptions-item :label="t('strategy.termination')">{{ config?.tcp?.termination ? t('common.yes') : t('common.no') }}</el-descriptions-item>
      <el-descriptions-item :label="t('strategy.mss')">{{ config?.tcp?.mss ?? '-' }}</el-descriptions-item>
      <el-descriptions-item :label="t('strategy.windowSize')">{{ config?.tcp?.window_size ?? '-' }}</el-descriptions-item>
    </el-descriptions>

    <!-- UDP -->
    <el-descriptions v-if="strategy.protocol === 'udp'" :column="2" border size="small">
      <el-descriptions-item :label="t('strategy.udpResponse')">{{ config?.udp?.response ? t('common.yes') : t('common.no') }}</el-descriptions-item>
    </el-descriptions>

    <!-- HTTP -->
    <template v-if="strategy.protocol === 'http'">
      <el-descriptions :column="2" border size="small">
        <el-descriptions-item :label="t('strategy.method')">
          <el-tag v-for="m in (config?.http?.methods || [])" :key="m" size="small" effect="plain" style="margin-right: 4px;">{{ m }}</el-tag>
          <span v-if="!config?.http?.methods?.length">-</span>
        </el-descriptions-item>
        <el-descriptions-item :label="t('strategy.uri')">{{ displayValue(config?.http?.uri) }}</el-descriptions-item>
        <el-descriptions-item :label="t('strategy.keepAlive')">{{ config?.http?.keep_alive ? t('common.yes') : t('common.no') }}</el-descriptions-item>
        <el-descriptions-item :label="t('strategy.transactions')">{{ config?.http?.transactions ?? '-' }}</el-descriptions-item>
        <el-descriptions-item :label="t('strategy.thinkTime')">{{ config?.http?.think_time ?? '-' }}</el-descriptions-item>
      </el-descriptions>
      <!-- Headers -->
      <div v-if="config?.http?.headers && config.http.headers.length > 0" style="margin-top: 8px;">
        <el-descriptions :column="1" border size="small" :title="t('strategy.headers')">
          <el-descriptions-item v-for="(h, idx) in config.http.headers" :key="idx" :label="h.key || `Header ${idx + 1}`">
            {{ h.value || '-' }}
          </el-descriptions-item>
        </el-descriptions>
      </div>
      <!-- Body -->
      <div v-if="config?.http?.body" style="margin-top: 8px;">
        <el-descriptions :column="1" border size="small">
          <el-descriptions-item :label="t('strategy.body')">
            <pre class="body-preview">{{ truncateBody(config.http.body) }}</pre>
          </el-descriptions-item>
        </el-descriptions>
      </div>
    </template>

    <!-- DNS -->
    <el-descriptions v-if="strategy.protocol === 'dns'" :column="2" border size="small">
      <el-descriptions-item :label="t('strategy.domain')">{{ config?.dns?.domain || '-' }}</el-descriptions-item>
      <el-descriptions-item :label="t('strategy.queryType')">{{ config?.dns?.query_type ?? '-' }}</el-descriptions-item>
      <el-descriptions-item :label="t('strategy.dnsResponse')">{{ config?.dns?.response ? t('common.yes') : t('common.no') }}</el-descriptions-item>
      <el-descriptions-item :label="t('strategy.responseIP')">{{ config?.dns?.response_ip || '-' }}</el-descriptions-item>
    </el-descriptions>

    <!-- ICMP -->
    <el-descriptions v-if="strategy.protocol === 'icmp'" :column="2" border size="small">
      <el-descriptions-item :label="t('strategy.icmpType')">{{ config?.icmp?.type ?? '-' }}</el-descriptions-item>
      <el-descriptions-item :label="t('strategy.icmpCode')">{{ config?.icmp?.code ?? '-' }}</el-descriptions-item>
      <el-descriptions-item :label="t('strategy.sequence')">{{ config?.icmp?.sequence ?? '-' }}</el-descriptions-item>
      <el-descriptions-item :label="t('strategy.icmpData')">{{ config?.icmp?.data || '-' }}</el-descriptions-item>
    </el-descriptions>

    <!-- ARP -->
    <el-descriptions v-if="strategy.protocol === 'arp'" :column="2" border size="small">
      <el-descriptions-item :label="t('strategy.operation')">{{ config?.arp?.operation ?? '-' }}</el-descriptions-item>
      <el-descriptions-item :label="t('strategy.targetMAC')">{{ config?.arp?.target_mac || '-' }}</el-descriptions-item>
      <el-descriptions-item :label="t('strategy.targetIP')">{{ config?.arp?.target_ip || '-' }}</el-descriptions-item>
    </el-descriptions>

    <!-- Flow Control -->
    <template v-if="strategy.flow_control">
      <el-divider content-position="left">{{ t('strategy.sectionFlowControl') }}</el-divider>
      <el-descriptions :column="2" border size="small">
        <el-descriptions-item :label="t('strategy.flowControlType')">{{ flowControlLabel(strategy.flow_control.type) }}</el-descriptions-item>
        <el-descriptions-item :label="t('strategy.flowControlValue')">{{ strategy.flow_control.value }} {{ flowControlUnit(strategy.flow_control.type) }}</el-descriptions-item>
      </el-descriptions>
    </template>

    <!-- Payload -->
    <template v-if="config?.payload">
      <el-divider content-position="left">{{ t('strategy.payload') }}</el-divider>
      <el-descriptions :column="1" border size="small">
        <el-descriptions-item :label="t('strategy.payload')">
          <pre class="body-preview">{{ truncateBody(config.payload) }}</pre>
        </el-descriptions-item>
      </el-descriptions>
    </template>
  </el-card>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import type { Strategy } from '@/api'

const { t } = useI18n()

const props = defineProps<{
  strategy: Strategy
}>()

const config = computed(() => props.strategy.config || {})

function displayValue(val: any): string {
  if (!val) return '-'
  if (typeof val === 'object' && val.strategy) {
    if (val.strategy === 'fixed') return String(val.value || '-')
    if (val.strategy === 'inc') return `${val.range?.[0] ?? '?'} ~ ${val.range?.[1] ?? '?'} (step ${val.step ?? 1})`
    if (val.strategy === 'random') return `${val.range?.[0] ?? '?'} ~ ${val.range?.[1] ?? '?'} (random)`
    if (val.strategy === 'pattern') return `${val.pattern || '-'} (n: ${val.n_range?.[0] ?? '?'}~${val.n_range?.[1] ?? '?'})`
    if (val.strategy === 'list') return (val.list || []).join(', ') || '-'
    if (val.strategy === 'file') return `file: ${val.path || '-'}`
  }
  return String(val)
}

function flowControlLabel(type: string): string {
  const map: Record<string, string> = {
    flows: t('strategy.flows'),
    cps: t('strategy.cps'),
    bps: t('strategy.bps'),
    ratio: t('strategy.ratio'),
    time: t('strategy.time')
  }
  return map[type] || type
}

function flowControlUnit(type: string): string {
  const map: Record<string, string> = {
    flows: t('strategy.unitFlows'),
    bps: t('strategy.unitBps'),
    cps: t('strategy.unitCps'),
    ratio: t('strategy.unitRatio'),
    time: t('strategy.unitTime')
  }
  return map[type] || ''
}

function truncateBody(body: string): string {
  if (!body) return '-'
  if (body.length > 200) return body.substring(0, 200) + '...'
  return body
}
</script>

<style scoped>
.strategy-preview {
  margin-bottom: 12px;
}

.strategy-preview :deep(.el-card__header) {
  padding: 12px 16px;
  border-bottom: 1px solid var(--tg-border-light, #E5E7EB);
}

.strategy-preview :deep(.el-card__body) {
  padding: 8px 16px 16px;
}

.preview-header {
  display: flex;
  align-items: center;
  gap: 8px;
}

.preview-name {
  font-weight: 600;
  color: var(--tg-text-primary, #0F172A);
}

.body-preview {
  background: var(--tg-bg-page, #f5f7fa);
  padding: 8px;
  border-radius: 4px;
  font-family: 'SF Mono', 'Monaco', 'Menlo', 'Consolas', monospace;
  font-size: 12px;
  line-height: 1.6;
  white-space: pre-wrap;
  word-break: break-all;
  margin: 0;
  color: var(--tg-text-body, #606266);
  max-height: 120px;
  overflow-y: auto;
}
</style>