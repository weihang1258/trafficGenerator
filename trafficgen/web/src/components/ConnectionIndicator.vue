<template>
  <span class="connection-indicator" :class="statusClass" :aria-label="statusText">
    <span class="status-dot" />
    <span class="status-label">{{ statusText }}</span>
  </span>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const props = defineProps<{
  connected: boolean
  error?: string | null
}>()

const statusClass = computed(() => {
  if (props.error) return 'disconnected'
  return props.connected ? 'live' : 'polling'
})

const statusText = computed(() => {
  if (props.error) return t('task.disconnected')
  return props.connected ? t('task.live') : t('task.polling')
})
</script>

<style scoped>
.connection-indicator {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
}

.status-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  display: inline-block;
}

.live .status-dot {
  background-color: var(--tg-success, #67c23a);
  box-shadow: 0 0 4px var(--tg-success, #67c23a);
}

.polling .status-dot {
  background-color: var(--tg-warning, #e6a23c);
}

.disconnected .status-dot {
  background-color: var(--tg-danger, #f56c6c);
}

.status-label {
  color: var(--tg-text-secondary, #64748b);
}
</style>
