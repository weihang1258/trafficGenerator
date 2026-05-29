<template>
  <el-tag :type="statusType" :effect="effect" :size="size">
    {{ statusText }}
  </el-tag>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

interface Props {
  status?: string
  size?: 'large' | 'default' | 'small'
  effect?: 'dark' | 'light' | 'plain'
}

const props = withDefaults(defineProps<Props>(), {
  status: 'pending',
  size: 'default',
  effect: 'light'
})

const statusConfig: Record<string, { type: string; i18nKey: string }> = {
  pending: { type: 'info', i18nKey: 'task.pending' },
  created: { type: 'info', i18nKey: 'task.pending' },
  running: { type: 'success', i18nKey: 'task.running' },
  completed: { type: '', i18nKey: 'task.completed' },
  failed: { type: 'danger', i18nKey: 'task.failed' },
  error: { type: 'danger', i18nKey: 'task.failed' },
  stopped: { type: 'warning', i18nKey: 'task.stopped' },
  paused: { type: 'warning', i18nKey: 'task.paused' }
}

const statusType = computed(() => {
  const config = statusConfig[props.status]
  return config ? config.type : 'info'
})

const statusText = computed(() => {
  const config = statusConfig[props.status]
  return config ? t(config.i18nKey) : props.status
})
</script>