<template>
  <el-tag :type="statusType" :effect="effect" :size="size">
    {{ statusText }}
  </el-tag>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { TASK_STATUS_TYPE } from '@/constants/status'

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

const statusI18nMap: Record<string, string> = {
  pending: 'task.pending',
  created: 'task.pending',
  starting: 'task.running',
  running: 'task.running',
  completed: 'task.completed',
  failed: 'task.failed',
  error: 'task.failed',
  stopped: 'task.stopped',
  paused: 'task.paused'
}

const statusType = computed(() => {
  return TASK_STATUS_TYPE[props.status] || 'info'
})

const statusText = computed(() => {
  const key = statusI18nMap[props.status]
  return key ? t(key) : props.status
})
</script>