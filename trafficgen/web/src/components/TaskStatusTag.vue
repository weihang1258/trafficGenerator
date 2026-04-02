<template>
  <el-tag :type="statusType" :effect="effect" :size="size">
    {{ statusText }}
  </el-tag>
</template>

<script setup lang="ts">
import { computed } from 'vue'

interface Props {
  status: string
  size?: 'large' | 'default' | 'small'
  effect?: 'dark' | 'light' | 'plain'
}

const props = withDefaults(defineProps<Props>(), {
  size: 'default',
  effect: 'light'
})

const statusMap: Record<string, { type: string; text: string }> = {
  pending: { type: 'info', text: '待运行' },
  running: { type: 'success', text: '运行中' },
  completed: { type: '', text: '已完成' },
  failed: { type: 'danger', text: '失败' },
  stopped: { type: 'warning', text: '已停止' }
}

const statusType = computed(() => {
  const status = statusMap[props.status]
  return status ? status.type : 'info'
})

const statusText = computed(() => {
  const status = statusMap[props.status]
  return status ? status.text : props.status
})
</script>
