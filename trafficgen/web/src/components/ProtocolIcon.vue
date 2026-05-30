<template>
  <el-icon :size="size" :color="color">
    <component :is="iconComponent" />
  </el-icon>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import {
  Connection,
  Promotion,
  Document,
  Search,
  Position,
  Link
} from '@element-plus/icons-vue'

interface Props {
  protocol: string
  size?: number
  color?: string
}

const props = withDefaults(defineProps<Props>(), {
  size: 20,
  color: '#2563EB'
})

const protocolIconMap: Record<string, any> = {
  tcp: Connection,
  udp: Promotion,
  http: Document,
  dns: Search,
  icmp: Position,
  arp: Link
}

const iconComponent = computed(() => {
  return protocolIconMap[props.protocol.toLowerCase()] || Document
})
</script>
