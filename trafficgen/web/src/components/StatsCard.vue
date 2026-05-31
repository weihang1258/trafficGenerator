<template>
  <el-card class="stats-card" :body-style="{ padding: '20px' }">
    <div class="stats-content">
      <div class="stats-icon" :style="{ backgroundColor: iconBgColor }">
        <el-icon :size="32">
          <component :is="icon" />
        </el-icon>
      </div>
      <div class="stats-info">
        <div class="stats-value">{{ formattedValue }}</div>
        <div class="stats-label">{{ label }}</div>
      </div>
    </div>
    <div v-if="trend !== undefined" class="stats-trend">
      <el-icon :class="trendClass">
        <component :is="trendIcon" />
      </el-icon>
      <span :class="trendClass">{{ trendText }}</span>
    </div>
  </el-card>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { TrendCharts, ArrowUp, ArrowDown, Minus } from '@element-plus/icons-vue'
import { formatBytes, formatBps } from '@/utils/format'

interface Props {
  value: number | string
  label: string
  icon?: any
  iconBgColor?: string
  unit?: string
  trend?: number
  format?: 'number' | 'bytes' | 'percent' | 'bps'
}

const props = withDefaults(defineProps<Props>(), {
  icon: TrendCharts,
  iconBgColor: '#2563EB',
  unit: '',
  format: 'number'
})

const formattedValue = computed(() => {
  if (typeof props.value === 'string') {
    return props.value
  }

  let value = props.value

  if (props.format === 'bytes') {
    return formatBytes(value)
  } else if (props.format === 'bps') {
    return formatBps(value)
  } else if (props.format === 'percent') {
    return `${value.toFixed(2)}%`
  } else {
    return value.toLocaleString() + (props.unit ? ` ${props.unit}` : '')
  }
})

const trendIcon = computed(() => {
  if (props.trend === undefined || props.trend === 0) return Minus
  return props.trend > 0 ? ArrowUp : ArrowDown
})

const trendClass = computed(() => {
  if (props.trend === undefined || props.trend === 0) return 'trend-neutral'
  return props.trend > 0 ? 'trend-up' : 'trend-down'
})

const trendText = computed(() => {
  if (props.trend === undefined) return ''
  if (props.trend === 0) return '持平'
  return `${Math.abs(props.trend)}%`
})

</script>

<style scoped>
.stats-card {
  margin-bottom: 20px;
}

.stats-content {
  display: flex;
  align-items: center;
  gap: 20px;
}

.stats-icon {
  width: 64px;
  height: 64px;
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: white;
}

.stats-info {
  flex: 1;
}

.stats-value {
  font-size: 28px;
  font-weight: bold;
  color: var(--tg-text-primary, #0F172A);
  line-height: 1.2;
}

.stats-label {
  font-size: 14px;
  color: var(--tg-text-secondary, #64748B);
  margin-top: 5px;
}

.stats-trend {
  display: flex;
  align-items: center;
  gap: 5px;
  margin-top: 10px;
  font-size: 14px;
}

.trend-up {
  color: var(--tg-success, #10B981);
}

.trend-down {
  color: var(--tg-danger, #EF4444);
}

.trend-neutral {
  color: var(--tg-text-secondary, #64748B);
}
</style>
