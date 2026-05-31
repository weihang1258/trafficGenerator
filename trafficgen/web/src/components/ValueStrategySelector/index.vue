<template>
  <div class="value-strategy">
    <div class="strategy-row">
      <el-select
        :model-value="modelValue.strategy"
        class="strategy-select"
        @update:model-value="handleStrategyChange"
      >
        <el-option v-for="opt in strategyOptions" :key="opt.value" :label="opt.label" :value="opt.value" />
      </el-select>
      <div class="strategy-controls">
        <!-- Fixed -->
        <template v-if="modelValue.strategy === 'fixed'">
          <el-input-number
            v-if="fieldType === 'number'"
            :model-value="modelValue.value"
            :min="min"
            :max="max"
            :step="step"
            controls-position="right"
            @update:model-value="val => emit('update:modelValue', { ...modelValue, value: val })"
          />
          <el-input
            v-else
            :model-value="String(modelValue.value || '')"
            :placeholder="placeholder"
            clearable
            @update:model-value="val => emit('update:modelValue', { ...modelValue, value: val })"
          />
        </template>

        <!-- Increment -->
        <template v-else-if="modelValue.strategy === 'inc'">
          <div class="range-group">
            <span class="range-label">{{ t('strategy.from') }}</span>
            <el-input
              :model-value="String(modelValue.range?.[0] ?? '')"
              :placeholder="rangePlaceholder"
              style="width: 140px;"
              @update:model-value="val => emit('update:modelValue', { ...modelValue, range: [val, modelValue.range?.[1] ?? ''] })"
            />
            <span class="range-sep">~</span>
            <el-input
              :model-value="String(modelValue.range?.[1] ?? '')"
              :placeholder="rangePlaceholder"
              style="width: 140px;"
              @update:model-value="val => emit('update:modelValue', { ...modelValue, range: [modelValue.range?.[0] ?? '', val] })"
            />
            <span class="range-label">Step</span>
            <el-input-number
              :model-value="modelValue.step || 1"
              :min="1"
              controls-position="right"
              style="width: 100px;"
              @update:model-value="val => emit('update:modelValue', { ...modelValue, step: val })"
            />
          </div>
        </template>

        <!-- Random -->
        <template v-else-if="modelValue.strategy === 'random'">
          <div class="range-group">
            <span class="range-label">{{ t('strategy.from') }}</span>
            <el-input
              :model-value="String(modelValue.range?.[0] ?? '')"
              :placeholder="rangePlaceholder"
              style="width: 140px;"
              @update:model-value="val => emit('update:modelValue', { ...modelValue, range: [val, modelValue.range?.[1] ?? ''] })"
            />
            <span class="range-sep">~</span>
            <el-input
              :model-value="String(modelValue.range?.[1] ?? '')"
              :placeholder="rangePlaceholder"
              style="width: 140px;"
              @update:model-value="val => emit('update:modelValue', { ...modelValue, range: [modelValue.range?.[0] ?? '', val] })"
            />
            <span class="range-label">Seed</span>
            <el-input-number
              :model-value="modelValue.seed ?? 0"
              :min="0"
              controls-position="right"
              style="width: 100px;"
              @update:model-value="val => emit('update:modelValue', { ...modelValue, seed: val })"
            />
          </div>
        </template>

        <!-- Pattern -->
        <template v-else-if="modelValue.strategy === 'pattern'">
          <el-input
            :model-value="modelValue.pattern || ''"
            :placeholder="t('strategy.patternPlaceholder')"
            style="flex: 1; min-width: 120px;"
            @update:model-value="val => emit('update:modelValue', { ...modelValue, pattern: val })"
          />
          <span class="range-label">{{ t('strategy.from') }}</span>
          <el-input-number
            :model-value="modelValue.n_range?.[0] ?? 1"
            :min="1"
            controls-position="right"
            style="width: 90px;"
            @update:model-value="val => emit('update:modelValue', { ...modelValue, n_range: [val, modelValue.n_range?.[1] ?? 100] })"
          />
          <span class="range-sep">~</span>
          <el-input-number
            :model-value="modelValue.n_range?.[1] ?? 100"
            :min="1"
            controls-position="right"
            style="width: 90px;"
            @update:model-value="val => emit('update:modelValue', { ...modelValue, n_range: [modelValue.n_range?.[0] ?? 1, val] })"
          />
        </template>

        <!-- List -->
        <template v-else-if="modelValue.strategy === 'list'">
          <el-select
            :model-value="modelValue.list || []"
            multiple
            filterable
            allow-create
            default-first-option
            :placeholder="t('strategy.listPlaceholder')"
            style="flex: 1;"
            @update:model-value="val => emit('update:modelValue', { ...modelValue, list: val })"
          >
            <el-option v-for="opt in listOptions" :key="opt" :label="opt" :value="opt" />
          </el-select>
        </template>

        <!-- File -->
        <template v-else-if="modelValue.strategy === 'file'">
          <el-input
            :model-value="String(modelValue.value || '')"
            :placeholder="t('strategy.filePathPlaceholder')"
            clearable
            style="flex: 1;"
            @update:model-value="val => emit('update:modelValue', { ...modelValue, value: val })"
          />
        </template>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'

export interface StrategyValue {
  strategy: 'fixed' | 'inc' | 'random' | 'pattern' | 'list' | 'file'
  value?: any
  range?: [any, any]
  step?: number
  seed?: number
  pattern?: string
  n_range?: [number, number]
  list?: any[]
}

const props = withDefaults(defineProps<{
  modelValue: StrategyValue
  fieldType?: 'ip' | 'port' | 'text' | 'number'
  placeholder?: string
  min?: number
  max?: number
  step?: number
  listOptions?: string[]
  availableStrategies?: string[]
}>(), {
  fieldType: 'text',
  placeholder: '',
  min: undefined,
  max: undefined,
  step: 1,
  listOptions: () => [],
  availableStrategies: () => ['fixed', 'inc', 'random', 'pattern', 'list']
})

const emit = defineEmits<{
  'update:modelValue': [value: StrategyValue]
}>()

const { t } = useI18n()

const strategyLabels: Record<string, string> = {
  fixed: t('strategy.strategyFixed'),
  inc: t('strategy.strategyInc'),
  random: t('strategy.strategyRandom'),
  pattern: t('strategy.strategyPattern'),
  list: t('strategy.strategyList'),
  file: t('strategy.strategyFile')
}

const strategyOptions = computed(() =>
  props.availableStrategies.map(s => ({ label: strategyLabels[s] || s, value: s }))
)

const rangePlaceholder = computed(() => {
  if (props.fieldType === 'ip') return '192.168.1.1'
  if (props.fieldType === 'port') return '1024'
  return ''
})

function handleStrategyChange(newStrategy: string) {
  const base: StrategyValue = { strategy: newStrategy as StrategyValue['strategy'] }
  if (newStrategy === 'fixed') {
    base.value = props.modelValue.value ?? (props.fieldType === 'number' ? props.min ?? 0 : '')
  } else if (newStrategy === 'inc') {
    base.range = props.modelValue.range ?? ['', '']
    base.step = props.modelValue.step ?? 1
  } else if (newStrategy === 'random') {
    base.range = props.modelValue.range ?? ['', '']
    base.seed = props.modelValue.seed ?? 42
  } else if (newStrategy === 'pattern') {
    base.pattern = props.modelValue.pattern ?? ''
    base.n_range = props.modelValue.n_range ?? [1, 100]
  } else if (newStrategy === 'list') {
    base.list = props.modelValue.list ?? []
  } else if (newStrategy === 'file') {
    base.value = props.modelValue.value ?? ''
  }
  emit('update:modelValue', base)
}
</script>

<style scoped>
.value-strategy {
  width: 100%;
}

.strategy-row {
  display: flex;
  align-items: flex-start;
  gap: 8px;
}

.strategy-select {
  width: 100px;
  flex-shrink: 0;
}

.strategy-controls {
  flex: 1;
  min-width: 0;
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.range-group {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}

.range-label {
  font-size: 12px;
  color: var(--tg-text-secondary, #909399);
  white-space: nowrap;
}

.range-sep {
  color: var(--tg-text-secondary, #909399);
  margin: 0 2px;
}
</style>
