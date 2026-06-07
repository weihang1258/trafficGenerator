<template>
  <div class="pro-filter-bar">
    <div class="filter-bar">
      <slot />
      <slot name="append" />
    </div>
    <div v-if="hasActiveFilters" class="active-filters">
      <el-tag
        v-for="entry in activeEntries"
        :key="entry.key"
        closable
        @close="entry.onClear"
      >
        {{ entry.label }}: {{ entry.value }}
      </el-tag>
      <el-button link type="primary" size="small" @click="resetFilters">
        {{ t('common.reset') }}
      </el-button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import { useActiveFilters, type FilterFieldDef } from '@/composables/useActiveFilters'
import type { ProFilterBarProps, ProFilterBarEmits } from './types'

const props = withDefaults(defineProps<ProFilterBarProps>(), {
  fieldDefs: () => [],
  filterId: ''
})

const emit = defineEmits<ProFilterBarEmits>()
const { t } = useI18n()

const { activeEntries, hasActiveFilters, resetFilters } = useActiveFilters(
  props.filters as any,
  props.fieldDefs,
  () => emit('reset')
)
</script>

<style scoped>
.filter-bar {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 16px;
  flex-wrap: wrap;
}

.active-filters {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 12px;
}

@media (max-width: 768px) {
  .filter-bar {
    flex-direction: column;
    align-items: flex-start;
  }
}
</style>
