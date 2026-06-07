import { computed } from 'vue'
import type { ComputedRef, Reactive } from 'vue'

export interface FilterFieldDef {
  /** Key matching filters[key] */
  key: string
  /** Display label for the active filter tag */
  label: string
  /** Custom formatter for the tag display value (e.g., uppercase protocol) */
  valueFormatter?: (v: any) => string
  /** Value to reset to on clear. Default: ''. Use [] for multi-select arrays. */
  emptyValue?: any
}

export interface ActiveFilterEntry {
  key: string
  label: string
  value: string
  onClear: () => void
}

/**
 * Computes active filter entries from a filters reactive object + field definitions.
 * Each entry provides display info and an onClear callback.
 * Used by ProFilterBar for active-tag rendering.
 */
export function useActiveFilters(
  filters: Reactive<Record<string, any>>,
  fieldDefs: FilterFieldDef[],
  onReset: () => void
): {
  activeEntries: ComputedRef<ActiveFilterEntry[]>
  hasActiveFilters: ComputedRef<boolean>
  resetFilters: () => void
} {
  const isEmptyValue = (value: any): boolean => {
    if (value === '' || value === null || value === undefined) return true
    if (Array.isArray(value) && value.length === 0) return true
    return false
  }

  const activeEntries = computed<ActiveFilterEntry[]>(() => {
    return fieldDefs
      .filter(def => !isEmptyValue(filters[def.key]))
      .map(def => {
        const rawValue = filters[def.key]
        const displayValue = def.valueFormatter ? def.valueFormatter(rawValue) : String(rawValue)
        const emptyVal = def.emptyValue !== undefined ? def.emptyValue : (Array.isArray(rawValue) ? [] : '')
        return {
          key: def.key,
          label: def.label,
          value: displayValue,
          onClear: () => {
            filters[def.key] = emptyVal
            onReset()
          }
        }
      })
  })

  const hasActiveFilters = computed(() => activeEntries.value.length > 0)

  const resetFilters = () => {
    for (const def of fieldDefs) {
      const emptyVal = def.emptyValue !== undefined ? def.emptyValue : (Array.isArray(filters[def.key]) ? [] : '')
      filters[def.key] = emptyVal
    }
    onReset()
  }

  return {
    activeEntries,
    hasActiveFilters,
    resetFilters
  }
}
