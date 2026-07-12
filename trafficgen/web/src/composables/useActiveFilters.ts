import { computed } from 'vue'
import type { ComputedRef } from 'vue'

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
 * Computes active filter entries from a filters object + field definitions.
 * Each entry provides display info and an onClear callback.
 * Used by ProFilterBar for active-tag rendering.
 *
 * onClearFilter: called when a single filter key should be cleared; parent
 *   must perform the actual mutation since the filters object may be readonly
 *   (Vue props or computed).
 * onReset: called when all filters should be cleared; parent must perform
 *   the actual mutations.
 */
export function useActiveFilters(
  filters: Record<string, any>,
  fieldDefs: FilterFieldDef[],
  onClearFilter: (key: string) => void,
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

  const getEmptyValue = (def: FilterFieldDef): any => {
    if (def.emptyValue !== undefined) return def.emptyValue
    const rawValue = filters[def.key]
    return Array.isArray(rawValue) ? [] : ''
  }

  const activeEntries = computed<ActiveFilterEntry[]>(() => {
    return fieldDefs
      .filter(def => !isEmptyValue(filters[def.key]))
      .map(def => {
        const rawValue = filters[def.key]
        const displayValue = def.valueFormatter ? def.valueFormatter(rawValue) : String(rawValue)
        return {
          key: def.key,
          label: def.label,
          value: displayValue,
          onClear: () => {
            onClearFilter(def.key)
          }
        }
      })
  })

  const hasActiveFilters = computed(() => activeEntries.value.length > 0)

  const resetFilters = () => {
    onReset()
  }

  return {
    activeEntries,
    hasActiveFilters,
    resetFilters
  }
}
