import { ref, computed } from 'vue'
import type { Ref, ComputedRef } from 'vue'

/**
 * Manages table row selection state.
 * Used by TaskList, UserList, StrategyList for batch operations.
 */
export function useSelection<T extends Record<string, any>>(): {
  selectedItems: Ref<T[]>
  handleSelectionChange: (items: T[]) => void
  clearSelection: (tableRef?: any) => void
  hasSelection: ComputedRef<boolean>
  selectionCount: ComputedRef<number>
} {
  const selectedItems = ref<T[]>([]) as Ref<T[]>

  const handleSelectionChange = (items: T[]) => {
    selectedItems.value = items
  }

  const clearSelection = (tableRef?: any) => {
    selectedItems.value = []
    tableRef?.clearSelection?.()
  }

  const hasSelection = computed(() => selectedItems.value.length > 0)

  const selectionCount = computed(() => selectedItems.value.length)

  return {
    selectedItems,
    handleSelectionChange,
    clearSelection,
    hasSelection,
    selectionCount
  }
}
