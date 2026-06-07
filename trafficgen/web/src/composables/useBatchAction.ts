import { ref } from 'vue'
import type { Ref } from 'vue'
import { ElMessageBox, ElMessage } from 'element-plus'

export interface UseBatchActionOptions<T> {
  /** The async action to execute on each item */
  action: (item: T) => Promise<any>
  /** Returns the confirmation message for the given count */
  confirmMessage: (count: number) => string
  /** Returns the success message for the given count */
  successMessage: (count: number) => string
  /** Returns the partial-failure message */
  partialMessage: (succeeded: number, failed: number) => string
}

/**
 * Standardizes the confirm → Promise.allSettled → success/partial-failure toast pattern.
 * Used by TaskList (batch delete, batch stop), UserList (batch delete), StrategyList (bulk delete).
 */
export function useBatchAction<T>(options: UseBatchActionOptions<T>): {
  execute: (items: T[]) => Promise<void>
  loading: Ref<boolean>
} {
  const loading = ref(false)

  const execute = async (items: T[]) => {
    if (items.length === 0) return

    try {
      await ElMessageBox.confirm(
        options.confirmMessage(items.length),
        '',
        { type: 'warning' }
      )
    } catch {
      return // User cancelled
    }

    loading.value = true
    try {
      const results = await Promise.allSettled(
        items.map(item => options.action(item))
      )
      const succeeded = results.filter(r => r.status === 'fulfilled').length
      const failed = results.filter(r => r.status === 'rejected').length

      if (failed > 0) {
        ElMessage.warning(options.partialMessage(succeeded, failed))
      } else {
        ElMessage.success(options.successMessage(succeeded))
      }
    } finally {
      loading.value = false
    }
  }

  return { execute, loading }
}
