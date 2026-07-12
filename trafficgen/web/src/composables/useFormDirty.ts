import { ref, watch, toRaw, onBeforeUnmount } from 'vue'
import { ElMessageBox } from 'element-plus'
import { useI18n } from 'vue-i18n'

export interface UseFormDirtyReturn {
  isDirty: import('vue').Ref<boolean>
  captureSnapshot: () => void
  resetDirty: () => void
  confirmDiscard: () => Promise<boolean>
}

/**
 * Tracks whether a reactive form object has changed from its last snapshot.
 * Uses toRaw() + JSON.stringify for Vue proxy correctness.
 *
 * Usage:
 *   const formDirty = useFormDirty(userForm)
 *   // After form initialization:
 *   formDirty.captureSnapshot()
 *   // In dialog before-close:
 *   if (formDirty.isDirty.value) { ... }
 */
export function useFormDirty<T extends object>(source: T | import('vue').Ref<T>): UseFormDirtyReturn {
  const { t } = useI18n()
  const isDirty = ref(false)
  let snapshotJson = ''

  function serialize(obj: T): string {
    const raw = toRaw(obj)
    return JSON.stringify(raw, (_key, value) => {
      // Handle Vue reactive proxies in nested objects
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        return toRaw(value)
      }
      return value
    })
  }

  function captureSnapshot() {
    snapshotJson = serialize(source as T)
    isDirty.value = false
  }

  function resetDirty() {
    snapshotJson = serialize(source as T)
    isDirty.value = false
  }

  async function confirmDiscard(): Promise<boolean> {
    if (!isDirty.value) return true
    try {
      await ElMessageBox.confirm(
        t('common.unsavedChanges'),
        t('common.warning'),
        {
          confirmButtonText: t('common.discard'),
          cancelButtonText: t('common.cancel'),
          type: 'warning'
        }
      )
      resetDirty()
      return true
    } catch {
      return false
    }
  }

  // Watch for changes - use deep watch on the source object
  // Debounce serialization to avoid excessive JSON.stringify on rapid keystrokes
  let dirtyCheckTimer: number | null = null
  const stopWatch = watch(
    () => source,
    () => {
      if (snapshotJson) {
        if (dirtyCheckTimer) clearTimeout(dirtyCheckTimer)
        dirtyCheckTimer = window.setTimeout(() => {
          const currentJson = serialize(source as T)
          isDirty.value = currentJson !== snapshotJson
          dirtyCheckTimer = null
        }, 150) // 150ms debounce — fast enough for UX, slow enough for performance
      }
    },
    { deep: true }
  )

  onBeforeUnmount(() => {
    stopWatch()
    if (dirtyCheckTimer) clearTimeout(dirtyCheckTimer)
  })

  return {
    isDirty,
    captureSnapshot,
    resetDirty,
    confirmDiscard
  }
}
