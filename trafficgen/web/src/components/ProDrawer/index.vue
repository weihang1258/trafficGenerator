<template>
  <el-drawer
    :model-value="visible"
    :title="title"
    :size="size"
    :direction="direction"
    :destroy-on-close="destroyOnClose"
    :before-close="handleBeforeClose"
    @closed="handleClosed"
  >
    <slot />
    <template #footer>
      <slot name="footer" />
    </template>
  </el-drawer>
</template>

<script setup lang="ts">
import { ElMessageBox } from 'element-plus'
import { useI18n } from 'vue-i18n'
import type { UseFormDirtyReturn } from '@/composables/useFormDirty'

export interface ProDrawerProps {
  visible: boolean
  title: string
  dirty?: boolean
  dirtyGuard?: UseFormDirtyReturn | null
  size?: string
  direction?: 'rtl' | 'ltr'
  destroyOnClose?: boolean
}

const props = withDefaults(defineProps<ProDrawerProps>(), {
  dirty: false,
  dirtyGuard: null,
  size: '50%',
  direction: 'rtl',
  destroyOnClose: true
})

const emit = defineEmits<{
  (e: 'update:visible', value: boolean): void
}>()

const { t } = useI18n()

async function handleBeforeClose(done: () => void) {
  const isDirty = props.dirtyGuard ? props.dirtyGuard.isDirty.value : props.dirty

  if (!isDirty) {
    done()
    return
  }

  if (props.dirtyGuard) {
    const confirmed = await props.dirtyGuard.confirmDiscard()
    if (confirmed) done()
    return
  }

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
    done()
  } catch {
    // User cancelled
  }
}

function handleClosed() {
  emit('update:visible', false)
}
</script>
