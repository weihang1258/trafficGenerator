<template>
  <el-dialog
    :model-value="visible"
    :title="title"
    :width="width"
    :destroy-on-close="destroyOnClose"
    :close-on-click-modal="closeOnClickModal"
    :before-close="handleBeforeClose"
    @closed="handleClosed"
  >
    <slot />
    <template #footer>
      <slot name="footer" />
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { ElMessageBox } from 'element-plus'
import { useI18n } from 'vue-i18n'
import type { ProDialogProps, ProDialogEmits } from './types'

const props = withDefaults(defineProps<ProDialogProps>(), {
  dirty: false,
  dirtyGuard: null,
  width: '600px',
  destroyOnClose: true,
  closeOnClickModal: false
})

const emit = defineEmits<ProDialogEmits>()
const { t } = useI18n()

async function handleBeforeClose(done: () => void) {
  const isDirty = props.dirtyGuard ? props.dirtyGuard.isDirty.value : props.dirty

  if (!isDirty) {
    done()
    return
  }

  if (props.dirtyGuard) {
    const confirmed = await props.dirtyGuard.confirmDiscard()
    if (confirmed) {
      done()
    }
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
    // User cancelled — keep dialog open
  }
}

function handleClosed() {
  emit('closed')
}
</script>
