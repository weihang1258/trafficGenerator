import type { UseFormDirtyReturn } from '@/composables/useFormDirty'

export interface ProDialogProps {
  visible: boolean
  title: string
  dirty?: boolean
  dirtyGuard?: UseFormDirtyReturn | null
  width?: string
  destroyOnClose?: boolean
  closeOnClickModal?: boolean
}

export interface ProDialogEmits {
  (e: 'update:visible', value: boolean): void
  (e: 'closed'): void
}
