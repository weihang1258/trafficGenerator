<template>
  <el-form
    ref="formRef"
    :model="model"
    :rules="rules"
    :label-width="labelWidth"
    :label-position="labelPosition"
  >
    <slot />
  </el-form>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import type { FormInstance, FormRules } from 'element-plus'
import { useFormDirty } from '@/composables/useFormDirty'

export interface ProFormProps {
  model: Record<string, any>
  rules?: FormRules
  labelWidth?: string
  labelPosition?: 'left' | 'right' | 'top'
}

const props = withDefaults(defineProps<ProFormProps>(), {
  rules: () => ({}),
  labelWidth: '100px',
  labelPosition: 'right'
})

const formRef = ref<FormInstance>()
const formDirty = useFormDirty(props.model)

// Expose methods for parent components
defineExpose({
  validate: () => formRef.value?.validate(),
  resetFields: () => formRef.value?.resetFields(),
  formRef,
  isDirty: formDirty.isDirty,
  captureSnapshot: formDirty.captureSnapshot,
  resetDirty: formDirty.resetDirty,
  confirmDiscard: formDirty.confirmDiscard
})

</script>
