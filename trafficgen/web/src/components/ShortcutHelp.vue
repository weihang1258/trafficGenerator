<template>
  <el-dialog
    v-model="visible"
    :title="t('shortcuts.title')"
    width="520px"
    append-to-body
  >
    <div class="shortcuts-list">
      <div v-for="shortcut in shortcuts" :key="shortcut.description" class="shortcut-item">
        <span class="shortcut-description">{{ shortcut.description }}</span>
        <span class="shortcut-keys">
          <kbd v-if="shortcut.ctrl">Ctrl</kbd>
          <kbd v-if="shortcut.shift">Shift</kbd>
          <kbd v-if="shortcut.alt">Alt</kbd>
          <kbd>{{ shortcut.key === ' ' ? 'Space' : shortcut.key.toUpperCase() }}</kbd>
        </span>
      </div>
    </div>
    <template #footer>
      <el-button @click="visible = false">{{ t('common.close') }}</el-button>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import { useI18n } from 'vue-i18n'
import type { ShortcutConfig } from '@/composables/useKeyboardShortcuts'

const { t } = useI18n()
const visible = ref(false)
const shortcuts = ref<ShortcutConfig[]>([])

function show(list: ShortcutConfig[]) {
  shortcuts.value = list
  visible.value = true
}

onMounted(() => {
  window.addEventListener('shortcut:help', () => {
    // Will be called by useKeyboardShortcuts
    visible.value = !visible.value
  })
})

defineExpose({ show })
</script>

<style scoped>
.shortcuts-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.shortcut-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 8px 0;
  border-bottom: 1px solid var(--tg-border-light, #f0f0f0);
}

.shortcut-item:last-child {
  border-bottom: none;
}

.shortcut-description {
  color: var(--tg-text-body, #606266);
  font-size: 14px;
}

.shortcut-keys {
  display: flex;
  gap: 4px;
}

kbd {
  display: inline-block;
  padding: 2px 8px;
  font-size: 12px;
  font-family: monospace;
  color: var(--tg-text-body, #606266);
  background: var(--tg-bg-hover, #f5f7fa);
  border: 1px solid var(--tg-border, #dcdfe6);
  border-radius: 4px;
  box-shadow: 0 1px 0 var(--tg-border, #dcdfe6);
}
</style>