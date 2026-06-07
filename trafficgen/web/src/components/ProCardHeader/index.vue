<template>
  <div class="card-header">
    <span>{{ title }}</span>
    <div class="header-actions">
      <slot />
    </div>
  </div>
</template>

<script setup lang="ts">
export interface ProCardHeaderProps {
  title: string
}

defineProps<ProCardHeaderProps>()
</script>

<style scoped>
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.header-actions {
  display: flex;
  gap: 8px;
  align-items: center;
  min-height: 32px;
}
</style>
