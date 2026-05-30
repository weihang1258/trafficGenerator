<template>
  <el-config-provider :locale="elementLocale">
    <router-view />
  </el-config-provider>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue'
import zhCn from 'element-plus/es/locale/lang/zh-cn'
import en from 'element-plus/es/locale/lang/en'
import { getLocale } from '@/i18n'

const currentLocale = ref(getLocale())

const elementLocale = computed(() => {
  return currentLocale.value === 'en-US' ? en : zhCn
})

const updateLocale = () => {
  const saved = localStorage.getItem('locale')
  if (saved && saved !== currentLocale.value) {
    currentLocale.value = saved
  }
}

onMounted(() => {
  window.addEventListener('storage', updateLocale)
})

watch(
  () => localStorage.getItem('locale'),
  (val) => {
    if (val && val !== currentLocale.value) {
      currentLocale.value = val
    }
  }
)
</script>

<style>
#app {
  width: 100%;
  height: 100%;
}

html, body {
  margin: 0;
  padding: 0;
  width: 100%;
  height: 100%;
}
</style>
