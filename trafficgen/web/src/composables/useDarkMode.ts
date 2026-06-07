import { ref, watch } from 'vue'

const STORAGE_KEY = 'theme-mode'

export function useDarkMode() {
  const isDark = ref(false)

  function loadPreference() {
    try {
      const saved = localStorage.getItem(STORAGE_KEY)
      if (saved !== null) {
        isDark.value = saved === 'dark'
      } else {
        // Check system preference
        isDark.value = window.matchMedia('(prefers-color-scheme: dark)').matches
      }
    } catch {
      isDark.value = false
    }
    applyTheme()
  }

  function applyTheme() {
    if (isDark.value) {
      document.documentElement.classList.add('dark')
    } else {
      document.documentElement.classList.remove('dark')
    }
  }

  function toggleDark() {
    isDark.value = !isDark.value
  }

  function setDark(dark: boolean) {
    isDark.value = dark
  }

  watch(isDark, () => {
    localStorage.setItem(STORAGE_KEY, isDark.value ? 'dark' : 'light')
    applyTheme()
  })

  // Listen for system preference changes
  if (window.matchMedia) {
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
      const saved = localStorage.getItem(STORAGE_KEY)
      if (!saved) {
        isDark.value = e.matches
      }
    })
  }

  loadPreference()

  return {
    isDark,
    toggleDark,
    setDark
  }
}