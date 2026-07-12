import { ref, watch } from 'vue'

const STORAGE_KEY = 'theme-mode'

// Module-scoped singleton: all callers share the same reactive state
const isDark = ref(false)
let initialized = false
let mediaListener: ((e: MediaQueryListEvent) => void) | null = null

function applyTheme() {
  if (isDark.value) {
    document.documentElement.classList.add('dark')
  } else {
    document.documentElement.classList.remove('dark')
  }
}

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

// Set up persistence watch once
watch(isDark, () => {
  localStorage.setItem(STORAGE_KEY, isDark.value ? 'dark' : 'light')
  applyTheme()
})

export function useDarkMode() {
  if (!initialized) {
    initialized = true

    // Listen for system preference changes
    if (window.matchMedia) {
      const mql = window.matchMedia('(prefers-color-scheme: dark)')
      mediaListener = (e: MediaQueryListEvent) => {
        const saved = localStorage.getItem(STORAGE_KEY)
        if (!saved) {
          isDark.value = e.matches
        }
      }
      mql.addEventListener('change', mediaListener)
    }

    loadPreference()
  }

  function toggleDark() {
    isDark.value = !isDark.value
  }

  function setDark(dark: boolean) {
    isDark.value = dark
  }

  return {
    isDark,
    toggleDark,
    setDark
  }
}
