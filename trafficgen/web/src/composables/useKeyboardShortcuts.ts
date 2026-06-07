import { onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'

export interface ShortcutConfig {
  key: string
  ctrl?: boolean
  shift?: boolean
  alt?: boolean
  description: string
  handler: (e: KeyboardEvent) => void
  global?: boolean
}

const STORAGE_KEY = 'keyboard-shortcuts-enabled'

export function useKeyboardShortcuts() {
  const router = useRouter()
  const shortcuts = new Map<string, ShortcutConfig>()
  let enabled = true

  function loadEnabled(): boolean {
    try {
      const saved = localStorage.getItem(STORAGE_KEY)
      return saved !== 'false'
    } catch {
      return true
    }
  }

  function setEnabled(val: boolean) {
    enabled = val
    localStorage.setItem(STORAGE_KEY, String(val))
  }

  function shortcutId(config: ShortcutConfig): string {
    const parts: string[] = []
    if (config.ctrl) parts.push('ctrl')
    if (config.shift) parts.push('shift')
    if (config.alt) parts.push('alt')
    parts.push(config.key.toLowerCase())
    return parts.join('+')
  }

  function register(config: ShortcutConfig) {
    shortcuts.set(shortcutId(config), config)
  }

  function unregister(config: ShortcutConfig) {
    shortcuts.delete(shortcutId(config))
  }

  function handleKeydown(e: KeyboardEvent) {
    if (!enabled) return

    // Skip when typing in input/textarea
    const target = e.target as HTMLElement
    const isInput = target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable

    // Build id from event
    const parts: string[] = []
    if (e.ctrlKey || e.metaKey) parts.push('ctrl')
    if (e.shiftKey) parts.push('shift')
    if (e.altKey) parts.push('alt')
    parts.push(e.key.toLowerCase())
    const id = parts.join('+')

    const shortcut = shortcuts.get(id)
    if (!shortcut) return

    // In inputs, only allow Escape and specific combos
    if (isInput && e.key !== 'Escape' && !(e.ctrlKey || e.metaKey)) return

    e.preventDefault()
    shortcut.handler(e)
  }

  function getShortcutsList(): ShortcutConfig[] {
    return Array.from(shortcuts.values())
  }

  // Register default shortcuts
  function registerDefaults() {
    register({
      key: 'k',
      ctrl: true,
      description: 'Global search',
      handler: () => {
        const searchInput = document.querySelector('.advanced-filter .filter-search input, .filter-bar input') as HTMLInputElement
        if (searchInput) {
          searchInput.focus()
        }
      }
    })

    register({
      key: 'n',
      ctrl: true,
      description: 'Create new item',
      handler: () => {
        const path = window.location.pathname
        if (path.includes('/tasks')) {
          router.push('/tasks/create')
        } else if (path.includes('/strategies')) {
          // Emit custom event for strategy creation
          window.dispatchEvent(new CustomEvent('shortcut:create'))
        }
      }
    })

    register({
      key: 'Escape',
      description: 'Close dialog/drawer',
      handler: () => {
        // Close any open dialog
        const closeBtn = document.querySelector('.el-dialog__headerbtn') as HTMLElement
        if (closeBtn) closeBtn.click()
      }
    })

    register({
      key: '?',
      shift: true,
      description: 'Show keyboard shortcuts help',
      handler: () => {
        window.dispatchEvent(new CustomEvent('shortcut:help'))
      }
    })

    register({
      key: 'r',
      ctrl: true,
      description: 'Refresh current page data',
      handler: (e) => {
        e.preventDefault()
        window.dispatchEvent(new CustomEvent('shortcut:refresh'))
      }
    })
  }

  onMounted(() => {
    enabled = loadEnabled()
    registerDefaults()
    document.addEventListener('keydown', handleKeydown)
  })

  onUnmounted(() => {
    document.removeEventListener('keydown', handleKeydown)
    shortcuts.clear()
  })

  return {
    register,
    unregister,
    getShortcutsList,
    setEnabled,
    isEnabled: () => enabled
  }
}