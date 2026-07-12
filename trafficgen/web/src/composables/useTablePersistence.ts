import { ref } from 'vue'

export interface ColumnSetting {
  prop: string
  label: string
  width?: string | number
  minWidth?: string | number
  fixed?: 'left' | 'right'
  sortable?: boolean | 'custom'
  showOverflowTooltip?: boolean
  type?: 'selection' | 'index'
  required?: boolean
  hidden?: boolean
}

export interface ColumnVisibility {
  prop: string
  visible: boolean
}

export interface ColumnWidths {
  prop: string
  width: number
}

export function useTablePersistence(tableId: string) {
  const STORAGE_KEY = `pro-table-columns-${tableId}`
  const WIDTH_KEY = `pro-table-widths-${tableId}`

  function loadSettings(): ColumnVisibility[] {
    try {
      const saved = localStorage.getItem(STORAGE_KEY)
      if (saved) {
        return JSON.parse(saved)
      }
    } catch {}
    return []
  }

  function saveSettings(columns: ColumnVisibility[]) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(columns))
  }

  function loadWidths(): ColumnWidths[] {
    try {
      const saved = localStorage.getItem(WIDTH_KEY)
      if (saved) {
        return JSON.parse(saved)
      }
    } catch {}
    return []
  }

  function saveWidths(widths: ColumnWidths[]) {
    localStorage.setItem(WIDTH_KEY, JSON.stringify(widths))
  }

  function clearSettings() {
    localStorage.removeItem(STORAGE_KEY)
    localStorage.removeItem(WIDTH_KEY)
  }

  return {
    loadSettings,
    saveSettings,
    loadWidths,
    saveWidths,
    clearSettings
  }
}
