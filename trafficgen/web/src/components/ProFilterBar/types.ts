import type { FilterFieldDef } from '@/composables/useActiveFilters'

export interface ProFilterBarProps {
  filters: Record<string, any>
  fieldDefs?: FilterFieldDef[]
  filterId?: string
}

export interface ProFilterBarEmits {
  (e: 'reset'): void
}
