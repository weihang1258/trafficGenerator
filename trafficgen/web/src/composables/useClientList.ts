import { ref, reactive } from 'vue'
import type { Ref, Reactive } from 'vue'
import { ElMessage } from 'element-plus'
import { useI18n } from 'vue-i18n'

export interface UseClientListOptions<T> {
  /** Fetch function that loads all data at once */
  fetchFn: () => Promise<T[]>
  /** Client-side filter function. Receives all data + current filters. */
  clientFilter?: (items: T[], filters: Record<string, any>) => T[]
  /** Client-side sort function. Receives filtered data + sort state. */
  clientSort?: (items: T[], sort: { prop: string; order: string }) => T[]
  defaultSort?: { prop: string; order: string }
}

/**
 * Client-side filter/sort data loading composable.
 * Loads all data once, then applies clientFilter + clientSort locally.
 * Used by StrategyList, InterfaceList, UserList, PortManagement.
 */
export function useClientList<T>(options: UseClientListOptions<T>): {
  loading: Ref<boolean>
  data: Ref<T[]>
  allData: Ref<T[]>
  sortState: Reactive<{ prop: string; order: string }>
  refresh: () => Promise<void>
  applyFilters: (filters: Record<string, any>) => void
  handleSortChange: (sort: { prop: string; order: string }) => void
} {
  const { t } = useI18n()
  const loading = ref(false)
  const allData = ref<T[]>([]) as Ref<T[]>
  const data = ref<T[]>([]) as Ref<T[]>
  let currentFilters: Record<string, any> = {}

  const sortState = reactive({
    prop: options.defaultSort?.prop || 'created_at',
    order: options.defaultSort?.order || 'descending'
  })

  const applyFilters = (filters: Record<string, any>) => {
    currentFilters = filters
    recompute()
  }

  const recompute = () => {
    let result = [...allData.value]

    // Apply client-side filter
    if (options.clientFilter) {
      result = options.clientFilter(result, currentFilters)
    }

    // Apply client-side sort
    if (options.clientSort && sortState.prop) {
      result = options.clientSort(result, { prop: sortState.prop, order: sortState.order })
    }

    data.value = result
  }

  const refresh = async () => {
    loading.value = true
    try {
      allData.value = await options.fetchFn()
      recompute()
    } catch (error) {
      console.error('Failed to load data:', error)
      ElMessage.error(t('error.networkError'))
    } finally {
      loading.value = false
    }
  }

  const handleSortChange = (sort: { prop: string; order: string }) => {
    sortState.prop = sort.prop
    sortState.order = sort.order
    recompute()
  }

  return {
    loading,
    data,
    allData,
    sortState,
    refresh,
    applyFilters,
    handleSortChange
  }
}
