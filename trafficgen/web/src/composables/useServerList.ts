import { ref, reactive } from 'vue'
import type { Ref, Reactive } from 'vue'
import { ElMessage } from 'element-plus'
import { useI18n } from 'vue-i18n'

export interface UseServerListOptions<T> {
  /** Fetch function that receives pagination/sort params plus any extra filter params.
   *  Must return { items: T[], total: number } */
  fetchFn: (params: Record<string, any>) => Promise<{ items: T[]; total: number }>
  defaultPageSize?: number
  defaultSort?: { prop: string; order: string }
}

/**
 * Server-paginated data loading composable.
 * Passes page/size/sort params to API. Reads items + total from response.
 * Used by TaskList, History.
 */
export function useServerList<T>(options: UseServerListOptions<T>): {
  loading: Ref<boolean>
  data: Ref<T[]>
  pagination: Reactive<{ page: number; pageSize: number; total: number }>
  sortState: Reactive<{ prop: string; order: string }>
  refresh: (extraParams?: Record<string, any>) => Promise<void>
  handleSortChange: (sort: { prop: string; order: string }) => void
  handlePageChange: (page: number, pageSize: number) => void
} {
  const { t } = useI18n()
  const loading = ref(false)
  const data = ref<T[]>([]) as Ref<T[]>
  let loadErrorShown = false

  const pagination = reactive({
    page: 1,
    pageSize: options.defaultPageSize || 20,
    total: 0
  })

  const sortState = reactive({
    prop: options.defaultSort?.prop || 'created_at',
    order: options.defaultSort?.order || 'descending'
  })

  const refresh = async (extraParams?: Record<string, any>) => {
    loading.value = true
    try {
      const params: Record<string, any> = {
        page: pagination.page,
        size: pagination.pageSize,
        ...extraParams
      }
      if (sortState.prop) {
        params.sort_by = sortState.prop
        params.sort_order = sortState.order
      }
      const result = await options.fetchFn(params)
      data.value = result.items || []
      pagination.total = result.total || 0
      loadErrorShown = false
    } catch (error) {
      console.error('Failed to load data:', error)
      if (!loadErrorShown) {
        ElMessage.error(t('error.networkError'))
        loadErrorShown = true
      }
    } finally {
      loading.value = false
    }
  }

  const handleSortChange = (sort: { prop: string; order: string }) => {
    sortState.prop = sort.prop
    sortState.order = sort.order
    refresh()
  }

  const handlePageChange = (page: number, pageSize: number) => {
    pagination.page = page
    pagination.pageSize = pageSize
    refresh()
  }

  return {
    loading,
    data,
    pagination,
    sortState,
    refresh,
    handleSortChange,
    handlePageChange
  }
}
