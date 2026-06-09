<template>
  <div class="pro-table">
    <div v-if="$slots.toolbar" class="pro-table-toolbar">
      <slot name="toolbar" />
    </div>

    <!-- Virtual table for large datasets -->
    <el-table-v2
      v-if="useVirtual"
      :columns="virtualColumns"
      :data="data"
      :width="tableWidth"
      :height="virtualTableHeight"
      :row-key="rowKey"
      :fixed="true"
      v-loading="loading"
    >
      <template #empty>
        <slot name="empty">
          <el-empty :description="emptyText || t('common.noData')" />
        </slot>
      </template>
    </el-table-v2>

    <!-- Standard table for normal datasets -->
    <el-table
      v-else
      ref="tableRef"
      v-loading="loading"
      :data="data"
      :row-key="rowKey"
      :stripe="stripe"
      :border="border"
      :size="size"
      :default-sort="defaultSort"
      :scrollbar-always-on="true"
      :max-height="maxHeight"
      :height="height"
      @selection-change="handleSelectionChange"
      @sort-change="handleSortChange"
      @row-click="handleRowClick"
      @row-dblclick="handleRowDblclick"
      @header-dragend="handleHeaderDragend"
    >
      <template v-for="col in visibleColumns" :key="col.prop">
        <el-table-column
          v-if="col.type === 'selection'"
          type="selection"
          :width="col.width || 45"
          :fixed="col.fixed"
          :resizable="false"
        />
        <el-table-column
          v-else-if="col.type === 'expand'"
          type="expand"
          :width="col.width"
        >
          <template #default="scope">
            <slot name="expand" v-bind="scope" />
          </template>
        </el-table-column>
        <el-table-column
          v-else
          :prop="col.prop"
          :label="col.label"
          :width="col.width"
          :min-width="col.minWidth"
          :fixed="col.fixed"
          :sortable="col.sortable"
          :show-overflow-tooltip="col.showOverflowTooltip !== false"
          :align="col.align"
          :resizable="col.resizable !== false && col.fixed !== 'right'"
          :class-name="col.fixed === 'right' ? 'col-fixed-right' : col.fixed === 'left' ? 'col-fixed-left' : ''"
        >
          <template #default="scope">
            <slot v-if="$slots[col.prop]" :name="col.prop" v-bind="scope" />
            <template v-else>{{ scope.row[col.prop] }}</template>
          </template>
        </el-table-column>
      </template>

      <template #empty>
        <slot name="empty">
          <el-empty :description="emptyText || t('common.noData')" />
        </slot>
      </template>
    </el-table>

    <div v-if="pagination" class="pro-table-pagination">
      <el-pagination
        v-model:current-page="currentPage"
        v-model:page-size="currentPageSize"
        :total="pagination.total"
        :page-sizes="pagination.pageSizes || [10, 20, 50, 100]"
        layout="total, sizes, prev, pager, next, jumper"
        @size-change="handlePageChange"
        @current-change="handlePageChange"
      />
    </div>

    <el-dialog
      v-model="columnSettingsVisible"
      :title="t('common.columnSettings')"
      width="400px"
      append-to-body
    >
      <div class="column-settings-list">
        <div
          v-for="(col, index) in columnSettingsList"
          :key="col.prop"
          class="column-settings-item"
        >
          <el-checkbox v-model="col.visible" :disabled="col.required" />
          <span class="column-settings-label">{{ col.label }}</span>
          <el-button
            v-if="index > 0"
            link
            size="small"
            @click="moveColumn(index, index - 1)"
          >
            <el-icon><ArrowUp /></el-icon>
          </el-button>
          <el-button
            v-if="index < columnSettingsList.length - 1"
            link
            size="small"
            @click="moveColumn(index, index + 1)"
          >
            <el-icon><ArrowDown /></el-icon>
          </el-button>
        </div>
      </div>
      <template #footer>
        <el-button @click="columnSettingsVisible = false">{{ t('common.close') }}</el-button>
        <el-button type="primary" @click="saveColumnSettings">{{ t('common.confirm') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, nextTick, onMounted, onUnmounted, h, useSlots } from 'vue'
import { useI18n } from 'vue-i18n'
import { ArrowUp, ArrowDown } from '@element-plus/icons-vue'
import { useTablePersistence } from '@/composables/useTablePersistence'

export interface ProTableColumn {
  prop: string
  label: string
  type?: 'selection' | 'expand'
  width?: number | string
  minWidth?: number | string
  fixed?: 'left' | 'right' | boolean
  sortable?: boolean | 'custom'
  align?: 'left' | 'center' | 'right'
  showOverflowTooltip?: boolean
  visible?: boolean
  required?: boolean
  resizable?: boolean
}

export interface ProTablePagination {
  total: number
  pageSizes?: number[]
}

const props = withDefaults(defineProps<{
  columns: ProTableColumn[]
  data: any[]
  loading?: boolean
  rowKey?: string
  stripe?: boolean
  border?: boolean
  size?: 'large' | 'default' | 'small'
  defaultSort?: { prop: string; order: string }
  maxHeight?: number | string
  height?: number | string
  pagination?: ProTablePagination
  emptyText?: string
  tableId?: string
  virtualScroll?: boolean
  virtualThreshold?: number
}>(), {
  loading: false,
  rowKey: 'id',
  stripe: true,
  border: true,
  size: 'default',
  emptyText: '',
  tableId: 'default',
  virtualScroll: false,
  virtualThreshold: 200
})

const emit = defineEmits<{
  selectionChange: [selection: any[]]
  sortChange: [sort: { prop: string; order: string }]
  pageChange: [page: number, pageSize: number]
  rowClick: [row: any]
  rowDblclick: [row: any]
}>()

const { t } = useI18n()
const slots = useSlots()
const tableRef = ref()
const columnSettingsVisible = ref(false)
const currentPage = ref(1)
const currentPageSize = ref(20)

const { loadSettings, saveSettings, loadWidths, saveWidths } = useTablePersistence(props.tableId)

interface ColumnSetting {
  prop: string
  label: string
  visible: boolean
  required: boolean
}

const columnSettingsList = ref<ColumnSetting[]>([])

const visibleColumns = computed(() => {
  if (columnSettingsList.value.length === 0) return props.columns
  const visibilityMap = new Map(columnSettingsList.value.map(s => [s.prop, s.visible]))
  const orderMap = new Map(columnSettingsList.value.map((s, i) => [s.prop, i]))
  return [...props.columns]
    .filter(col => {
      if (col.type === 'selection' || col.type === 'expand') return true
      return visibilityMap.get(col.prop) !== false
    })
    .sort((a, b) => {
      if (a.type === 'selection') return -1
      if (b.type === 'selection') return 1
      const oa = orderMap.get(a.prop) ?? 0
      const ob = orderMap.get(b.prop) ?? 0
      return oa - ob
    })
})

const useVirtual = computed(() =>
  props.virtualScroll || props.data.length > props.virtualThreshold
)

const tableWidth = ref(800)
const virtualTableHeight = computed(() => {
  if (props.height) return Number(props.height) || 500
  if (props.maxHeight) return Number(props.maxHeight) || 500
  return 500
})

const virtualColumns = computed(() =>
  visibleColumns.value
    .filter(col => col.type !== 'selection' && col.type !== 'expand')
    .map(col => ({
      key: col.prop,
      dataKey: col.prop,
      title: col.label,
      width: Number(col.width) || Number(col.minWidth) || 150,
      cellRenderer: ({ rowData }: any) => {
        const slot = slots[col.prop as string]
        if (slot) {
          return h('div', {}, slot({ row: rowData }))
        }
        return h('span', {}, rowData[col.prop])
      }
    }))
)

const containerObserver = ref<ResizeObserver | null>(null)

onMounted(() => {
  initColumnSettings()
  if (tableRef.value?.$el) {
    tableWidth.value = tableRef.value.$el.offsetWidth || 800
  }
  const container = document.querySelector('.pro-table')
  if (container) {
    containerObserver.value = new ResizeObserver((entries) => {
      for (const entry of entries) {
        tableWidth.value = entry.contentRect.width || 800
      }
    })
    containerObserver.value.observe(container)
  }
})

onUnmounted(() => {
  containerObserver.value?.disconnect()
})

function handleSelectionChange(selection: any[]) {
  emit('selectionChange', selection)
}

function handleSortChange(sort: { prop: string; order: string }) {
  emit('sortChange', sort)
}

function handlePageChange() {
  emit('pageChange', currentPage.value, currentPageSize.value)
}

function handleRowClick(row: any) {
  emit('rowClick', row)
}

function handleRowDblclick(row: any) {
  emit('rowDblclick', row)
}

/**
 * Column resize handler — Commercial standard (Excel/Jira model):
 * - Fixed-left columns (e.g. name) ARE resizable for usability
 * - Fixed-right columns (e.g. actions) are NOT resizable
 * - The dragged column and its right neighbor compensate each other
 * - All other columns stay unchanged; total table width stays constant
 * - Width changes are persisted to localStorage
 */
function handleHeaderDragend(newWidth: number, oldWidth: number, column: any) {
  if (!column?.property) return
  const delta = newWidth - oldWidth
  if (Math.abs(delta) < 1) return

  // Find the dragged column in visibleColumns
  const cols = visibleColumns.value
  const dragIndex = cols.findIndex(c => c.prop === column.property)
  if (dragIndex < 0) return

  // Only block fixed-right columns (actions); fixed-left is allowed
  const dragCol = cols[dragIndex]
  if (dragCol.fixed === 'right') return

  // For fixed-left columns, find the first non-fixed-right neighbor to compensate
  let adjIndex = -1
  for (let i = dragIndex + 1; i < cols.length; i++) {
    const c = cols[i]
    if (c.type === 'selection' || c.type === 'expand') continue
    if (c.fixed === 'right') continue
    // Skip adjacent fixed-left columns (they're part of the fixed group)
    if (c.fixed === 'left') continue
    adjIndex = i
    break
  }

  if (adjIndex < 0) {
    // No resizable neighbor — allow free resize, just persist
    dragCol.width = newWidth
    const widths = loadWidths().filter(w => w.prop !== dragCol.prop)
    widths.push({ prop: dragCol.prop, width: Number(newWidth) })
    saveWidths(widths)
    nextTick(() => tableRef.value?.doLayout())
    return
  }

  const adjCol = cols[adjIndex]
  const adjCurrentWidth = Number(adjCol.width) || Number(adjCol.minWidth) || 100
  const minAdjWidth = Math.max(60, Math.round(adjCurrentWidth * 0.3))

  if (delta > 0) {
    // Growing: cap by how much the neighbor can shrink
    const maxDelta = adjCurrentWidth - minAdjWidth
    const actualDelta = Math.min(delta, maxDelta)
    dragCol.width = oldWidth + actualDelta
    adjCol.width = adjCurrentWidth - actualDelta
  } else {
    // Shrinking: cap by drag column's minimum
    const minDragWidth = Math.max(60, Math.round(oldWidth * 0.3))
    const maxShrink = oldWidth - minDragWidth
    const actualShrink = Math.min(-delta, maxShrink)
    dragCol.width = oldWidth - actualShrink
    adjCol.width = adjCurrentWidth + actualShrink
  }

  // Persist both widths
  const widths = loadWidths().filter(
    w => w.prop !== dragCol.prop && w.prop !== adjCol.prop
  )
  widths.push(
    { prop: dragCol.prop, width: Number(dragCol.width) },
    { prop: adjCol.prop, width: Number(adjCol.width) }
  )
  saveWidths(widths)

  nextTick(() => tableRef.value?.doLayout())
}

function moveColumn(from: number, to: number) {
  const list = [...columnSettingsList.value]
  const [item] = list.splice(from, 1)
  list.splice(to, 0, item)
  columnSettingsList.value = list
}

function saveColumnSettings() {
  columnSettingsVisible.value = false
  saveSettings(columnSettingsList.value.map(s => ({
    prop: s.prop,
    visible: s.visible
  })))
}

function openColumnSettings() {
  columnSettingsList.value = props.columns
    .filter(col => col.type !== 'selection' && col.type !== 'expand')
    .map(col => ({
      prop: col.prop,
      label: col.label,
      visible: col.visible !== false,
      required: col.required || false
    }))
  columnSettingsVisible.value = true
}

function initColumnSettings() {
  const saved = loadSettings()
  if (saved && saved.length > 0) {
    const savedMap = new Map(saved.map(s => [s.prop, s.visible]))
    props.columns.forEach(col => {
      if (savedMap.has(col.prop) && col.type !== 'selection' && col.type !== 'expand') {
        col.visible = savedMap.get(col.prop)
      }
    })
  }
  const widths = loadWidths()
  if (widths && widths.length > 0) {
    const widthMap = new Map(widths.map(w => [w.prop, w.width]))
    props.columns.forEach(col => {
      if (widthMap.has(col.prop) && col.type !== 'selection' && col.type !== 'expand') {
        col.width = widthMap.get(col.prop)
      }
    })
  }
}

watch(() => props.pagination, (val) => {
  if (val) {
    currentPage.value = 1
    currentPageSize.value = val.pageSizes?.[1] || 20
  }
}, { immediate: true })

defineExpose({
  openColumnSettings,
  tableRef
})
</script>

<style scoped>
.pro-table {
  width: 100%;
}

/* Enable horizontal scrolling so fixed columns work */
:deep(.el-table__body-wrapper),
:deep(.el-table__header-wrapper) {
  overflow-x: auto !important;
}

.pro-table-toolbar {
  margin-bottom: 12px;
}

.pro-table-pagination {
  margin-top: 16px;
  display: flex;
  justify-content: flex-end;
}

.column-settings-list {
  max-height: 400px;
  overflow-y: auto;
}

.column-settings-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 0;
  border-bottom: 1px solid var(--tg-border-light, #f0f0f0);
}

.column-settings-item:last-child {
  border-bottom: none;
}

.column-settings-label {
  flex: 1;
  font-size: 14px;
}
</style>
