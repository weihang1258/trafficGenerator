<template>
  <div class="strategy-list">
    <el-card>
      <template #header>
        <ProCardHeader :title="t('strategy.title')">
          <template v-if="selectedStrategies.length === 0">
            <el-button @click="proTableRef?.openColumnSettings()" circle size="small">
              <el-icon><Setting /></el-icon>
            </el-button>
            <el-button @click="loadStrategies" circle size="small">
              <el-icon><Refresh /></el-icon>
            </el-button>
            <el-button type="primary" @click="openCreateDialog">
              <el-icon><Plus /></el-icon>
              {{ t('strategy.createStrategy') }}
            </el-button>
          </template>
          <template v-else>
            <span class="batch-info">{{ t('common.selected') }} {{ selectedStrategies.length }} {{ t('strategy.strategiesUnit') }}</span>
            <el-button type="danger" size="small" @click="handleBulkDelete">{{ t('strategy.bulkDelete') }}</el-button>
            <el-button size="small" link type="primary" @click="clearSelection">{{ t('common.reset') }}</el-button>
          </template>
        </ProCardHeader>
      </template>

      <!-- Filter bar -->
      <ProFilterBar
        :filters="filters"
        :field-defs="filterFieldDefs"
        filter-id="strategy-list"
        @reset="resetFilters"
        @clear-filter="handleClearFilter"
      >
        <el-input v-model="filters.search" :placeholder="t('strategy.searchPlaceholder')" clearable style="width: 240px" @keyup.enter="loadStrategies" @clear="loadStrategies">
          <template #prefix><el-icon><Search /></el-icon></template>
        </el-input>
        <el-select v-model="filters.protocol" :placeholder="t('task.protocol')" multiple collapse-tags collapse-tags-tooltip clearable style="width: 200px" @change="loadStrategies">
          <el-option v-for="p in ['tcp','udp','http','dns','icmp','arp']" :key="p" :label="t('protocol.' + p)" :value="p" />
        </el-select>
        <el-button @click="loadStrategies" circle size="small"><el-icon><Search /></el-icon></el-button>
        <el-button link type="primary" @click="resetFilters">{{ t('common.reset') }}</el-button>
      </ProFilterBar>

      <ProTable ref="proTableRef" table-id="strategy-list" :columns="columns" :data="filteredStrategies" :loading="loading" :default-sort="{ prop: 'created_at', order: 'descending' }" :pagination="{ total: filteredStrategies.length }" :empty-text="t('strategy.noStrategies')" @selection-change="handleSelectionChange" @sort-change="handleSortChange" @page-change="(page: number, size: number) => { pagination.page = page; pagination.size = size }">
        <template #id="{ row }">{{ row.id?.substring(0, 8) }}</template>
        <template #protocol="{ row }"><el-tag size="small">{{ row.protocol.toUpperCase() }}</el-tag></template>
        <template #task_count="{ row }">
          <el-popover
            v-if="(row.task_count || 0) > 0"
            trigger="hover"
            :width="280"
            @show="loadStrategyTasks(row.id)"
          >
            <template #reference>
              <el-button link type="primary" size="small">{{ row.task_count }} {{ t('strategy.taskCount') }}</el-button>
            </template>
            <div v-loading="taskPopoverLoading">
              <div v-if="strategyTasks.length > 0" class="task-popover-list">
                <div v-for="task in strategyTasks" :key="task.id" class="task-popover-item">
                  <router-link :to="`/tasks/${task.id}`" class="task-popover-name">{{ task.name }}</router-link>
                  <el-tag size="small" :type="TASK_STATUS_TYPE[task.status]">{{ task.status }}</el-tag>
                </div>
              </div>
              <div v-else class="task-popover-empty">{{ t('common.noData') }}</div>
            </div>
          </el-popover>
          <span v-else class="text-muted">0</span>
        </template>
        <template #flow_control="{ row }">
          <span v-if="row.flow_control">{{ row.flow_control.type }}: {{ row.flow_control.value }}</span>
          <span v-else>-</span>
        </template>
        <template #created_at="{ row }">{{ formatTimestamp(row.created_at) }}</template>
        <template #updated_at="{ row }">{{ formatTimestamp(row.updated_at) }}</template>
        <template #actions="{ row }">
          <div class="action-buttons">
            <el-button type="primary" link size="small" @click="openEditDialog(row)">{{ t('common.edit') }}</el-button>
            <el-dropdown trigger="click" @command="(cmd: string) => handleAction(cmd, row)">
              <el-button size="small" link><el-icon><More /></el-icon></el-button>
              <template #dropdown>
                <el-dropdown-menu>
                  <el-dropdown-item command="detail">{{ t('task.viewDetail') }}</el-dropdown-item>
                  <el-dropdown-item command="clone">{{ t('strategy.clone') }}</el-dropdown-item>
                  <el-dropdown-item command="delete" style="color: var(--el-color-danger)">{{ t('common.delete') }}</el-dropdown-item>
                </el-dropdown-menu>
              </template>
            </el-dropdown>
          </div>
        </template>
        <template #empty>
          <el-empty :description="t('strategy.noStrategies')">
            <el-button type="primary" @click="openCreateDialog">{{ t('strategy.createStrategy') }}</el-button>
          </el-empty>
        </template>
      </ProTable>
    </el-card>

    <!-- Detail Drawer -->
    <ProDrawer v-model:visible="drawerVisible" :title="drawerStrategy?.name || t('strategy.strategyId')" size="50%" direction="rtl">
      <div v-if="drawerStrategy" v-loading="drawerLoading">
        <el-descriptions :column="2" border>
          <el-descriptions-item :label="t('strategy.strategyId')">{{ drawerStrategy.id }}</el-descriptions-item>
          <el-descriptions-item :label="t('strategy.strategyName')">{{ drawerStrategy.name }}</el-descriptions-item>
          <el-descriptions-item :label="t('task.protocol')"><el-tag>{{ drawerStrategy.protocol.toUpperCase() }}</el-tag></el-descriptions-item>
          <el-descriptions-item :label="t('common.createdAt')">{{ formatTimestamp(drawerStrategy.created_at) }}</el-descriptions-item>
        </el-descriptions>
        <el-divider content-position="left">{{ t('strategy.networkConfig') }}</el-divider>
        <el-descriptions :column="2" border v-if="drawerStrategy.config">
          <el-descriptions-item :label="t('strategy.srcIP')">{{ strategyConfigValue(drawerStrategy.config.src_ip) }}</el-descriptions-item>
          <el-descriptions-item :label="t('strategy.dstIP')">{{ strategyConfigValue(drawerStrategy.config.dst_ip) }}</el-descriptions-item>
          <el-descriptions-item :label="t('strategy.srcPort')">{{ strategyConfigValue(drawerStrategy.config.src_port) }}</el-descriptions-item>
          <el-descriptions-item :label="t('strategy.dstPort')">{{ strategyConfigValue(drawerStrategy.config.dst_port) }}</el-descriptions-item>
          <el-descriptions-item :label="t('strategy.ttl')">{{ drawerStrategy.config.ttl ?? 64 }}</el-descriptions-item>
          <el-descriptions-item :label="t('strategy.tos')">{{ drawerStrategy.config.tos ?? 0 }}</el-descriptions-item>
        </el-descriptions>
      </div>
    </ProDrawer>

    <!-- Create/Edit Dialog -->
    <ProDialog v-model="dialogVisible" :title="editingStrategy ? `${t('common.edit')}: ${editingStrategy.name}` : t('strategy.createStrategy')" width="900px" :dirty-guard="formDirty">
      <el-form ref="formRef" :model="form" :rules="rules" label-width="130px" class="strategy-form">
        <!-- Section 1: Basic Info (always visible) -->
        <el-divider content-position="left">{{ t('strategy.sectionBasicInfo') }}</el-divider>

        <template v-if="!editingStrategy">
          <el-form-item :label="t('strategy.selectTemplate')">
            <el-select v-model="selectedTemplateId" :placeholder="t('strategy.selectTemplate')" clearable style="width: 100%;" @change="applyTemplate">
              <el-option-group :label="t('strategy.builtinTemplates')">
                <el-option v-for="tp in builtinTemplates" :key="tp.id" :label="`${tp.name} (${tp.protocol.toUpperCase()})`" :value="tp.id" />
              </el-option-group>
              <el-option-group v-if="customTemplates.length > 0" :label="t('strategy.customTemplates')">
                <el-option v-for="tp in customTemplates" :key="tp.id" :label="`${tp.name} (${tp.protocol.toUpperCase()})`" :value="tp.id" />
              </el-option-group>
            </el-select>
          </el-form-item>
        </template>

        <el-row :gutter="16">
          <el-col :span="12">
            <el-form-item :label="t('strategy.strategyName')" prop="name">
              <el-input v-model="form.name" :placeholder="t('strategy.strategyNamePlaceholder')" />
            </el-form-item>
          </el-col>
          <el-col :span="12">
            <el-form-item :label="t('task.protocol')" prop="protocol">
              <el-select v-model="form.protocol" :placeholder="t('strategy.selectProtocol')" :disabled="!!editingStrategy" style="width: 100%;" @change="onProtocolChange">
                <el-option v-for="p in ['tcp','udp','http','dns','icmp','arp']" :key="p" :label="t('protocol.' + p)" :value="p" />
              </el-select>
            </el-form-item>
          </el-col>
        </el-row>

        <!-- Section 2: Network Config (IP + Port with strategy) -->
        <template v-if="form.protocol">
          <el-divider content-position="left">{{ t('strategy.sectionNetworkConfig') }}</el-divider>

          <el-form-item :label="t('strategy.srcIP')">
            <ValueStrategySelector
              v-model="form.config.src_ip"
              field-type="ip"
              :placeholder="t('strategy.srcIPPlaceholder')"
              :available-strategies="['fixed', 'inc', 'random']"
              :list-options="srcIPPresets"
            />
          </el-form-item>

          <el-form-item :label="t('strategy.dstIP')" prop="config.dst_ip">
            <ValueStrategySelector
              v-model="form.config.dst_ip"
              field-type="ip"
              :placeholder="t('strategy.dstIPPlaceholder')"
              :available-strategies="['fixed', 'inc', 'random']"
              :list-options="dstIPPresets"
            />
          </el-form-item>

          <el-row :gutter="16">
            <el-col :span="12">
              <el-form-item :label="t('strategy.srcPort')">
                <ValueStrategySelector
                  v-model="form.config.src_port"
                  field-type="port"
                  :min="1" :max="65535"
                  :available-strategies="['fixed', 'inc', 'random']"
                />
              </el-form-item>
            </el-col>
            <el-col :span="12">
              <el-form-item :label="t('strategy.dstPort')">
                <ValueStrategySelector
                  v-model="form.config.dst_port"
                  field-type="port"
                  :min="1" :max="65535"
                  :available-strategies="['fixed', 'inc', 'random']"
                />
              </el-form-item>
            </el-col>
          </el-row>
        </template>

        <!-- Section 3: Protocol Config -->
        <template v-if="form.protocol">
          <el-divider content-position="left">{{ t('strategy.sectionProtocolConfig') }}</el-divider>

          <!-- TCP -->
          <template v-if="form.protocol === 'tcp'">
            <el-row :gutter="16">
              <el-col :span="12">
                <el-form-item :label="t('strategy.handshake')">
                  <el-switch v-model="form.config.tcp.handshake" />
                </el-form-item>
              </el-col>
              <el-col :span="12">
                <el-form-item :label="t('strategy.termination')">
                  <el-switch v-model="form.config.tcp.termination" />
                </el-form-item>
              </el-col>
            </el-row>
            <el-row :gutter="16">
              <el-col :span="12">
                <el-form-item :label="t('strategy.mss')">
                  <el-input-number v-model="form.config.tcp.mss" :min="536" :max="65535" controls-position="right" style="width: 100%;" />
                </el-form-item>
              </el-col>
              <el-col :span="12">
                <el-form-item :label="t('strategy.windowSize')">
                  <el-input-number v-model="form.config.tcp.window_size" :min="1" :max="65535" controls-position="right" style="width: 100%;" />
                </el-form-item>
              </el-col>
            </el-row>
          </template>

          <!-- UDP -->
          <template v-if="form.protocol === 'udp'">
            <el-form-item :label="t('strategy.udpResponse')">
              <el-switch v-model="form.config.udp.response" />
            </el-form-item>
          </template>

          <!-- HTTP -->
          <template v-if="form.protocol === 'http'">
            <el-form-item :label="t('strategy.method')">
              <el-select v-model="form.config.http.methods" multiple filterable allow-create default-first-option style="width: 100%;" :placeholder="t('strategy.method')">
                <el-option v-for="m in ['GET','POST','PUT','DELETE','PATCH','HEAD','OPTIONS']" :key="m" :label="m" :value="m" />
              </el-select>
            </el-form-item>
            <el-form-item :label="t('strategy.uri')">
              <ValueStrategySelector v-model="form.config.http.uri" field-type="text" :placeholder="t('strategy.uriPlaceholder')" :available-strategies="['fixed', 'random', 'pattern', 'list']" :list-options="['/', '/api', '/health', '/login', '/index.html']" />
            </el-form-item>
            <el-form-item :label="t('strategy.headers')">
              <div style="width: 100%;">
                <div v-for="(header, index) in form.config.http.headers" :key="index" class="header-row">
                  <el-select v-model="header.key" filterable allow-create style="width: 200px;" :placeholder="t('strategy.headerKey')">
                    <el-option v-for="hp in HEADER_PRESETS" :key="hp.key" :label="hp.key" :value="hp.key" />
                  </el-select>
                  <el-input v-model="header.value" :placeholder="t('strategy.headerValue')" style="flex: 1;" />
                  <el-button type="danger" link @click="form.config.http.headers.splice(index, 1)">{{ t('common.delete') }}</el-button>
                </div>
                <el-button type="primary" link @click="addHeader">{{ t('strategy.addHeader') }}</el-button>
              </div>
            </el-form-item>
            <el-form-item :label="t('strategy.body')">
              <ValueStrategySelector v-model="form.config.http.body" field-type="text" :placeholder="t('strategy.bodyPlaceholder')" :available-strategies="['fixed', 'file']" />
            </el-form-item>
            <el-row :gutter="16">
              <el-col :span="8">
                <el-form-item :label="t('strategy.keepAlive')">
                  <el-switch v-model="form.config.http.keep_alive" />
                </el-form-item>
              </el-col>
              <el-col :span="8">
                <el-form-item :label="t('strategy.transactions')">
                  <el-input-number v-model="form.config.http.transactions" :min="1" controls-position="right" style="width: 100%;" />
                </el-form-item>
              </el-col>
            </el-row>
          </template>

          <!-- DNS -->
          <template v-if="form.protocol === 'dns'">
            <el-row :gutter="16">
              <el-col :span="16">
                <el-form-item :label="t('strategy.domain')" prop="config.dns.domain">
                  <el-input v-model="form.config.dns.domain" :placeholder="t('strategy.domainPlaceholder')" />
                </el-form-item>
              </el-col>
              <el-col :span="8">
                <el-form-item :label="t('strategy.queryType')">
                  <el-select v-model="form.config.dns.query_type" style="width: 100%;">
                    <el-option label="A" :value="1" /><el-option label="AAAA" :value="28" /><el-option label="CNAME" :value="5" /><el-option label="MX" :value="15" />
                  </el-select>
                </el-form-item>
              </el-col>
            </el-row>
            <el-row :gutter="16">
              <el-col :span="8">
                <el-form-item :label="t('strategy.dnsResponse')">
                  <el-switch v-model="form.config.dns.response" />
                </el-form-item>
              </el-col>
              <el-col v-if="form.config.dns.response" :span="16">
                <el-form-item :label="t('strategy.responseIP')">
                  <el-input v-model="form.config.dns.response_ip" :placeholder="t('strategy.responseIPPlaceholder')" />
                </el-form-item>
              </el-col>
            </el-row>
          </template>

          <!-- ICMP -->
          <template v-if="form.protocol === 'icmp'">
            <el-row :gutter="16">
              <el-col :span="8">
                <el-form-item :label="t('strategy.icmpType')">
                  <el-select v-model="form.config.icmp.type" style="width: 100%;">
                    <el-option :label="t('strategy.echoRequest')" :value="8" /><el-option :label="t('strategy.echoReply')" :value="0" />
                  </el-select>
                </el-form-item>
              </el-col>
              <el-col :span="8">
                <el-form-item :label="t('strategy.icmpCode')">
                  <el-input-number v-model="form.config.icmp.code" :min="0" :max="255" controls-position="right" style="width: 100%;" />
                </el-form-item>
              </el-col>
              <el-col :span="8">
                <el-form-item :label="t('strategy.sequence')">
                  <el-input-number v-model="form.config.icmp.sequence" :min="0" :max="65535" controls-position="right" style="width: 100%;" />
                </el-form-item>
              </el-col>
            </el-row>
            <el-form-item :label="t('strategy.icmpData')">
              <el-input v-model="form.config.icmp.data" :placeholder="t('strategy.icmpDataPlaceholder')" />
            </el-form-item>
          </template>

          <!-- ARP -->
          <template v-if="form.protocol === 'arp'">
            <el-row :gutter="16">
              <el-col :span="8">
                <el-form-item :label="t('strategy.operation')">
                  <el-select v-model="form.config.arp.operation" style="width: 100%;">
                    <el-option :label="t('strategy.arpRequest')" :value="1" /><el-option :label="t('strategy.arpReply')" :value="2" />
                  </el-select>
                </el-form-item>
              </el-col>
              <el-col :span="8">
                <el-form-item :label="t('strategy.targetMAC')">
                  <el-input v-model="form.config.arp.target_mac" :placeholder="t('strategy.srcMACPlaceholder')" />
                </el-form-item>
              </el-col>
              <el-col :span="8">
                <el-form-item :label="t('strategy.targetIP')">
                  <el-input v-model="form.config.arp.target_ip" :placeholder="t('strategy.dstIPPlaceholder')" />
                </el-form-item>
              </el-col>
            </el-row>
          </template>
        </template>

        <!-- Section 4: Advanced Config (collapsible) -->
        <template v-if="form.protocol">
          <el-divider content-position="left">
            <el-button link type="primary" @click="showAdvanced = !showAdvanced">
              {{ t('strategy.advancedConfig') }}
              <el-icon :class="{ 'el-icon--right': true, 'rotate-icon': showAdvanced }"><ArrowRight /></el-icon>
            </el-button>
          </el-divider>

          <div v-show="showAdvanced">
            <el-row :gutter="16">
              <el-col :span="12">
                <el-form-item :label="t('strategy.srcMAC')">
                  <el-input v-model="form.config.src_mac" :placeholder="t('strategy.srcMACPlaceholder')" />
                </el-form-item>
              </el-col>
              <el-col :span="12">
                <el-form-item :label="t('strategy.dstMAC')">
                  <el-input v-model="form.config.dst_mac" :placeholder="t('strategy.dstMACPlaceholder')" />
                </el-form-item>
              </el-col>
            </el-row>
            <el-row :gutter="16">
              <el-col :span="8">
                <el-form-item :label="t('strategy.vlanEnable')">
                  <el-switch v-model="form.config.vlan_enable" />
                </el-form-item>
              </el-col>
              <el-col v-if="form.config.vlan_enable" :span="8">
                <el-form-item :label="t('strategy.vlanID')">
                  <el-input-number v-model="form.config.vlan_id" :min="1" :max="4094" controls-position="right" style="width: 100%;" />
                </el-form-item>
              </el-col>
              <el-col v-if="form.config.vlan_enable" :span="8">
                <el-form-item :label="t('strategy.vlanPriority')">
                  <el-input-number v-model="form.config.vlan_priority" :min="0" :max="7" controls-position="right" style="width: 100%;" />
                </el-form-item>
              </el-col>
            </el-row>
            <el-row v-if="form.protocol !== 'arp'" :gutter="16">
              <el-col :span="12">
                <el-form-item :label="t('strategy.ttl')">
                  <ValueStrategySelector v-model="form.config.ttl" field-type="number" :min="1" :max="255" :available-strategies="['fixed', 'random']" />
                </el-form-item>
              </el-col>
              <el-col :span="12">
                <el-form-item :label="t('strategy.tos')">
                  <ValueStrategySelector v-model="form.config.tos" field-type="number" :min="0" :max="255" :available-strategies="['fixed', 'random', 'list']" :list-options="['0', '8', '16', '32', '40', '48', '56', '64', '104', '136']" />
                </el-form-item>
              </el-col>
            </el-row>
            <el-form-item v-if="form.protocol !== 'arp'" :label="t('strategy.payload')">
              <ValueStrategySelector v-model="form.config.payload" field-type="text" :placeholder="t('strategy.payloadPlaceholder')" :available-strategies="['fixed', 'file']" />
            </el-form-item>

            <el-divider content-position="left">{{ t('strategy.sectionFlowControl') }}</el-divider>
            <el-row :gutter="16">
              <el-col :span="12">
                <el-form-item :label="t('strategy.flowControlType')">
                  <el-select v-model="form.flow_control.type" clearable style="width: 100%;" :placeholder="t('strategy.flowControlType')">
                    <el-option :label="t('strategy.flows')" value="flows" /><el-option :label="t('strategy.bps')" value="bps" /><el-option :label="t('strategy.time')" value="time" />
                  </el-select>
                </el-form-item>
              </el-col>
              <el-col :span="12">
                <el-form-item v-if="form.flow_control.type" :label="t('strategy.flowControlValue')">
                  <div style="display: flex; align-items: center; gap: 8px; width: 100%;">
                    <el-input-number v-model="form.flow_control.value" :min="0" style="flex: 1;" />
                    <span class="flow-unit">{{ flowControlUnit }}</span>
                  </div>
                </el-form-item>
              </el-col>
            </el-row>
          </div>
        </template>
      </el-form>

      <template #footer>
        <el-tooltip :content="(!form.name || !form.protocol) ? t('strategy.templateDisabledHint') : ''" placement="top">
          <el-button @click="handleSaveTemplate" :disabled="!form.name || !form.protocol">{{ t('strategy.saveAsTemplate') }}</el-button>
        </el-tooltip>
        <el-button @click="dialogVisible = false">{{ t('common.cancel') }}</el-button>
        <el-button type="primary" :loading="submitLoading" @click="handleSubmit">{{ t('common.confirm') }}</el-button>
      </template>
    </ProDialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, computed, watch, nextTick } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Search, Setting, Refresh, More, ArrowRight, Plus } from '@element-plus/icons-vue'
import type { FormInstance, FormRules } from 'element-plus'
import { strategyApi, type Strategy, type TaskBrief } from '@/api'
import { useStrategyTemplates } from '@/composables/useStrategyTemplates'
import { useClientList } from '@/composables/useClientList'
import { useSelection } from '@/composables/useSelection'
import { useBatchAction } from '@/composables/useBatchAction'
import { useFormDirty } from '@/composables/useFormDirty'
import ProTable from '@/components/ProTable/index.vue'
import ProCardHeader from '@/components/ProCardHeader/index.vue'
import ProFilterBar from '@/components/ProFilterBar/index.vue'
import ProDialog from '@/components/ProDialog/index.vue'
import ProDrawer from '@/components/ProDrawer/index.vue'
import ValueStrategySelector, { type StrategyValue } from '@/components/ValueStrategySelector/index.vue'
import { formatTimestamp } from '@/utils/format'
import { createClientSort } from '@/utils/sort'
import { TASK_STATUS_TYPE } from '@/constants/status'
import type { FilterFieldDef } from '@/composables/useActiveFilters'

const STORAGE_KEY = 'strategy-list-state'
const { t } = useI18n()

// Client list composable (replaces loading, strategies, sortState, fetch, sort logic)
const { loading, data: strategies, sortState, refresh, handleSortChange } = useClientList<Strategy>({
  fetchFn: async () => {
    const res = await strategyApi.list()
    return Array.isArray(res.data) ? res.data : (res.data as any).items || []
  },
  clientSort: (items, sort) => {
    if (!sort.prop || !sort.order) return items
    return [...items].sort(createClientSort(sort.prop as keyof Strategy, sort.order))
  },
  defaultSort: { prop: 'created_at', order: 'descending' }
})

// Selection composable (replaces selectedStrategies, handleSelectionChange, clearSelection)
const { selectedItems: selectedStrategies, handleSelectionChange, clearSelection } = useSelection<Strategy>()

// Batch action composable (replaces handleBulkDelete inline)
const batchDelete = useBatchAction<Strategy>({
  action: (strategy) => strategyApi.delete(strategy.id),
  confirmMessage: (count) => t('strategy.confirmBulkDelete', { count }),
  successMessage: (count) => t('strategy.bulkDeleted', { count }),
  partialMessage: (succeeded, failed) => t('task.bulkPartial', { succeeded, failed })
})

const submitLoading = ref(false)
const dialogVisible = ref(false)
const editingStrategy = ref<Strategy | null>(null)
const formRef = ref<FormInstance>()
const proTableRef = ref()
const strategyTasks = ref<TaskBrief[]>([])
const taskPopoverLoading = ref(false)
const drawerVisible = ref(false)
const drawerLoading = ref(false)
const drawerStrategy = ref<Strategy | null>(null)
const showAdvanced = ref(false)

const columns = computed(() => [
  { type: 'selection' as const, width: 45, fixed: 'left' },
  { prop: 'id', label: t('strategy.strategyId'), width: 100, required: true, sortable: 'custom' },
  { prop: 'name', label: t('strategy.strategyName'), minWidth: 180, sortable: 'custom', required: true },
  { prop: 'protocol', label: t('task.protocol'), width: 90, sortable: 'custom' },
  { prop: 'task_count', label: t('strategy.taskCount'), width: 100, align: 'center' as const, sortable: 'custom' },
  { prop: 'flow_control', label: t('strategy.flowControl'), width: 110, sortable: 'custom' },
  { prop: 'created_at', label: t('common.createdAt'), width: 170, sortable: 'custom' },
  { prop: 'updated_at', label: t('common.updatedAt'), width: 170, sortable: 'custom' },
  { prop: 'actions', label: t('task.actions'), width: 120, fixed: 'right', required: true }
])

function loadState() { try { const r = localStorage.getItem(STORAGE_KEY); if (r) return JSON.parse(r) } catch {} return null }
const saved = loadState()
const filters = reactive({ search: saved?.filters?.search || '', protocol: saved?.filters?.protocol || [] as string[] })
const pagination = reactive({ page: saved?.pagination?.page || 1, size: saved?.pagination?.size || 20 })

watch([() => ({ ...filters }), () => ({ ...pagination })], () => {
  localStorage.setItem(STORAGE_KEY, JSON.stringify({ filters: { search: filters.search, protocol: filters.protocol }, pagination: { page: pagination.page, size: pagination.size } }))
}, { deep: true })

// ProFilterBar field definitions
const filterFieldDefs: FilterFieldDef[] = [
  { key: 'search', label: t('strategy.searchPlaceholder'), type: 'text' },
  { key: 'protocol', label: t('task.protocol'), type: 'select', multiple: true }
]

// Presets
const srcIPPresets = ['192.168.1.100', '10.0.0.1', '172.16.0.1']
const dstIPPresets = ['192.168.1.1', '10.0.0.2', '172.16.0.2']

const HEADER_PRESETS = [
  { key: 'Content-Type', value: 'application/json' },
  { key: 'Accept', value: '*/*' },
  { key: 'User-Agent', value: 'Mozilla/5.0' },
  { key: 'Authorization', value: 'Bearer ' },
  { key: 'Host', value: '' },
]

const PROTOCOL_PRESETS: Record<string, number> = { tcp: 80, udp: 5000, http: 80, dns: 53, icmp: 0, arp: 0 }

// Templates
const { allTemplates, customTemplates, addTemplate, getTemplate } = useStrategyTemplates()
const builtinTemplates = computed(() => allTemplates.value.filter(t => t.isBuiltin))
const selectedTemplateId = ref<string>('')

function sv(val: any): StrategyValue {
  return { strategy: 'fixed', value: val ?? '' }
}
function svPort(val: number): StrategyValue {
  return { strategy: 'fixed', value: val }
}

interface StrategyForm {
  name: string
  protocol: string
  config: {
    src_ip: StrategyValue; dst_ip: StrategyValue
    src_port: StrategyValue; dst_port: StrategyValue
    src_mac: string; dst_mac: string
    ttl: StrategyValue; tos: StrategyValue; payload: StrategyValue
    vlan_enable: boolean; vlan_id: number; vlan_priority: number
    tcp: { handshake: boolean; termination: boolean; mss: number; window_size: number; seq?: number; flags?: number; wscale?: boolean; sack?: boolean; timestamps?: boolean }
    udp: { response: boolean }
    http: { methods: string[]; uri: StrategyValue; headers: { key: string; value: string }[]; body: StrategyValue; keep_alive: boolean; transactions: number }
    dns: { domain: string; query_type: number; response: boolean; response_ip: string }
    icmp: { type: number; code: number; sequence: number; data: string }
    arp: { operation: number; target_mac: string; target_ip: string }
  }
  flow_control: { type: string; value: number }
}

function defaultForm(): StrategyForm {
  return {
    name: '', protocol: 'tcp',
    config: {
      src_ip: sv('192.168.1.100'), dst_ip: sv(''),
      src_port: svPort(Math.floor(Math.random() * (65535 - 49152 + 1)) + 49152),
      dst_port: svPort(PROTOCOL_PRESETS['tcp']),
      src_mac: '', dst_mac: '',
      ttl: svPort(64), tos: svPort(0), payload: sv(''),
      vlan_enable: false, vlan_id: 1, vlan_priority: 0,
      tcp: { handshake: true, termination: true, mss: 1460, window_size: 65535, seq: 0, flags: 0, wscale: false, sack: false, timestamps: false },
      udp: { response: false },
      http: { methods: ['GET'], uri: sv('/'), headers: [], body: sv(''), keep_alive: true, transactions: 10 },
      dns: { domain: 'example.com', query_type: 1, response: false, response_ip: '' },
      icmp: { type: 8, code: 0, sequence: 1, data: 'ping' },
      arp: { operation: 1, target_mac: '', target_ip: '' },
    },
    flow_control: { type: 'flows', value: 1 },
  }
}

const form = reactive<StrategyForm>(defaultForm())

// Form dirty tracking (replaced by useFormDirty)
const formDirty = useFormDirty(form)

const flowControlUnit = computed(() => {
  const u: Record<string, string> = { flows: t('strategy.unitFlows'), bps: t('strategy.unitBps'), cps: t('strategy.unitCps'), ratio: t('strategy.unitRatio'), time: t('strategy.unitTime') }
  return u[form.flow_control.type] || ''
})

// Validation
const ipValidator = (_r: any, value: string, cb: (e?: Error) => void) => {
  if (!value) { cb(); return }
  const sv = typeof value === 'object' ? (value as StrategyValue).value : value
  if (typeof sv === 'string' && sv) {
    if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(sv) || sv.split('.').some(p => Number(p) > 255)) { cb(new Error(t('strategy.validation.invalidIP'))); return }
  }
  cb()
}

const rules: FormRules = {
  name: [{ required: true, message: t('strategy.strategyNamePlaceholder'), trigger: 'blur' }],
  protocol: [{ required: true, message: () => t('strategy.selectProtocol'), trigger: 'change' }],
  'config.dst_ip': [
    { required: true, validator: (_r: any, v: StrategyValue, cb: (e?: Error) => void) => { if (!v?.value) cb(new Error(t('strategy.validation.dstIPRequired'))); else cb() }, trigger: 'blur' },
  ],
}

// Strategy config helpers
function strategyConfigValue(val: any): string {
  if (!val) return '-'
  if (typeof val === 'object' && val.strategy) {
    const sv = val as StrategyValue
    if (sv.strategy === 'fixed') return String(sv.value || '-')
    if (sv.strategy === 'inc') return `${sv.range?.[0] ?? '?'} ~ ${sv.range?.[1] ?? '?'} (step ${sv.step ?? 1})`
    if (sv.strategy === 'random') return `${sv.range?.[0] ?? '?'} ~ ${sv.range?.[1] ?? '?'} (random)`
    if (sv.strategy === 'pattern') return sv.pattern || '-'
    if (sv.strategy === 'list') return (sv.list || []).join(', ') || '-'
  }
  return String(val)
}

function normalizeStrategyValue(val: any, defaultVal: any): StrategyValue {
  if (!val) return sv(defaultVal)
  if (typeof val === 'object' && val.strategy) return val
  return sv(val)
}

function extractConfigValue(sv: StrategyValue): any {
  if (!sv || sv.strategy === 'fixed') return sv?.value
  return sv // pass through strategy object for backend
}

function onProtocolChange() {
  form.config.dst_port = svPort(PROTOCOL_PRESETS[form.protocol] ?? 0)
  showAdvanced.value = false
  switch (form.protocol) {
    case 'tcp': form.config.tcp = { handshake: true, termination: true, mss: 1460, window_size: 65535, seq: 0, flags: 0, wscale: false, sack: false, timestamps: false }; break
    case 'udp': form.config.udp = { response: false }; break
    case 'http': form.config.http = { methods: ['GET'], uri: sv('/'), headers: [], body: '', keep_alive: true, transactions: 10 }; break
    case 'dns': form.config.dns = { domain: 'example.com', query_type: 1, response: false, response_ip: '' }; break
    case 'icmp': form.config.icmp = { type: 8, code: 0, sequence: 1, data: 'ping' }; break
    case 'arp': form.config.arp = { operation: 1, target_mac: '', target_ip: '' }; break
  }
}

function addHeader() {
  form.config.http.headers.push({ key: '', value: '' })
}

function applyTemplate(templateId: string) {
  if (!templateId) return
  const template = getTemplate(templateId)
  if (!template) return
  form.protocol = template.protocol
  const cfg = template.config || {}
  if (cfg.src_ip) form.config.src_ip = normalizeStrategyValue(cfg.src_ip, cfg.src_ip)
  if (cfg.dst_ip) form.config.dst_ip = normalizeStrategyValue(cfg.dst_ip, cfg.dst_ip)
  if (cfg.src_port) form.config.src_port = normalizeStrategyValue(cfg.src_port, cfg.src_port)
  if (cfg.dst_port) form.config.dst_port = normalizeStrategyValue(cfg.dst_port, cfg.dst_port)
  if (cfg.ttl) form.config.ttl = cfg.ttl
  if (cfg.tos) form.config.tos = cfg.tos
  if (cfg.payload) form.config.payload = cfg.payload
  if (cfg.vlan_id) { form.config.vlan_enable = true; form.config.vlan_id = cfg.vlan_id; if (cfg.vlan_priority) form.config.vlan_priority = cfg.vlan_priority }
  if (cfg.tcp && typeof cfg.tcp === 'object') form.config.tcp = { ...form.config.tcp, ...cfg.tcp }
  if (cfg.udp && typeof cfg.udp === 'object') form.config.udp = { ...form.config.udp, ...cfg.udp }
  if (cfg.http && typeof cfg.http === 'object') {
    const h = { ...cfg.http }
    if (h.headers && typeof h.headers === 'object' && !Array.isArray(h.headers)) {
      form.config.http.headers = Object.entries(h.headers).map(([k, v]) => ({ key: k, value: String(v) }))
      delete h.headers
    }
    if (h.method && !h.methods) { form.config.http.methods = [h.method]; delete h.method }
    if (h.uri) form.config.http.uri = normalizeStrategyValue(h.uri, h.uri)
    form.config.http = { ...form.config.http, ...h }
  }
  if (cfg.dns && typeof cfg.dns === 'object') form.config.dns = { ...form.config.dns, ...cfg.dns }
  if (cfg.icmp && typeof cfg.icmp === 'object') form.config.icmp = { ...form.config.icmp, ...cfg.icmp }
  if (cfg.arp && typeof cfg.arp === 'object') form.config.arp = { ...form.config.arp, ...cfg.arp }
  if (template.flow_control) form.flow_control = { ...template.flow_control }
  ElMessage.success(t('strategy.templateApplied'))
}

function handleSaveTemplate() {
  if (!form.name || !form.protocol) return
  ElMessageBox.prompt(t('strategy.templateDescriptionPlaceholder'), t('strategy.saveAsTemplate'), {
    confirmButtonText: t('common.save'), cancelButtonText: t('common.cancel'),
    inputPlaceholder: t('strategy.templateDescriptionPlaceholder')
  }).then(({ value: description }) => {
    addTemplate({ name: form.name, description: description || '', protocol: form.protocol, config: buildConfigForSubmit(), flow_control: form.flow_control.type ? { ...form.flow_control } : undefined })
    ElMessage.success(t('strategy.templateSaved'))
  }).catch(() => {})
}

function openCreateDialog() {
  editingStrategy.value = null; selectedTemplateId.value = ''
  Object.assign(form, defaultForm()); showAdvanced.value = false
  dialogVisible.value = true
  nextTick(() => formDirty.captureSnapshot())
}

function cloneStrategy(s: Strategy) {
  openEditDialog(s)
  form.name = s.name + ' ' + t('strategy.cloneSuffix')
  editingStrategy.value = null
}

function openEditDialog(s: Strategy) {
  editingStrategy.value = s
  Object.assign(form, defaultForm())
  form.name = s.name; form.protocol = s.protocol
  const cfg = s.config || {}
  form.config.src_ip = normalizeStrategyValue(cfg.src_ip, '192.168.1.100')
  form.config.dst_ip = normalizeStrategyValue(cfg.dst_ip, '')
  form.config.src_port = normalizeStrategyValue(cfg.src_port, 0)
  form.config.dst_port = normalizeStrategyValue(cfg.dst_port, PROTOCOL_PRESETS[s.protocol] ?? 0)
  if (cfg.src_mac) form.config.src_mac = cfg.src_mac
  if (cfg.dst_mac) form.config.dst_mac = cfg.dst_mac
  form.config.ttl = normalizeStrategyValue(cfg.ttl, 64)
  form.config.tos = normalizeStrategyValue(cfg.tos, 0)
  form.config.payload = normalizeStrategyValue(cfg.payload, '')
  if (cfg.vlan_id) { form.config.vlan_enable = true; form.config.vlan_id = cfg.vlan_id; if (cfg.vlan_priority) form.config.vlan_priority = cfg.vlan_priority }
  if (cfg.tcp && typeof cfg.tcp === 'object') form.config.tcp = { ...form.config.tcp, ...cfg.tcp }
  if (cfg.udp && typeof cfg.udp === 'object') form.config.udp = { ...form.config.udp, ...cfg.udp }
  if (cfg.http && typeof cfg.http === 'object') {
    const h = { ...cfg.http }
    if (h.headers && typeof h.headers === 'object' && !Array.isArray(h.headers)) {
      form.config.http.headers = Object.entries(h.headers).map(([k, v]) => ({ key: k, value: String(v) }))
      delete h.headers
    }
    if (h.method && !h.methods) { form.config.http.methods = Array.isArray(h.method) ? h.method : [h.method]; delete h.method }
    if (h.uri) form.config.http.uri = normalizeStrategyValue(h.uri, h.uri)
    if (h.body) form.config.http.body = normalizeStrategyValue(h.body, '')
    form.config.http = { ...form.config.http, ...h }
  }
  if (cfg.dns && typeof cfg.dns === 'object') form.config.dns = { ...form.config.dns, ...cfg.dns }
  if (cfg.icmp && typeof cfg.icmp === 'object') form.config.icmp = { ...form.config.icmp, ...cfg.icmp }
  if (cfg.arp && typeof cfg.arp === 'object') form.config.arp = { ...form.config.arp, ...cfg.arp }
  if (s.flow_control) form.flow_control = { ...s.flow_control }
  showAdvanced.value = false
  dialogVisible.value = true
  nextTick(() => formDirty.captureSnapshot())
}

function buildConfigForSubmit(): Record<string, any> {
  const cfg: Record<string, any> = {}
  cfg.src_ip = extractConfigValue(form.config.src_ip)
  cfg.dst_ip = extractConfigValue(form.config.dst_ip)
  cfg.src_port = extractConfigValue(form.config.src_port)
  cfg.dst_port = extractConfigValue(form.config.dst_port)
  if (form.config.src_mac) cfg.src_mac = form.config.src_mac
  if (form.config.dst_mac) cfg.dst_mac = form.config.dst_mac
  const ttlVal = extractConfigValue(form.config.ttl)
  if (ttlVal && ttlVal !== 64) cfg.ttl = ttlVal
  const tosVal = extractConfigValue(form.config.tos)
  if (tosVal) cfg.tos = tosVal
  const payloadVal = extractConfigValue(form.config.payload)
  if (payloadVal) cfg.payload = payloadVal
  if (form.config.vlan_enable && form.config.vlan_id) { cfg.vlan_id = form.config.vlan_id; if (form.config.vlan_priority) cfg.vlan_priority = form.config.vlan_priority }
  switch (form.protocol) {
    case 'tcp': cfg.tcp = { handshake: form.config.tcp.handshake, termination: form.config.tcp.termination, mss: form.config.tcp.mss, window_size: form.config.tcp.window_size }; break
    case 'udp': cfg.udp = { response: form.config.udp.response }; break
    case 'http':
      cfg.http = { method: form.config.http.methods.length === 1 ? form.config.http.methods[0] : form.config.http.methods, uri: extractConfigValue(form.config.http.uri), body: extractConfigValue(form.config.http.body), keep_alive: form.config.http.keep_alive, transactions: form.config.http.transactions }
      const hdrs: Record<string, string> = {}
      for (const h of form.config.http.headers) { if (h.key) hdrs[h.key] = h.value }
      if (Object.keys(hdrs).length > 0) cfg.http.headers = hdrs
      break
    case 'dns': cfg.dns = { domain: form.config.dns.domain, query_type: form.config.dns.query_type, response: form.config.dns.response }; if (form.config.dns.response && form.config.dns.response_ip) cfg.dns.response_ip = form.config.dns.response_ip; break
    case 'icmp': cfg.icmp = { type: form.config.icmp.type, code: form.config.icmp.code, sequence: form.config.icmp.sequence, data: form.config.icmp.data }; break
    case 'arp': cfg.arp = { operation: form.config.arp.operation, target_mac: form.config.arp.target_mac, target_ip: form.config.arp.target_ip }; break
  }
  return cfg
}

async function handleSubmit() {
  const valid = await formRef.value?.validate()
  if (!valid) return
  submitLoading.value = true
  try {
    const cfg = buildConfigForSubmit()
    const data: any = { name: form.name, protocol: form.protocol, config: cfg }
    data.flow_control = form.flow_control.type ? { type: form.flow_control.type, value: form.flow_control.value } : { type: 'flows', value: 1 }
    if (editingStrategy.value) { await strategyApi.update(editingStrategy.value.id, data); ElMessage.success(t('strategy.updateSuccess')) }
    else { await strategyApi.create(data); ElMessage.success(t('strategy.createSuccess')) }
    dialogVisible.value = false; loadStrategies()
  } catch (e) { console.error(e); ElMessage.error(editingStrategy.value ? t('strategy.updateFailed') : t('strategy.createFailed')) }
  finally { submitLoading.value = false }
}

const filteredStrategies = computed(() => {
  let r = strategies.value
  if (filters.search) { const s = filters.search.toLowerCase(); r = r.filter(x => x.name.toLowerCase().includes(s) || x.id.toLowerCase().includes(s)) }
  if (filters.protocol.length > 0) r = r.filter(x => filters.protocol.includes(x.protocol))
  // Sort is now handled by useClientList, so we don't apply it here
  return r
})

function resetFilters() { filters.search = ''; filters.protocol = []; pagination.page = 1 }

function handleClearFilter(key: string) {
  const emptyValues: Record<string, any> = { search: '', protocol: [] }
  if (key in emptyValues) {
    filters[key as keyof typeof filters] = emptyValues[key]
  }
}

async function handleBulkDelete() {
  await batchDelete.execute(selectedStrategies.value)
  clearSelection(proTableRef.value)
  refresh()
}

async function openDrawer(s: Strategy) { drawerStrategy.value = s; drawerVisible.value = true; drawerLoading.value = true; try { const r = await strategyApi.get(s.id); if (r.data) drawerStrategy.value = r.data as Strategy } catch {} finally { drawerLoading.value = false } }

async function handleDelete(id: string) { try { await ElMessageBox.confirm(t('strategy.confirmDelete'), t('common.confirm'), { type: 'warning' }); await strategyApi.delete(id); ElMessage.success(t('strategy.deleteSuccess')); refresh() } catch (e) { if (e !== 'cancel') { ElMessage.error(t('strategy.deleteFailed')) } } }

function handleAction(cmd: string, s: Strategy) { if (cmd === 'detail') openDrawer(s); else if (cmd === 'clone') cloneStrategy(s); else if (cmd === 'delete') handleDelete(s.id) }

async function loadStrategies() { await refresh() }

async function loadStrategyTasks(strategyId: string) {
  taskPopoverLoading.value = true
  try {
    const res = await strategyApi.getTasks(strategyId)
    strategyTasks.value = (res.data as TaskBrief[]) || []
  } catch {
    strategyTasks.value = []
  } finally {
    taskPopoverLoading.value = false
  }
}

onMounted(() => { refresh() })
</script>

<style scoped>
.batch-info { font-size: 13px; color: var(--tg-text-secondary, #606266); }
.action-buttons { display: flex; gap: 4px; flex-wrap: wrap; }
.header-row { display: flex; gap: 8px; margin-bottom: 8px; align-items: center; }
.flow-unit { font-size: 12px; color: var(--tg-text-secondary, #909399); white-space: nowrap; }

.strategy-form :deep(.el-divider__text) {
  font-weight: 600;
  font-size: 14px;
  color: var(--el-text-color-primary);
}

.strategy-form :deep(.el-form-item) {
  margin-bottom: 16px;
}

.rotate-icon {
  transform: rotate(90deg);
}

.text-muted {
  color: var(--tg-text-disabled, #94A3B8);
}

.task-popover-list {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.task-popover-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}

.task-popover-name {
  color: var(--tg-primary, #409eff);
  text-decoration: none;
  font-size: 13px;
}

.task-popover-name:hover {
  text-decoration: underline;
}

.task-popover-empty {
  color: var(--tg-text-secondary, #909399);
  text-align: center;
  padding: 8px 0;
}
</style>
