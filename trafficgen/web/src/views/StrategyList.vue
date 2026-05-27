<template>
  <div class="strategy-list">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>{{ t('strategy.title') }}</span>
          <el-button type="primary" @click="openCreateDialog">
            {{ t('strategy.createStrategy') }}
          </el-button>
        </div>
      </template>

      <!-- 筛选栏 -->
      <div class="filter-bar">
        <el-input
          v-model="filters.search"
          :placeholder="t('strategy.searchPlaceholder')"
          clearable
          style="width: 300px"
          @keyup.enter="loadStrategies"
        >
          <template #prefix>
            <el-icon><Search /></el-icon>
          </template>
        </el-input>

        <el-select
          v-model="filters.protocol"
          :placeholder="t('task.protocol')"
          multiple
          collapse-tags
          collapse-tags-tooltip
          clearable
          style="width: 200px"
          @change="loadStrategies"
        >
          <el-option :label="t('protocol.tcp')" value="tcp" />
          <el-option :label="t('protocol.udp')" value="udp" />
          <el-option :label="t('protocol.http')" value="http" />
          <el-option :label="t('protocol.dns')" value="dns" />
          <el-option :label="t('protocol.icmp')" value="icmp" />
          <el-option :label="t('protocol.arp')" value="arp" />
        </el-select>

        <el-button link type="primary" @click="resetFilters">
          {{ t('common.reset') }}
        </el-button>
      </div>

      <!-- 批量操作工具栏 -->
      <div v-if="selectedStrategies.length > 0" class="bulk-toolbar">
        <el-space>
          <span class="bulk-text">
            {{ t('common.selected') }} {{ selectedStrategies.length }} {{ t('strategy.strategiesUnit') }}
          </span>
          <el-button size="small" type="danger" @click="handleBulkDelete">
            {{ t('strategy.bulkDelete') }}
          </el-button>
          <el-button size="small" @click="clearSelection">
            {{ t('strategy.clearSelection') }}
          </el-button>
        </el-space>
      </div>

      <el-table :data="paginatedStrategies" v-loading="loading" stripe @selection-change="handleSelectionChange">
        <el-table-column type="selection" width="55" />
        <el-table-column prop="id" :label="t('strategy.strategyId')" width="100" show-overflow-tooltip>
          <template #default="{ row }">
            {{ row.id?.substring(0, 8) }}
          </template>
        </el-table-column>
        <el-table-column prop="name" :label="t('strategy.strategyName')" min-width="150" show-overflow-tooltip />
        <el-table-column prop="protocol" :label="t('task.protocol')" width="100" align="center">
          <template #default="{ row }">
            <el-tag size="small">{{ row.protocol.toUpperCase() }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="t('strategy.flowControl')" width="180">
          <template #default="{ row }">
            <span v-if="row.flow_control">{{ row.flow_control.type }}: {{ row.flow_control.value }}</span>
            <span v-else>-</span>
          </template>
        </el-table-column>
        <el-table-column :label="t('common.createdAt')" width="160">
          <template #default="{ row }">
            {{ formatTime(row.created_at) }}
          </template>
        </el-table-column>
        <el-table-column :label="t('common.action')" width="260" fixed="right">
          <template #default="{ row }">
            <el-space>
              <el-button type="primary" link size="small" @click="openEditDialog(row)">
                {{ t('common.edit') }}
              </el-button>
              <el-button link size="small" @click="openDrawer(row)">
                {{ t('task.viewDetail') }}
              </el-button>
              <el-button link size="small" @click="cloneStrategy(row)">
                {{ t('strategy.clone') }}
              </el-button>
              <el-popconfirm :title="t('strategy.confirmDelete')" @confirm="handleDelete(row.id)">
                <template #reference>
                  <el-button type="danger" link size="small">
                    {{ t('common.delete') }}
                  </el-button>
                </template>
              </el-popconfirm>
            </el-space>
          </template>
        </el-table-column>
      </el-table>

      <!-- 分页 -->
      <el-pagination
        v-model:current-page="pagination.page"
        v-model:page-size="pagination.size"
        :total="filteredStrategies.length"
        :page-sizes="[10, 20, 50, 100]"
        layout="total, sizes, prev, pager, next, jumper"
        style="margin-top: 20px; justify-content: flex-end;"
      />
    </el-card>

    <!-- 策略详情抽屉 -->
    <el-drawer
      v-model="drawerVisible"
      :title="drawerStrategy?.name || t('strategy.strategyId')"
      size="50%"
      direction="rtl"
    >
      <div v-if="drawerStrategy" v-loading="drawerLoading">
        <el-descriptions :column="2" border>
          <el-descriptions-item :label="t('strategy.strategyId')">{{ drawerStrategy.id }}</el-descriptions-item>
          <el-descriptions-item :label="t('strategy.strategyName')">{{ drawerStrategy.name }}</el-descriptions-item>
          <el-descriptions-item :label="t('task.protocol')">
            <el-tag>{{ drawerStrategy.protocol.toUpperCase() }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item :label="t('common.createdAt')">{{ formatTime(drawerStrategy.created_at) }}</el-descriptions-item>
        </el-descriptions>

        <el-divider content-position="left">{{ t('strategy.networkConfig') }}</el-divider>
        <el-descriptions :column="2" border v-if="drawerStrategy.config">
          <el-descriptions-item :label="t('strategy.srcIP')">{{ drawerStrategy.config.src_ip || '-' }}</el-descriptions-item>
          <el-descriptions-item :label="t('strategy.dstIP')">{{ drawerStrategy.config.dst_ip || '-' }}</el-descriptions-item>
          <el-descriptions-item :label="t('strategy.srcPort')">{{ drawerStrategy.config.src_port || '-' }}</el-descriptions-item>
          <el-descriptions-item :label="t('strategy.dstPort')">{{ drawerStrategy.config.dst_port || '-' }}</el-descriptions-item>
          <el-descriptions-item :label="t('strategy.srcMAC')">{{ drawerStrategy.config.src_mac || '-' }}</el-descriptions-item>
          <el-descriptions-item :label="t('strategy.dstMAC')">{{ drawerStrategy.config.dst_mac || '-' }}</el-descriptions-item>
          <el-descriptions-item v-if="drawerStrategy.config.vlan_id" :label="t('strategy.vlanID')">{{ drawerStrategy.config.vlan_id }}</el-descriptions-item>
          <el-descriptions-item v-if="drawerStrategy.config.vlan_id" :label="t('strategy.vlanPriority')">{{ drawerStrategy.config.vlan_priority || 0 }}</el-descriptions-item>
          <el-descriptions-item :label="t('strategy.ttl')">{{ drawerStrategy.config.ttl || 64 }}</el-descriptions-item>
          <el-descriptions-item :label="t('strategy.tos')">{{ drawerStrategy.config.tos || 0 }}</el-descriptions-item>
        </el-descriptions>

        <!-- 协议特定配置 -->
        <template v-if="drawerStrategy.config?.tcp">
          <el-divider content-position="left">{{ t('protocol.tcp') }} {{ t('strategy.protocolConfig') }}</el-divider>
          <el-descriptions :column="2" border>
            <el-descriptions-item :label="t('strategy.handshake')">{{ drawerStrategy.config.tcp.handshake ? t('common.yes') : t('common.no') }}</el-descriptions-item>
            <el-descriptions-item :label="t('strategy.termination')">{{ drawerStrategy.config.tcp.termination ? t('common.yes') : t('common.no') }}</el-descriptions-item>
            <el-descriptions-item :label="t('strategy.mss')">{{ drawerStrategy.config.tcp.mss }}</el-descriptions-item>
            <el-descriptions-item :label="t('strategy.windowSize')">{{ drawerStrategy.config.tcp.window_size }}</el-descriptions-item>
          </el-descriptions>
        </template>

        <template v-if="drawerStrategy.config?.http">
          <el-divider content-position="left">{{ t('protocol.http') }} {{ t('strategy.protocolConfig') }}</el-divider>
          <el-descriptions :column="2" border>
            <el-descriptions-item :label="t('strategy.method')">{{ drawerStrategy.config.http.method }}</el-descriptions-item>
            <el-descriptions-item :label="t('strategy.uri')">{{ drawerStrategy.config.http.uri }}</el-descriptions-item>
            <el-descriptions-item :label="t('strategy.keepAlive')">{{ drawerStrategy.config.http.keep_alive ? t('common.yes') : t('common.no') }}</el-descriptions-item>
            <el-descriptions-item :label="t('strategy.transactions')">{{ drawerStrategy.config.http.transactions }}</el-descriptions-item>
          </el-descriptions>
        </template>

        <template v-if="drawerStrategy.config?.dns">
          <el-divider content-position="left">{{ t('protocol.dns') }} {{ t('strategy.protocolConfig') }}</el-divider>
          <el-descriptions :column="2" border>
            <el-descriptions-item :label="t('strategy.domain')">{{ drawerStrategy.config.dns.domain }}</el-descriptions-item>
            <el-descriptions-item :label="t('strategy.queryType')">{{ drawerStrategy.config.dns.query_type }}</el-descriptions-item>
          </el-descriptions>
        </template>

        <template v-if="drawerStrategy.config?.icmp">
          <el-divider content-position="left">{{ t('protocol.icmp') }} {{ t('strategy.protocolConfig') }}</el-divider>
          <el-descriptions :column="2" border>
            <el-descriptions-item :label="t('strategy.icmpType')">{{ drawerStrategy.config.icmp.type }}</el-descriptions-item>
            <el-descriptions-item :label="t('strategy.icmpCode')">{{ drawerStrategy.config.icmp.code }}</el-descriptions-item>
          </el-descriptions>
        </template>

        <el-divider content-position="left">{{ t('strategy.flowControl') }}</el-divider>
        <el-descriptions :column="1" border>
          <el-descriptions-item :label="t('strategy.flowControl')">
            <span v-if="drawerStrategy.flow_control">{{ drawerStrategy.flow_control.type }}: {{ drawerStrategy.flow_control.value }}</span>
            <span v-else>{{ t('common.noData') }}</span>
          </el-descriptions-item>
        </el-descriptions>
      </div>
    </el-drawer>

    <!-- Create/Edit Dialog -->
    <el-dialog
      v-model="dialogVisible"
      :title="editingStrategy ? t('common.edit') : t('strategy.createStrategy')"
      width="720px"
      :close-on-click-modal="false"
      destroy-on-close
    >
      <el-form ref="formRef" :model="form" :rules="{ ...rules, ...configRules }" label-width="120px">
        <!-- Template Selector (only for create mode) -->
        <template v-if="!editingStrategy">
          <el-divider content-position="left">{{ t('strategy.templates') }}</el-divider>
          <el-form-item :label="t('strategy.selectTemplate')">
            <el-select v-model="selectedTemplateId" :placeholder="t('strategy.selectTemplate')" clearable style="width: 100%;" @change="applyTemplate">
              <el-option-group :label="t('strategy.builtinTemplates')">
                <el-option v-for="tp in builtinTemplates" :key="tp.id" :label="`${tp.name} (${tp.protocol.toUpperCase()}) - ${tp.description}`" :value="tp.id" />
              </el-option-group>
              <el-option-group v-if="customTemplates.length > 0" :label="t('strategy.customTemplates')">
                <el-option v-for="tp in customTemplates" :key="tp.id" :label="`${tp.name} (${tp.protocol.toUpperCase()}) - ${tp.description}`" :value="tp.id" />
              </el-option-group>
            </el-select>
          </el-form-item>
        </template>

        <!-- Basic Info -->
        <el-divider content-position="left">{{ t('task.basicInfo') }}</el-divider>

        <el-form-item :label="t('strategy.strategyName')" prop="name">
          <el-input v-model="form.name" :placeholder="t('strategy.strategyNamePlaceholder')" />
        </el-form-item>

        <el-form-item :label="t('task.protocol')" prop="protocol">
          <el-select v-model="form.protocol" :placeholder="t('strategy.selectProtocol')" :disabled="!!editingStrategy" @change="onProtocolChange">
            <el-option :label="t('protocol.tcp')" value="tcp" />
            <el-option :label="t('protocol.udp')" value="udp" />
            <el-option :label="t('protocol.http')" value="http" />
            <el-option :label="t('protocol.dns')" value="dns" />
            <el-option :label="t('protocol.icmp')" value="icmp" />
            <el-option :label="t('protocol.arp')" value="arp" />
          </el-select>
        </el-form-item>

        <!-- Network Config (all protocols except ARP) -->
        <template v-if="form.protocol && form.protocol !== 'arp'">
          <el-divider content-position="left">{{ t('strategy.networkConfig') }}</el-divider>

          <el-row :gutter="20">
            <el-col :span="12">
              <el-form-item :label="t('strategy.srcIP')">
                <el-input v-model="form.config.src_ip" placeholder="192.168.1.100" />
              </el-form-item>
            </el-col>
            <el-col :span="12">
              <el-form-item :label="t('strategy.dstIP')">
                <el-input v-model="form.config.dst_ip" placeholder="192.168.1.1" />
              </el-form-item>
            </el-col>
          </el-row>

          <el-row :gutter="20">
            <el-col :span="12">
              <el-form-item :label="t('strategy.srcPort')">
                <el-input-number v-model="form.config.src_port" :min="1" :max="65535" style="width: 100%;" />
              </el-form-item>
            </el-col>
            <el-col :span="12">
              <el-form-item :label="t('strategy.dstPort')">
                <el-input-number v-model="form.config.dst_port" :min="1" :max="65535" style="width: 100%;" />
              </el-form-item>
            </el-col>
          </el-row>
        </template>

        <!-- L2 Config -->
        <template v-if="form.protocol">
          <el-divider content-position="left">{{ t('strategy.l2Config') }}</el-divider>

          <el-row :gutter="20">
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

          <!-- VLAN -->
          <el-row :gutter="20">
            <el-col :span="6">
              <el-form-item :label="t('strategy.vlanEnable')">
                <el-switch v-model="form.config.vlan_enable" />
              </el-form-item>
            </el-col>
            <el-col v-if="form.config.vlan_enable" :span="9">
              <el-form-item :label="t('strategy.vlanID')">
                <el-input-number v-model="form.config.vlan_id" :min="1" :max="4094" style="width: 100%;" />
              </el-form-item>
            </el-col>
            <el-col v-if="form.config.vlan_enable" :span="9">
              <el-form-item :label="t('strategy.vlanPriority')">
                <el-input-number v-model="form.config.vlan_priority" :min="0" :max="7" style="width: 100%;" />
              </el-form-item>
            </el-col>
          </el-row>
        </template>

        <!-- L3 Config (all protocols except ARP) -->
        <template v-if="form.protocol && form.protocol !== 'arp'">
          <el-divider content-position="left">{{ t('strategy.l3Config') }}</el-divider>

          <el-row :gutter="20">
            <el-col :span="8">
              <el-form-item :label="t('strategy.ttl')">
                <el-input-number v-model="form.config.ttl" :min="1" :max="255" style="width: 100%;" />
              </el-form-item>
            </el-col>
            <el-col :span="8">
              <el-form-item :label="t('strategy.tos')">
                <el-input-number v-model="form.config.tos" :min="0" :max="255" style="width: 100%;" />
              </el-form-item>
            </el-col>
            <el-col :span="8">
              <el-form-item :label="t('strategy.payload')">
                <el-input v-model="form.config.payload" :placeholder="t('strategy.payloadPlaceholder')" />
              </el-form-item>
            </el-col>
          </el-row>
        </template>

        <!-- Protocol-Specific Config -->
        <template v-if="form.protocol === 'tcp'">
          <el-divider content-position="left">{{ t('protocol.tcp') }} {{ t('strategy.protocolConfig') }}</el-divider>
          <el-row :gutter="20">
            <el-col :span="6">
              <el-form-item :label="t('strategy.handshake')">
                <el-switch v-model="form.config.tcp.handshake" />
              </el-form-item>
            </el-col>
            <el-col :span="6">
              <el-form-item :label="t('strategy.termination')">
                <el-switch v-model="form.config.tcp.termination" />
              </el-form-item>
            </el-col>
            <el-col :span="6">
              <el-form-item :label="t('strategy.mss')">
                <el-input-number v-model="form.config.tcp.mss" :min="536" :max="65535" style="width: 100%;" />
              </el-form-item>
            </el-col>
            <el-col :span="6">
              <el-form-item :label="t('strategy.windowSize')">
                <el-input-number v-model="form.config.tcp.window_size" :min="1" :max="65535" style="width: 100%;" />
              </el-form-item>
            </el-col>
          </el-row>
        </template>

        <template v-if="form.protocol === 'udp'">
          <el-divider content-position="left">{{ t('protocol.udp') }} {{ t('strategy.protocolConfig') }}</el-divider>
          <el-row :gutter="20">
            <el-col :span="8">
              <el-form-item :label="t('strategy.udpResponse')">
                <el-switch v-model="form.config.udp.response" />
              </el-form-item>
            </el-col>
          </el-row>
        </template>

        <template v-if="form.protocol === 'http'">
          <el-divider content-position="left">{{ t('protocol.http') }} {{ t('strategy.protocolConfig') }}</el-divider>
          <el-row :gutter="20">
            <el-col :span="8">
              <el-form-item :label="t('strategy.method')">
                <el-select v-model="form.config.http.method" style="width: 100%;">
                  <el-option label="GET" value="GET" />
                  <el-option label="POST" value="POST" />
                  <el-option label="PUT" value="PUT" />
                  <el-option label="DELETE" value="DELETE" />
                  <el-option label="PATCH" value="PATCH" />
                  <el-option label="HEAD" value="HEAD" />
                  <el-option label="OPTIONS" value="OPTIONS" />
                </el-select>
              </el-form-item>
            </el-col>
            <el-col :span="16">
              <el-form-item :label="t('strategy.uri')">
                <el-input v-model="form.config.http.uri" :placeholder="t('strategy.uriPlaceholder')" />
              </el-form-item>
            </el-col>
          </el-row>

          <!-- Headers -->
          <el-form-item :label="t('strategy.headers')">
            <div style="width: 100%;">
              <div v-for="(header, index) in form.config.http.headers" :key="index" style="display: flex; gap: 8px; margin-bottom: 8px;">
                <el-input v-model="header.key" :placeholder="t('strategy.headerKey')" style="flex: 1;" />
                <el-input v-model="header.value" :placeholder="t('strategy.headerValue')" style="flex: 1;" />
                <el-button type="danger" link @click="form.config.http.headers.splice(index, 1)">
                  {{ t('common.delete') }}
                </el-button>
              </div>
              <el-button type="primary" link @click="form.config.http.headers.push({ key: '', value: '' })">
                + {{ t('strategy.addHeader') }}
              </el-button>
            </div>
          </el-form-item>

          <el-form-item :label="t('strategy.body')">
            <el-input v-model="form.config.http.body" type="textarea" rows="3" />
          </el-form-item>

          <el-row :gutter="20">
            <el-col :span="8">
              <el-form-item :label="t('strategy.keepAlive')">
                <el-switch v-model="form.config.http.keep_alive" />
              </el-form-item>
            </el-col>
            <el-col :span="8">
              <el-form-item :label="t('strategy.transactions')">
                <el-input-number v-model="form.config.http.transactions" :min="1" style="width: 100%;" />
              </el-form-item>
            </el-col>
            <el-col :span="8">
              <el-form-item :label="t('strategy.thinkTime')">
                <el-input-number v-model="form.config.http.think_time" :min="0" style="width: 100%;" />
              </el-form-item>
            </el-col>
          </el-row>
        </template>

        <template v-if="form.protocol === 'dns'">
          <el-divider content-position="left">{{ t('protocol.dns') }} {{ t('strategy.protocolConfig') }}</el-divider>
          <el-row :gutter="20">
            <el-col :span="16">
              <el-form-item :label="t('strategy.domain')">
                <el-input v-model="form.config.dns.domain" :placeholder="t('strategy.domainPlaceholder')" />
              </el-form-item>
            </el-col>
            <el-col :span="8">
              <el-form-item :label="t('strategy.queryType')">
                <el-select v-model="form.config.dns.query_type" style="width: 100%;">
                  <el-option label="A" :value="1" />
                  <el-option label="AAAA" :value="28" />
                  <el-option label="CNAME" :value="5" />
                  <el-option label="MX" :value="15" />
                </el-select>
              </el-form-item>
            </el-col>
          </el-row>
          <el-row :gutter="20">
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

        <template v-if="form.protocol === 'icmp'">
          <el-divider content-position="left">{{ t('protocol.icmp') }} {{ t('strategy.protocolConfig') }}</el-divider>
          <el-row :gutter="20">
            <el-col :span="8">
              <el-form-item :label="t('strategy.icmpType')">
                <el-select v-model="form.config.icmp.type" style="width: 100%;">
                  <el-option :label="t('strategy.echoRequest')" :value="8" />
                  <el-option :label="t('strategy.echoReply')" :value="0" />
                </el-select>
              </el-form-item>
            </el-col>
            <el-col :span="8">
              <el-form-item :label="t('strategy.icmpCode')">
                <el-input-number v-model="form.config.icmp.code" :min="0" :max="255" style="width: 100%;" />
              </el-form-item>
            </el-col>
            <el-col :span="8">
              <el-form-item :label="t('strategy.sequence')">
                <el-input-number v-model="form.config.icmp.sequence" :min="0" :max="65535" style="width: 100%;" />
              </el-form-item>
            </el-col>
          </el-row>
          <el-form-item :label="t('strategy.icmpData')">
            <el-input v-model="form.config.icmp.data" placeholder="ping" />
          </el-form-item>
        </template>

        <template v-if="form.protocol === 'arp'">
          <el-divider content-position="left">{{ t('protocol.arp') }} {{ t('strategy.protocolConfig') }}</el-divider>
          <el-row :gutter="20">
            <el-col :span="8">
              <el-form-item :label="t('strategy.operation')">
                <el-select v-model="form.config.arp.operation" style="width: 100%;">
                  <el-option :label="t('strategy.arpRequest')" :value="1" />
                  <el-option :label="t('strategy.arpReply')" :value="2" />
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
                <el-input v-model="form.config.arp.target_ip" placeholder="192.168.1.1" />
              </el-form-item>
            </el-col>
          </el-row>
          <!-- ARP still needs src/dst MAC from L2 section above -->
          <el-row :gutter="20">
            <el-col :span="12">
              <el-form-item :label="t('strategy.srcIP')">
                <el-input v-model="form.config.src_ip" placeholder="192.168.1.100" />
              </el-form-item>
            </el-col>
            <el-col :span="12">
              <el-form-item :label="t('strategy.dstIP')">
                <el-input v-model="form.config.dst_ip" placeholder="192.168.1.1" />
              </el-form-item>
            </el-col>
          </el-row>
        </template>

        <!-- Flow Control -->
        <el-divider content-position="left">{{ t('strategy.flowControl') }}</el-divider>
        <el-row :gutter="20">
          <el-col :span="12">
            <el-form-item :label="t('strategy.flowControlType')">
              <el-select v-model="form.flow_control.type" clearable :placeholder="t('strategy.flowControlType')" style="width: 100%;">
                <el-option :label="t('strategy.bps')" value="bps" />
                <el-option :label="t('strategy.flows')" value="flows" />
                <el-option :label="t('strategy.cps')" value="cps" />
                <el-option :label="t('strategy.ratio')" value="ratio" />
                <el-option :label="t('strategy.time')" value="time" />
              </el-select>
            </el-form-item>
          </el-col>
          <el-col :span="12">
            <el-form-item v-if="form.flow_control.type" :label="t('strategy.flowControlValue')">
              <el-input-number v-model="form.flow_control.value" :min="0" style="width: 100%;" />
            </el-form-item>
          </el-col>
        </el-row>
      </el-form>

      <template #footer>
        <el-button @click="handleSaveTemplate" :disabled="!form.name || !form.protocol">
          {{ t('strategy.saveAsTemplate') }}
        </el-button>
        <el-button @click="dialogVisible = false">{{ t('common.cancel') }}</el-button>
        <el-button type="primary" :loading="submitLoading" @click="handleSubmit">
          {{ t('common.confirm') }}
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, computed, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Search } from '@element-plus/icons-vue'
import type { FormInstance, FormRules } from 'element-plus'
import { strategyApi, type Strategy } from '@/api'
import { useStrategyTemplates, type StrategyTemplate } from '@/composables/useStrategyTemplates'

const STORAGE_KEY = 'strategy-list-state'

const { t } = useI18n()
const loading = ref(false)
const submitLoading = ref(false)
const dialogVisible = ref(false)
const editingStrategy = ref<Strategy | null>(null)
const strategies = ref<Strategy[]>([])
const formRef = ref<FormInstance>()
const selectedStrategies = ref<Strategy[]>([])
const drawerVisible = ref(false)
const drawerLoading = ref(false)
const drawerStrategy = ref<Strategy | null>(null)

function loadState() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (raw) return JSON.parse(raw)
  } catch {}
  return null
}

const saved = loadState()

const filters = reactive({
  search: saved?.filters?.search || '',
  protocol: saved?.filters?.protocol || [] as string[]
})

const pagination = reactive({
  page: saved?.pagination?.page || 1,
  size: saved?.pagination?.size || 20
})

watch([() => ({ ...filters }), () => ({ ...pagination })], () => {
  localStorage.setItem(STORAGE_KEY, JSON.stringify({ filters: { search: filters.search, protocol: filters.protocol }, pagination: { page: pagination.page, size: pagination.size } }))
}, { deep: true })

// Template system
const { allTemplates, customTemplates, addTemplate, deleteTemplate: deleteCustomTemplate, getTemplate } = useStrategyTemplates()
const builtinTemplates = computed(() => allTemplates.value.filter(t => t.isBuiltin))
const selectedTemplateId = ref<string>('')

function applyTemplate(templateId: string) {
  if (!templateId) return
  const template = getTemplate(templateId)
  if (!template) return

  form.protocol = template.protocol
  const cfg = template.config || {}
  if (cfg.src_ip) form.config.src_ip = cfg.src_ip
  if (cfg.dst_ip) form.config.dst_ip = cfg.dst_ip
  if (cfg.src_port) form.config.src_port = cfg.src_port
  if (cfg.dst_port) form.config.dst_port = cfg.dst_port
  if (cfg.src_mac) form.config.src_mac = cfg.src_mac
  if (cfg.dst_mac) form.config.dst_mac = cfg.dst_mac
  if (cfg.ttl) form.config.ttl = cfg.ttl
  if (cfg.tos) form.config.tos = cfg.tos
  if (cfg.payload) form.config.payload = cfg.payload
  if (cfg.vlan_id) {
    form.config.vlan_enable = true
    form.config.vlan_id = cfg.vlan_id
    if (cfg.vlan_priority) form.config.vlan_priority = cfg.vlan_priority
  }
  if (cfg.tcp && typeof cfg.tcp === 'object') {
    form.config.tcp = { ...form.config.tcp, ...cfg.tcp }
  }
  if (cfg.udp && typeof cfg.udp === 'object') {
    form.config.udp = { ...form.config.udp, ...cfg.udp }
  }
  if (cfg.http && typeof cfg.http === 'object') {
    const httpCfg = { ...cfg.http }
    if (httpCfg.headers && typeof httpCfg.headers === 'object' && !Array.isArray(httpCfg.headers)) {
      form.config.http.headers = Object.entries(httpCfg.headers).map(([key, value]) => ({
        key, value: String(value)
      }))
      delete httpCfg.headers
    }
    form.config.http = { ...form.config.http, ...httpCfg }
  }
  if (cfg.dns && typeof cfg.dns === 'object') {
    form.config.dns = { ...form.config.dns, ...cfg.dns }
  }
  if (cfg.icmp && typeof cfg.icmp === 'object') {
    form.config.icmp = { ...form.config.icmp, ...cfg.icmp }
  }
  if (cfg.arp && typeof cfg.arp === 'object') {
    form.config.arp = { ...form.config.arp, ...cfg.arp }
  }
  if (template.flow_control) {
    form.flow_control = { ...template.flow_control }
  }

  ElMessage.success(t('strategy.templateApplied'))
}

function handleSaveTemplate() {
  if (!form.name || !form.protocol) return
  ElMessageBox.prompt(t('strategy.templateDescriptionPlaceholder'), t('strategy.saveAsTemplate'), {
    confirmButtonText: t('common.save'),
    cancelButtonText: t('common.cancel'),
    inputPlaceholder: t('strategy.templateDescriptionPlaceholder')
  }).then(({ value: description }) => {
    const cfg = buildConfigForSubmit()
    addTemplate({
      name: form.name,
      description: description || '',
      protocol: form.protocol,
      config: cfg,
      flow_control: form.flow_control.type ? { ...form.flow_control } : undefined
    })
    ElMessage.success(t('strategy.templateSaved'))
  }).catch(() => {})
}

const filteredStrategies = computed(() => {
  let result = strategies.value

  // 搜索筛选
  if (filters.search) {
    const searchLower = filters.search.toLowerCase()
    result = result.filter(s =>
      s.name.toLowerCase().includes(searchLower) ||
      s.id.toLowerCase().includes(searchLower)
    )
  }

  // 协议筛选
  if (filters.protocol.length > 0) {
    result = result.filter(s => filters.protocol.includes(s.protocol))
  }

  return result
})

const paginatedStrategies = computed(() => {
  const start = (pagination.page - 1) * pagination.size
  const end = start + pagination.size
  return filteredStrategies.value.slice(start, end)
})

function resetFilters() {
  filters.search = ''
  filters.protocol = []
  pagination.page = 1
}

interface HttpHeader {
  key: string
  value: string
}

interface StrategyForm {
  name: string
  protocol: string
  config: {
    src_ip: string
    dst_ip: string
    src_port: number
    dst_port: number
    src_mac: string
    dst_mac: string
    ttl: number
    tos: number
    payload: string
    vlan_enable: boolean
    vlan_id: number
    vlan_priority: number
    tcp: {
      handshake: boolean
      termination: boolean
      mss: number
      window_size: number
    }
    udp: {
      response: boolean
    }
    http: {
      method: string
      uri: string
      headers: HttpHeader[]
      body: string
      keep_alive: boolean
      transactions: number
      think_time: number
    }
    dns: {
      domain: string
      query_type: number
      response: boolean
      response_ip: string
    }
    icmp: {
      type: number
      code: number
      sequence: number
      data: string
    }
    arp: {
      operation: number
      target_mac: string
      target_ip: string
    }
  }
  flow_control: {
    type: string
    value: number
  }
}

const defaultForm = (): StrategyForm => ({
  name: '',
  protocol: 'tcp',
  config: {
    src_ip: '192.168.1.100',
    dst_ip: '192.168.1.1',
    src_port: 12345,
    dst_port: 80,
    src_mac: '',
    dst_mac: '',
    ttl: 64,
    tos: 0,
    payload: '',
    vlan_enable: false,
    vlan_id: 1,
    vlan_priority: 0,
    tcp: {
      handshake: true,
      termination: true,
      mss: 1460,
      window_size: 65535
    },
    udp: {
      response: false
    },
    http: {
      method: 'GET',
      uri: '/',
      headers: [],
      body: '',
      keep_alive: false,
      transactions: 1,
      think_time: 0
    },
    dns: {
      domain: 'example.com',
      query_type: 1,
      response: false,
      response_ip: ''
    },
    icmp: {
      type: 8,
      code: 0,
      sequence: 1,
      data: 'ping'
    },
    arp: {
      operation: 1,
      target_mac: '',
      target_ip: ''
    }
  },
  flow_control: {
    type: '',
    value: 1
  }
})

const form = reactive<StrategyForm>(defaultForm())

const rules: FormRules = {
  name: [{ required: true, message: t('strategy.strategyNamePlaceholder'), trigger: 'blur' }],
  protocol: [{ required: true, message: () => t('strategy.selectProtocol'), trigger: 'change' }]
}

// 自定义验证器
const ipValidator = (_rule: any, value: string, callback: (err?: Error) => void) => {
  if (!value) { callback(); return }
  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/
  if (!ipRegex.test(value)) {
    callback(new Error(t('strategy.validation.invalidIP')))
    return
  }
  const parts = value.split('.')
  if (parts.some(p => Number(p) > 255)) {
    callback(new Error(t('strategy.validation.invalidIP')))
    return
  }
  callback()
}

const macValidator = (_rule: any, value: string, callback: (err?: Error) => void) => {
  if (!value) { callback(); return }
  const macRegex = /^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/
  if (!macRegex.test(value)) {
    callback(new Error(t('strategy.validation.invalidMAC')))
    return
  }
  callback()
}

const configRules: FormRules = {
  'config.src_ip': [{ validator: ipValidator, trigger: 'blur' }],
  'config.dst_ip': [{ validator: ipValidator, trigger: 'blur' }],
  'config.src_mac': [{ validator: macValidator, trigger: 'blur' }],
  'config.dst_mac': [{ validator: macValidator, trigger: 'blur' }]
}

function onProtocolChange() {
  // Set default dst_port for protocols
  switch (form.protocol) {
    case 'http':
      if (form.config.dst_port === 80) return
      form.config.dst_port = 80
      break
    case 'dns':
      form.config.dst_port = 53
      break
    case 'icmp':
      form.config.dst_port = 0
      break
  }
}

function openCreateDialog() {
  editingStrategy.value = null
  selectedTemplateId.value = ''
  Object.assign(form, defaultForm())
  dialogVisible.value = true
}

function cloneStrategy(strategy: Strategy) {
  // 克隆策略：复制配置，名称添加"(副本)"后缀
  openEditDialog(strategy)
  form.name = strategy.name + ' ' + t('strategy.cloneSuffix')
  editingStrategy.value = null // 设为新建模式
}

function openEditDialog(strategy: Strategy) {
  editingStrategy.value = strategy
  const base = defaultForm()
  Object.assign(form, base)

  form.name = strategy.name
  form.protocol = strategy.protocol

  // Restore config from strategy
  const cfg = strategy.config || {}
  if (cfg.src_ip) form.config.src_ip = cfg.src_ip
  if (cfg.dst_ip) form.config.dst_ip = cfg.dst_ip
  if (cfg.src_port) form.config.src_port = cfg.src_port
  if (cfg.dst_port) form.config.dst_port = cfg.dst_port
  if (cfg.src_mac) form.config.src_mac = cfg.src_mac
  if (cfg.dst_mac) form.config.dst_mac = cfg.dst_mac
  if (cfg.ttl) form.config.ttl = cfg.ttl
  if (cfg.tos) form.config.tos = cfg.tos
  if (cfg.payload) form.config.payload = cfg.payload
  if (cfg.vlan_id) {
    form.config.vlan_enable = true
    form.config.vlan_id = cfg.vlan_id
    if (cfg.vlan_priority) form.config.vlan_priority = cfg.vlan_priority
  }

  // Protocol-specific
  if (cfg.tcp && typeof cfg.tcp === 'object') {
    form.config.tcp = { ...form.config.tcp, ...cfg.tcp }
  }
  if (cfg.udp && typeof cfg.udp === 'object') {
    form.config.udp = { ...form.config.udp, ...cfg.udp }
  }
  if (cfg.http && typeof cfg.http === 'object') {
    const httpCfg = { ...cfg.http }
    // Convert headers object to array format
    if (httpCfg.headers && typeof httpCfg.headers === 'object' && !Array.isArray(httpCfg.headers)) {
      form.config.http.headers = Object.entries(httpCfg.headers).map(([key, value]) => ({
        key,
        value: String(value)
      }))
      delete httpCfg.headers
    }
    form.config.http = { ...form.config.http, ...httpCfg }
  }
  if (cfg.dns && typeof cfg.dns === 'object') {
    form.config.dns = { ...form.config.dns, ...cfg.dns }
  }
  if (cfg.icmp && typeof cfg.icmp === 'object') {
    form.config.icmp = { ...form.config.icmp, ...cfg.icmp }
  }
  if (cfg.arp && typeof cfg.arp === 'object') {
    form.config.arp = { ...form.config.arp, ...cfg.arp }
  }

  // Flow control
  if (strategy.flow_control) {
    form.flow_control = { ...strategy.flow_control }
  }

  dialogVisible.value = true
}

function buildConfigForSubmit(): Record<string, any> {
  const cfg: Record<string, any> = {}

  if (form.config.src_ip) cfg.src_ip = form.config.src_ip
  if (form.config.dst_ip) cfg.dst_ip = form.config.dst_ip
  if (form.config.src_port) cfg.src_port = form.config.src_port
  if (form.config.dst_port) cfg.dst_port = form.config.dst_port
  if (form.config.src_mac) cfg.src_mac = form.config.src_mac
  if (form.config.dst_mac) cfg.dst_mac = form.config.dst_mac
  if (form.config.ttl && form.config.ttl !== 64) cfg.ttl = form.config.ttl
  if (form.config.tos) cfg.tos = form.config.tos
  if (form.config.payload) cfg.payload = form.config.payload

  // VLAN
  if (form.config.vlan_enable && form.config.vlan_id) {
    cfg.vlan_id = form.config.vlan_id
    if (form.config.vlan_priority) cfg.vlan_priority = form.config.vlan_priority
  }

  // Protocol-specific
  switch (form.protocol) {
    case 'tcp':
      cfg.tcp = {
        handshake: form.config.tcp.handshake,
        termination: form.config.tcp.termination,
        mss: form.config.tcp.mss,
        window_size: form.config.tcp.window_size
      }
      break
    case 'udp':
      cfg.udp = { response: form.config.udp.response }
      break
    case 'http':
      cfg.http = {
        method: form.config.http.method,
        uri: form.config.http.uri,
        body: form.config.http.body,
        keep_alive: form.config.http.keep_alive,
        transactions: form.config.http.transactions,
        think_time: form.config.http.think_time
      }
      // Convert headers array to object
      const headersObj: Record<string, string> = {}
      for (const h of form.config.http.headers) {
        if (h.key) headersObj[h.key] = h.value
      }
      if (Object.keys(headersObj).length > 0) {
        cfg.http.headers = headersObj
      }
      break
    case 'dns':
      cfg.dns = {
        domain: form.config.dns.domain,
        query_type: form.config.dns.query_type,
        response: form.config.dns.response
      }
      if (form.config.dns.response && form.config.dns.response_ip) {
        cfg.dns.response_ip = form.config.dns.response_ip
      }
      break
    case 'icmp':
      cfg.icmp = {
        type: form.config.icmp.type,
        code: form.config.icmp.code,
        sequence: form.config.icmp.sequence,
        data: form.config.icmp.data
      }
      break
    case 'arp':
      cfg.arp = {
        operation: form.config.arp.operation,
        target_mac: form.config.arp.target_mac,
        target_ip: form.config.arp.target_ip
      }
      break
  }

  return cfg
}

function handleSelectionChange(selection: Strategy[]) {
  selectedStrategies.value = selection
}

function clearSelection() {
  selectedStrategies.value = []
}

async function handleBulkDelete() {
  try {
    await ElMessageBox.confirm(
      t('strategy.confirmBulkDelete', { count: selectedStrategies.value.length }),
      t('common.confirm'),
      { type: 'warning' }
    )
    await Promise.allSettled(selectedStrategies.value.map(s => strategyApi.delete(s.id)))
    ElMessage.success(t('strategy.bulkDeleted', { count: selectedStrategies.value.length }))
    selectedStrategies.value = []
    loadStrategies()
  } catch (error) {
    // Cancelled
  }
}

async function openDrawer(strategy: Strategy) {
  drawerStrategy.value = strategy
  drawerVisible.value = true
  drawerLoading.value = true
  try {
    const res = await strategyApi.get(strategy.id)
    if (res.data) {
      drawerStrategy.value = res.data as Strategy
    }
  } catch (error) {
    console.error('Failed to load strategy detail:', error)
  } finally {
    drawerLoading.value = false
  }
}

async function handleSubmit() {
  const valid = await formRef.value?.validate()
  if (!valid) return

  submitLoading.value = true
  try {
    const cfg = buildConfigForSubmit()

    const submitData: any = {
      name: form.name,
      protocol: form.protocol,
      config: cfg
    }

    if (form.flow_control.type) {
      submitData.flow_control = {
        type: form.flow_control.type,
        value: form.flow_control.value
      }
    }

    if (editingStrategy.value) {
      await strategyApi.update(editingStrategy.value.id, submitData)
      ElMessage.success(t('strategy.updateSuccess'))
    } else {
      await strategyApi.create(submitData)
      ElMessage.success(t('strategy.createSuccess'))
    }

    dialogVisible.value = false
    loadStrategies()
  } catch (error) {
    console.error('Failed to save strategy:', error)
    ElMessage.error(editingStrategy.value ? t('strategy.updateFailed') : t('strategy.createFailed'))
  } finally {
    submitLoading.value = false
  }
}

async function handleDelete(id: string) {
  try {
    await strategyApi.delete(id)
    ElMessage.success(t('strategy.deleteSuccess'))
    loadStrategies()
  } catch (error) {
    console.error('Failed to delete strategy:', error)
    ElMessage.error(t('strategy.deleteFailed'))
  }
}

async function loadStrategies() {
  loading.value = true
  try {
    const res = await strategyApi.list()
    if (res.data) {
      strategies.value = res.data as Strategy[]
    }
  } catch (error) {
    console.error('Failed to load strategies:', error)
  } finally {
    loading.value = false
  }
}

function formatTime(timestamp: number): string {
  if (!timestamp) return '-'
  return new Date(timestamp * 1000).toLocaleString()
}

onMounted(() => {
  loadStrategies()
})
</script>

<style scoped>
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.filter-bar {
  display: flex;
  align-items: center;
  gap: 16px;
  margin-bottom: 20px;
}

.bulk-toolbar {
  margin-bottom: 16px;
  padding: 12px 16px;
  background: #f4f4f5;
  border-radius: 4px;
}

.bulk-text {
  color: #606266;
  font-size: 14px;
}
</style>