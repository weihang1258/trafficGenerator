<template>
  <div class="layout">
    <el-container>
      <el-header class="header">
        <Header />
      </el-header>
      <el-container>
        <el-aside width="200px" class="sidebar">
          <Sidebar />
        </el-aside>
        <el-main class="main">
          <router-view />
        </el-main>
      </el-container>
    </el-container>
  </div>
</template>

<script setup lang="ts">
import Header from './Header.vue'
import Sidebar from './Sidebar.vue'
</script>

<style scoped>
.layout {
  height: 100vh;
  overflow: hidden;
}

.header {
  background-color: #409eff;
  color: white;
  padding: 0;
  height: 60px;
  line-height: 60px;
}

.sidebar {
  background-color: #545c64;
  color: white;
  overflow-y: auto;
}

.main {
  background-color: #f0f2f5;
  padding: 20px;
  overflow-y: auto;
}
</style>
