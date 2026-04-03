import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { listTasks, getTask, createTask, deleteTask, startTask, stopTask, getTaskStats } from '@/api/task'
import type { Task, TaskCreate, TaskStats } from '@/api/task'
import i18n from '@/i18n'

const t = (key: string) => i18n.global.t(key)

export const useTaskStore = defineStore('task', () => {
  // State
  const tasks = ref<Task[]>([])
  const currentTask = ref<Task | null>(null)
  const taskStats = ref<TaskStats | null>(null)
  const total = ref(0)
  const loading = ref(false)
  const error = ref<string | null>(null)

  // Filters
  const filters = ref({
    status: '',
    protocol: '',
    page: 1,
    page_size: 20
  })

  // Getters
  const activeTasks = computed(() => {
    return tasks.value.filter(task => task.status === 'running')
  })

  const pendingTasks = computed(() => {
    return tasks.value.filter(task => task.status === 'pending')
  })

  const completedTasks = computed(() => {
    return tasks.value.filter(task => task.status === 'completed')
  })

  const failedTasks = computed(() => {
    return tasks.value.filter(task => task.status === 'failed')
  })

  const taskCount = computed(() => {
    return {
      total: total.value,
      active: activeTasks.value.length,
      pending: pendingTasks.value.length,
      completed: completedTasks.value.length,
      failed: failedTasks.value.length
    }
  })

  // Actions
  const fetchTasks = async () => {
    loading.value = true
    error.value = null

    try {
      const response = await listTasks(filters.value)
      tasks.value = response.tasks
      total.value = response.total
    } catch (err: any) {
      error.value = err.message || t('task.createFailed')
      throw err
    } finally {
      loading.value = false
    }
  }

  const fetchTask = async (taskId: string) => {
    loading.value = true
    error.value = null

    try {
      const task = await getTask(taskId)
      currentTask.value = task
      return task
    } catch (err: any) {
      error.value = err.message || t('error.serverError')
      throw err
    } finally {
      loading.value = false
    }
  }

  const createNewTask = async (data: TaskCreate) => {
    loading.value = true
    error.value = null

    try {
      const task = await createTask(data)
      tasks.value.unshift(task)
      total.value++
      return task
    } catch (err: any) {
      error.value = err.message || t('task.createFailed')
      throw err
    } finally {
      loading.value = false
    }
  }

  const removeTask = async (taskId: string) => {
    loading.value = true
    error.value = null

    try {
      await deleteTask(taskId)
      const index = tasks.value.findIndex(t => t.id === taskId)
      if (index > -1) {
        tasks.value.splice(index, 1)
        total.value--
      }
    } catch (err: any) {
      error.value = err.message || t('task.deleteFailed')
      throw err
    } finally {
      loading.value = false
    }
  }

  const startTaskById = async (taskId: string) => {
    loading.value = true
    error.value = null

    try {
      const task = await startTask(taskId)
      updateTaskInList(task)
      return task
    } catch (err: any) {
      error.value = err.message || t('task.startFailed')
      throw err
    } finally {
      loading.value = false
    }
  }

  const stopTaskById = async (taskId: string) => {
    loading.value = true
    error.value = null

    try {
      const task = await stopTask(taskId)
      updateTaskInList(task)
      return task
    } catch (err: any) {
      error.value = err.message || t('task.stopFailed')
      throw err
    } finally {
      loading.value = false
    }
  }

  const fetchTaskStats = async (taskId: string) => {
    try {
      const stats = await getTaskStats(taskId)
      taskStats.value = stats
      return stats
    } catch (err: any) {
      error.value = err.message || t('error.serverError')
      throw err
    }
  }

  const updateTaskInList = (task: Task) => {
    const index = tasks.value.findIndex(t => t.id === task.id)
    if (index > -1) {
      tasks.value[index] = task
    }
    if (currentTask.value?.id === task.id) {
      currentTask.value = task
    }
  }

  const setFilters = (newFilters: Partial<typeof filters.value>) => {
    filters.value = { ...filters.value, ...newFilters }
  }

  const resetFilters = () => {
    filters.value = {
      status: '',
      protocol: '',
      page: 1,
      page_size: 20
    }
  }

  const clearError = () => {
    error.value = null
  }

  return {
    // State
    tasks,
    currentTask,
    taskStats,
    total,
    loading,
    error,
    filters,

    // Getters
    activeTasks,
    pendingTasks,
    completedTasks,
    failedTasks,
    taskCount,

    // Actions
    fetchTasks,
    fetchTask,
    createNewTask,
    removeTask,
    startTaskById,
    stopTaskById,
    fetchTaskStats,
    setFilters,
    resetFilters,
    clearError
  }
})