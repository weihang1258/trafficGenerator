import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import TaskStatusTag from '@/components/TaskStatusTag.vue'

describe('TaskStatusTag', () => {
  it('renders pending status correctly', () => {
    const wrapper = mount(TaskStatusTag, {
      props: { status: 'pending' }
    })

    expect(wrapper.text()).toContain('待运行')
    expect(wrapper.find('.el-tag').classes()).toContain('el-tag--info')
  })

  it('renders running status correctly', () => {
    const wrapper = mount(TaskStatusTag, {
      props: { status: 'running' }
    })

    expect(wrapper.text()).toContain('运行中')
    expect(wrapper.find('.el-tag').classes()).toContain('el-tag--success')
  })

  it('renders completed status correctly', () => {
    const wrapper = mount(TaskStatusTag, {
      props: { status: 'completed' }
    })

    expect(wrapper.text()).toContain('已完成')
  })

  it('renders failed status correctly', () => {
    const wrapper = mount(TaskStatusTag, {
      props: { status: 'failed' }
    })

    expect(wrapper.text()).toContain('失败')
    expect(wrapper.find('.el-tag').classes()).toContain('el-tag--danger')
  })

  it('renders stopped status correctly', () => {
    const wrapper = mount(TaskStatusTag, {
      props: { status: 'stopped' }
    })

    expect(wrapper.text()).toContain('已停止')
    expect(wrapper.find('.el-tag').classes()).toContain('el-tag--warning')
  })

  it('renders unknown status as-is', () => {
    const wrapper = mount(TaskStatusTag, {
      props: { status: 'unknown' }
    })

    expect(wrapper.text()).toContain('unknown')
  })

  it('applies size prop correctly', () => {
    const wrapper = mount(TaskStatusTag, {
      props: {
        status: 'running',
        size: 'large'
      }
    })

    expect(wrapper.find('.el-tag').classes()).toContain('el-tag--large')
  })

  it('applies effect prop correctly', () => {
    const wrapper = mount(TaskStatusTag, {
      props: {
        status: 'running',
        effect: 'dark'
      }
    })

    expect(wrapper.find('.el-tag').classes()).toContain('el-tag--dark')
  })
})
