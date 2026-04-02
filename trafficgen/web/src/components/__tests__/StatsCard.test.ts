import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import StatsCard from '@/components/StatsCard.vue'
import { TrendCharts } from '@element-plus/icons-vue'

describe('StatsCard', () => {
  it('renders numeric value correctly', () => {
    const wrapper = mount(StatsCard, {
      props: {
        value: 1234,
        label: 'Total Tasks'
      }
    })

    expect(wrapper.text()).toContain('1,234')
    expect(wrapper.text()).toContain('Total Tasks')
  })

  it('renders string value as-is', () => {
    const wrapper = mount(StatsCard, {
      props: {
        value: 'Active',
        label: 'Status'
      }
    })

    expect(wrapper.text()).toContain('Active')
  })

  it('formats bytes correctly', () => {
    const wrapper = mount(StatsCard, {
      props: {
        value: 1536,
        label: 'Data Sent',
        format: 'bytes'
      }
    })

    expect(wrapper.text()).toContain('1.50 KB')
  })

  it('formats MB bytes correctly', () => {
    const wrapper = mount(StatsCard, {
      props: {
        value: 1572864,
        label: 'Data Sent',
        format: 'bytes'
      }
    })

    expect(wrapper.text()).toContain('1.50 MB')
  })

  it('formats bps correctly', () => {
    const wrapper = mount(StatsCard, {
      props: {
        value: 1500000,
        label: 'Throughput',
        format: 'bps'
      }
    })

    expect(wrapper.text()).toContain('1.50 Mbps')
  })

  it('formats percent correctly', () => {
    const wrapper = mount(StatsCard, {
      props: {
        value: 85.5,
        label: 'CPU Usage',
        format: 'percent'
      }
    })

    expect(wrapper.text()).toContain('85.50%')
  })

  it('renders with unit', () => {
    const wrapper = mount(StatsCard, {
      props: {
        value: 100,
        label: 'Tasks',
        unit: 'tasks'
      }
    })

    expect(wrapper.text()).toContain('100 tasks')
  })

  it('renders upward trend correctly', () => {
    const wrapper = mount(StatsCard, {
      props: {
        value: 100,
        label: 'Tasks',
        trend: 15
      }
    })

    expect(wrapper.text()).toContain('15%')
    expect(wrapper.find('.trend-up').exists()).toBe(true)
  })

  it('renders downward trend correctly', () => {
    const wrapper = mount(StatsCard, {
      props: {
        value: 100,
        label: 'Tasks',
        trend: -10
      }
    })

    expect(wrapper.text()).toContain('10%')
    expect(wrapper.find('.trend-down').exists()).toBe(true)
  })

  it('renders neutral trend correctly', () => {
    const wrapper = mount(StatsCard, {
      props: {
        value: 100,
        label: 'Tasks',
        trend: 0
      }
    })

    expect(wrapper.text()).toContain('持平')
    expect(wrapper.find('.trend-neutral').exists()).toBe(true)
  })

  it('renders without trend when undefined', () => {
    const wrapper = mount(StatsCard, {
      props: {
        value: 100,
        label: 'Tasks'
      }
    })

    expect(wrapper.find('.stats-trend').exists()).toBe(false)
  })

  it('applies custom icon background color', () => {
    const wrapper = mount(StatsCard, {
      props: {
        value: 100,
        label: 'Tasks',
        icon: TrendCharts,
        iconBgColor: '#67c23a'
      }
    })

    const iconElement = wrapper.find('.stats-icon')
    expect(iconElement.attributes('style')).toContain('background-color: rgb(103, 194, 58)')
  })
})
