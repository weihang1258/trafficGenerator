import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { chromium, Browser, Page } from 'playwright'

describe('E2E Tests', () => {
  let browser: Browser
  let page: Page

  beforeAll(async () => {
    browser = await chromium.launch({
      headless: true
    })
    page = await browser.newPage()
  })

  afterAll(async () => {
    await browser.close()
  })

  describe('Login Flow', () => {
    it('should display login page', async () => {
      await page.goto('http://localhost:8080/login')

      const title = await page.title()
      expect(title).toContain('Traffic Generator')

      // Check for login form elements
      const usernameInput = await page.$('input[placeholder="用户名"]')
      const passwordInput = await page.$('input[placeholder="密码"]')
      const loginButton = await page.$('button:has-text("登录")')

      expect(usernameInput).toBeTruthy()
      expect(passwordInput).toBeTruthy()
      expect(loginButton).toBeTruthy()
    })

    it('should login successfully with correct credentials', async () => {
      await page.goto('http://localhost:8080/login')

      // Fill login form
      await page.fill('input[placeholder="用户名"]', 'admin')
      await page.fill('input[placeholder="密码"]', 'admin')
      await page.click('button:has-text("登录")')

      // Wait for navigation to dashboard
      await page.waitForURL('http://localhost:8080/dashboard', { timeout: 5000 })

      // Verify we're on dashboard
      const currentUrl = page.url()
      expect(currentUrl).toContain('/dashboard')
    })

    it('should show error with incorrect credentials', async () => {
      await page.goto('http://localhost:8080/login')

      // Fill login form with wrong credentials
      await page.fill('input[placeholder="用户名"]', 'admin')
      await page.fill('input[placeholder="密码"]', 'wrongpassword')
      await page.click('button:has-text("登录")')

      // Wait for error message
      const errorMessage = await page.waitForSelector('.el-message--error', { timeout: 3000 })
      expect(errorMessage).toBeTruthy()
    })
  })

  describe('Dashboard', () => {
    it('should display dashboard after login', async () => {
      // Login first
      await page.goto('http://localhost:8080/login')
      await page.fill('input[placeholder="用户名"]', 'admin')
      await page.fill('input[placeholder="密码"]', 'admin')
      await page.click('button:has-text("登录")')
      await page.waitForURL('http://localhost:8080/dashboard', { timeout: 5000 })

      // Check dashboard elements
      const dashboardTitle = await page.$('h2:has-text("仪表盘")')
      expect(dashboardTitle).toBeTruthy()

      // Check stats cards
      const statsCards = await page.$$('.stats-card')
      expect(statsCards.length).toBeGreaterThan(0)
    })
  })

  describe('Task Management', () => {
    beforeAll(async () => {
      // Login before task tests
      await page.goto('http://localhost:8080/login')
      await page.fill('input[placeholder="用户名"]', 'admin')
      await page.fill('input[placeholder="密码"]', 'admin')
      await page.click('button:has-text("登录")')
      await page.waitForURL('http://localhost:8080/dashboard', { timeout: 5000 })
    })

    it('should navigate to task list', async () => {
      await page.click('text=任务管理')
      await page.click('text=任务列表')

      await page.waitForURL('http://localhost:8080/tasks', { timeout: 3000 })

      const taskListTitle = await page.$('h2:has-text("任务列表")')
      expect(taskListTitle).toBeTruthy()
    })

    it('should display create task page', async () => {
      await page.goto('http://localhost:8080/tasks/create')

      const createTitle = await page.$('h2:has-text("创建任务")')
      expect(createTitle).toBeTruthy()

      // Check form elements
      const nameInput = await page.$('input[placeholder="请输入任务名称"]')
      const protocolSelect = await page.$('.el-select:has-text("选择协议")')
      const createButton = await page.$('button:has-text("创建")')

      expect(nameInput).toBeTruthy()
      expect(protocolSelect).toBeTruthy()
      expect(createButton).toBeTruthy()
    })

    it('should create a TCP task', async () => {
      await page.goto('http://localhost:8080/tasks/create')

      // Fill task form
      await page.fill('input[placeholder="请输入任务名称"]', 'E2E Test Task')

      // Select protocol
      await page.click('.el-select:has-text("选择协议")')
      await page.click('.el-select-dropdown__item:has-text("TCP")')

      // Fill network config
      await page.fill('input[placeholder="源 IP"]', '192.168.1.1')
      await page.fill('input[placeholder="目标 IP"]', '192.168.1.2')
      await page.fill('input[placeholder="源端口"]', '12345')
      await page.fill('input[placeholder="目标端口"]', '80')

      // Submit
      await page.click('button:has-text("创建")')

      // Wait for success message or redirect
      const successMessage = await page.waitForSelector('.el-message--success', { timeout: 5000 })
      expect(successMessage).toBeTruthy()
    })

    it('should display task in task list', async () => {
      await page.goto('http://localhost:8080/tasks')

      // Wait for table to load
      await page.waitForSelector('.el-table', { timeout: 5000 })

      // Check if task exists
      const taskRow = await page.$('tr:has-text("E2E Test Task")')
      expect(taskRow).toBeTruthy()
    })

    it('should start a task', async () => {
      await page.goto('http://localhost:8080/tasks')

      // Wait for table to load
      await page.waitForSelector('.el-table', { timeout: 5000 })

      // Find task and click start button
      const taskRow = await page.$('tr:has-text("E2E Test Task")')
      expect(taskRow).toBeTruthy()

      await taskRow!.$eval('button:has-text("启动")', (el) => (el as HTMLElement).click())

      // Wait for success message
      const successMessage = await page.waitForSelector('.el-message--success', { timeout: 5000 })
      expect(successMessage).toBeTruthy()
    })

    it('should stop a running task', async () => {
      await page.goto('http://localhost:8080/tasks')

      // Wait for table to load
      await page.waitForSelector('.el-table', { timeout: 5000 })

      // Find running task and click stop button
      const taskRow = await page.$('tr:has-text("E2E Test Task")')
      expect(taskRow).toBeTruthy()

      await taskRow!.$eval('button:has-text("停止")', (el) => (el as HTMLElement).click())

      // Wait for success message
      const successMessage = await page.waitForSelector('.el-message--success', { timeout: 5000 })
      expect(successMessage).toBeTruthy()
    })

    it('should delete a task', async () => {
      await page.goto('http://localhost:8080/tasks')

      // Wait for table to load
      await page.waitForSelector('.el-table', { timeout: 5000 })

      // Find task and click delete button
      const taskRow = await page.$('tr:has-text("E2E Test Task")')
      expect(taskRow).toBeTruthy()

      await taskRow!.$eval('button:has-text("删除")', (el) => (el as HTMLElement).click())

      // Confirm deletion
      await page.click('.el-message-box__btns button:has-text("确定")')

      // Wait for success message
      const successMessage = await page.waitForSelector('.el-message--success', { timeout: 5000 })
      expect(successMessage).toBeTruthy()
    })
  })

  describe('Strategy Management', () => {
    beforeAll(async () => {
      // Login before strategy tests
      await page.goto('http://localhost:8080/login')
      await page.fill('input[placeholder="用户名"]', 'admin')
      await page.fill('input[placeholder="密码"]', 'admin')
      await page.click('button:has-text("登录")')
      await page.waitForURL('http://localhost:8080/dashboard', { timeout: 5000 })
    })

    it('should navigate to strategy list', async () => {
      await page.click('text=策略管理')
      await page.waitForURL('http://localhost:8080/strategies', { timeout: 3000 })

      const strategyTitle = await page.$('h2:has-text("策略管理")')
      expect(strategyTitle).toBeTruthy()
    })

    it('should create a strategy', async () => {
      await page.goto('http://localhost:8080/strategies')

      // Click create button
      await page.click('button:has-text("新建策略")')

      // Fill strategy form
      await page.fill('input[placeholder="请输入策略名称"]', 'E2E Test Strategy')
      await page.fill('textarea[placeholder="请输入策略描述"]', 'Test strategy description')

      // Submit
      await page.click('button:has-text("保存")')

      // Wait for success message
      const successMessage = await page.waitForSelector('.el-message--success', { timeout: 5000 })
      expect(successMessage).toBeTruthy()
    })
  })

  describe('Interface Management', () => {
    beforeAll(async () => {
      // Login before interface tests
      await page.goto('http://localhost:8080/login')
      await page.fill('input[placeholder="用户名"]', 'admin')
      await page.fill('input[placeholder="密码"]', 'admin')
      await page.click('button:has-text("登录")')
      await page.waitForURL('http://localhost:8080/dashboard', { timeout: 5000 })
    })

    it('should display interface list', async () => {
      await page.click('text=网卡管理')
      await page.waitForURL('http://localhost:8080/interfaces', { timeout: 3000 })

      const interfaceTitle = await page.$('h2:has-text("网卡管理")')
      expect(interfaceTitle).toBeTruthy()

      // Check for interface table
      const interfaceTable = await page.$('.el-table')
      expect(interfaceTable).toBeTruthy()
    })

    it('should refresh interface list', async () => {
      await page.goto('http://localhost:8080/interfaces')

      // Click refresh button
      await page.click('button:has-text("刷新")')

      // Wait for success message
      const successMessage = await page.waitForSelector('.el-message--success', { timeout: 5000 })
      expect(successMessage).toBeTruthy()
    })
  })

  describe('Settings', () => {
    beforeAll(async () => {
      // Login before settings tests
      await page.goto('http://localhost:8080/login')
      await page.fill('input[placeholder="用户名"]', 'admin')
      await page.fill('input[placeholder="密码"]', 'admin')
      await page.click('button:has-text("登录")')
      await page.waitForURL('http://localhost:8080/dashboard', { timeout: 5000 })
    })

    it('should display settings page', async () => {
      await page.click('text=系统设置')
      await page.waitForURL('http://localhost:8080/settings', { timeout: 3000 })

      const settingsTitle = await page.$('h2:has-text("系统设置")')
      expect(settingsTitle).toBeTruthy()
    })
  })

  describe('Logout', () => {
    it('should logout successfully', async () => {
      // Login first
      await page.goto('http://localhost:8080/login')
      await page.fill('input[placeholder="用户名"]', 'admin')
      await page.fill('input[placeholder="密码"]', 'admin')
      await page.click('button:has-text("登录")')
      await page.waitForURL('http://localhost:8080/dashboard', { timeout: 5000 })

      // Click user dropdown
      await page.click('.el-dropdown-link')

      // Click logout
      await page.click('text=退出登录')

      // Confirm logout
      await page.click('.el-message-box__btns button:has-text("确定")')

      // Wait for redirect to login page
      await page.waitForURL('http://localhost:8080/login', { timeout: 5000 })

      const currentUrl = page.url()
      expect(currentUrl).toContain('/login')
    })
  })
})