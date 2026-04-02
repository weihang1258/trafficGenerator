import { createI18n } from 'vue-i18n'
import zhCN from './locales/zh-CN'
import enUS from './locales/en-US'

// 获取浏览器语言
function getBrowserLocale(): string {
  const navigatorLocale =
    navigator.languages !== undefined
      ? navigator.languages[0]
      : navigator.language

  if (!navigatorLocale) {
    return 'zh-CN'
  }

  // 标准化语言代码
  const trimmedLocale = navigatorLocale.trim()

  // 如果是中文
  if (trimmedLocale.startsWith('zh')) {
    return 'zh-CN'
  }

  // 如果是英文
  if (trimmedLocale.startsWith('en')) {
    return 'en-US'
  }

  // 默认中文
  return 'zh-CN'
}

// 从 localStorage 获取保存的语言设置
function getSavedLocale(): string | null {
  return localStorage.getItem('locale')
}

// 创建 i18n 实例
const i18n = createI18n({
  legacy: false, // 使用 Composition API 模式
  locale: getSavedLocale() || getBrowserLocale(), // 优先使用保存的设置，然后是浏览器语言，最后默认中文
  fallbackLocale: 'zh-CN', // 回退语言
  messages: {
    'zh-CN': zhCN,
    'en-US': enUS
  }
})

export default i18n

// 切换语言
export function setLocale(locale: string): void {
  i18n.global.locale.value = locale
  localStorage.setItem('locale', locale)
  document.querySelector('html')?.setAttribute('lang', locale)
}

// 获取当前语言
export function getLocale(): string {
  return i18n.global.locale.value
}
