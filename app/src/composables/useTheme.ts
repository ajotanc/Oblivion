import { ref, watchEffect } from 'vue'

import { i18n, type Locale } from '../i18n'

export type Theme = 'auto' | 'light' | 'dark'

function read<T extends string>(key: string, allowed: readonly T[], fallback: T): T {
  try {
    const v = localStorage.getItem(key)
    return allowed.includes(v as T) ? (v as T) : fallback
  } catch {
    return fallback // sem armazenamento (janela privada, bloqueio): segue sem lembrar
  }
}

function write(key: string, value: string): void {
  try {
    localStorage.setItem(key, value)
  } catch {
    /* sem armazenamento: só não lembra da escolha */
  }
}

const theme = ref<Theme>(read('oblivion.theme', ['auto', 'light', 'dark'] as const, 'auto'))

watchEffect(() => {
  const root = document.documentElement
  if (theme.value === 'auto') delete root.dataset.theme
  else root.dataset.theme = theme.value
})

export function useTheme() {
  return {
    theme,
    setTheme(next: Theme) {
      theme.value = next
      write('oblivion.theme', next)
    },
    setLocale(next: Locale) {
      i18n.global.locale.value = next
      document.documentElement.lang = next
      write('oblivion.locale', next)
    },
  }
}
