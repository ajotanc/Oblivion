<script setup lang="ts">
import { Languages, Monitor, Moon, ShieldCheck, ShieldOff, Sun } from '@lucide/vue'
import { useI18n } from 'vue-i18n'

import { useTheme, type Theme } from '../composables/useTheme'
import type { Locale } from '../i18n'
import type { AppInfo } from '../types'

defineProps<{ info: AppInfo | null }>()
defineEmits<{ restartAdmin: [] }>()

const { t, locale } = useI18n()
const { theme, setTheme, setLocale } = useTheme()

const themes: { id: Theme; icon: typeof Sun; key: string }[] = [
  { id: 'auto', icon: Monitor, key: 'themeAuto' },
  { id: 'light', icon: Sun, key: 'themeLight' },
  { id: 'dark', icon: Moon, key: 'themeDark' },
]
</script>

<template>
  <header class="flex flex-wrap items-center gap-x-4 gap-y-2 border-b border-line bg-card px-5 py-3">
    <div class="flex items-center gap-3">
      <svg viewBox="0 0 64 64" class="size-9 shrink-0" aria-hidden="true">
        <defs>
          <linearGradient id="logo-g" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stop-color="#0a1f44" />
            <stop offset="1" stop-color="#1d4ed8" />
          </linearGradient>
        </defs>
        <rect width="64" height="64" rx="14" fill="url(#logo-g)" />
        <path d="M32 10 49 16.5v17L32 54 15 33.5v-17z" fill="#fff" />
        <circle cx="32" cy="31" r="7.5" fill="none" stroke="#0a1f44" stroke-width="4.5" />
      </svg>
      <div>
        <h1 class="text-lg leading-tight font-bold">Oblivion</h1>
        <p class="hidden text-xs text-muted sm:block">{{ t('app.tagline') }}</p>
      </div>
      <!-- Versão sempre visível. -->
      <span
        data-testid="version"
        class="rounded-full border border-line px-2.5 py-0.5 font-mono text-xs text-muted"
        :aria-label="`${t('header.version')} ${info?.version ?? ''}`"
      >
        v{{ info?.version ?? '…' }}
      </span>
    </div>

    <div class="ml-auto flex flex-wrap items-center gap-3">
      <span
        v-if="info"
        data-testid="privilege"
        class="inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-semibold"
        :class="info.elevated ? 'bg-ok-bg text-ok' : 'bg-susp-bg text-susp'"
      >
        <ShieldCheck v-if="info.elevated" class="size-4" aria-hidden="true" />
        <ShieldOff v-else class="size-4" aria-hidden="true" />
        {{ info.elevated ? t('header.admin') : t('header.notAdmin') }}
      </span>
      <button
        v-if="info && !info.elevated && info.platform === 'windows'"
        type="button"
        class="min-h-11 rounded-lg border border-line px-3 text-sm font-medium hover:bg-bg"
        @click="$emit('restartAdmin')"
      >
        {{ t('header.restartAdmin') }}
      </button>

      <div role="group" :aria-label="t('header.theme')" class="flex rounded-lg border border-line p-0.5">
        <button
          v-for="opt in themes"
          :key="opt.id"
          type="button"
          class="flex min-h-10 min-w-10 items-center justify-center rounded-md"
          :class="theme === opt.id ? 'bg-primary text-primary-fg' : 'text-muted hover:bg-bg'"
          :aria-pressed="theme === opt.id"
          :title="t(`header.${opt.key}`)"
          :aria-label="t(`header.${opt.key}`)"
          @click="setTheme(opt.id)"
        >
          <component :is="opt.icon" class="size-4" aria-hidden="true" />
        </button>
      </div>

      <label class="flex items-center gap-1.5 text-sm text-muted">
        <Languages class="size-4" aria-hidden="true" />
        <span class="sr-only">{{ t('header.language') }}</span>
        <select
          class="min-h-10 rounded-lg border border-line bg-card px-2 text-fg"
          :value="locale"
          @change="setLocale(($event.target as HTMLSelectElement).value as Locale)"
        >
          <option value="pt-BR">Português</option>
          <option value="en">English</option>
        </select>
      </label>
    </div>
  </header>
</template>
