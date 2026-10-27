<script setup lang="ts">
import { CircleAlert, CircleCheck, Loader, Play, RefreshCw } from '@lucide/vue'
import { nextTick, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'

import { useOblivion } from '../composables/useOblivion'
import AdvancedOptions from './AdvancedOptions.vue'

const { t } = useI18n()
const o = useOblivion()
const { state } = o

const consoleBox = ref<HTMLElement | null>(null)
// O console rola sozinho para a última linha.
watch(
  () => state.log.length,
  async () => {
    await nextTick()
    consoleBox.value?.scrollTo({ top: consoleBox.value.scrollHeight })
  },
)

const start = () =>
  o.startScan(t('scan.started'), (total, high, susp) => t('scan.finished', { total, high, susp }))
</script>

<template>
  <section aria-labelledby="scan-title" class="flex h-full flex-col gap-4 overflow-y-auto">
    <div>
      <h2 id="scan-title" class="text-xl font-bold">{{ t('scan.title') }}</h2>
      <p class="mt-1 max-w-3xl text-sm text-muted">{{ t('scan.intro') }}</p>
      <p v-if="state.info && !state.info.elevated" class="mt-2 text-sm text-susp">{{ t('scan.adminWarning') }}</p>
    </div>

    <div>
      <button
        type="button"
        data-testid="start-scan"
        class="inline-flex min-h-11 items-center gap-2 rounded-lg bg-primary px-5 font-semibold text-primary-fg disabled:opacity-60"
        :disabled="state.scanning"
        @click="start"
      >
        <Loader v-if="state.scanning" class="size-4 animate-spin" aria-hidden="true" />
        <RefreshCw v-else-if="state.scanned" class="size-4" aria-hidden="true" />
        <Play v-else class="size-4" aria-hidden="true" />
        {{ state.scanning ? t('scan.running') : state.scanned ? t('scan.again') : t('scan.start') }}
      </button>
      <p v-if="state.scanError" role="alert" class="mt-2 text-sm text-high">
        {{ t('scan.error', { message: state.scanError }) }}
      </p>
    </div>

    <AdvancedOptions />

    <div class="grid flex-1 gap-4 lg:min-h-0 lg:grid-cols-[18rem_1fr] lg:grid-rows-[minmax(0,1fr)]">
      <ul class="space-y-1.5 text-sm lg:min-h-0 lg:overflow-y-auto" :aria-label="t('scan.title')">
        <li
          v-for="(s, label) in state.scanners"
          :key="label"
          class="flex items-center gap-2 rounded-lg border border-line bg-card px-3 py-2"
        >
          <Loader v-if="s.state === 'running'" class="size-4 shrink-0 animate-spin text-primary" aria-hidden="true" />
          <CircleCheck v-else-if="s.state === 'done'" class="size-4 shrink-0 text-ok" aria-hidden="true" />
          <CircleAlert v-else class="size-4 shrink-0 text-high" aria-hidden="true" />
          <span class="min-w-0 flex-1">
            <span class="block truncate font-medium">{{ label }}</span>
            <span class="block text-xs text-muted">
              {{
                s.state === 'running'
                  ? t('scan.working')
                  : s.state === 'done'
                    ? t('scan.done', { count: s.count })
                    : t('scan.failed')
              }}
            </span>
          </span>
        </li>
      </ul>

      <!-- Console (fundo azul, texto claro, fonte monoespaçada), acessível. -->
      <div class="flex min-h-64 flex-col overflow-hidden rounded-xl border border-line bg-console shadow-sm">
        <div class="flex items-center gap-2 bg-console-bar px-3 py-2 text-xs text-console-dim">
          <span class="size-2.5 rounded-full bg-console-dim/60" aria-hidden="true"></span>
          <span class="font-mono">{{ t('scan.console') }}</span>
        </div>
        <div
          ref="consoleBox"
          role="log"
          aria-live="polite"
          :aria-busy="state.scanning"
          tabindex="0"
          data-testid="console"
          class="flex-1 overflow-y-auto p-3 font-mono text-[13px] leading-relaxed text-console-fg"
        >
          <p v-if="!state.log.length" class="text-console-dim">{{ t('scan.idle') }}</p>
          <p v-for="(line, i) in state.log" :key="i" class="break-words">
            <span class="text-console-dim">[{{ line.time }}]</span>
            <span
              :class="{
                'text-[#7ee787]': line.level === 'ok',
                'text-[#ff9b93]': line.level === 'error',
                'text-[#fbbf24]': line.level === 'warn',
              }"
            >
              {{ line.text }}
            </span>
          </p>
          <span v-if="state.scanning" class="cursor-blink text-console-fg" aria-hidden="true">▌</span>
        </div>
      </div>
    </div>
  </section>
</template>
