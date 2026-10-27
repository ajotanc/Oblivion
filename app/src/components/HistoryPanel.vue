<script setup lang="ts">
import { RefreshCw, Undo2 } from '@lucide/vue'
import { onMounted } from 'vue'
import { useI18n } from 'vue-i18n'

import { useOblivion } from '../composables/useOblivion'

const { t } = useI18n()
const o = useOblivion()
const { state } = o

onMounted(() => void o.loadQuarantines())
</script>

<template>
  <section aria-labelledby="history-title" class="flex h-full min-h-0 flex-col gap-4 overflow-y-auto">
    <div class="flex flex-wrap items-start justify-between gap-3">
      <div>
        <h2 id="history-title" class="text-xl font-bold">{{ t('history.title') }}</h2>
        <p class="mt-1 max-w-3xl text-sm text-muted">{{ t('history.intro') }}</p>
      </div>
      <button
        type="button"
        class="inline-flex min-h-11 items-center gap-2 rounded-lg border border-line px-3 text-sm font-medium hover:bg-bg"
        @click="o.loadQuarantines()"
      >
        <RefreshCw class="size-4" aria-hidden="true" />
        {{ t('history.refresh') }}
      </button>
    </div>

    <p v-if="state.info && !state.info.elevated" class="text-sm text-susp">{{ t('history.needAdmin') }}</p>
    <p v-if="state.historyError" role="alert" class="text-sm text-high">{{ t('history.error', { message: state.historyError }) }}</p>

    <p v-if="!state.quarantines.length && !state.historyError" class="rounded-lg border border-dashed border-line p-6 text-center text-muted">
      {{ t('history.empty') }}
    </p>

    <ul class="space-y-2">
      <li
        v-for="q in state.quarantines"
        :key="q.path"
        class="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-line bg-card p-3"
        data-testid="quarantine"
      >
        <div class="min-w-0">
          <p class="font-mono text-sm font-semibold">{{ q.name }}</p>
          <p class="text-xs text-muted">{{ t('history.items', { done: q.done, items: q.items }) }}</p>
          <p class="truncate text-xs text-muted" :title="q.path">{{ q.path }}</p>
        </div>
        <button
          type="button"
          class="inline-flex min-h-11 items-center gap-2 rounded-lg bg-primary px-4 text-sm font-semibold text-primary-fg"
          @click="o.undo(q.path)"
        >
          <Undo2 class="size-4" aria-hidden="true" />
          {{ t('history.undo') }}
        </button>
      </li>
    </ul>

    <section v-if="state.undoResults.length" aria-labelledby="undo-title" class="rounded-xl border border-line bg-card p-4">
      <h3 id="undo-title" class="font-bold">{{ t('history.undoDone') }}</h3>
      <ul class="mt-2 space-y-1 text-sm">
        <li v-for="(r, i) in state.undoResults" :key="i" class="break-words" :class="r.ok ? 'text-ok' : 'text-high'">
          {{ r.ok ? '✓' : '✗' }} {{ r.description }}<span v-if="r.error"> — {{ r.error }}</span>
        </li>
      </ul>
    </section>
  </section>
</template>
