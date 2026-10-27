<script setup lang="ts">
import { TriangleAlert } from '@lucide/vue'
import { nextTick, ref } from 'vue'
import { useI18n } from 'vue-i18n'

import { useOblivion } from '../composables/useOblivion'
import SeverityBadge from './SeverityBadge.vue'

const { t } = useI18n()
const o = useOblivion()
const { state } = o

const dialog = ref<HTMLDialogElement | null>(null)
const understood = ref(false)

async function openDialog(): Promise<void> {
  understood.value = false
  dialog.value?.showModal()
  await nextTick()
}

async function confirm(): Promise<void> {
  dialog.value?.close()
  await o.runClean(false)
}

const needsAdmin = () => state.info !== null && !state.info.elevated
</script>

<template>
  <section aria-labelledby="clean-title" class="flex h-full min-h-0 flex-col gap-4 overflow-y-auto">
    <div>
      <h2 id="clean-title" class="text-xl font-bold">{{ t('clean.title') }}</h2>
      <p class="mt-1 max-w-3xl text-sm text-muted">{{ t('clean.how') }}</p>
    </div>

    <p v-if="!state.selected.size && !state.cleanResult" class="rounded-lg border border-dashed border-line p-6 text-center text-muted">
      {{ t('clean.none') }}
    </p>

    <template v-else-if="state.selected.size">
      <p class="font-medium" data-testid="selected-count">{{ t('clean.selected', { count: state.selected.size }) }}</p>
      <p v-if="needsAdmin()" class="text-sm text-susp">{{ t('clean.needAdmin') }}</p>

      <ul class="space-y-2">
        <li v-for="f in o.selectedFindings.value" :key="f.id" class="rounded-lg border border-line bg-card p-3 text-sm">
          <div class="flex flex-wrap items-center gap-2">
            <SeverityBadge :severity="f.severity" />
            <span class="font-semibold break-words">{{ f.name }}</span>
          </div>
          <p class="mt-1 font-mono text-xs break-all text-muted">{{ f.target }}</p>
          <p class="mt-1 text-xs">{{ f.action }}</p>
          <p v-if="f.weakSignal" class="mt-1 flex items-start gap-1.5 text-xs text-susp">
            <TriangleAlert class="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
            {{ t('clean.weakSignal') }}
          </p>
        </li>
      </ul>

      <div class="flex flex-wrap gap-2">
        <button
          type="button"
          class="min-h-11 rounded-lg border border-line px-4 font-medium hover:bg-bg disabled:opacity-50"
          :disabled="state.cleaning"
          data-testid="simulate"
          @click="o.runClean(true)"
        >
          {{ t('clean.simulate') }}
        </button>
        <button
          type="button"
          class="min-h-11 rounded-lg bg-high px-4 font-semibold text-white disabled:opacity-50 dark:text-black"
          :disabled="state.cleaning || needsAdmin()"
          data-testid="remove"
          @click="openDialog"
        >
          {{ state.cleaning ? t('clean.working') : t('clean.remove') }}
        </button>
      </div>
    </template>

    <p v-if="state.cleanError" role="alert" class="text-sm text-high">{{ t('clean.error', { message: state.cleanError }) }}</p>

    <section v-if="state.cleanResult" aria-labelledby="result-title" class="space-y-2 rounded-xl border border-line bg-card p-4" data-testid="result">
      <h3 id="result-title" class="font-bold">{{ t('clean.resultTitle') }}</h3>
      <p v-if="state.cleanResult.dryRun" class="text-sm text-muted">{{ t('clean.resultDry') }}</p>
      <p v-if="state.cleanResult.aborted" role="alert" class="text-sm text-high">
        {{ t('clean.aborted') }}: {{ state.cleanResult.aborted }}
      </p>
      <p class="text-sm"><strong>{{ t('clean.restore') }}:</strong> {{ state.cleanResult.restore }}</p>
      <p v-if="state.cleanResult.quarantineDir" class="text-sm break-all">
        <strong>{{ t('clean.quarantine') }}:</strong> <code class="font-mono text-xs">{{ state.cleanResult.quarantineDir }}</code>
      </p>
      <ul class="divide-y divide-line text-sm">
        <li v-for="(r, i) in state.cleanResult.records" :key="i" class="py-2">
          <div class="flex flex-wrap items-center gap-2">
            <SeverityBadge :severity="r.severity" />
            <span class="font-semibold break-words">{{ r.name }}</span>
            <span
              class="rounded-md px-2 py-0.5 text-xs font-semibold"
              :class="r.outcome === 'done' ? 'bg-ok-bg text-ok' : r.outcome === 'failed' ? 'bg-high-bg text-high' : 'bg-info-bg text-info'"
            >
              {{ t(`clean.outcome.${r.outcome}`) }}
            </span>
          </div>
          <p class="mt-0.5 text-xs text-muted break-words">{{ r.action }}</p>
          <p v-if="r.note" class="mt-0.5 text-xs break-all">{{ r.note }}</p>
          <p v-if="r.outcome === 'failed' || r.outcome === 'skipped'" class="mt-0.5 text-xs text-susp break-words">{{ r.outcomeLabel }}</p>
        </li>
      </ul>
      <div class="flex flex-wrap gap-2 pt-2">
        <button type="button" class="min-h-11 rounded-lg border border-line px-4 text-sm hover:bg-bg" @click="o.setStep('scan')">
          {{ t('clean.rescan') }}
        </button>
        <button
          v-if="state.cleanResult.quarantineDir"
          type="button"
          class="min-h-11 rounded-lg border border-line px-4 text-sm hover:bg-bg"
          @click="o.setStep('history')"
        >
          {{ t('steps.history') }}
        </button>
      </div>
    </section>

    <!-- <dialog> nativo: foco preso, Esc fecha e leitor de tela anuncia como diálogo modal. -->
    <dialog
      ref="dialog"
      aria-labelledby="dlg-title"
      class="m-auto w-[min(40rem,92vw)] rounded-xl border border-line bg-card p-5 text-fg backdrop:bg-black/50"
    >
      <h3 id="dlg-title" class="text-lg font-bold">{{ t('clean.dialogTitle') }}</h3>
      <p class="mt-2 text-sm">{{ t('clean.dialogBody', { count: state.selected.size }) }}</p>
      <ul class="mt-2 max-h-56 list-disc space-y-1 overflow-y-auto pl-5 text-sm">
        <li v-for="f in o.selectedFindings.value" :key="f.id" class="break-words">{{ f.name }}</li>
      </ul>
      <label class="mt-4 flex min-h-11 cursor-pointer items-start gap-2 text-sm">
        <input v-model="understood" type="checkbox" class="mt-1 size-5" data-testid="understood" />
        <span>{{ t('clean.understand') }}</span>
      </label>
      <div class="mt-4 flex justify-end gap-2">
        <button type="button" class="min-h-11 rounded-lg border border-line px-4 hover:bg-bg" @click="dialog?.close()">
          {{ t('clean.cancel') }}
        </button>
        <button
          type="button"
          class="min-h-11 rounded-lg bg-high px-4 font-semibold text-white disabled:opacity-50 dark:text-black"
          :disabled="!understood"
          data-testid="confirm"
          @click="confirm"
        >
          {{ t('clean.confirm') }}
        </button>
      </div>
    </dialog>
  </section>
</template>
