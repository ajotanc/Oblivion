<script setup lang="ts">
import { Download } from '@lucide/vue'
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'

import { ALL_SEVERITIES } from '../lib/filter'
import { useOblivion } from '../composables/useOblivion'
import type { Severity } from '../types'
import SeverityBadge from './SeverityBadge.vue'

const { t } = useI18n()
const o = useOblivion()
const { state } = o
const exportMessage = ref('')

function toggleSeverity(s: Severity): void {
  const next = new Set(state.filters.severities)
  if (!next.delete(s)) next.add(s)
  state.filters.severities = next
}

async function doExport(): Promise<void> {
  try {
    exportMessage.value = t('review.exported', { path: await o.exportReport() })
  } catch (e) {
    exportMessage.value = String(e)
  }
}
</script>

<template>
  <section aria-labelledby="review-title" class="flex h-full min-h-0 flex-col gap-3">
    <div class="flex flex-wrap items-end justify-between gap-3">
      <div>
        <h2 id="review-title" class="text-xl font-bold">{{ t('review.title') }}</h2>
        <p class="text-sm text-muted" aria-live="polite" data-testid="counter">
          {{ t('review.showing', { shown: o.visibleFindings.value.length, total: state.findings.length }) }}
        </p>
      </div>
      <div class="flex flex-wrap items-center gap-2">
        <button
          type="button"
          class="inline-flex min-h-11 items-center gap-2 rounded-lg border border-line px-3 text-sm font-medium hover:bg-bg disabled:opacity-50"
          :disabled="!state.findings.length"
          @click="doExport"
        >
          <Download class="size-4" aria-hidden="true" />
          {{ t('review.export') }}
        </button>
        <button
          type="button"
          class="min-h-11 rounded-lg bg-primary px-4 text-sm font-semibold text-primary-fg disabled:opacity-50"
          :disabled="!state.selected.size"
          @click="o.setStep('clean')"
        >
          {{ t('review.goClean') }} ({{ state.selected.size }})
        </button>
      </div>
    </div>
    <p v-if="exportMessage" class="text-sm text-muted" role="status">{{ exportMessage }}</p>

    <p v-if="!state.findings.length" class="rounded-lg border border-dashed border-line p-6 text-center text-muted">
      {{ t('review.empty') }}
    </p>

    <template v-else>
      <div class="flex flex-wrap items-end gap-4" role="search">
        <div>
          <label for="q" class="block text-xs font-semibold text-muted">{{ t('review.search') }}</label>
          <input
            id="q"
            v-model="state.filters.query"
            type="search"
            autocomplete="off"
            :placeholder="t('review.searchPlaceholder')"
            class="min-h-11 w-64 rounded-lg border border-line bg-card px-3"
          />
        </div>
        <div>
          <label for="origin" class="block text-xs font-semibold text-muted">{{ t('review.origin') }}</label>
          <select id="origin" v-model="state.filters.scanner" class="min-h-11 rounded-lg border border-line bg-card px-2">
            <option value="">{{ t('review.allOrigins') }}</option>
            <option v-for="s in o.origins.value" :key="s" :value="s">{{ s }}</option>
          </select>
        </div>
        <fieldset class="flex items-center gap-1.5">
          <legend class="mb-0.5 text-xs font-semibold text-muted">{{ t('review.severity') }}</legend>
          <label
            v-for="s in ALL_SEVERITIES"
            :key="s"
            class="inline-flex min-h-11 cursor-pointer items-center gap-1.5 rounded-lg border border-line px-3 text-sm"
            :class="state.filters.severities.has(s) ? 'bg-card' : 'opacity-60'"
          >
            <input
              type="checkbox"
              class="size-4"
              :checked="state.filters.severities.has(s)"
              :data-testid="`sev-${s}`"
              @change="toggleSeverity(s)"
            />
            {{ t(`review.${s}`) }} ({{ o.severityCounts.value[s] }})
          </label>
        </fieldset>
        <div class="ml-auto flex gap-2">
          <button type="button" class="min-h-11 rounded-lg border border-line px-3 text-sm hover:bg-bg" @click="o.selectVisible()">
            {{ t('review.selectVisible') }}
          </button>
          <button
            type="button"
            class="min-h-11 rounded-lg border border-line px-3 text-sm hover:bg-bg disabled:opacity-50"
            :disabled="!state.selected.size"
            @click="o.clearSelection()"
          >
            {{ t('review.clearSelection') }}
          </button>
        </div>
      </div>

      <div class="min-h-0 flex-1 overflow-auto rounded-xl border border-line bg-card" tabindex="0" role="region" :aria-label="t('review.title')">
        <table class="w-full min-w-[1180px] table-fixed border-collapse text-left text-sm" data-testid="table">
          <caption class="sr-only">{{ t('review.title') }}</caption>
          <thead class="sticky top-0 bg-card text-xs text-muted">
            <tr class="border-b border-line">
              <th scope="col" class="w-20 px-3 py-2">{{ t('review.select') }}</th>
              <th scope="col" class="w-28 px-3 py-2">{{ t('review.severity') }}</th>
              <th scope="col" class="w-44 px-3 py-2">{{ t('review.colName') }}</th>
              <th scope="col" class="w-72 px-3 py-2">{{ t('review.colTarget') }}</th>
              <th scope="col" class="w-56 px-3 py-2">{{ t('review.colWhere') }}</th>
              <th scope="col" class="w-60 px-3 py-2">{{ t('review.colReason') }}</th>
              <th scope="col" class="w-64 px-3 py-2">{{ t('review.colAction') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="!o.visibleFindings.value.length">
              <td colspan="7" class="px-3 py-6 text-center text-muted">{{ t('review.noMatch') }}</td>
            </tr>
            <tr
              v-for="f in o.visibleFindings.value"
              :key="f.id"
              class="border-b border-line align-top last:border-0"
              :class="state.selected.has(f.id) ? 'bg-info-bg' : ''"
              data-testid="row"
            >
              <td class="px-3 py-2">
                <input
                  v-if="f.actionable"
                  type="checkbox"
                  class="size-5"
                  :checked="state.selected.has(f.id)"
                  :aria-label="`${t('review.select')}: ${f.name}`"
                  @change="o.toggleSelect(f.id)"
                />
                <span v-else class="text-muted" :title="t('review.manual')">–<span class="sr-only">{{ t('review.manual') }}</span></span>
              </td>
              <td class="px-3 py-2"><SeverityBadge :severity="f.severity" /></td>
              <td class="px-3 py-2 font-medium break-words">{{ f.name }}</td>
              <td class="px-3 py-2 font-mono text-xs break-all">{{ f.target }}</td>
              <td class="px-3 py-2 text-xs break-words text-muted">{{ f.location }} <span class="opacity-70">· {{ f.scanner }}</span></td>
              <td class="px-3 py-2 break-words">{{ f.reason }}</td>
              <td class="px-3 py-2 text-xs break-words text-muted">{{ f.action ?? '' }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>
  </section>
</template>
