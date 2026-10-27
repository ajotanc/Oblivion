<script setup lang="ts">
import { onMounted } from 'vue'
import { useI18n } from 'vue-i18n'

import AppHeader from './components/AppHeader.vue'
import CleanPanel from './components/CleanPanel.vue'
import HistoryPanel from './components/HistoryPanel.vue'
import ReviewPanel from './components/ReviewPanel.vue'
import ScanPanel from './components/ScanPanel.vue'
import StepNav from './components/StepNav.vue'
import { useOblivion } from './composables/useOblivion'

const { t } = useI18n()
const o = useOblivion()
const { state } = o

onMounted(() => void o.init())
</script>

<template>
  <div class="flex h-full flex-col">
    <a
      href="#content"
      class="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50 focus:rounded-lg focus:bg-card focus:px-3 focus:py-2"
    >
      {{ t('app.skip') }}
    </a>
    <AppHeader :info="state.info" @restart-admin="o.restartAsAdmin()" />

    <div class="grid min-h-0 flex-1 grid-cols-1 md:grid-cols-[16rem_1fr]">
      <StepNav :step="state.step" :findings="state.findings.length" :selected="state.selected.size" @go="o.setStep" />
      <main id="content" tabindex="-1" class="min-h-0 overflow-hidden p-5">
        <ScanPanel v-if="state.step === 'scan'" />
        <ReviewPanel v-else-if="state.step === 'review'" />
        <CleanPanel v-else-if="state.step === 'clean'" />
        <HistoryPanel v-else />
      </main>
    </div>

    <footer class="flex flex-wrap items-center justify-between gap-2 border-t border-line bg-card px-5 py-2 text-xs text-muted">
      <span>{{ t('app.footer') }}</span>
      <span class="font-mono" data-testid="footer-version">Oblivion v{{ state.info?.version ?? '…' }}</span>
    </footer>
  </div>
</template>
