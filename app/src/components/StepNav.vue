<script setup lang="ts">
import { History, ListChecks, ScanSearch, Trash2 } from '@lucide/vue'
import { useI18n } from 'vue-i18n'

import type { Step } from '../types'

defineProps<{ step: Step; findings: number; selected: number }>()
defineEmits<{ go: [step: Step] }>()
const { t } = useI18n()

const steps = [
  { id: 'scan' as Step, icon: ScanSearch },
  { id: 'review' as Step, icon: ListChecks },
  { id: 'clean' as Step, icon: Trash2 },
  { id: 'history' as Step, icon: History },
]
</script>

<template>
  <nav :aria-label="t('steps.label')" class="border-r border-line bg-card p-3">
    <ol class="flex flex-col gap-1">
      <li v-for="(s, i) in steps" :key="s.id">
        <button
          type="button"
          class="flex min-h-14 w-full items-center gap-3 rounded-lg px-3 py-2 text-left"
          :class="step === s.id ? 'bg-primary text-primary-fg' : 'hover:bg-bg'"
          :aria-current="step === s.id ? 'step' : undefined"
          :data-testid="`step-${s.id}`"
          @click="$emit('go', s.id)"
        >
          <span
            class="flex size-8 shrink-0 items-center justify-center rounded-full border text-xs font-bold"
            :class="step === s.id ? 'border-primary-fg/60' : 'border-line text-muted'"
            aria-hidden="true"
          >
            <component :is="s.icon" class="size-4" />
          </span>
          <span class="min-w-0">
            <span class="block text-sm leading-tight font-semibold">
              {{ i + 1 }}. {{ t(`steps.${s.id}`) }}
              <span v-if="s.id === 'review' && findings" class="font-normal opacity-80">({{ findings }})</span>
              <span v-if="s.id === 'clean' && selected" class="font-normal opacity-80">({{ selected }})</span>
            </span>
            <span class="block text-xs leading-tight" :class="step === s.id ? 'opacity-90' : 'text-muted'">
              {{ t(`steps.${s.id}Hint`) }}
            </span>
          </span>
        </button>
      </li>
    </ol>
  </nav>
</template>
