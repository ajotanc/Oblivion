<script setup lang="ts">
import { Info, ShieldAlert, TriangleAlert } from '@lucide/vue'
import { useI18n } from 'vue-i18n'

import type { Severity } from '../types'

defineProps<{ severity: Severity }>()
const { t } = useI18n()
</script>

<template>
  <!-- Ícone + texto: a cor nunca é o único sinal. -->
  <span
    class="inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-semibold whitespace-nowrap"
    :class="{
      'bg-high-bg text-high': severity === 'high',
      'bg-susp-bg text-susp': severity === 'suspicious',
      'bg-info-bg text-info': severity === 'info',
    }"
  >
    <ShieldAlert v-if="severity === 'high'" class="size-3.5" aria-hidden="true" />
    <TriangleAlert v-else-if="severity === 'suspicious'" class="size-3.5" aria-hidden="true" />
    <Info v-else class="size-3.5" aria-hidden="true" />
    {{ t(`review.${severity}`) }}
  </span>
</template>
