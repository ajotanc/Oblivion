<script setup lang="ts">
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { ChevronDown, FileUp, SlidersHorizontal } from '@lucide/vue'

import { useOblivion } from '../composables/useOblivion'

const { t } = useI18n()
const o = useOblivion()
const { state } = o

const recipe = ref('')

/** Lê um arquivo de texto escolhido pelo usuário para dentro da caixa (tudo local, nada é enviado). */
async function fill(event: Event, set: (text: string) => void): Promise<void> {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (file) set(await file.text())
  input.value = ''
}

const field = 'field'
const button =
  'inline-flex min-h-11 items-center rounded-lg border border-line bg-card px-4 text-sm font-semibold hover:bg-card/70 disabled:opacity-60'
</script>

<template>
  <details class="accordion" data-testid="advanced">
    <summary>
      <span class="icon-tile" aria-hidden="true"><SlidersHorizontal class="size-5" /></span>
      <span class="min-w-0 flex-1">
        <span class="block text-sm font-semibold">{{ t('advanced.title') }}</span>
        <span class="block text-xs text-muted">{{ t('advanced.hint') }}</span>
      </span>
      <ChevronDown class="accordion-chevron size-5 text-muted" aria-hidden="true" />
    </summary>

    <div class="accordion-body grid gap-4 lg:grid-cols-2">
      <div>
        <label for="adv-ioc" class="text-sm font-semibold">{{ t('advanced.iocTitle') }}</label>
        <p class="mb-1 text-xs text-muted lg:min-h-12">{{ t('advanced.iocHelp') }}</p>
        <textarea id="adv-ioc" v-model="state.options.ioc" rows="4" placeholder="sha256:…&#10;nome:arquivo.exe" spellcheck="false" :class="field" data-testid="adv-ioc"></textarea>
        <label class="file-button mt-2">
          <FileUp class="size-4" aria-hidden="true" />
          {{ t('advanced.openFile') }}
          <input type="file" accept=".txt,text/plain" class="sr-only" @change="fill($event, (x) => (state.options.ioc = x))" />
        </label>
      </div>

      <div>
        <label for="adv-allow" class="text-sm font-semibold">{{ t('advanced.allowTitle') }}</label>
        <p class="mb-1 text-xs text-muted lg:min-h-12">{{ t('advanced.allowHelp') }}</p>
        <textarea id="adv-allow" v-model="state.options.allow" rows="4" placeholder="C:\Programas\app.exe" spellcheck="false" :class="field" data-testid="adv-allow"></textarea>
        <label class="file-button mt-2">
          <FileUp class="size-4" aria-hidden="true" />
          {{ t('advanced.openFile') }}
          <input type="file" accept=".txt,text/plain" class="sr-only" @change="fill($event, (x) => (state.options.allow = x))" />
        </label>
      </div>

      <div>
        <label for="adv-recipe" class="text-sm font-semibold">{{ t('advanced.recipeTitle') }}</label>
        <p class="mb-1 text-xs text-muted">{{ t('advanced.recipeHelp') }}</p>
        <textarea id="adv-recipe" v-model="recipe" rows="4" placeholder="valor: HKCU\…\Run | NomeDoValor" spellcheck="false" :class="field" data-testid="adv-recipe"></textarea>
        <div class="mt-2 flex flex-wrap items-center gap-3">
          <button type="button" :class="button" data-testid="adv-recipe-apply" :disabled="state.recipeBusy || !recipe.trim()" @click="o.applyRecipe(recipe)">
            {{ state.recipeBusy ? t('advanced.recipeBusy') : t('advanced.recipeApply') }}
          </button>
          <label class="file-button">
            <FileUp class="size-4" aria-hidden="true" />
            {{ t('advanced.openFile') }}
            <input type="file" accept=".txt,text/plain" class="sr-only" @change="fill($event, (x) => (recipe = x))" />
          </label>
        </div>
        <p v-if="state.recipeError" role="alert" class="mt-2 text-sm text-high">{{ t('advanced.recipeError', { message: state.recipeError }) }}</p>
      </div>

      <div>
        <h3 class="text-sm font-semibold">{{ t('advanced.recentTitle') }}</h3>
        <p class="mb-1 text-xs text-muted">{{ t('advanced.recentHelp') }}</p>
        <div class="flex flex-wrap items-center gap-3">
          <label for="adv-days" class="text-sm">{{ t('advanced.recentDays') }}</label>
          <select id="adv-days" v-model.number="state.recentDays" class="field">
            <option v-for="d in [1, 3, 7, 14, 30]" :key="d" :value="d">{{ d }}</option>
          </select>
          <button type="button" :class="button" data-testid="adv-recent" :disabled="state.recentBusy" @click="o.loadRecent()">
            {{ state.recentBusy ? t('advanced.recentBusy') : t('advanced.recentShow') }}
          </button>
        </div>
        <p v-if="state.recentError" role="alert" class="mt-2 text-sm text-high">{{ t('advanced.recentError', { message: state.recentError }) }}</p>
        <div v-if="state.recentDone" class="mt-2" data-testid="recent-result" aria-live="polite">
          <p class="text-sm">
            {{ state.recent.length ? t('advanced.recentCount', { count: state.recent.length, days: state.recentDays }) : t('advanced.recentNone') }}
          </p>
          <ul v-if="state.recent.length" class="mt-1 max-h-48 overflow-y-auto rounded-lg border border-line bg-card p-2 font-mono text-xs">
            <li v-for="(r, i) in state.recent" :key="i" class="break-all py-0.5">
              <span class="font-semibold">{{ r.name }}</span>
              <span class="block text-muted">{{ r.path }}</span>
            </li>
          </ul>
        </div>
      </div>
    </div>

    <div v-if="state.notes.length" class="mx-4 mb-4 rounded-lg border border-line p-2 text-sm" role="status" data-testid="notes">
      <p class="font-semibold">{{ t('advanced.notes') }}</p>
      <ul class="list-disc pl-5">
        <li v-for="(n, i) in state.notes" :key="i" class="text-susp">{{ n }}</li>
      </ul>
    </div>
  </details>
</template>
