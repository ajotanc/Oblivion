<script setup lang="ts">
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'

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

const field =
  'w-full rounded-lg border border-line bg-card p-2 font-mono text-xs text-fg focus-visible:outline-2 focus-visible:outline-primary'
const button =
  'inline-flex min-h-11 items-center rounded-lg border border-line bg-card px-4 text-sm font-semibold hover:bg-card/70 disabled:opacity-60'
</script>

<template>
  <details class="rounded-xl border border-line bg-card/50 p-3" data-testid="advanced">
    <summary class="cursor-pointer text-sm font-semibold">{{ t('advanced.title') }}</summary>
    <p class="mt-2 text-sm text-muted">{{ t('advanced.hint') }}</p>

    <div class="mt-3 grid gap-4 lg:grid-cols-2">
      <div>
        <label for="adv-ioc" class="text-sm font-semibold">{{ t('advanced.iocTitle') }}</label>
        <p class="mb-1 text-xs text-muted">{{ t('advanced.iocHelp') }}</p>
        <textarea id="adv-ioc" v-model="state.options.ioc" rows="4" spellcheck="false" :class="field" data-testid="adv-ioc"></textarea>
        <label class="mt-1 inline-block cursor-pointer text-xs font-semibold text-primary underline">
          {{ t('advanced.openFile') }}
          <input type="file" accept=".txt,text/plain" class="sr-only" @change="fill($event, (x) => (state.options.ioc = x))" />
        </label>
      </div>

      <div>
        <label for="adv-allow" class="text-sm font-semibold">{{ t('advanced.allowTitle') }}</label>
        <p class="mb-1 text-xs text-muted">{{ t('advanced.allowHelp') }}</p>
        <textarea id="adv-allow" v-model="state.options.allow" rows="4" spellcheck="false" :class="field" data-testid="adv-allow"></textarea>
        <label class="mt-1 inline-block cursor-pointer text-xs font-semibold text-primary underline">
          {{ t('advanced.openFile') }}
          <input type="file" accept=".txt,text/plain" class="sr-only" @change="fill($event, (x) => (state.options.allow = x))" />
        </label>
      </div>

      <div>
        <label for="adv-recipe" class="text-sm font-semibold">{{ t('advanced.recipeTitle') }}</label>
        <p class="mb-1 text-xs text-muted">{{ t('advanced.recipeHelp') }}</p>
        <textarea id="adv-recipe" v-model="recipe" rows="4" spellcheck="false" :class="field" data-testid="adv-recipe"></textarea>
        <div class="mt-2 flex flex-wrap items-center gap-3">
          <button type="button" :class="button" data-testid="adv-recipe-apply" :disabled="state.recipeBusy || !recipe.trim()" @click="o.applyRecipe(recipe)">
            {{ state.recipeBusy ? t('advanced.recipeBusy') : t('advanced.recipeApply') }}
          </button>
          <label class="cursor-pointer text-xs font-semibold text-primary underline">
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
          <select id="adv-days" v-model.number="state.recentDays" class="min-h-11 rounded-lg border border-line bg-card px-2 text-sm">
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

    <div v-if="state.notes.length" class="mt-3 rounded-lg border border-line p-2 text-sm" role="status" data-testid="notes">
      <p class="font-semibold">{{ t('advanced.notes') }}</p>
      <ul class="list-disc pl-5">
        <li v-for="(n, i) in state.notes" :key="i" class="text-susp">{{ n }}</li>
      </ul>
    </div>
  </details>
</template>
