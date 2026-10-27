import { mount } from '@vue/test-utils'
import axe from 'axe-core'
import { beforeEach, describe, expect, it } from 'vitest'
import { nextTick } from 'vue'

import App from './App.vue'
import { useOblivion } from './composables/useOblivion'
import { i18n } from './i18n'
import type { Step } from './types'

const flush = async (ms = 0) => {
  await new Promise((r) => setTimeout(r, ms))
  await nextTick()
}

/** Roda o axe (WCAG 2.1 A/AA). O contraste é conferido à parte, em `contrast.test.ts`: o ambiente de teste
 * não tem layout nem cores calculadas, então a regra de contraste do axe não funcionaria aqui. */
async function violations(): Promise<string[]> {
  const result = await axe.run(document.body, {
    runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'] },
    rules: { 'color-contrast': { enabled: false } },
  })
  return result.violations.map((v) => `${v.id}: ${v.help} (${v.nodes.map((n) => n.target.join(' ')).join(' | ')})`)
}

const steps: Step[] = ['scan', 'review', 'clean', 'history']

describe('acessibilidade (axe, WCAG 2.1 A/AA)', () => {
  beforeEach(() => {
    const { state } = useOblivion()
    state.step = 'scan'
    state.findings = []
    state.selected = new Set()
    state.cleanResult = null
    state.scanned = false
    state.log = []
    state.scanners = {}
    state.info = null
  })

  for (const locale of ['pt-BR', 'en'] as const) {
    it(`todas as telas, em ${locale}, sem violações`, async () => {
      i18n.global.locale.value = locale
      const w = mount(App, { global: { plugins: [i18n] }, attachTo: document.body })
      const o = useOblivion()
      await flush(20)
      await w.get('[data-testid=start-scan]').trigger('click')
      await flush(3200)
      await w.get('[data-testid=step-review]').trigger('click')
      await w.get('[data-testid=row] input[type=checkbox]').setValue(true)
      o.state.info = { version: '0.1.0', elevated: true, platform: 'windows', alert: '' }

      for (const step of steps) {
        o.setStep(step)
        await flush(100)
        if (step === 'clean') {
          await w.get('[data-testid=simulate]').trigger('click')
          await flush(700) // mostra também o resultado da simulação
        }
        expect(await violations(), `tela "${step}" em ${locale}`).toEqual([])
      }
      w.unmount()
    }, 20000)
  }

  it('o diálogo de confirmação aberto também passa', async () => {
    i18n.global.locale.value = 'pt-BR'
    const w = mount(App, { global: { plugins: [i18n] }, attachTo: document.body })
    const o = useOblivion()
    await w.get('[data-testid=start-scan]').trigger('click')
    await flush(3200)
    o.state.info = { version: '0.1.0', elevated: true, platform: 'windows', alert: '' }
    await w.get('[data-testid=step-review]').trigger('click')
    await w.get('[data-testid=row] input[type=checkbox]').setValue(true)
    await w.get('[data-testid=step-clean]').trigger('click')
    await w.get('[data-testid=remove]').trigger('click')
    expect((w.get('dialog').element as HTMLDialogElement).open).toBe(true)
    expect(await violations()).toEqual([])
    w.unmount()
  }, 20000)
})
