import { mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it } from 'vitest'
import { nextTick } from 'vue'

import App from './App.vue'
import { useOblivion } from './composables/useOblivion'
import { i18n } from './i18n'

/** Fora do app (sem Tauri) a API é a simulada: dá para testar o fluxo inteiro sem o backend. */
const flush = async (ms = 0) => {
  await new Promise((r) => setTimeout(r, ms))
  await nextTick()
}

const mountApp = () => mount(App, { global: { plugins: [i18n] }, attachTo: document.body })

async function scan(wrapper: ReturnType<typeof mountApp>): Promise<void> {
  await wrapper.get('[data-testid=start-scan]').trigger('click')
  await flush(3200) // o simulado leva ~2,1 s
}

describe('Oblivion UI', () => {
  beforeEach(() => {
    const { state } = useOblivion()
    state.step = 'scan'
    state.findings = []
    state.selected = new Set()
    state.cleanResult = null
    state.scanned = false
    state.log = []
    state.scanners = {}
    i18n.global.locale.value = 'pt-BR'
  })

  it('shows the version in the header and in the footer', async () => {
    const w = mountApp()
    await flush(20)
    expect(w.get('[data-testid=version]').text()).toMatch(/^v\d+\.\d+\.\d+/)
    expect(w.get('[data-testid=footer-version]').text()).toMatch(/Oblivion v\d+\.\d+\.\d+/)
    w.unmount()
  })

  it('scans, logs the progress live and moves on to review', async () => {
    const w = mountApp()
    await scan(w)
    const consoleText = w.get('[data-testid=console]').text()
    expect(consoleText).toContain('Persistência, serviços e tarefas agendadas')
    expect(consoleText).toMatch(/Varredura concluída: 9 item/)
    await w.get('[data-testid=step-review]').trigger('click')
    expect(w.findAll('[data-testid=row]').length).toBe(9)
    w.unmount()
  })

  it('renders hostile names as plain text and never creates elements from them', async () => {
    const w = mountApp()
    await scan(w)
    await w.get('[data-testid=step-review]').trigger('click')
    expect(w.text()).toContain('<img src=x onerror=alert(1)>')
    expect(w.find('main img').exists()).toBe(false)
    expect(w.find('main script').exists()).toBe(false)
    w.unmount()
  })

  it('filters live and only lets removable rows be selected', async () => {
    const w = mountApp()
    await scan(w)
    await w.get('[data-testid=step-review]').trigger('click')
    await w.get('[data-testid=sev-info]').setValue(false)
    expect(w.findAll('[data-testid=row]').length).toBe(7)
    await w.get('#q').setValue('xmrig')
    expect(w.findAll('[data-testid=row]').length).toBe(1)
    expect(w.get('[data-testid=counter]').text()).toContain('Mostrando 1 de 9')
    const boxes = w.findAll('[data-testid=row] input[type=checkbox]')
    expect(boxes.length).toBe(1)
    w.unmount()
  })

  it('needs an explicit confirmation before removing, and simulates without it', async () => {
    const w = mountApp()
    await scan(w)
    await w.get('[data-testid=step-review]').trigger('click')
    await w.get('[data-testid=row] input[type=checkbox]').setValue(true)
    expect(useOblivion().state.selected.size).toBe(1)
    await w.get('[data-testid=step-clean]').trigger('click')
    // Sem administrador (simulado) o botão de remover fica desligado; a simulação funciona.
    expect(w.get('[data-testid=remove]').attributes('disabled')).toBeDefined()
    await w.get('[data-testid=simulate]').trigger('click')
    await flush(700)
    expect(w.get('[data-testid=result]').text()).toContain('Simulação: nada foi alterado.')
    w.unmount()
  })

  it('opens a modal dialog, keeps Remove disabled until the user confirms understanding, then removes', async () => {
    const w = mountApp()
    await scan(w)
    useOblivion().state.info = { version: '0.1.0', elevated: true, platform: 'windows', alert: '' }
    await w.get('[data-testid=step-review]').trigger('click')
    await w.get('[data-testid=row] input[type=checkbox]').setValue(true)
    await w.get('[data-testid=step-clean]').trigger('click')
    await w.get('[data-testid=remove]').trigger('click')
    const dialog = w.get('dialog').element as HTMLDialogElement
    expect(dialog.open).toBe(true)
    expect(w.get('[data-testid=confirm]').attributes('disabled')).toBeDefined()
    await w.get('[data-testid=understood]').setValue(true)
    expect(w.get('[data-testid=confirm]').attributes('disabled')).toBeUndefined()
    await w.get('[data-testid=confirm]').trigger('click')
    await flush(700)
    expect(dialog.open).toBe(false)
    const result = w.get('[data-testid=result]').text()
    expect(result).toContain('feito')
    expect(result).not.toContain('Simulação: nada foi alterado.')
    w.unmount()
  })

  it('cancelling the dialog removes nothing', async () => {
    const w = mountApp()
    await scan(w)
    useOblivion().state.info = { version: '0.1.0', elevated: true, platform: 'windows', alert: '' }
    await w.get('[data-testid=step-review]').trigger('click')
    await w.get('[data-testid=row] input[type=checkbox]').setValue(true)
    await w.get('[data-testid=step-clean]').trigger('click')
    await w.get('[data-testid=remove]').trigger('click')
    await w.get('dialog button').trigger('click') // o primeiro botão é "Cancelar"
    await flush(50)
    expect(w.find('[data-testid=result]').exists()).toBe(false)
    w.unmount()
  })
  it('switches language and keeps working', async () => {
    const w = mountApp()
    await flush(20)
    i18n.global.locale.value = 'en'
    await nextTick()
    expect(w.text()).toContain('System scan')
    expect(w.text()).toContain('Nothing is sent over the network.')
    w.unmount()
  })
})
