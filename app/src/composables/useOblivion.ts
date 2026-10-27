import { computed, reactive } from 'vue'

import { createApi } from '../api'
import { actionableIds, applyFilters, countBySeverity, newFilters, scannerOptions } from '../lib/filter'
import type { AppInfo, CleanResult, Finding, Quarantine, RecentItem, ScanProgress, Step, UndoItem } from '../types'

export interface LogLine {
  time: string
  text: string
  level: 'info' | 'ok' | 'warn' | 'error'
}

export type ScannerState = { state: 'waiting' | 'running' | 'done' | 'failed'; count: number }

const api = createApi()

const state = reactive({
  step: 'scan' as Step,
  info: null as AppInfo | null,
  scanning: false,
  scanned: false,
  scanError: '',
  log: [] as LogLine[],
  scanners: {} as Record<string, ScannerState>,
  findings: [] as Finding[],
  filters: newFilters(),
  selected: new Set<number>(),
  cleaning: false,
  cleanError: '',
  cleanResult: null as CleanResult | null,
  quarantines: [] as Quarantine[],
  historyError: '',
  undoResults: [] as UndoItem[],
  reportPath: '',
  /** Opções avançadas: o mesmo que `--ioc` e `--allow` na linha de comando. */
  options: { ioc: '', allow: '' },
  /** Avisos da última varredura ou receita (linhas ignoradas etc.). */
  notes: [] as string[],
  recipeBusy: false,
  recipeError: '',
  recent: [] as RecentItem[],
  recentDays: 7,
  recentBusy: false,
  recentDone: false,
  recentError: '',
})

const message = (e: unknown): string => (e instanceof Error ? e.message : String(e))

function log(text: string, level: LogLine['level'] = 'info'): void {
  state.log.push({ time: new Date().toLocaleTimeString(), text, level })
}

async function init(): Promise<void> {
  try {
    state.info = await api.appInfo()
  } catch (e) {
    state.info = { version: '?', elevated: false, platform: '', alert: message(e) }
  }
}

function onProgress(p: ScanProgress): void {
  if (p.kind === 'started') {
    state.scanners[p.label] = { state: 'running', count: 0 }
    log(`▸ ${p.label}…`)
  } else if (p.kind === 'finished') {
    state.scanners[p.label] = { state: 'done', count: p.count }
    log(`✓ ${p.label}: ${p.count}`, 'ok')
  } else {
    state.scanners[p.label] = { state: 'failed', count: 0 }
    log(`✗ ${p.label}: falhou, NÃO verificado`, 'error')
  }
}

async function startScan(startedText: string, finishedText: (total: number, high: number, susp: number) => string): Promise<void> {
  if (state.scanning) return
  state.scanning = true
  state.scanError = ''
  state.log = []
  state.scanners = {}
  state.selected = new Set()
  state.cleanResult = null
  log(startedText)
  try {
    const result = await api.runScan(onProgress, { ioc: state.options.ioc, allow: state.options.allow })
    state.findings = result.findings
    state.notes = result.notes
    result.notes.forEach((n) => log(n, 'warn'))
    state.scanned = true
    const c = countBySeverity(state.findings)
    log(finishedText(state.findings.length, c.high, c.suspicious), 'ok')
  } catch (e) {
    state.scanError = message(e)
    log(state.scanError, 'error')
  } finally {
    state.scanning = false
  }
}

/** Receita: não varre; trata só o que o texto pede, pelo mesmo caminho de revisão e limpeza. */
async function applyRecipe(text: string): Promise<boolean> {
  if (state.recipeBusy || !text.trim()) return false
  state.recipeBusy = true
  state.recipeError = ''
  try {
    const result = await api.loadRecipe(text)
    state.findings = result.findings
    state.notes = result.notes
    state.selected = new Set()
    state.cleanResult = null
    state.scanned = true
    state.step = 'review'
    return true
  } catch (e) {
    state.recipeError = message(e)
    return false
  } finally {
    state.recipeBusy = false
  }
}

async function loadRecent(): Promise<void> {
  if (state.recentBusy) return
  state.recentBusy = true
  state.recentError = ''
  try {
    state.recent = await api.recentFiles(state.recentDays)
    state.recentDone = true
  } catch (e) {
    state.recentError = message(e)
  } finally {
    state.recentBusy = false
  }
}

function toggleSelect(id: number): void {
  const next = new Set(state.selected)
  if (!next.delete(id)) next.add(id)
  state.selected = next
}

function selectVisible(): void {
  const visible = new Set(actionableIds(visibleFindings.value))
  state.selected = new Set([...state.selected, ...visible])
}

/** Marca só os itens recomendados (sinal forte e ação reversível), junto com o que já estava marcado. */
function selectRecommended(): void {
  const ids = state.findings.filter((f) => f.recommended && f.actionable).map((f) => f.id)
  state.selected = new Set([...state.selected, ...ids])
}

function clearSelection(): void {
  state.selected = new Set()
}

async function runClean(dryRun: boolean): Promise<void> {
  if (state.cleaning || state.selected.size === 0) return
  state.cleaning = true
  state.cleanError = ''
  state.cleanResult = null
  try {
    state.cleanResult = await api.runClean([...state.selected], dryRun)
  } catch (e) {
    state.cleanError = message(e)
  } finally {
    state.cleaning = false
  }
}

async function loadQuarantines(): Promise<void> {
  state.historyError = ''
  try {
    state.quarantines = await api.listQuarantines()
  } catch (e) {
    state.quarantines = []
    state.historyError = message(e)
  }
}

async function undo(path: string): Promise<void> {
  state.historyError = ''
  try {
    state.undoResults = await api.undoQuarantine(path)
  } catch (e) {
    state.historyError = message(e)
  }
}

async function exportReport(): Promise<string> {
  state.reportPath = await api.exportReport()
  return state.reportPath
}

const visibleFindings = computed(() => applyFilters(state.findings, state.filters))
const severityCounts = computed(() => countBySeverity(state.findings))
const origins = computed(() => scannerOptions(state.findings))
const selectedFindings = computed(() => state.findings.filter((f) => state.selected.has(f.id)))

export function useOblivion() {
  return {
    state,
    visibleFindings,
    severityCounts,
    origins,
    selectedFindings,
    init,
    startScan,
    applyRecipe,
    loadRecent,
    toggleSelect,
    selectVisible,
    selectRecommended,
    clearSelection,
    runClean,
    loadQuarantines,
    undo,
    exportReport,
    restartAsAdmin: () => api.restartAsAdmin(),
    setStep: (s: Step) => {
      state.step = s
    },
  }
}
