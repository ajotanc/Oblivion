import { computed, reactive } from 'vue'

import { createApi } from '../api'
import { actionableIds, applyFilters, countBySeverity, newFilters, scannerOptions } from '../lib/filter'
import type { AppInfo, CleanResult, Finding, Quarantine, ScanProgress, Step, UndoItem } from '../types'

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
    state.findings = await api.runScan(onProgress)
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

function toggleSelect(id: number): void {
  const next = new Set(state.selected)
  if (!next.delete(id)) next.add(id)
  state.selected = next
}

function selectVisible(): void {
  const visible = new Set(actionableIds(visibleFindings.value))
  state.selected = new Set([...state.selected, ...visible])
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
    toggleSelect,
    selectVisible,
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
