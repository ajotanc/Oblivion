/** Espelha os DTOs do backend (`app/src-tauri/src/lib.rs`), em camelCase. */
export type Severity = 'high' | 'suspicious' | 'info'

export interface Finding {
  id: number
  severity: Severity
  scanner: string
  name: string
  location: string
  target: string
  reason: string
  /** O que a limpeza faria; `null` para INFO. */
  action: string | null
  /** Há uma ação automática (não só instrução manual). */
  actionable: boolean
  /** Processo marcado só por sinais fracos (CPU/GPU): a tela avisa para conferir antes de encerrar. */
  weakSignal: boolean
}

export interface AppInfo {
  version: string
  elevated: boolean
  platform: string
  alert: string
}

export interface ScanProgress {
  kind: 'started' | 'finished' | 'failed'
  label: string
  count: number
}

export type OutcomeKind = 'done' | 'dryRun' | 'declined' | 'manual' | 'skipped' | 'failed'

export interface CleanRecord {
  name: string
  severity: Severity
  target: string
  action: string
  outcome: OutcomeKind
  outcomeLabel: string
  note: string
}

export interface CleanResult {
  dryRun: boolean
  restore: string
  quarantineDir: string | null
  aborted: string | null
  records: CleanRecord[]
}

export interface Quarantine {
  name: string
  path: string
  items: number
  done: number
}

export interface UndoItem {
  description: string
  ok: boolean
  error: string | null
}

export type Step = 'scan' | 'review' | 'clean' | 'history'
