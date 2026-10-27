import { invoke } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'

import type { AppInfo, CleanResult, Quarantine, RecentItem, ScanProgress, ScanResult, UndoItem } from '../types'
import { mockApi } from './mock'

export interface Api {
  appInfo(): Promise<AppInfo>
  /** `ioc` e `allow` são o texto das listas `--ioc` e `--allow` da linha de comando. */
  runScan(onProgress: (e: ScanProgress) => void, options?: { ioc?: string; allow?: string }): Promise<ScanResult>
  /** Receita: em vez de varrer, trata só o que o texto pede (igual a `clean --recipe`). */
  loadRecipe(text: string): Promise<ScanResult>
  /** Arquivos novos nas pastas onde malware costuma se instalar (igual a `oblivion recent`). */
  recentFiles(days: number): Promise<RecentItem[]>
  /** Só números: o backend guarda os achados e resolve caminho e comando do lado dele. */
  runClean(ids: number[], dryRun: boolean): Promise<CleanResult>
  listQuarantines(): Promise<Quarantine[]>
  undoQuarantine(path: string): Promise<UndoItem[]>
  exportReport(): Promise<string>
  restartAsAdmin(): Promise<void>
}

export const inTauri = (): boolean => typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window

function tauriApi(): Api {
  return {
    appInfo: () => invoke<AppInfo>('app_info'),
    async runScan(onProgress, options = {}) {
      const unlisten = await listen<ScanProgress>('scan-progress', (e) => onProgress(e.payload))
      try {
        return await invoke<ScanResult>('run_scan', { ioc: options.ioc || null, allow: options.allow || null })
      } finally {
        unlisten()
      }
    },
    loadRecipe: (text) => invoke<ScanResult>('load_recipe', { text }),
    recentFiles: (days) => invoke<RecentItem[]>('recent_files', { days }),
    runClean: (ids, dryRun) => invoke<CleanResult>('run_clean', { ids, dryRun }),
    listQuarantines: () => invoke<Quarantine[]>('list_quarantines'),
    undoQuarantine: (path) => invoke<UndoItem[]>('undo_quarantine', { path }),
    exportReport: () => invoke<string>('export_report'),
    restartAsAdmin: () => invoke<void>('restart_as_admin'),
  }
}

/** Dentro do app usa o backend; no navegador (só para pré-visualizar o visual) usa dados simulados. */
export function createApi(): Api {
  return inTauri() ? tauriApi() : mockApi()
}
