import { invoke } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'

import type { AppInfo, CleanResult, Finding, Quarantine, ScanProgress, UndoItem } from '../types'
import { mockApi } from './mock'

export interface Api {
  appInfo(): Promise<AppInfo>
  runScan(onProgress: (e: ScanProgress) => void): Promise<Finding[]>
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
    async runScan(onProgress) {
      const unlisten = await listen<ScanProgress>('scan-progress', (e) => onProgress(e.payload))
      try {
        return await invoke<Finding[]>('run_scan')
      } finally {
        unlisten()
      }
    },
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
