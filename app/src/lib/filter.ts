import type { Finding, Severity } from '../types'

export interface Filters {
  query: string
  severities: Set<Severity>
  scanner: string
}

export const ALL_SEVERITIES: Severity[] = ['high', 'suspicious', 'info']

export function newFilters(): Filters {
  return { query: '', severities: new Set(ALL_SEVERITIES), scanner: '' }
}

/** Linhas que passam na busca (nome, alvo, local ou motivo), na gravidade e na origem. */
export function applyFilters(rows: Finding[], f: Filters): Finding[] {
  const q = f.query.trim().toLowerCase()
  return rows.filter(
    (r) =>
      f.severities.has(r.severity) &&
      (!f.scanner || r.scanner === f.scanner) &&
      (!q || `${r.name} ${r.target} ${r.location} ${r.reason}`.toLowerCase().includes(q)),
  )
}

export function countBySeverity(rows: Finding[]): Record<Severity, number> {
  const c: Record<Severity, number> = { high: 0, suspicious: 0, info: 0 }
  for (const r of rows) c[r.severity]++
  return c
}

/** Origens presentes, em ordem alfabética e sem repetir. */
export function scannerOptions(rows: Finding[]): string[] {
  return [...new Set(rows.map((r) => r.scanner))].sort((a, b) => a.localeCompare(b))
}

/** Números das linhas que podem ser removidas automaticamente. */
export function actionableIds(rows: Finding[]): number[] {
  return rows.filter((r) => r.actionable).map((r) => r.id)
}
