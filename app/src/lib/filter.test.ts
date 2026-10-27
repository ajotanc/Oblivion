import { describe, expect, it } from 'vitest'

import type { Finding, Severity } from '../types'
import { actionableIds, applyFilters, countBySeverity, newFilters, scannerOptions } from './filter'

const f = (id: number, severity: Severity, scanner: string, name: string, actionable = false): Finding => ({
  id,
  severity,
  scanner,
  name,
  location: `local-${id}`,
  target: `alvo-${name}`,
  reason: 'motivo',
  action: actionable ? 'agir' : null,
  actionable,
  weakSignal: false,
})

const rows = [
  f(0, 'high', 'minerador', 'xmrig', true),
  f(1, 'suspicious', 'tarefas', 'Backup', true),
  f(2, 'info', 'mbr', 'Boot'),
  f(3, 'info', 'persistencia', 'Servico'),
]

describe('applyFilters', () => {
  it('shows everything by default', () => {
    expect(applyFilters(rows, newFilters())).toHaveLength(4)
  })

  it('filters by severity, origin and text (name, target, location or reason), ignoring case', () => {
    const filters = newFilters()
    filters.severities = new Set<Severity>(['high', 'suspicious'])
    expect(applyFilters(rows, filters).map((r) => r.id)).toEqual([0, 1])
    filters.scanner = 'tarefas'
    expect(applyFilters(rows, filters).map((r) => r.id)).toEqual([1])
    const byText = newFilters()
    byText.query = '  XMRIG '
    expect(applyFilters(rows, byText).map((r) => r.id)).toEqual([0])
    byText.query = 'local-3'
    expect(applyFilters(rows, byText).map((r) => r.id)).toEqual([3])
    byText.query = 'motivo'
    expect(applyFilters(rows, byText)).toHaveLength(4)
  })

  it('returns nothing when no severity is checked or nothing matches', () => {
    const none = newFilters()
    none.severities = new Set()
    expect(applyFilters(rows, none)).toEqual([])
    const miss = newFilters()
    miss.query = 'zzzz-nada'
    expect(applyFilters(rows, miss)).toEqual([])
  })

  it('does not interpret the query as a pattern', () => {
    const odd = newFilters()
    odd.query = '.*'
    expect(applyFilters(rows, odd)).toEqual([])
    odd.query = '('
    expect(applyFilters(rows, odd)).toEqual([])
  })
})

describe('helpers', () => {
  it('counts by severity', () => {
    expect(countBySeverity(rows)).toEqual({ high: 1, suspicious: 1, info: 2 })
    expect(countBySeverity([])).toEqual({ high: 0, suspicious: 0, info: 0 })
  })

  it('lists each origin once, sorted', () => {
    expect(scannerOptions([...rows, f(9, 'info', 'mbr', 'X')])).toEqual(['mbr', 'minerador', 'persistencia', 'tarefas'])
  })

  it('lists only the removable rows', () => {
    expect(actionableIds(rows)).toEqual([0, 1])
  })
})
