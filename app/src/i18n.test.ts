import { describe, expect, it } from 'vitest'

import { messages } from './i18n'

/** Todas as chaves de uma árvore de mensagens, como `a.b.c`. */
function keys(obj: Record<string, unknown>, prefix = ''): string[] {
  return Object.entries(obj).flatMap(([k, v]) =>
    typeof v === 'object' && v !== null ? keys(v as Record<string, unknown>, `${prefix}${k}.`) : [`${prefix}${k}`],
  )
}

describe('i18n', () => {
  it('has exactly the same keys in pt-BR and en', () => {
    expect(keys(messages.en).sort()).toEqual(keys(messages['pt-BR']).sort())
  })

  it('has no empty message', () => {
    for (const [locale, tree] of Object.entries(messages)) {
      const flat = keys(tree)
      expect(flat.length).toBeGreaterThan(50)
      const get = (path: string) => path.split('.').reduce<unknown>((o, k) => (o as Record<string, unknown>)[k], tree)
      for (const key of flat) expect(String(get(key)).trim(), `${locale}:${key}`).not.toBe('')
    }
  })

  it('keeps the same placeholders in both languages', () => {
    const placeholders = (s: string) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort()
    const get = (tree: Record<string, unknown>, path: string) =>
      path.split('.').reduce<unknown>((o, k) => (o as Record<string, unknown>)[k], tree) as string
    for (const key of keys(messages['pt-BR'])) {
      expect(placeholders(get(messages.en, key)), key).toEqual(placeholders(get(messages['pt-BR'], key)))
    }
  })
})
