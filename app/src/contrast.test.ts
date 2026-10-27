import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

/** Lê as cores `--nome: #hex;` de um bloco do CSS (o tema claro é `:root {`, o escuro `:root[data-theme='dark'] {`). */
function tokens(css: string, selector: string): Record<string, string> {
  const start = css.indexOf(`${selector} {`)
  if (start < 0) throw new Error(`bloco não encontrado: ${selector}`)
  const block = css.slice(start, css.indexOf('}', start))
  const out: Record<string, string> = {}
  for (const m of block.matchAll(/--([\w-]+):\s*(#[0-9a-fA-F]{6})\s*;/g)) out[m[1]!] = m[2]!
  return out
}

function luminance(hex: string): number {
  const channel = (i: number) => {
    const v = parseInt(hex.slice(1 + i * 2, 3 + i * 2), 16) / 255
    return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4
  }
  return 0.2126 * channel(0) + 0.7152 * channel(1) + 0.0722 * channel(2)
}

export function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number]
  return (hi + 0.05) / (lo + 0.05)
}

const css = readFileSync(resolve(process.cwd(), 'src', 'style.css'), 'utf8')
const themes = {
  claro: tokens(css, ':root'),
  // O escuro só redefine parte dos tokens; o resto (como as cores do console) vem do claro.
  escuro: { ...tokens(css, ':root'), ...tokens(css, ":root[data-theme='dark']") },
}

// [texto, fundo]: pares que a interface realmente usa. WCAG 2.1 AA: 4,5:1 para texto comum.
const pairs: [string, string][] = [
  ['fg', 'bg'], ['fg', 'card'], ['fg', 'info-bg'],
  ['muted', 'bg'], ['muted', 'card'], ['muted', 'info-bg'],
  ['primary-fg', 'primary'],
  ['high', 'high-bg'], ['high', 'card'], ['high', 'bg'], ['high-fg', 'high'],
  ['susp', 'susp-bg'], ['susp', 'card'], ['susp', 'bg'],
  ['info', 'info-bg'], ['info', 'card'],
  ['ok', 'ok-bg'], ['ok', 'card'], ['ok', 'bg'],
  ['console-fg', 'console'], ['console-dim', 'console'], ['console-dim', 'console-bar'],
]

describe('contraste das cores (WCAG AA, 4,5:1)', () => {
  for (const [theme, t] of Object.entries(themes)) {
    it(`tema ${theme}: todos os pares de texto passam`, () => {
      const failures = pairs
        .map(([fg, bg]) => ({ fg, bg, ratio: t[fg] && t[bg] ? contrast(t[fg], t[bg]) : NaN }))
        .filter((p) => !(p.ratio >= 4.5))
        .map((p) => `${p.fg} sobre ${p.bg}: ${Number.isNaN(p.ratio) ? 'cor não definida' : p.ratio.toFixed(2)}`)
      expect(failures, failures.join('\n')).toEqual([])
    })
  }

  it('calcula a razão de contraste corretamente (preto sobre branco = 21)', () => {
    expect(contrast('#000000', '#ffffff')).toBeCloseTo(21, 1)
    expect(contrast('#777777', '#777777')).toBeCloseTo(1, 5)
  })
})
