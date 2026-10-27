import type { Api } from './index'
import type { CleanResult, Finding, ScanResult } from '../types'

/** Dados simulados, usados só quando a tela abre fora do app (pré-visualização no navegador e testes). */
type Sample = Omit<Finding, 'id' | 'weakSignal'> & { weakSignal?: boolean }
const sample: Sample[] = [
  { severity: 'high', scanner: 'minerador', name: 'editor-de-video.exe', location: 'PID 777 | RAM 2048 MB', target: 'C:\\Users\\Demo\\AppData\\Local\\Editor\\editor-de-video.exe --render', reason: 'Mais de um sinal de mineração ao mesmo tempo', action: 'Encerrar o processo 777 e mover o executável para a quarentena (se estiver numa pasta do usuário)', actionable: true, weakSignal: true },
  { severity: 'high', scanner: 'minerador', name: 'xmrig.exe', location: 'PID 4242 | RAM 310 MB', target: 'C:\\Users\\Demo\\AppData\\Local\\Temp\\xmrig.exe -o stratum+tcp://pool.example:3333', reason: 'Nome ou linha de comando típicos de minerador', action: 'Encerrar o processo 4242 e mover o executável para a quarentena (se estiver numa pasta do usuário)', actionable: true },
  { severity: 'high', scanner: 'persistencia', name: 'Updater', location: 'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', target: 'powershell.exe -nop -enc SQBFAFgA', reason: 'PowerShell com comando codificado', action: 'Apagar o valor "Updater" de HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run (o valor fica guardado na quarentena)', actionable: true },
  { severity: 'suspicious', scanner: 'tarefas', name: 'Vendor\\SyncHelper', location: 'Agendador de Tarefas', target: 'C:\\ProgramData\\Vendor\\sync.vbs', reason: 'Arquivo de script', action: 'Apagar a tarefa agendada "Vendor\\SyncHelper" (o XML fica guardado na quarentena)', actionable: true },
  { severity: 'suspicious', scanner: 'persistencia', name: 'OldTool', location: 'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', target: 'C:\\Programs\\OldTool\\tool.exe', reason: 'O arquivo não existe mais (entrada órfã, sobra de programa removido)', action: 'Apagar o valor "OldTool" de HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run (o valor fica guardado na quarentena)', actionable: true },
  { severity: 'suspicious', scanner: 'extensoes', name: 'VPN Rápida', location: 'Chrome (Default)', target: 'id abcdefghijklmnop v3.1 | permissões: proxy | sites: <all_urls>', reason: 'Pode interceptar o tráfego ou controlar páginas (proxy/debugger) em todos os sites', action: 'Remova a extensão pelo próprio navegador (menu de extensões).', actionable: false },
  // Texto hostil de propósito: a tela precisa mostrá-lo como TEXTO, nunca interpretá-lo.
  { severity: 'suspicious', scanner: 'persistencia', name: '<img src=x onerror=alert(1)> fatura?fdp.exe', location: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', target: '"><script>alert(1)</script>', reason: 'Fora das pastas padrão do sistema (AppData)', action: null, actionable: false },
  { severity: 'info', scanner: 'mbr', name: 'Setor de boot (MBR)', location: '\\\\.\\PhysicalDrive0', target: 'início do código: 00 00 00 | tipos de partição: EE 00 00 00', reason: 'Disco GPT (MBR protetor): o código de boot é ignorado em boot UEFI; confirme que o PC inicia em UEFI', action: null, actionable: false },
  { severity: 'info', scanner: 'persistencia', name: 'wuauserv (ServiceDll)', location: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\wuauserv\\Parameters', target: '%SystemRoot%\\system32\\wuaueng.dll', reason: 'Sem padrão suspeito conhecido', action: null, actionable: false },
]

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms))
const labels = ['Extensões do Chromium', 'Extensões do Firefox', 'Setor de boot (MBR)', 'Mineradores (CPU, GPU e rede)', 'Persistência, serviços e tarefas agendadas', 'WMI']

export function mockApi(): Api {
  let findings: Finding[] = []
  return {
    appInfo: async () => ({
      version: '0.1.0-prévia',
      elevated: false,
      platform: 'windows',
      alert: 'ATENÇÃO: o Oblivion está rodando SEM privilégios de administrador, então o resultado ficará incompleto.',
    }),
    async runScan(onProgress, options = {}): Promise<ScanResult> {
      for (const label of labels) onProgress({ kind: 'started', label, count: 0 })
      for (const label of labels) {
        await wait(350)
        onProgress({ kind: 'finished', label, count: label.startsWith('Persist') ? 5 : 1 })
      }
      findings = sample.map((f, id) => ({ weakSignal: false, ...f, id }))
      const notes = options.ioc ? ["1 linha(s) da lista de indicadores foram ignoradas (formato inválido)."] : []
      return { findings, notes }
    },
    async loadRecipe(text): Promise<ScanResult> {
      await wait(150)
      findings = sample.slice(0, 2).map((f, id) => ({ weakSignal: false, ...f, id }))
      return { findings, notes: text.includes("apagar") ? ["linha 1: tipo desconhecido: apagar"] : [] }
    },
    recentFiles: async (days) => [{ name: `novo-programa.exe (há ${days} h)`, path: "C:\\Users\\Demo\\AppData\\Local\\Temp\\novo-programa.exe" }],
    async runClean(ids, dryRun): Promise<CleanResult> {
      await wait(500)
      const chosen = findings.filter((f) => ids.includes(f.id) && f.actionable)
      return {
        dryRun,
        restore: dryRun ? 'não necessário (simulação)' : 'Já existe um ponto de restauração das últimas 24 h (o Windows não cria outro); ele serve de proteção.',
        quarantineDir: dryRun ? null : 'C:\\ProgramData\\Oblivion\\Quarantine\\q1793110000',
        aborted: null,
        records: chosen.map((f) => ({
          name: f.name,
          severity: f.severity,
          target: f.target,
          action: f.action ?? '',
          outcome: dryRun ? 'dryRun' : 'done',
          outcomeLabel: dryRun ? 'simulado' : 'feito',
          note: dryRun ? '' : 'Guardado na quarentena.',
        })),
      }
    },
    listQuarantines: async () => [{ name: 'q1793110000', path: 'C:\\ProgramData\\Oblivion\\Quarantine\\q1793110000', items: 3, done: 3 }],
    undoQuarantine: async () => [{ description: 'Recriar o valor "Updater" em HKCU\\...\\Run', ok: true, error: null }],
    exportReport: async () => 'C:\\Users\\Demo\\Documents\\Oblivion\\relatorio-1793110000.html',
    restartAsAdmin: async () => {},
  }
}
