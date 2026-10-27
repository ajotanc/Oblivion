# 🛡️ Oblivion

**Documento do projeto. Segue o `D:\Apps\utility_project_guidelines.md`.**

Utilitário de diagnóstico e limpeza de segurança para Windows e Linux, sucessor moderno do ComboFix,
descontinuado. Escrito em Rust, executável local, sem rede e sem telemetria.

## 🎯 Objetivo

1. **Identificar** (`scan`, só leitura): o que inicia sozinho no sistema, mineradores de criptomoeda
   (CPU, GPU, rede), extensões de navegador, WMI e o setor de boot.
2. **Remover** (`clean`, opt-in): com a confirmação do usuário, ponto de restauração antes, quarentena
   reversível (`undo`) e relatório do que foi feito.
3. Servir de material de estudo: o código é pequeno, legível e documentado em português.

**Não é** antivírus nem garante um sistema limpo. Os achados são indícios para análise.

## 📍 Estado atual

| Módulo | Estado |
|---|---|
| Modelo (`Finding`, `Severity`), classificador por padrões (Windows e Linux) | pronto, com testes |
| Persistência Windows: Run/RunOnce, Winlogon (caminho exato), pasta Startup (`.lnk` resolvido), serviços | pronto |
| Tarefas agendadas (XML; só o `<Enabled>` de `<Settings>` vale) | pronto; sem administrador mostra "NÃO verificadas" |
| WMI (consumidores de comando e de script) | pronto; 0 consumidores nesta máquina |
| Extensões Chromium e Firefox | pronto; isenção `...Private` só para IDs embutidos conhecidos |
| MBR (assinatura 55AA, tabela, início do código, GPT protetor) | pronto; exige administrador/root |
| Persistência Linux (systemd, cron, autostart, `ld.so.preload`) | pronto; verificado em container Debian |
| Minerador: nome/argumentos, CPU, GPU, rede (Windows e Linux) | pronto; GPU real nunca testada |
| Confiança por assinatura digital, scripts em System32, entradas órfãs, lista `--allow` (igualdade exata) | pronto |
| Aviso de privilégios (terminal e alerta no HTML) | pronto; verificado nos dois sistemas |
| Relatório HTML com busca e filtros; terminal com caracteres de controle neutralizados | pronto |
| Ponto de restauração (aceita um ponto recente como proteção) | pronto |
| **Remoção** (`clean`): valor Run, tarefa agendada, item Startup, processo + executável | pronto; verificado de ponta a ponta no Windows (UAC) e no Linux (container) |
| **Desfazer** (`undo`) a partir do `manifest.json` da quarentena | pronto; verificado nos dois sistemas |
| Relatório do que foi feito (terminal, HTML, e `report.html` dentro da quarentena) | pronto |
| Leitura estrita dos argumentos (opção desconhecida = erro) | pronto, com testes |
| Executável de release (`dist/oblivion.exe` + `SHA256SUMS.txt`) | pronto; sem assinatura digital |
| Quarentena privada (admin/root), `undo` que não obedece manifesto adulterado, nomes únicos por execução | pronto; verificado no Windows (permissões lidas por SID) e no Linux (modo 700) |
| `--yes` seguro: processos só por sinal forte; URL sozinha é SUSPEITO; órfã só com a unidade presente; ancestrais não são marcados como minerador | pronto, com testes |
| Testes repetíveis da remoção (valor Run em HKCU temporário, atalho Startup, processo filho, undo) | pronto; rodam sem administrador |
| Scan em paralelo; scanner que quebra vira aviso "falhou", nunca some | pronto, com testes; ~6 s (antes ~12 s) |
| Mais persistência: Policies Run, Winlogon do usuário, IFEO, AppInit_DLLs, ServiceDll, drivers de terceiros, tarefas COM, contas com perfil carregado | pronto, com testes; verificado em scan real (IFEO plantado foi achado) |
| Testes | 289 no núcleo (Windows), 202 no Linux e 28 no frontend; clippy `-D warnings` limpo; CI passou no GitHub (antes desta rodada) |
| Remoção no Linux de cron, systemd e autostart | pendente (hoje: instrução manual) |
| Serviço (desativar), WMI (remover), Winlogon e valores fixos (restaurar ao padrão), hosts (comentar linha) | pronto com desfazer; **só testado em simulação e por testes automáticos**: falta rodar o teste elevado `real_service_wmi_and_hosts` |
| Extensão de navegador, driver, exclusões do Defender, DNS e MBR | por decisão, manual |
| Novos scanners: processos, rede, defesas, padrões do Windows, programas conhecidos, atalhos, ADS, visão cruzada de rootkit | pronto, com testes; sem falso positivo no scan desta máquina |
| Medição de detecção (`--features bench`): 20 casos, 100%, 0 falso positivo nos controles | mede só casos que o projeto já conhece |
| Ransomware | só **rastros** (bilhete de resgate, extensão incomum em massa); não decifra nem vê a criptografia acontecendo; benchmark simula e acha |
| Explicações simples, "recomendado", `clean --recommended` e botão da interface | pronto, com testes |
| Revisão de segurança do código novo (feita pelo próprio autor, **não independente**) | hosts em bytes, `undo` só desfaz se o valor não mudou e com tipo conferido; falta revisão por outra pessoa/ferramenta |
| Interface gráfica (Tauri 2 + Vue 3): console ao vivo, filtros, confirmação, histórico/desfazer, tema claro/escuro, pt-BR e en, versão sempre visível | pronta (v0.1); janela real abre e fecha limpa; 18 testes de frontend; a remoção pela tela só foi verificada pela lógica (o backend usa o mesmo núcleo do CLI) e no navegador com dados simulados |
| Teste REAL da remoção pelo backend da interface (valor Run + processo; simulação, remoção, quarentena em ProgramData, listagem, desfazer, limpeza) | passou elevado (UAC); nada sobrou no sistema |
| Contraste (WCAG AA, 2 temas) e acessibilidade (axe: 4 telas, 2 idiomas, diálogo) automatizados | prontos; o contraste achou um botão vermelho sem token de texto no tema escuro (corrigido) |
| `pnpm audit` e CI no GitHub (Windows, Linux, frontend, cargo audit) | `pnpm audit` limpo; CI passou no GitHub; release automática por tag (rascunho) |
| Atualização automática | retirada a pedido; fica para uma fase futura (precisa de onde publicar e de chave de assinatura) |

## 🛠️ Stack

* Rust (edição 2024), workspace do Cargo. Dependências: `winreg` (Windows), `sysinfo`, `serde_json`.
* PowerShell só como ferramenta de apoio no Windows (assinatura, GPU, WMI, ponto de restauração), sempre
  por um helper único com tempo-limite, UTF-8 e verificação do código de saída (`sys.rs`).

## 📂 Estrutura

```text
D:\Apps\Oblivion\
├── Cargo.toml
├── crates/
│   ├── core/src/
│   │   ├── finding.rs, classify.rs, allow.rs, privilege.rs, restore.rs, sys.rs, trust.rs
│   │   ├── scanners/    persistence_win, persistence_linux, tasks_win, wmi_win, miner, browser, firefox, mbr
│   │   ├── clean/       mod.rs (plano e decisão), exec.rs (ações), undo.rs
│   │   └── report/      text, html, clean
│   └── cli/src/         main.rs, args.rs
├── app/                 # interface: src/ (Vue) e src-tauri/ (backend Tauri)
├── docs/ESTUDO.md
├── README.md
├── oblivion_project.md  # este arquivo
├── dist/                # executável de release e hash
└── _research/           # amostra do ComboFix e arquivos extraídos (não executar)
```

## ▶️ Comandos

```bash
cargo test                                            # testes
cargo fmt && cargo clippy --all-targets -- -D warnings
cargo build --release                                 # target/release/oblivion.exe
oblivion scan --html relatorio.html                   # só leitura
oblivion clean --dry-run                              # simulação
oblivion clean --only NOME --yes --report r.html      # remove (administrador/root)
oblivion undo PASTA_DA_QUARENTENA
```

## 🔐 Regras específicas do Oblivion

* **`scan` é só leitura.** Remoção só acontece em `clean`, nunca como efeito colateral.
* **Dado do sistema é hostil**: escapado no HTML, caracteres de controle trocados por `?` no terminal,
  tamanhos limitados ao ler arquivos, nomes validados antes de virarem comando ou caminho.
* **Nunca confiar em texto que o dono do item escreve** para rebaixar a gravidade (ex.: permissão
  `...Private` num manifest; argumento que cita o caminho da lista `--allow`).
* **Remoção**: só itens SUSPEITO/ALTO; pergunta item a item (`--yes` só para ALTO e órfãs); ponto de
  restauração antes; revalida o item; guarda antes de apagar; para se não conseguir gravar o registro;
  nunca mexe na pasta do Windows nem no MBR; só remove o que sabe desfazer.
* **Falhar de forma segura**: comando auxiliar que falha vira aviso ("NÃO verificado"), nunca "limpo".
* **Sem promessa de "detectar tudo"**: o que o Oblivion não cobre está no README.

## 🧪 Material de pesquisa (`_research/`)

* `combofix_dl/ComboFix.exe`: baixado do BleepingComputer (5.659.583 bytes, SHA-256
  `23EA3C510C9B0D48047A4B236A82A7FDBED3BD58C1B3EECF82729EF1C849D421`). Instalador NSIS com UPX, 32 bits.
* `combofix_extracted/`: 226 arquivos extraídos com 7-Zip (scripts, utilitários `.3XE`, listas).
* **Nunca executar** nada daqui. Não incluir no pacote de entrega nem em repositório.

## ✅ Checklist de entrega

* [x] `cargo test` e `cargo clippy -- -D warnings` sem falhas, no Windows e no Linux (container).
* [x] Execução real em modo só leitura e, para a remoção, teste de ponta a ponta com itens de teste.
* [x] `cargo audit`: 0 vulnerabilidades (2 avisos, só na pilha Linux do Tauri: glib e proc-macro-error).
* [x] Auditoria de ponta a ponta feita duas vezes; os itens críticos e recomendados foram corrigidos e testados.
* [ ] Assinar o executável (Authenticode) quando houver certificado.
* [x] SHA-256 do binário publicado; texto sem promessa absoluta de segurança.

## 🗺️ Próximos passos

1. Rodar o teste elevado (`cargo test -p oblivion-app --lib -- --ignored real_service_wmi_and_hosts`, terminal de administrador).
2. Ransomware: arquivos-isca para avisar durante a criptografia (hoje só há rastros depois). Decifrar fica fora de alcance.
3. Ampliar a base de conhecimento (`known.txt`, `hashes.txt` via `tools/refresh-iocs.ps1`).
4. Medir de verdade em uma VM isolada (kit em `tools/sandbox/`, nunca testado) e ampliar o benchmark.
5. Remoção de cron, systemd e autostart no Linux, com o mesmo contrato (quarentena, undo, relatório).
6. Assinar o executável (precisa de certificado) e atualização automática opt-in (precisa de onde publicar).
7. Detectar UEFI/BIOS legado para julgar o MBR de discos GPT; GPU AMD/Intel no Linux.