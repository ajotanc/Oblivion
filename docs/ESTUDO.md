# Mapa de estudo: ComboFix -> Oblivion

O ComboFix (extraído em `_research/combofix_extracted/$0`) é um instalador NSIS que reúne scripts
`.bat/.cmd/.vbs`, ferramentas de terceiros renomeadas `.3XE` e arquivos de dados. Foi escrito para XP, Vista, 7 e 8.

| ComboFix | O que faz | Oblivion |
|---|---|---|
| `Combobatch.bat` | Entrada: checa privilégio, define ambiente | `cli/src/main.rs` |
| `restore_pt.vbs` | Ponto de restauração via WMI (`SystemRestore`) | pendente, antes de qualquer remoção |
| `RegScan.cmd`, `SuppScan.cmd` + `swreg`, `swsc` | Varre registro e serviços | `scanners/persistence_win.rs` |
| `svc_wht.dat`, `MDWht.dat` | Listas de permissão (o que é legítimo) | pendente (arquivo de dados) |
| `rogues.dat`, `srizbi.md5`, `badclsid.c` | Listas de ameaças conhecidas | pendente (arquivo de dados) |
| `*.cfx` | Pastas e arquivos suspeitos por perfil de usuário | pendente |
| `CF-Script.cmd` | Interpreta o "CFScript" colado pelo usuário | fora de escopo (modo só leitura) |
| `mbr.3XE`, `rmbr.3XE`, `Boot-Rk.cmd` | Setor de boot e rootkits | pendente |
| `catchme.3XE` | Anti-rootkit | pendente |
| `Kill-All.cmd` | Encerra processos (poupando os do sistema) | fora de escopo (só leitura) |

## Roteiro de leitura sugerido

1. `crates/core/src/finding.rs`: o modelo.
2. `crates/core/src/classify.rs`: como decidir a gravidade (e os testes no fim do arquivo).
3. `crates/core/src/scanners/persistence_win.rs`: de onde vêm os dados (um bloco por técnica).
4. `crates/core/src/report/html.rs`: como o relatório é montado e por que tudo é escapado.

## Para ir além

- Comparar `svc_wht.dat` com os serviços desta máquina e criar a lista de permissão do Oblivion.
- Ler `restore_pt.vbs` e reimplementar em Rust (API de Restauração do Sistema).
- Adicionar o scanner de tarefas agendadas (`C:\Windows\System32\Tasks`, XML).
