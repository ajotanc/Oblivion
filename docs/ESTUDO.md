# Fontes de referência

A cobertura de persistência do Oblivion segue listas públicas e abertas:

- Autoruns (Sysinternals): https://learn.microsoft.com/sysinternals/downloads/autoruns
- MITRE ATT&CK, persistência: T1546 (eventos), T1547 (inicialização/logon), T1037 (scripts de logon),
  T1053 (tarefas), T1543 (serviços), T1112 (registro). https://attack.mitre.org/tactics/TA0003/
- Regras Sigma (detecção em registro): https://github.com/SigmaHQ/sigma
- LOLBAS (programas do Windows abusados): https://lolbas-project.github.io/

## Cobertura

Em `crates/core/src/scanners/`:

- `persistence_win.rs`: Run/RunOnce (inclusive WOW64 e outras contas), Policies\Explorer\Run, Winlogon, pasta
  Startup, serviços e drivers, IFEO, AppInit_DLLs.
- `tasks_win.rs`: tarefas agendadas (XML, inclusive `ComHandler`).
- `wmi_win.rs`: consumidores de evento do WMI.
- `baseline_win.rs`: BootExecute, shell do modo seguro, LSA, BHO, ShellExecuteHooks, win.ini/system.ini,
  AppCertDLLs, AutoRun do cmd.exe, UserInitMprLogonScript, protetor de tela, provedores de hora, monitores de
  impressão, ajudantes do netsh, Active Setup, SilentProcessExit, classes COM do usuário, suplementos do
  Office e catálogos do Winsock.

Ainda não cobertos: Appx/MSIX de inicialização, extensões de shell (`ContextMenuHandlers`) e pastas de
inicialização de políticas de grupo.

## Roteiro de leitura

1. `crates/core/src/finding.rs`: o modelo.
2. `crates/core/src/classify.rs`: como decidir a gravidade (e os testes no fim do arquivo).
3. `crates/core/src/scanners/persistence_win.rs`: de onde vêm os dados (um bloco por técnica).
4. `crates/core/src/report/html.rs`: como o relatório é montado e por que tudo é escapado.
