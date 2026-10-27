# Oblivion

Utilitário de diagnóstico e limpeza de segurança, escrito em Rust, para Windows e Linux. Dois modos separados:

- **`scan`**: só leitura. Identifica o que existe e gera um relatório. Nada é alterado.
- **`clean`**: opt-in. Procura, **remove com a sua confirmação** e gera o relatório do que foi feito.
  Guarda tudo em quarentena e dá para desfazer (`undo`).

Os achados são indícios, não veredito. Nenhuma ferramenta detecta "qualquer malware".

## Interface gráfica

O Oblivion tem uma interface com um console que mostra o log da varredura ao vivo:
tema claro/escuro, português e inglês, filtros, confirmação antes de remover e histórico de quarentenas com
desfazer. A **versão aparece sempre** no cabeçalho e no rodapé (e `oblivion --version` no terminal).
Passos: **1. Escanear** (só leitura) → **2. Revisar** (filtros e seleção) → **3. Limpar** (simulação ou remoção
com confirmação) → **4. Histórico** (desfazer). Sem administrador, a tela avisa e oferece reiniciar como
administrador; a simulação funciona sem ele.

```bash
cd app
pnpm install
pnpm tauri dev       # abre a janela (desenvolvimento)
pnpm tauri build     # gera o instalador (NSIS)
pnpm test            # testes do frontend (Vitest)
```

Testes da interface: filtros, fluxo da tela, tradução (as chaves de pt-BR e en têm de ser iguais), **contraste
das cores** (WCAG AA em todos os pares de texto, nos dois temas) e **acessibilidade com o axe-core** (zero
violações nas quatro telas, nos dois idiomas e com o diálogo aberto). No backend há um teste **real** da
remoção, que só roda elevado e de propósito (ele cria itens de teste, remove, confere a quarentena, desfaz e limpa):

```bash
cargo test -p oblivion-app --lib -- --ignored real_clean   # em um terminal de administrador
```

A interface é Tauri 2 + Vue 3 + TypeScript + Tailwind, chama o mesmo núcleo Rust do CLI, não abre porta de rede
e manda ao backend só **números** de achados (o backend guarda os achados e resolve caminhos e comandos).
Não há atualização automática: foi retirada a pedido e fica para uma fase futura.

## O que ele verifica

| Área | O que olha | Se achar |
|---|---|---|
| Inicialização | chaves Run, pasta Startup, Winlogon, IFEO, AppInit, serviços, drivers, tarefas agendadas, WMI | remove (Run, Startup, tarefa, assinatura do WMI), **desativa** serviços comuns (`Start=4`, reversível) ou restaura o padrão (Winlogon); serviços essenciais do Windows e drivers só orientam |
| Processos | processos disfarçados de programas do Windows, assinatura digital, mineradores (CPU, GPU, rede) | encerra e move o executável |
| Padrões do Windows | BootExecute, shell do modo seguro, pacotes do LSA, extensões do Explorer (BHO), win.ini e system.ini | restaura o padrão onde há um seguro |
| Defesas | Defender, UAC, firewall, Gerenciador de Tarefas, Editor de Registro, atualizações, exclusões do Defender | restaura o padrão (as exclusões do Defender só orientam) |
| Rede | arquivo hosts, proxy, DNS fixo | comenta a linha do hosts, desliga o proxy; DNS é manual |
| Programas conhecidos | falsos antivírus e adware de uma lista curta e curada | orienta a desinstalar |
| Navegadores | extensões do Chromium e do Firefox | orienta remover (não é automático: o navegador regrava as preferências e pode reinstalar) |
| Atalhos | atalhos da Área de Trabalho e do menu Iniciar com comando de ataque ou que abrem sempre um endereço fixo no navegador | orienta corrigir o destino |
| Fluxos ocultos (ADS) | programas e scripts escondidos dentro de outros arquivos (NTFS) nas pastas onde malware se instala | orienta apagar o arquivo hospedeiro |
| Disco de boot | MBR | só avisa: não grava no disco de boot |
| Rootkits | processos que aparecem numa forma de listar e somem de outra; nomes ocultos no registro | avisa; **não detecta rootkits de kernel** |

Tudo o que muda o sistema guarda o valor antigo na quarentena (e exporta o trecho do registro em `.reg`),
pergunta antes e pode ser desfeito com `undo` ou pela tela **Histórico**.

**CLI e interface fazem o mesmo.** Em **Opções avançadas** da tela de varredura estão a lista de indicadores
(`--ioc`), os itens que você reconhece (`--allow`), a receita (`clean --recipe`) e os arquivos recentes (`recent`).
O motor é o mesmo código do núcleo, então o resultado é igual nos dois.

Formato da receita (uma linha por item; `#` comenta; nunca aceita caminho livre nem processos do Windows):

```text
valor: HKCU\Software\Microsoft\Windows\CurrentVersion\Run | NomeDoValor
inicializacao: atalho-suspeito.lnk
processo: programa.exe
```

**Como medir.** `cargo test -p oblivion-core --features bench --test detection_benchmark -- --ignored --nocapture`
cria itens falsos (persistência, processos, IOC, ADS) no seu usuário e mostra quantos a varredura achou, mais controles
que não podem virar alarme. O teste elevado `cargo test -p oblivion-app --lib -- --ignored real_service_wmi_and_hosts`
(terminal de administrador) cobre serviço, WMI e hosts. `tools/sandbox/` roda a medição dentro do Windows Sandbox.
Esses números medem os casos que o projeto conhece; **não** são uma taxa de detecção de malware real.

A base de indicadores embutida é **pequena e curada à mão** (`crates/core/data/`); o Oblivion não promete
reconhecer todo malware. `tools/refresh-iocs.ps1` atualiza a lista de hashes a partir do MalwareBazaar (abuse.ch,
CC0) usando a **sua** chave, lida da variável de ambiente `ABUSECH_AUTH_KEY` (nunca guarde a chave no repositório).

## Uso (linha de comando)

```bash
oblivion scan --html relatorio.html          # só leitura
oblivion clean --dry-run                     # mostra o que seria removido, sem mudar nada
oblivion clean                               # remove, perguntando item a item (administrador/root)
oblivion clean --only NOME --report r.html   # só os itens cujo nome/alvo contém NOME
oblivion clean --yes                         # dispensa a pergunta só para itens ALTOS e entradas órfãs
oblivion scan --ioc lista.txt --allow meus.txt   # com a sua lista de indicadores e de itens que você reconhece
oblivion clean --recipe receita.txt          # em vez de varrer, trata só o que a receita pede (sempre confirma)
oblivion recent --days 7                     # arquivos novos nas pastas onde malware se instala (só lista)
oblivion undo PASTA_DA_QUARENTENA            # devolve o que a limpeza removeu
oblivion restore-point                       # cria um ponto de restauração (Windows, administrador)
oblivion --help                              # mostra o uso
oblivion --version                           # mostra a versão
```

Durante o desenvolvimento: `cargo run -p oblivion -- scan`, `cargo test`.

### Como a remoção protege você

1. Só age em itens **SUSPEITO** ou **ALTO**. INFO nunca.
2. **Pergunta** antes de cada ação. `--yes` cobre só ALTO e entradas órfãs; os outros SUSPEITOS sempre perguntam.
   Para **processos**, o `--yes` só vale quando o motivo é o sinal forte (nome ou argumentos de minerador):
   CPU e GPU altas juntas também descrevem um editor de vídeo ou um jogo, e esses sempre perguntam.
3. **Ponto de restauração** antes de remover (Windows). Sem ele o Oblivion não remove nada, a menos que
   você use `--no-restore-point`. Um ponto criado nas últimas 24 h conta (o Windows só cria um por dia).
4. **Revalida** o item antes de agir: se o valor, a tarefa ou o processo mudou desde o scan, ele é ignorado.
5. **Quarentena reversível e privada**: o que foi apagado fica em `%ProgramData%\Oblivion\Quarantine\q<hora>`
   (Windows) ou `/var/lib/oblivion/quarantine` (Linux), com `manifest.json` e `report.html`. A pasta é criada
   **só para administradores/SYSTEM** (Windows: dono Administradores e permissões restritas; Linux: modo `0700`),
   porque em `ProgramData` usuários comuns conseguem criar pastas e um deles poderia trocar o manifesto ou usar
   uma junção para fazer o administrador gravar em outro lugar. Duas limpezas no mesmo segundo ganham pastas
   diferentes (`q…` e `q…-1`). Arquivos movidos ganham o sufixo `.quarantined` (e perdem a permissão de execução no Linux).
6. **`undo` desconfia do manifesto**: antes de ler, confere que a pasta (e a pasta pai) é privada, que não é
   link e que pertence a quem executa; só devolve arquivos que estão DENTRO da quarentena e nunca para uma pasta
   do sistema; só recria valores nas chaves Run e só mexe em valores de registro da **lista fixa** de reparos
   (a mesma que a limpeza usa); só recria tarefas e assinaturas do WMI a partir de arquivos da quarentena.
   Não sobrescreve o que é de outra pessoa: se um valor do registro ou o arquivo hosts foi alterado **depois** da
   correção do Oblivion, o `undo` recusa e explica.
7. **Só altera o que sabe desfazer**: remove valor `Run`, tarefa agendada, item da pasta Startup, assinatura do
   WMI e processo (e o executável dele, se estiver numa pasta do usuário como AppData ou Temp); **desativa**
   serviços comuns (`Start=4`); e **devolve ao padrão** um conjunto fixo de valores (UAC, políticas, Defender,
   firewall, proxy, Winlogon, BootExecute...) e comenta linhas suspeitas do hosts. Extensões de navegador, drivers,
   exclusões do Defender, DNS, serviços essenciais e MBR **não** são alterados sozinhos: o relatório diz o que fazer à mão.
8. Nunca move arquivo da pasta do Windows (ou `/usr`, `/etc`...), e nunca altera o MBR.
9. Se não conseguir gravar o registro do que fez, **para** (não age sem registro).

## Funcionalidade total exige administrador/root

O `scan` roda sem elevação, mas com cobertura reduzida: tarefas agendadas, setor de boot (MBR) e ponto de
restauração exigem **administrador** (Windows); crontabs de usuários, MBR e detalhes de rede de outros
usuários exigem **root** (Linux, use `sudo`). Sem elevação o programa avisa antes de varrer, repete um
lembrete no fim (stderr) e o relatório HTML abre com um alerta. O `clean` **exige** elevação (só o
`--dry-run` roda sem ela).

## Lista `--allow`

Arquivo de texto, um padrão por linha (`#` comenta). O padrão deve ser **igual** ao nome ou à linha de
comando inteira do achado (copie o "alvo" do relatório), sem diferenciar maiúsculas; um `*` no fim vale como
prefixo. Itens SUSPEITOS que casam passam a INFO; ALTOS nunca são escondidos. Casar por "contém" foi
descartado de propósito: um malware poderia escapar só citando o seu padrão como argumento.

## Licença

Oblivion é software livre, sob a **GNU General Public License v3.0 (somente)**; veja o arquivo [LICENSE](LICENSE).
Em resumo: você pode usar, estudar, modificar e redistribuir; quem distribuir uma versão modificada deve
mantê-la sob a mesma licença e fornecer o código-fonte. O programa vem **sem garantia** (texto da licença,
seções 15 e 16): uma ferramenta que remove itens do sistema deve ser usada com cuidado e com backup.
O código é original, escrito para este projeto.

## Verificações automáticas (CI)

O GitHub Actions (`.github/workflows/ci.yml`) roda a cada envio: tipos, build e testes da interface, `pnpm audit`,
`cargo fmt`, `clippy` com avisos como erro e os testes Rust no Windows (workspace inteiro) e no Linux (núcleo e CLI),
e `cargo audit`. O CI só tem permissão de leitura do código.

## Publicar uma versão


1. Aumente a versão nos três lugares (têm de ser iguais): `Cargo.toml` (`[workspace.package]`), `app/package.json`
   e `app/src-tauri/tauri.conf.json`.
2. Envie e crie a tag: `git tag v0.2.0 && git push origin v0.2.0`.
3. O workflow `.github/workflows/release.yml` confere a tag contra as versões, roda os testes, gera o instalador
   do Windows, o CLI do Windows e do Linux e o `SHA256SUMS.txt`, e cria um **rascunho** de release. Revise e publique
   pela página de Releases do GitHub; nada fica público sozinho.

Os arquivos saem **sem assinatura** por padrão (o Windows pode mostrar o aviso do SmartScreen). Se você cadastrar os
segredos `WINDOWS_CERT_PFX_BASE64` e `WINDOWS_CERT_PASSWORD` em Settings > Secrets and variables > Actions, o
workflow assina o instalador e o CLI do Windows; o certificado nunca entra em arquivo do repositório. A lista de hashes
(`crates/core/data/hashes.txt`) vai como estiver no repositório no momento da tag; atualize-a antes, na sua máquina.

## Estrutura (um domínio por pasta)

```text
crates/
  core/src/
    finding.rs, classify.rs, allow.rs, privilege.rs, restore.rs, sys.rs, trust.rs
    scanners/   persistence_win, persistence_linux, tasks_win, wmi_win, processes, miner, browser, firefox, mbr,
                baseline_win, tamper_win, network, known, shortcuts_win, ads_win, rootkit
    clean/      plano, execução, reparos (repair), WMI, quarentena e desfazer (remoção opt-in)
    ioc.rs, recipe.rs, recent.rs   lista de indicadores, receitas e arquivos recentes
    data/       known.txt (programas conhecidos) e hashes.txt (hashes)
    report/     text, html, clean (relatório do que foi feito)
  cli/src/      main.rs (comandos) e args.rs (leitura estrita dos argumentos)
app/
  src/          interface Vue (componentes, composables, i18n, API real e simulada)
  src-tauri/    backend Tauri (comandos que usam o núcleo)
```

## Convenções (de `D:\Apps\utility_project_guidelines.md`)

- Identificadores em inglês, comentários e textos exibidos em português (pt-BR).
  Em Rust os nomes seguem `snake_case`/`PascalCase` (exigência do compilador), não `camelCase`.
- Sem rede e sem telemetria. Dados do sistema são tratados como hostis: escapados no HTML e com
  caracteres de controle neutralizados no terminal (com teste).
- Relatório acessível: contraste AA, gravidade por texto (não só cor), foco visível, link para pular conteúdo.
- Sem promessas de segurança absoluta: o relatório diz que são indícios.

## Executável

`cargo build --release` gera o CLI em `target/release/oblivion.exe`; a interface sai com `pnpm tauri build`
(dentro de `app/`). Os binários **não ficam no repositório**: devem ir em "Releases" junto do SHA-256. Confira o
hash antes de usar; o executável **não é assinado digitalmente**, então o SmartScreen ou o antivírus podem alertar:

```bash
certutil -hashfile oblivion.exe SHA256   # compare com o hash publicado na release
```

## Limites conhecidos

- Programas legítimos **sem** assinatura digital em AppData/ProgramData ainda aparecem como SUSPEITO.
  A assinatura reduz falso positivo, mas não prova inocência: malware também pode ser assinado.
- Não varre todos os arquivos por assinatura/hash/YARA: não é um antivírus. A lista de hashes (`--ioc` e a embutida)
  só confere os programas em execução e os executáveis citados pelos achados.
- A detecção de elevação é um teste prático (Windows: abrir o disco cru para leitura; Linux: dono do
  processo é o root), não a leitura do token de elevação.
- Atalhos `.lnk` da pasta Startup têm o destino resolvido; se a resolução falhar, classifica só pelo nome.
- Um endereço de rede (`http://`, `https://`) sozinho na linha de comando é SUSPEITO (comum em atalhos de
  aplicativos web); só vira ALTO junto de `powershell`, `certutil`, `bitsadmin`, `regsvr32`, `curl`, etc.
- "Entrada órfã" (arquivo sumiu) só é julgada se a unidade existe agora: unidades de rede mapeadas na sessão
  normal (que o terminal elevado não enxerga) e pendrives desconectados não contam, e caminhos de rede (`\\servidor`) não são julgados.
- Persistência no Windows, além de Run/RunOnce, Winlogon (do computador e do usuário), Startup, serviços e tarefas:
  `Policies\Explorer\Run`, `ServiceDll` dos serviços `svchost`, drivers de terceiros que iniciam com o Windows,
  `Image File Execution Options` (`Debugger`), `AppInit_DLLs`, tarefas do tipo `ComHandler` (a DLL da classe COM
  é resolvida pelo registro) e as chaves Run das **outras contas com perfil carregado** (só com administrador;
  perfis de contas desligadas não são lidos). Ainda não cobre: drivers do próprio Windows, WMI de outros
  namespaces e a substituição de um arquivo do sistema por outro sem assinatura (não há verificação de hash).
- `ServiceDll` e drivers entram como INFO (centenas de linhas); só viram SUSPEITOS quando saem das pastas
  padrão ou o arquivo sumiu. IFEO e AppInit_DLLs com qualquer valor são pelo menos SUSPEITOS.
- **Remoção no Linux**: por enquanto só encerra processos (e move o executável). Cron, units do systemd e
  autostart são identificados mas ficam como instrução manual.
- **Remoção no Windows**: não cobre extensões, drivers, exclusões do Defender, DNS, ADS, atalhos nem MBR (instrução
  manual). Serviços e WMI são tratados, mas essa parte **só foi testada em simulação e por testes automáticos**: o teste
  elevado `real_service_wmi_and_hosts` existe, porém ainda não foi rodado de verdade.
- **Ransomware**: o Oblivion **não detecta nem decifra ransomware**. Só reconhece um comando que apaga cópias de
  sombra e, se o programa estiver numa pasta suspeita ou persistir por Run/tarefa/serviço/WMI, pode removê-lo.
  Arquivos já criptografados não são recuperados.
- O scan roda os scanners **em paralelo** (cerca de 6 s; o do minerador sozinho mede a CPU por 4 s). Se um
  scanner quebrar por erro interno, o relatório mostra "Scanner ... falhou" em vez de omitir essa parte.
- Minerador: sinais Sinais: nome/argumentos, CPU sustentada, GPU em
  computação e conexão a portas de pools; um sinal fraco é SUSPEITO, dois ou mais são ALTO. A GPU é uma
  amostra única (Windows: contadores do sistema; Linux: `nvidia-smi`, só NVIDIA) e nunca foi testada com
  placa real. Mineradores renomeados, sem argumentos típicos e de baixo uso passam despercebidos.
- Extensões: Chromium (Chrome, Edge, Brave, Vivaldi, Opera) e Firefox, só do usuário atual. A heurística
  olha as permissões; não verifica a loja nem o código. Só `proxy`/`debugger` com acesso a todos os sites
  vira SUSPEITO. A isenção `...Private` vale só para IDs de componentes embutidos conhecidos (hoje: Opera AI).
- WMI: só consumidores de comando e de script (sempre SUSPEITO); filtros e vínculos isolados são ignorados.
- MBR: só o INÍCIO do código de boot é comparado (Windows/DOS e GRUB); código desconhecido é SUSPEITO, o
  que não prova bootkit. Em disco GPT o código é ignorado em boot UEFI, e o Oblivion ainda não detecta se o
  PC inicia em UEFI ou BIOS legado.
- Linux: verificado num container Debian; não testado em outras distros. Rede do minerador usa `ss`
  (instale `iproute2`; sem root só vê os processos do próprio usuário).
