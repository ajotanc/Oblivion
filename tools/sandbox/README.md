# Medição no Windows Sandbox

Roda a medição de detecção (`crates/core/tests/detection_benchmark.rs`) e uma varredura dentro do **Windows
Sandbox**, um Windows descartável: ao fechar a janela, tudo o que foi criado some. Os itens de teste e qualquer
reparo real não tocam no seu PC.

**Segurança da configuração:** a pasta compartilhada é somente leitura, a rede fica desligada e a GPU virtual
também. Nada do Sandbox consegue alterar o seu disco.

## Requisitos

- Windows 10/11 **Pro, Enterprise ou Education** (a edição Home não tem o Sandbox).
- Recurso ligado em *Ativar ou desativar recursos do Windows → Windows Sandbox*, e virtualização ativa na BIOS.

## Passo a passo

0. Se o projeto não está em `D:\Apps\Oblivion`, troque o caminho em `HostFolder` dentro de `oblivion-bench.wsb`.
1. Na raiz do projeto: `.\tools\sandbox\prepare.ps1` (compila e copia os executáveis para `target\sandbox`).
2. Dê dois cliques em `tools\sandbox\oblivion-bench.wsb`.
3. O Sandbox abre, roda o benchmark e a varredura e mostra o resultado. O texto também fica em
   `resultado.txt` na Área de Trabalho do Sandbox (copie para fora antes de fechar, se quiser guardar).

> Os arquivos desta pasta nunca foram executados pelo assistente que os escreveu: o Windows Sandbox não está
> verificado nesta máquina. Se o `.wsb` não abrir, confira os requisitos acima.

## O que isto mede e o que não mede

Mede os mesmos casos do benchmark (persistência e processos falsos, IOC, ADS). Como roda como administrador
dentro do Sandbox, também dá para rodar lá o teste elevado de serviço, WMI e hosts:

```text
cargo test -p oblivion-app --lib -- --ignored real_service_wmi_and_hosts
```

(exige Rust instalado no Sandbox; é mais simples rodar esse teste direto no seu PC, num terminal de administrador,
porque ele desfaz tudo sozinho.)

Amostras de malware **reais** não fazem parte deste kit, de propósito. Se quiser medir contra elas, faça isso só
em uma máquina virtual isolada e descartável, nunca no seu PC.
