<#
  Prepara a pasta que o Windows Sandbox vai enxergar (target\sandbox): o executável do benchmark de detecção
  e o script que roda lá dentro. Não altera nada fora da pasta target.

  Uso (na raiz do projeto):  .\tools\sandbox\prepare.ps1
  Depois abra tools\sandbox\oblivion-bench.wsb.
#>
# Continue: o cargo escreve o andamento no stderr e o PowerShell 5.1 não pode tratar isso como erro; os códigos de saída são conferidos abaixo.
$ErrorActionPreference = 'Continue'
$root = Resolve-Path (Join-Path $PSScriptRoot '..\..')
Set-Location $root
$out = Join-Path $root 'target\sandbox'
New-Item -ItemType Directory -Force $out | Out-Null

# Compila o benchmark e o aplicativo de linha de comando (sem executar nada aqui).
# O cargo escreve o andamento no stderr; no PowerShell 5.1 isso não pode virar erro, então confere o código de saída.
$json = cargo test -p oblivion-core --features bench --test detection_benchmark --no-run --message-format=json 2>$null
if ($LASTEXITCODE -ne 0) { throw 'Falhou ao compilar o benchmark.' }
$exe = $json | ForEach-Object { try { $_ | ConvertFrom-Json } catch {} } |
    Where-Object { $_.reason -eq 'compiler-artifact' -and $_.target.name -eq 'detection_benchmark' -and $_.executable } |
    Select-Object -Last 1 -ExpandProperty executable
if (-not $exe) { throw 'Não encontrei o executável do benchmark.' }
Copy-Item $exe (Join-Path $out 'detection_benchmark.exe') -Force
cargo build --release -p oblivion 2>$null
if ($LASTEXITCODE -ne 0) { throw 'Falhou ao compilar o oblivion.' }
Copy-Item (Join-Path $root 'target\release\oblivion.exe') (Join-Path $out 'oblivion.exe') -Force

@'
# Roda DENTRO do Windows Sandbox.
$ErrorActionPreference = 'Continue'
Set-Location C:\Oblivion
"=== Medição de detecção (Sandbox) ===" | Tee-Object C:\Users\WDAGUtilityAccount\Desktop\resultado.txt
.\detection_benchmark.exe --ignored --nocapture 2>&1 | Tee-Object -Append C:\Users\WDAGUtilityAccount\Desktop\resultado.txt
"`n=== Varredura do Oblivion ===" | Tee-Object -Append C:\Users\WDAGUtilityAccount\Desktop\resultado.txt
.\oblivion.exe scan 2>&1 | Tee-Object -Append C:\Users\WDAGUtilityAccount\Desktop\resultado.txt
"`nPronto. O resultado está em resultado.txt na Área de Trabalho do Sandbox. Feche a janela para descartar tudo." | Write-Host
Read-Host 'Enter para fechar'
'@ | Set-Content -Path (Join-Path $out 'run-in-sandbox.ps1') -Encoding UTF8

"Pronto: $out. Agora abra tools\sandbox\oblivion-bench.wsb (dois cliques)."
