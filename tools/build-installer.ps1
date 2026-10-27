<#
  Gera o instalador do Windows com a INTERFACE e o CLI juntos (e o comando `oblivion` no PATH do usuário).

  Uso (na raiz do projeto):  .\tools\build-installer.ps1
  Saída: target\release\bundle\nsis\Oblivion_<versão>_x64-setup.exe

  Passos: compila o CLI, copia para app\src-tauri\resources (ignorada pelo git) e roda o Tauri com
  tauri.release.conf.json, que embute o CLI e liga os ganchos do instalador. O build normal de desenvolvimento
  (pnpm tauri dev) não usa nada disso. Não instala nada no seu computador.
#>
# Continue: o cargo e o pnpm escrevem andamento no stderr; os códigos de saída são conferidos abaixo.
$ErrorActionPreference = 'Continue'
$root = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $root

cargo build --release -p oblivion 2>$null
if ($LASTEXITCODE -ne 0) { throw 'Falhou ao compilar o CLI.' }
New-Item -ItemType Directory -Force (Join-Path $root 'app\src-tauri\resources') | Out-Null
Copy-Item (Join-Path $root 'target\release\oblivion.exe') (Join-Path $root 'app\src-tauri\resources\oblivion.exe') -Force

Set-Location (Join-Path $root 'app')
pnpm install --frozen-lockfile 2>$null
pnpm tauri build --config src-tauri/tauri.release.conf.json
if ($LASTEXITCODE -ne 0) { throw 'Falhou ao gerar o instalador.' }

Get-ChildItem (Join-Path $root 'target\release\bundle\nsis\*-setup.exe') | ForEach-Object {
    "{0}  ({1:N1} MB)  SHA-256 {2}" -f $_.FullName, ($_.Length / 1MB), (Get-FileHash $_.FullName -Algorithm SHA256).Hash
}
