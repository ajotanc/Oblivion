<#
  Atualiza crates/core/data/hashes.txt com hashes SHA-256 recentes de executáveis maliciosos
  (MalwareBazaar, abuse.ch; dados em CC0).

  A chave da sua conta NUNCA fica no repositório: o script lê a variável de ambiente ABUSECH_AUTH_KEY.
  Para definir só para o seu usuário (uma vez), num PowerShell normal:
      [Environment]::SetEnvironmentVariable('ABUSECH_AUTH_KEY', '<sua chave>', 'User')
  Feche e abra o terminal depois. Para apagar: ... , $null, 'User').

  Limite honesto: a API devolve as amostras mais recentes, então a lista só ajuda contra malware novo
  e envelhece rápido. Rode de vez em quando e revise o resultado (git diff) antes de enviar.
#>
$ErrorActionPreference = 'Stop'
$key = $env:ABUSECH_AUTH_KEY
if (-not $key) { throw 'Defina a variável de ambiente ABUSECH_AUTH_KEY (veja o topo deste script).' }

$resp = Invoke-RestMethod -Uri 'https://mb-api.abuse.ch/api/v1/' -Method Post `
    -Headers @{ 'Auth-Key' = $key } -Body @{ query = 'get_recent'; selector = '100' }
if ($resp.query_status -ne 'ok') { throw "A API respondeu: $($resp.query_status)" }

$hashes = $resp.data |
    Where-Object { $_.file_type -in 'exe', 'dll', 'scr', 'msi' -and $_.sha256_hash -match '^[0-9a-f]{64}$' } |
    ForEach-Object { $_.sha256_hash } | Sort-Object -Unique

$out = Join-Path $PSScriptRoot '..\crates\core\data\hashes.txt'
$header = @(
    '# Hashes SHA-256 de executáveis maliciosos recentes (MalwareBazaar, abuse.ch, CC0).',
    "# Gerado por tools/refresh-iocs.ps1 em $(Get-Date -Format 'yyyy-MM-dd'). Lista curta e que envelhece: não é uma base completa.",
    '# Formato: um hash por linha.'
)
($header + ($hashes | ForEach-Object { "sha256:$_" })) | Set-Content -Path $out -Encoding utf8
"$($hashes.Count) hashes gravados em $out"
