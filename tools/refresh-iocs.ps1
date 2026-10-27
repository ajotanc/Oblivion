<#
  Atualiza crates/core/data/hashes.txt com hashes SHA-256 de executáveis maliciosos
  (MalwareBazaar, abuse.ch; dados em CC0).

  A chave da sua conta NUNCA fica no repositório: o script lê a variável de ambiente ABUSECH_AUTH_KEY
  (usuário), e nunca a imprime. Para definir uma vez, num PowerShell normal:
      [Environment]::SetEnvironmentVariable('ABUSECH_AUTH_KEY', '<sua chave>', 'User')
  Feche e abra o terminal depois. Para apagar: ... , $null, 'User').

  A API devolve no máximo 100 amostras por consulta, então o script faz várias consultas (por tipo de arquivo e
  as mais recentes) e ACUMULA: soma os hashes novos aos que já estão no arquivo. Rode de vez em quando; a lista
  cresce até o limite abaixo (os mais antigos saem primeiro). Revise o `git diff` antes de enviar.
#>
$ErrorActionPreference = 'Stop'
$MaxHashes = 20000
$key = $env:ABUSECH_AUTH_KEY
if (-not $key) { $key = [Environment]::GetEnvironmentVariable('ABUSECH_AUTH_KEY', 'User') }
if (-not $key) { throw 'Defina a variável de ambiente ABUSECH_AUTH_KEY (veja o topo deste script).' }

function Invoke-Bazaar([hashtable]$Body) {
    try {
        $r = Invoke-RestMethod -Uri 'https://mb-api.abuse.ch/api/v1/' -Method Post `
            -Headers @{ 'Auth-Key' = $key } -Body $Body -TimeoutSec 60
    } catch {
        Write-Warning "Consulta '$($Body.query) $($Body.file_type)' falhou: $($_.Exception.Message)"
        return @()
    }
    if ($r.query_status -ne 'ok') {
        Write-Warning "Consulta '$($Body.query) $($Body.file_type)': $($r.query_status)"
        return @()
    }
    @($r.data)
}

$queries = @(
    @{ query = 'get_recent'; selector = '100' },
    @{ query = 'get_recent'; selector = 'time' }
) + ('exe', 'dll', 'scr', 'msi' | ForEach-Object { @{ query = 'get_file_type'; file_type = $_; limit = '100' } })

$new = foreach ($q in $queries) {
    Invoke-Bazaar $q | Where-Object { $_.file_type -in 'exe', 'dll', 'scr', 'msi' -and $_.sha256_hash -match '^[0-9a-f]{64}$' } |
        ForEach-Object { $_.sha256_hash }
}

$out = Join-Path $PSScriptRoot '..\crates\core\data\hashes.txt'
$old = @()
if (Test-Path $out) {
    $old = Get-Content $out -Encoding UTF8 | ForEach-Object { $_.TrimStart([char]0xFEFF).Trim() } |
        Where-Object { $_ -match '^sha256:[0-9a-f]{64}$' } | ForEach-Object { $_.Substring(7) }
}

# Os novos vão no fim: se passar do limite, saem os mais antigos (os do começo da lista acumulada).
$seen = [System.Collections.Generic.HashSet[string]]::new()
$all = foreach ($h in @($old) + @($new)) { if ($h -and $seen.Add($h)) { $h } }
$added = $seen.Count - @($old).Count
if ($all.Count -gt $MaxHashes) { $all = $all | Select-Object -Last $MaxHashes }

$header = @(
    '# Hashes SHA-256 de executáveis maliciosos (MalwareBazaar, abuse.ch, CC0), acumulados.',
    "# Atualizado por tools/refresh-iocs.ps1 em $(Get-Date -Format 'yyyy-MM-dd'). Lista curta: não é uma base completa de malware.",
    '# Formato: um hash por linha.'
)
$text = (($header + ($all | ForEach-Object { "sha256:$_" })) -join "`n") + "`n"
# UTF-8 sem BOM e fim de linha LF, como o resto do repositório.
[IO.File]::WriteAllText($out, $text, (New-Object Text.UTF8Encoding($false)))
"$added novo(s); $($all.Count) no total em $out"
