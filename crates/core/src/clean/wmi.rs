//! Remoção de assinaturas de eventos do WMI (persistência sem arquivo), com desfazer.
//! Antes de apagar, guarda o consumidor, o filtro e o vínculo em um JSON dentro da quarentena; o `undo`
//! recria os três a partir dele. Nada do que vem do scan entra no texto do script: os dados passam por
//! STDIN como JSON, então um nome de consumidor hostil não vira comando.
//! Escrever em `root/subscription` exige administrador.
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use serde_json::{Value, json};

use super::{Exec, Outcome};
use crate::finding::Finding;

pub const CMD_CLASS: &str = "CommandLineEventConsumer";
pub const SCRIPT_CLASS: &str = "ActiveScriptEventConsumer";

const REMOVE: &str = r#"
$ErrorActionPreference = 'Stop'
$in = [Console]::In.ReadToEnd() | ConvertFrom-Json
$ns = 'root\subscription'
$c = Get-WmiObject -Namespace $ns -Class $in.class | Where-Object { $_.Name -eq $in.name } | Select-Object -First 1
if (-not $c) { 'SKIP o consumidor já não existe'; exit 0 }
if ($in.class -eq 'CommandLineEventConsumer') {
    $cmd = $c.CommandLineTemplate + ' ' + $c.ExecutablePath
    $props = @{ CommandLineTemplate = $c.CommandLineTemplate; ExecutablePath = $c.ExecutablePath; WorkingDirectory = $c.WorkingDirectory }
} else {
    $cmd = $c.ScriptingEngine + ': ' + ($c.ScriptText -replace '\s+', ' ') + ' ' + $c.ScriptFilename
    $props = @{ ScriptingEngine = $c.ScriptingEngine; ScriptText = $c.ScriptText; ScriptFilename = $c.ScriptFilename }
}
if ($cmd.Trim() -ne ([string]$in.expect).Trim()) { 'SKIP o consumidor mudou desde o scan'; exit 0 }
$rel = $c.__RELPATH
$binds = @(Get-WmiObject -Namespace $ns -Class __FilterToConsumerBinding | Where-Object { $_.Consumer.EndsWith(':' + $rel, 'OrdinalIgnoreCase') })
$filters = @()
foreach ($b in $binds) {
    $fp = $b.Filter.Substring($b.Filter.IndexOf(':') + 1)
    $f = Get-WmiObject -Namespace $ns -Class __EventFilter | Where-Object { $_.__RELPATH -eq $fp } | Select-Object -First 1
    if ($f) { $filters += @{ Name = $f.Name; Query = $f.Query; QueryLanguage = $f.QueryLanguage; EventNamespace = $f.EventNamespace; Relpath = $fp } }
}
$backup = @{ class = $in.class; name = $c.Name; props = $props; filters = $filters }
$backup | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $in.backup -Encoding UTF8
foreach ($b in $binds) { $b | Remove-WmiObject }
$c | Remove-WmiObject
foreach ($f in $filters) {
    $still = @(Get-WmiObject -Namespace $ns -Class __FilterToConsumerBinding | Where-Object { $_.Filter.EndsWith(':' + $f.Relpath, 'OrdinalIgnoreCase') })
    if ($still.Count -eq 0) {
        Get-WmiObject -Namespace $ns -Class __EventFilter | Where-Object { $_.__RELPATH -eq $f.Relpath } | Remove-WmiObject
    }
}
$left = Get-WmiObject -Namespace $ns -Class $in.class | Where-Object { $_.Name -eq $in.name }
if ($left) { 'FAIL o consumidor continua lá depois de apagar'; exit 0 }
'OK'
"#;

const RESTORE: &str = r#"
$ErrorActionPreference = 'Stop'
$in = [Console]::In.ReadToEnd() | ConvertFrom-Json
$b = Get-Content -LiteralPath $in.backup -Raw -Encoding UTF8 | ConvertFrom-Json
if ($b.class -ne 'CommandLineEventConsumer' -and $b.class -ne 'ActiveScriptEventConsumer') { throw 'classe inválida' }
$ns = 'root\subscription'
$args = @{ Name = [string]$b.name }
foreach ($p in $b.props.PSObject.Properties) { if ($null -ne $p.Value) { $args[$p.Name] = $p.Value } }
$consumer = Set-WmiInstance -Namespace $ns -Class $b.class -Arguments $args
foreach ($f in @($b.filters)) {
    $filter = Set-WmiInstance -Namespace $ns -Class __EventFilter -Arguments @{ Name = [string]$f.Name; Query = [string]$f.Query; QueryLanguage = [string]$f.QueryLanguage; EventNamespace = [string]$f.EventNamespace }
    Set-WmiInstance -Namespace $ns -Class __FilterToConsumerBinding -Arguments @{ Filter = $filter; Consumer = $consumer } | Out-Null
}
'OK'
"#;

fn last_line(out: &str) -> &str {
    out.lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .trim()
}

fn next_backup(dir: &Path) -> std::io::Result<PathBuf> {
    let folder = dir.join("registry");
    fs::create_dir_all(&folder)?;
    let mut n = 0;
    loop {
        let p = folder.join(format!("wmi-{n}.json"));
        if !p.exists() {
            return Ok(p);
        }
        n += 1;
    }
}

pub(super) fn remove(name: &str, class: &str, f: &Finding, dir: &Path) -> Exec {
    let mk = |outcome: Outcome| Exec {
        outcome,
        note: String::new(),
        undo: Vec::new(),
    };
    if class != CMD_CLASS && class != SCRIPT_CLASS {
        return mk(Outcome::Skipped("tipo de consumidor desconhecido".into()));
    }
    let backup = match next_backup(dir) {
        Ok(p) => p,
        Err(e) => {
            return mk(Outcome::Failed(format!(
                "não consegui preparar a quarentena: {e}"
            )));
        }
    };
    let input =
        json!({"name": name, "class": class, "expect": f.target, "backup": backup}).to_string();
    let Some(out) = crate::sys::powershell(REMOVE, Some(&input), Duration::from_secs(90)) else {
        return mk(Outcome::Failed(
            "o WMI não respondeu (administrador?)".into(),
        ));
    };
    let line = last_line(&out);
    if let Some(why) = line.strip_prefix("SKIP ") {
        return mk(Outcome::Skipped(why.into()));
    }
    if line != "OK" {
        // Se algo foi gravado mas a remoção falhou no meio, o backup fica para o usuário ver.
        return mk(Outcome::Failed(
            line.strip_prefix("FAIL ")
                .unwrap_or("falha ao remover do WMI")
                .into(),
        ));
    }
    Exec {
        outcome: Outcome::Done,
        note: format!(
            "Consumidor, filtro e vínculo guardados em {}.",
            backup.display()
        ),
        undo: vec![json!({"kind": "wmi", "backup": backup, "name": name})],
    }
}

/// Usado pelo `undo`: recria consumidor, filtro e vínculo a partir do JSON da quarentena.
pub(crate) fn restore(dir: &Path, entry: &Value) -> Result<(), String> {
    let backup = Path::new(entry["backup"].as_str().ok_or("registro sem backup")?);
    if !super::secure::is_inside(dir, backup)
        || backup.extension().is_none_or(|e| e != "json")
        || !backup.is_file()
    {
        return Err("o backup do WMI não está dentro da quarentena (manifesto adulterado?)".into());
    }
    let input = json!({"backup": backup}).to_string();
    let out = crate::sys::powershell(RESTORE, Some(&input), Duration::from_secs(90))
        .ok_or("o WMI não respondeu ao recriar (administrador?)")?;
    if last_line(&out) == "OK" {
        Ok(())
    } else {
        Err("não consegui recriar a assinatura do WMI".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Erro de sintaxe nos scripts só apareceria com administrador: aqui eles são ao menos COMPILADOS.
    #[test]
    fn both_scripts_are_valid_powershell() {
        for (name, script) in [("remove", REMOVE), ("restore", RESTORE)] {
            let probe = "$s = [Console]::In.ReadToEnd(); $null = [scriptblock]::Create($s); 'OK'";
            let out = crate::sys::powershell(probe, Some(script), Duration::from_secs(30));
            assert_eq!(out.as_deref().map(str::trim), Some("OK"), "{name}");
        }
    }

    #[test]
    fn restore_refuses_a_backup_outside_the_quarantine_and_non_json() {
        let dir = std::env::temp_dir().join(format!("oblivion-wmi-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let outside = std::env::temp_dir().join("fora.json");
        fs::write(&outside, "{}").unwrap();
        let e = restore(&dir, &json!({"backup": outside})).unwrap_err();
        assert!(e.contains("dentro da quarentena"), "{e}");
        let txt = dir.join("a.txt");
        fs::write(&txt, "{}").unwrap();
        assert!(restore(&dir, &json!({"backup": txt})).is_err());
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_file(outside);
    }

    #[test]
    fn removing_with_an_unknown_class_does_nothing() {
        let f = Finding {
            scanner: "wmi",
            location: String::new(),
            name: "x".into(),
            target: "y".into(),
            severity: crate::finding::Severity::Suspicious,
            reason: "r",
        };
        let e = remove("x", "Win32_Process", &f, Path::new("."));
        assert!(matches!(e.outcome, Outcome::Skipped(_)));
    }
}
