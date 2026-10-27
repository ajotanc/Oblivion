//! Assinaturas de eventos WMI: persistência sem arquivo. O WMI guarda um comando ou script que o
//! Windows executa sozinho quando um evento acontece; não aparece em Startup, registro Run nem tarefas.
//! Consumidores de linha de comando e de script são raros em programas legítimos, então todo
//! achado é pelo menos SUSPEITO. O consumidor padrão do Windows (log de eventos) é ignorado.
//! Lê `root/subscription`, o que normalmente exige administrador; sem ele o relatório avisa.
use std::time::Duration;

use crate::classify::classify;
use crate::finding::{Finding, Severity};
use crate::sys;

const SCANNER: &str = "wmi";
const LOCATION: &str = r"WMI root\subscription";

// Texto fixo. Cada consumidor vira uma linha `TIPO<TAB>nome<TAB>comando`; falha vira `ERRO<TAB>msg`.
const SCRIPT: &str = "$ErrorActionPreference='Stop'; $t=\"`t\"; \
    try { Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer | \
        ForEach-Object { 'CMD' + $t + $_.Name + $t + ($_.CommandLineTemplate + ' ' + $_.ExecutablePath) } } \
    catch { 'ERRO' + $t + $_.Exception.Message }; \
    try { Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer | \
        ForEach-Object { 'SCRIPT' + $t + $_.Name + $t + ($_.ScriptingEngine + ': ' + ($_.ScriptText -replace '\\s+',' ') + ' ' + $_.ScriptFilename) } } \
    catch { 'ERRO' + $t + $_.Exception.Message }";

pub fn scan() -> Vec<Finding> {
    let out = sys::powershell(SCRIPT, None, Duration::from_secs(60));
    parse(out.as_deref())
}

fn parse(output: Option<&str>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut verified = output.is_some();
    for line in output.unwrap_or_default().lines() {
        let mut parts = line.splitn(3, '\t');
        match (parts.next(), parts.next(), parts.next()) {
            (Some("ERRO"), _, _) => verified = false,
            (Some(kind @ ("CMD" | "SCRIPT")), Some(name), Some(command)) => {
                let command = command.trim();
                let (found, reason) = classify(command);
                let (severity, reason) = if found > Severity::Info {
                    (found, reason)
                } else if kind == "CMD" {
                    (
                        Severity::Suspicious,
                        "Executa um comando por evento do WMI (persistência sem arquivo)",
                    )
                } else {
                    (
                        Severity::Suspicious,
                        "Executa um script por evento do WMI (persistência sem arquivo)",
                    )
                };
                findings.push(Finding {
                    scanner: SCANNER,
                    location: LOCATION.into(),
                    name: name.trim().to_string(),
                    target: if command.is_empty() {
                        "(vazio)".into()
                    } else {
                        command.to_string()
                    },
                    severity,
                    reason,
                });
            }
            _ => {}
        }
    }
    if !verified {
        findings.push(Finding {
            scanner: SCANNER,
            location: LOCATION.into(),
            name: "Assinaturas WMI NÃO verificadas".into(),
            target: String::new(),
            severity: Severity::Info,
            reason: "Sem acesso ao WMI; rode como administrador para verificá-las",
        });
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_found_and_verified_yields_no_findings() {
        assert!(parse(Some("")).is_empty());
    }

    #[test]
    fn command_consumer_is_suspicious_even_when_the_command_looks_normal() {
        let f = parse(Some("CMD\tBackupX\tC:\\Windows\\System32\\notepad.exe  \n"));
        assert_eq!(f.len(), 1);
        assert_eq!(
            (f[0].name.as_str(), f[0].severity),
            ("BackupX", Severity::Suspicious)
        );
        assert!(f[0].reason.contains("comando"));
    }

    #[test]
    fn strong_signals_in_the_command_make_it_high() {
        let f = parse(Some("CMD\tx\tpowershell.exe -nop -enc AAAA\n"));
        assert_eq!(f[0].severity, Severity::High);
    }

    #[test]
    fn script_consumer_is_reported_as_a_script() {
        let f = parse(Some("SCRIPT\tevil\tVBScript: CreateObject(\"x\")  \n"));
        assert_eq!(f[0].severity, Severity::Suspicious);
        assert!(f[0].reason.contains("script"));
    }

    #[test]
    fn failure_or_timeout_warns_instead_of_looking_clean() {
        for out in [None, Some("ERRO\tAcesso negado\n")] {
            let f = parse(out);
            assert_eq!(f.len(), 1);
            assert!(f[0].name.contains("NÃO verificadas") && f[0].reason.contains("administrador"));
        }
    }

    #[test]
    fn partial_failure_keeps_findings_and_still_warns() {
        let f = parse(Some("CMD\ta\tx.exe\nERRO\tfalhou\n"));
        assert_eq!(f.len(), 2);
    }

    #[test]
    fn malformed_lines_are_ignored_without_panic() {
        assert!(parse(Some("lixo\nCMD\nCMD\tso-nome\n\t\t\n")).is_empty());
    }
}
