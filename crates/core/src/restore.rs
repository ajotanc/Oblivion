//! Ponto de restauração do Windows, para criar antes de qualquer ação que altere o sistema.
//! Equivale ao restore_pt.vbs do ComboFix, mas com o cmdlet atual (Checkpoint-Computer).

#[cfg(windows)]
use std::time::Duration;

#[cfg(windows)]
use crate::sys;

/// O que aconteceu ao pedir o ponto de restauração. Os dois primeiros bastam para agir com segurança.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Restore {
    Created,
    /// O Windows limita a um ponto por 24 h; já existe um mais novo que isso, então serve de proteção.
    RecentExists,
    /// Linux (e outros): não existe o conceito; a quarentena reversível é a única proteção.
    NotApplicable,
}

impl Restore {
    pub fn describe(self) -> &'static str {
        match self {
            Restore::Created => "Ponto de restauração criado.",
            Restore::RecentExists => {
                "Já existe um ponto de restauração das últimas 24 h (o Windows não cria outro); ele serve de proteção."
            }
            Restore::NotApplicable => "Ponto de restauração não se aplica a este sistema.",
        }
    }
}

// Texto fixo de propósito: nada externo é concatenado no comando.
// O Windows só avisa (não falha) quando recusa criar, então comparamos o maior número de sequência
// e devolvemos o texto do aviso, que traz o motivo real da recusa. Se recusou porque já existe um
// ponto das últimas 24 h, isso conta como proteção (RECENTE).
#[cfg(windows)]
const SCRIPT: &str = "$ErrorActionPreference='Stop'; try { \
    $before = [int](Get-ComputerRestorePoint | Measure-Object SequenceNumber -Maximum).Maximum; \
    Checkpoint-Computer -Description 'Oblivion' -RestorePointType MODIFY_SETTINGS -WarningVariable w -WarningAction SilentlyContinue; \
    $after = [int](Get-ComputerRestorePoint | Measure-Object SequenceNumber -Maximum).Maximum; \
    if ($after -gt $before) { 'OK' } else { \
        $last = Get-ComputerRestorePoint | Sort-Object SequenceNumber -Descending | Select-Object -First 1; \
        if ($last -and [Management.ManagementDateTimeConverter]::ToDateTime($last.CreationTime) -gt (Get-Date).AddHours(-24)) { 'RECENTE' } \
        else { 'NAO_CRIADO: ' + (($w | Out-String).Trim() -replace '\\s+',' ') } } \
    } catch { 'ERRO: ' + $_.Exception.Message }";

/// Cria o ponto de restauração. Exige administrador e a Proteção do Sistema ativada.
#[cfg(windows)]
pub fn create() -> Result<Restore, String> {
    let out = sys::powershell(SCRIPT, None, Duration::from_secs(120));
    interpret(out.as_deref())
}

#[cfg(not(windows))]
pub fn create() -> Result<Restore, String> {
    Ok(Restore::NotApplicable)
}

/// Traduz a saída do PowerShell em resultado. Qualquer coisa inesperada conta como falha.
#[cfg_attr(not(windows), allow(dead_code))]
fn interpret(output: Option<&str>) -> Result<Restore, String> {
    let Some(text) = output else {
        return Err("PowerShell indisponível, falhou ou tempo esgotado".into());
    };
    let last = text
        .lines()
        .map(str::trim)
        .rfind(|l| !l.is_empty())
        .unwrap_or("");
    match last {
        "OK" => Ok(Restore::Created),
        "RECENTE" => Ok(Restore::RecentExists),
        other => {
            if let Some(detail) = other.strip_prefix("NAO_CRIADO") {
                let detail = detail.trim_start_matches(':').trim();
                return Err(if detail.is_empty() {
                    "o Windows não criou o ponto e não disse o motivo (confira se a Proteção do Sistema está ativada)"
                        .into()
                } else {
                    format!("o Windows recusou criar o ponto: {detail}")
                });
            }
            match other.strip_prefix("ERRO:") {
                Some(msg) => Err(format!("{} (rode como administrador?)", msg.trim())),
                None => Err("resposta inesperada do PowerShell".into()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ok_output_means_created() {
        assert_eq!(interpret(Some("OK\r\n")), Ok(Restore::Created));
    }

    #[test]
    fn recent_point_counts_as_protection() {
        assert_eq!(interpret(Some("RECENTE\n")), Ok(Restore::RecentExists));
        assert!(Restore::RecentExists.describe().contains("24 h"));
    }

    #[test]
    fn not_created_without_a_recent_point_is_an_error() {
        let e = interpret(Some("NAO_CRIADO")).unwrap_err();
        assert!(e.contains("Proteção do Sistema"));
    }

    #[test]
    fn windows_warning_text_is_shown_as_the_reason() {
        let e = interpret(Some("NAO_CRIADO: A proteção do sistema está desativada\n")).unwrap_err();
        assert!(e.contains("recusou") && e.contains("proteção do sistema está desativada"));
    }

    #[test]
    fn powershell_error_is_reported() {
        let e = interpret(Some("ERRO: Acesso negado\n")).unwrap_err();
        assert!(e.contains("Acesso negado") && e.contains("administrador"));
    }

    #[test]
    fn missing_or_unexpected_output_is_a_failure() {
        assert!(interpret(None).is_err());
        assert!(interpret(Some("")).is_err());
        assert!(interpret(Some("lixo qualquer")).is_err());
    }

    #[test]
    fn trailing_blank_lines_are_ignored() {
        assert_eq!(interpret(Some("OK\n\n  \n")), Ok(Restore::Created));
    }

    #[test]
    fn every_outcome_has_a_message() {
        for r in [
            Restore::Created,
            Restore::RecentExists,
            Restore::NotApplicable,
        ] {
            assert!(!r.describe().is_empty());
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_is_not_applicable_and_never_fails() {
        assert_eq!(create(), Ok(Restore::NotApplicable));
    }
}
