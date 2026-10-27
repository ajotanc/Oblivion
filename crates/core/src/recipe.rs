//! Receitas declarativas (no espírito do CFScript do ComboFix, com salvaguardas): um arquivo seu diz o
//! QUE remover, e o Oblivion transforma cada linha em um item do fluxo normal de limpeza. Por isso
//! valem as mesmas regras: confirmação item a item (`--yes` não vale para receitas), ponto de
//! restauração, quarentena e `undo`. A receita nunca roda comandos nem apaga caminho livre.
//!
//! Linhas (`#` comenta):
//! - `valor: HKCU\Software\Microsoft\Windows\CurrentVersion\Run | Nome`  (só chaves Run conhecidas)
//! - `inicializacao: arquivo.lnk`  (item da pasta Startup do usuário ou de todos os usuários)
//! - `processo: nome.exe`  (nunca processos do Windows: svchost, lsass, explorer...)
use std::path::PathBuf;

use crate::finding::{Finding, Severity};

#[cfg_attr(not(windows), allow(dead_code))] // só o Windows usa
const SCANNER_RUN: &str = "persistencia";
const SCANNER_PROCESS: &str = "processos";
const REASON: &str = "Pedido pela sua receita";

#[derive(Debug, PartialEq, Eq)]
enum Statement {
    Value {
        hive: String,
        subkey: String,
        name: String,
    },
    Startup(String),
    Process(String),
}

fn parse_line(line: &str) -> Result<Option<Statement>, String> {
    let line = line.split('#').next().unwrap_or("").trim();
    if line.is_empty() {
        return Ok(None);
    }
    let (kind, rest) = line
        .split_once(':')
        .ok_or("falta o tipo (valor:, inicializacao: ou processo:)")?;
    let rest = rest.trim();
    match kind.trim().to_lowercase().as_str() {
        "valor" => {
            let (path, name) = rest.split_once('|').ok_or("use: valor: CHAVE | Nome")?;
            let (hive, subkey) = path.trim().split_once('\\').ok_or("chave sem caminho")?;
            let name = name.trim();
            if name.is_empty() {
                return Err("nome do valor vazio".into());
            }
            Ok(Some(Statement::Value {
                hive: hive.to_uppercase(),
                subkey: subkey.to_string(),
                name: name.to_string(),
            }))
        }
        "inicializacao" => plain_name(rest).map(|n| Some(Statement::Startup(n))),
        "processo" => plain_name(rest).map(|n| Some(Statement::Process(n))),
        other => Err(format!("tipo desconhecido: {other}")),
    }
}

/// Só um nome de arquivo: pasta, curinga ou vazio não são aceitos (nada de caminho livre nem "apague tudo").
fn plain_name(s: &str) -> Result<String, String> {
    if s.is_empty() || s.contains(['\\', '/', '*', '?', ':', '"']) {
        return Err("informe só o nome do arquivo, sem pasta nem curinga".into());
    }
    Ok(s.to_string())
}

fn resolve(st: &Statement) -> Result<Vec<Finding>, String> {
    match st {
        Statement::Process(name) => resolve_process(name),
        Statement::Value { hive, subkey, name } => resolve_value(hive, subkey, name),
        Statement::Startup(name) => resolve_startup(name),
    }
}

fn resolve_process(name: &str) -> Result<Vec<Finding>, String> {
    use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
    if crate::scanners::is_critical_process(name) {
        return Err(format!(
            "{name} é um processo do Windows e não pode ser alvo de receita"
        ));
    }
    let mut sys = System::new();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing()
            .with_memory()
            .with_cmd(UpdateKind::Always)
            .with_exe(UpdateKind::Always),
    );
    let me = Pid::from_u32(std::process::id());
    Ok(sys
        .processes()
        .iter()
        .filter(|(pid, p)| **pid != me && p.name().to_string_lossy().eq_ignore_ascii_case(name))
        .map(|(pid, p)| Finding {
            scanner: SCANNER_PROCESS,
            location: format!("PID {} | RAM {} MB", pid.as_u32(), p.memory() / 1_048_576),
            name: p.name().to_string_lossy().into_owned(),
            target: p
                .cmd()
                .iter()
                .map(|a| a.to_string_lossy())
                .collect::<Vec<_>>()
                .join(" "),
            severity: Severity::Suspicious,
            reason: REASON,
        })
        .collect())
}

#[cfg(windows)]
fn resolve_value(hive: &str, subkey: &str, name: &str) -> Result<Vec<Finding>, String> {
    use winreg::{RegKey, enums::*};
    if !crate::scanners::persistence_win::is_run_key(hive, subkey) {
        return Err(
            "só chaves Run conhecidas são aceitas (Run, RunOnce, Policies\\Explorer\\Run)".into(),
        );
    }
    let root = if hive == "HKLM" {
        HKEY_LOCAL_MACHINE
    } else {
        HKEY_CURRENT_USER
    };
    let key = RegKey::predef(root)
        .open_subkey(subkey)
        .map_err(|_| "a chave não existe ou está sem acesso".to_string())?;
    let data: String = key
        .get_value(name)
        .map_err(|_| "o valor não existe (nada a fazer)".to_string())?;
    Ok(vec![Finding {
        scanner: SCANNER_RUN,
        location: format!(r"{hive}\{subkey}"),
        name: name.to_string(),
        target: data,
        severity: Severity::Suspicious,
        reason: REASON,
    }])
}

#[cfg(not(windows))]
fn resolve_value(_: &str, _: &str, _: &str) -> Result<Vec<Finding>, String> {
    Err("valor de registro só existe no Windows".into())
}

#[cfg(windows)]
fn resolve_startup(name: &str) -> Result<Vec<Finding>, String> {
    let mut out = Vec::new();
    for var in ["APPDATA", "ProgramData"] {
        let Some(base) = std::env::var_os(var) else {
            continue;
        };
        let dir = PathBuf::from(base).join(r"Microsoft\Windows\Start Menu\Programs\Startup");
        let file = dir.join(name);
        if file.is_file() {
            out.push(Finding {
                scanner: SCANNER_RUN,
                location: dir.to_string_lossy().into_owned(),
                name: name.to_string(),
                target: file.to_string_lossy().into_owned(),
                severity: Severity::Suspicious,
                reason: REASON,
            });
        }
    }
    if out.is_empty() {
        return Err("o arquivo não existe nas pastas Startup (nada a fazer)".into());
    }
    Ok(out)
}

#[cfg(not(windows))]
fn resolve_startup(_: &str) -> Result<Vec<Finding>, String> {
    let _ = PathBuf::new();
    Err("pasta Startup só existe no Windows".into())
}

/// Lê a receita. Devolve os itens e as linhas com problema (número + motivo); linha ruim não derruba as outras.
pub fn load(text: &str) -> (Vec<Finding>, Vec<String>) {
    let (mut findings, mut problems) = (Vec::new(), Vec::new());
    // Editores do Windows gravam UTF-8 com BOM; sem isso a primeira linha (um comentário) viraria erro.
    for (i, line) in text.trim_start_matches('\u{feff}').lines().enumerate() {
        let n = i + 1;
        match parse_line(line) {
            Ok(None) => {}
            Ok(Some(st)) => match resolve(&st) {
                Ok(found) => findings.extend(found),
                Err(e) => problems.push(format!("linha {n}: {e}")),
            },
            Err(e) => problems.push(format!("linha {n}: {e}")),
        }
    }
    (findings, problems)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_are_parsed_and_comments_are_ignored() {
        assert_eq!(parse_line("# nada").unwrap(), None);
        assert_eq!(parse_line("   ").unwrap(), None);
        assert_eq!(
            parse_line(
                r"valor: hkcu\Software\Microsoft\Windows\CurrentVersion\Run | Meu App # velho"
            )
            .unwrap(),
            Some(Statement::Value {
                hive: "HKCU".into(),
                subkey: r"Software\Microsoft\Windows\CurrentVersion\Run".into(),
                name: "Meu App".into()
            })
        );
        assert_eq!(
            parse_line("processo: evil.exe").unwrap(),
            Some(Statement::Process("evil.exe".into()))
        );
    }

    #[test]
    fn free_paths_wildcards_and_unknown_kinds_are_rejected() {
        for bad in [
            r"processo: C:\x\a.exe",
            "processo: *.exe",
            "inicializacao: ..\\a.lnk",
            "inicializacao:",
            "apagar: tudo",
            "sem tipo",
            "valor: HKCU | x",
            r"valor: HKCU\Run |",
        ] {
            assert!(parse_line(bad).is_err(), "devia recusar: {bad}");
        }
    }

    #[test]
    fn windows_processes_cannot_be_targeted() {
        for name in ["svchost.exe", "LSASS.EXE", "explorer.exe"] {
            assert!(resolve_process(name).is_err(), "{name}");
        }
    }

    #[test]
    fn a_process_that_is_not_running_gives_no_items_and_no_error() {
        assert!(
            resolve_process("zzz-nao-existe-123.exe")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_utf8_bom_on_the_first_line_is_tolerated() {
        let (found, problems) = load("\u{feff}# comentário\nprocesso: zzz-nao-existe-123.exe\n");
        assert!(found.is_empty() && problems.is_empty(), "{problems:?}");
    }

    #[test]
    fn bad_lines_are_reported_with_their_number_and_the_rest_still_load() {
        let (found, problems) =
            load("processo: zzz-nao-existe-123.exe\napagar: x\n\nprocesso: *\n");
        assert!(found.is_empty());
        assert_eq!(problems.len(), 2);
        assert!(problems[0].starts_with("linha 2:") && problems[1].starts_with("linha 4:"));
    }

    #[cfg(windows)]
    #[test]
    fn only_known_run_keys_are_accepted_for_values() {
        let e = resolve_value("HKLM", r"SYSTEM\CurrentControlSet\Services", "x").unwrap_err();
        assert!(e.contains("Run"));
        // Chave Run válida, valor que não existe: não é achado.
        assert!(
            resolve_value(
                "HKCU",
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                "zzz-nao-existe-123"
            )
            .is_err()
        );
    }
}
