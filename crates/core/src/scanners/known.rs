//! Programas instalados que constam na lista curada (`data/known.txt`): falsos antivírus e adware conhecidos.
//! A lista é curta e escrita à mão; não é uma base completa de malware (veja também `--ioc`).
//! A remoção é manual: desinstalar um programa pelo caminho dele pode falhar ou fazer coisa inesperada.
use crate::finding::{Finding, Severity};

const SCANNER: &str = "conhecidos";
const DATA: &str = include_str!("../../data/known.txt");
const ROGUE_REASON: &str = "Falso antivírus conhecido (finge achar vírus para vender a \"cura\")";
const PUP_REASON: &str =
    "Programa potencialmente indesejado conhecido (adware ou sequestrador de navegador)";

#[derive(Debug, PartialEq, Eq)]
enum Kind {
    Rogue,
    Pup,
}

#[derive(Debug, PartialEq, Eq)]
struct Entry {
    kind: Kind,
    name: String,
    exact: bool,
}

fn parse(text: &str) -> Vec<Entry> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let (kind, name) = l.split_once(':')?;
            let kind = match kind {
                "rogue" => Kind::Rogue,
                "pup" => Kind::Pup,
                _ => return None,
            };
            let (exact, name) = name.strip_prefix('=').map_or((false, name), |n| (true, n));
            Some(Entry {
                kind,
                name: name.trim().to_lowercase(),
                exact,
            })
        })
        .collect()
}

/// Classifica o nome de um programa instalado, se constar na lista.
fn lookup<'a>(entries: &'a [Entry], program: &str) -> Option<&'a Entry> {
    let p = program.trim().to_lowercase();
    entries.iter().find(|e| {
        if e.exact {
            p == e.name
        } else {
            p.starts_with(&e.name)
        }
    })
}

fn assess(entries: &[Entry], programs: &[(String, String)]) -> Vec<Finding> {
    programs
        .iter()
        .filter_map(|(name, location)| {
            let e = lookup(entries, name)?;
            let (severity, reason) = match e.kind {
                Kind::Rogue => (Severity::High, ROGUE_REASON),
                Kind::Pup => (Severity::Suspicious, PUP_REASON),
            };
            Some(Finding {
                scanner: SCANNER,
                location: location.clone(),
                name: name.clone(),
                target: name.clone(),
                severity,
                reason,
            })
        })
        .collect()
}

#[cfg(windows)]
fn installed_programs() -> Vec<(String, String)> {
    use winreg::{RegKey, enums::*};
    let uninstall = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    let wow = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall";
    let mut out = Vec::new();
    for (hive_name, hive, path) in [
        ("HKLM", HKEY_LOCAL_MACHINE, uninstall),
        ("HKLM", HKEY_LOCAL_MACHINE, wow),
        ("HKCU", HKEY_CURRENT_USER, uninstall),
    ] {
        let Ok(root) = RegKey::predef(hive).open_subkey(path) else {
            continue;
        };
        for id in root.enum_keys().flatten() {
            if let Ok(k) = root.open_subkey(&id)
                && let Ok(name) = k.get_value::<String, _>("DisplayName")
            {
                out.push((name, format!(r"{hive_name}\{path}\{id}")));
            }
        }
    }
    out
}

#[cfg(not(windows))]
fn installed_programs() -> Vec<(String, String)> {
    Vec::new()
}

pub fn scan() -> Vec<Finding> {
    assess(&parse(DATA), &installed_programs())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn programs(names: &[&str]) -> Vec<(String, String)> {
        names
            .iter()
            .map(|n| (n.to_string(), "loc".to_string()))
            .collect()
    }

    #[test]
    fn the_embedded_list_parses_and_has_both_kinds() {
        let entries = parse(DATA);
        assert!(
            entries.iter().any(|e| e.kind == Kind::Rogue)
                && entries.iter().any(|e| e.kind == Kind::Pup)
        );
        assert!(
            entries
                .iter()
                .all(|e| !e.name.is_empty() && e.name == e.name.to_lowercase())
        );
    }

    #[test]
    fn rogue_is_high_pup_is_suspicious_and_legit_programs_are_left_alone() {
        let entries = parse(DATA);
        let found = assess(
            &entries,
            &programs(&[
                "XP Antivirus 2009",
                "Babylon Toolbar",
                "Kaspersky Anti-Virus 2020",
                "Avast Free Antivirus",
                "Visual Studio Code",
            ]),
        );
        assert_eq!(found.len(), 2, "{found:?}");
        assert_eq!(found[0].severity, Severity::High);
        assert_eq!(found[1].severity, Severity::Suspicious);
    }

    #[test]
    fn exact_entries_do_not_match_longer_legit_names() {
        let entries = parse(DATA);
        assert_eq!(assess(&entries, &programs(&["Security Tool"])).len(), 1);
        assert!(
            assess(
                &entries,
                &programs(&["Security Tool Kit Pro", "System Security Scanner Plus"])
            )
            .is_empty()
        );
    }

    #[test]
    fn unknown_lines_and_comments_are_ignored() {
        assert!(parse("# c\n\nfoo:bar\nsemdoispontos\n").is_empty());
    }

    #[test]
    fn the_real_scan_runs() {
        for f in scan() {
            assert_eq!(f.scanner, SCANNER);
        }
    }
}
