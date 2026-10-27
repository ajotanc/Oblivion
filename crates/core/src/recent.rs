//! Diagnóstico de arquivos recentes (no espírito do Find3M do ComboFix): lista os executáveis e scripts
//! criados ou alterados há pouco nas pastas onde malware costuma se instalar. É só uma linha do tempo
//! para quem analisa: nada aqui é veredito, então tudo sai como INFO e nada é removido.
use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use crate::finding::{Finding, Severity};

const SCANNER: &str = "recentes";
const REASON: &str = "Executável ou script alterado há pouco (diagnóstico, não é veredito)";
const EXTENSIONS: &[&str] = &[
    "exe", "dll", "sys", "scr", "bat", "cmd", "ps1", "vbs", "js", "jar", "msi", "lnk", "sh", "so",
];
/// Passa disso a lista vira ruído; os mais novos vêm primeiro.
const MAX_RESULTS: usize = 300;

struct Hit {
    path: PathBuf,
    modified: SystemTime,
}

fn walk(dir: &Path, depth: u32, since: SystemTime, out: &mut Vec<Hit>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        // Não segue link simbólico: evita ciclos e sair da pasta que se quer olhar.
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        let path = entry.path();
        if kind.is_dir() {
            if depth > 0 {
                walk(&path, depth - 1, since, out);
            }
        } else if kind.is_file() {
            let ext = path
                .extension()
                .map(|e| e.to_string_lossy().to_lowercase())
                .unwrap_or_default();
            if !EXTENSIONS.contains(&ext.as_str()) {
                continue;
            }
            if let Ok(modified) = entry.metadata().and_then(|m| m.modified())
                && modified >= since
            {
                out.push(Hit { path, modified });
            }
        }
    }
}

/// Pastas e a profundidade a olhar em cada uma.
fn roots() -> Vec<(PathBuf, u32)> {
    let var = |n: &str| std::env::var_os(n).map(PathBuf::from);
    let mut r = Vec::new();
    if cfg!(windows) {
        for name in ["TEMP", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA"] {
            r.extend(var(name).map(|p| (p, 4)));
        }
        r.extend(var("USERPROFILE").map(|p| (p.join("Downloads"), 3)));
        if let Some(root) = var("SystemRoot") {
            r.push((root.join("System32"), 0));
            r.push((root, 0));
            r.push((root_tasks(), 1));
        }
    } else {
        for p in ["/tmp", "/var/tmp", "/dev/shm", "/etc/cron.d"] {
            r.push((PathBuf::from(p), 3));
        }
        if let Some(home) = var("HOME") {
            r.push((home.join(".config"), 3));
            r.push((home.join(".local"), 3));
        }
    }
    r
}

fn root_tasks() -> PathBuf {
    PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()))
        .join("System32")
        .join("Tasks")
}

pub fn collect(roots: &[(PathBuf, u32)], days: u64) -> Vec<Finding> {
    let since = SystemTime::now() - Duration::from_secs(days * 86_400);
    let mut hits = Vec::new();
    for (root, depth) in roots {
        walk(root, *depth, since, &mut hits);
    }
    hits.sort_by_key(|h| std::cmp::Reverse(h.modified));
    hits.dedup_by(|a, b| a.path == b.path);
    hits.truncate(MAX_RESULTS);
    hits.into_iter()
        .map(|h| {
            let age = SystemTime::now()
                .duration_since(h.modified)
                .unwrap_or_default();
            Finding {
                scanner: SCANNER,
                location: h
                    .path
                    .parent()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                name: format!(
                    "{} (há {} h)",
                    h.path.file_name().unwrap_or_default().to_string_lossy(),
                    age.as_secs() / 3600
                ),
                target: h.path.to_string_lossy().into_owned(),
                severity: Severity::Info,
                reason: REASON,
            }
        })
        .collect()
}

/// Arquivos recentes (últimos `days` dias) nas pastas padrão da plataforma.
pub fn scan(days: u64) -> Vec<Finding> {
    collect(&roots(), days)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("oblivion-recent-{tag}-{}", std::process::id()));
        fs::create_dir_all(d.join("sub/deep")).unwrap();
        d
    }

    #[test]
    fn only_new_programs_and_scripts_are_listed_newest_first() {
        let d = scratch("a");
        fs::write(d.join("novo.exe"), b"x").unwrap();
        fs::write(d.join("sub").join("script.ps1"), b"x").unwrap();
        fs::write(d.join("nota.txt"), b"x").unwrap();
        let found = collect(&[(d.clone(), 3)], 1);
        let names: Vec<_> = found.iter().map(|f| f.target.as_str()).collect();
        assert_eq!(found.len(), 2, "{names:?}");
        assert!(found.iter().all(|f| f.severity == Severity::Info));
        assert!(!names.iter().any(|n| n.ends_with("nota.txt")));
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn depth_limits_how_far_it_looks_and_old_files_are_skipped() {
        let d = scratch("b");
        fs::write(d.join("sub/deep").join("fundo.exe"), b"x").unwrap();
        assert!(collect(&[(d.clone(), 1)], 1).is_empty(), "fundo demais");
        assert_eq!(collect(&[(d.clone(), 2)], 1).len(), 1);
        // Janela de 0 dias: tudo o que foi gravado antes de agora fica de fora.
        std::thread::sleep(Duration::from_millis(20));
        assert!(collect(&[(d.clone(), 2)], 0).is_empty());
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_missing_folder_is_not_an_error() {
        assert!(collect(&[(PathBuf::from("/nao/existe/mesmo"), 2)], 7).is_empty());
    }
}
