//! Lista de IOCs (indicadores de comprometimento) do próprio usuário: hashes SHA-256 e nomes de arquivo
//! conhecidos de malware. O Oblivion não traz lista pronta (não se promete detecção que não existe); você
//! fornece a sua, por exemplo de um relatório de inteligência de ameaças, com `--ioc ARQUIVO`.
//!
//! Formato, um por linha (`#` comenta): `sha256:<64 hex>` (ou só os 64 hex) e `nome:<arquivo.exe>`.
//! Tudo roda local: nenhum hash ou arquivo sai da máquina.
use std::{
    collections::HashSet,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

use crate::finding::{Finding, Severity};

const SCANNER: &str = "ioc";
const HASH_REASON: &str = "O conteúdo do arquivo (SHA-256) está na sua lista de IOCs";
const NAME_REASON: &str = "O nome do arquivo está na sua lista de IOCs (confira o conteúdo)";
/// Arquivos maiores que isso só são conferidos pelo nome (ler tudo deixaria o scan lento).
const MAX_HASH_BYTES: u64 = 64 * 1024 * 1024;
const THREADS: usize = 8;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Iocs {
    hashes: HashSet<String>,
    names: HashSet<String>,
}

impl Iocs {
    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty() && self.names.is_empty()
    }

    /// Linhas inválidas são ignoradas (e contadas no segundo valor) em vez de derrubar a leitura.
    pub fn parse(text: &str) -> (Self, usize) {
        let mut iocs = Iocs::default();
        let mut ignored = 0;
        // O PowerShell e o Bloco de Notas gravam UTF-8 com BOM; sem isto a primeira linha viraria "inválida".
        for line in text.trim_start_matches('\u{feff}').lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let lower = line.to_lowercase();
            if let Some(name) = lower.strip_prefix("nome:") {
                let name = name.trim();
                if name.is_empty() || name.contains(['\\', '/']) {
                    ignored += 1;
                } else {
                    iocs.names.insert(name.to_string());
                }
                continue;
            }
            let hash = lower.strip_prefix("sha256:").unwrap_or(&lower).trim();
            if hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()) {
                iocs.hashes.insert(hash.to_string());
            } else {
                ignored += 1;
            }
        }
        (iocs, ignored)
    }
}

fn sha256_of(path: &Path) -> Option<String> {
    let mut file = File::open(path).ok()?;
    if file.metadata().ok()?.len() > MAX_HASH_BYTES {
        return None;
    }
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Some(
        hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    )
}

/// Confere um arquivo contra a lista; devolve o motivo se casar.
fn check_file(iocs: &Iocs, path: &Path) -> Option<&'static str> {
    if let Some(hash) = sha256_of(path)
        && iocs.hashes.contains(&hash)
    {
        return Some(HASH_REASON);
    }
    let name = path.file_name()?.to_string_lossy().to_lowercase();
    iocs.names.contains(&name).then_some(NAME_REASON)
}

/// Executáveis dos processos em execução e dos itens já achados por outros scanners.
fn candidates(findings: &[Finding]) -> Vec<PathBuf> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    let mut add = |p: PathBuf| {
        if seen.insert(p.to_string_lossy().to_lowercase()) {
            out.push(p);
        }
    };
    let mut sys = System::new();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing().with_exe(UpdateKind::Always),
    );
    for p in sys.processes().values() {
        if let Some(exe) = p.exe() {
            add(exe.to_path_buf());
        }
    }
    // Só o Windows tem como extrair o executável de uma linha de comando de inicialização.
    #[cfg(windows)]
    for f in findings {
        if let Some(path) = crate::trust::exe_path(&f.target) {
            add(PathBuf::from(path));
        }
    }
    #[cfg(not(windows))]
    let _ = findings;
    out
}

/// Confere os arquivos contra os IOCs, em várias linhas de execução (ler cada executável é o que custa).
fn check_paths(iocs: &Iocs, paths: Vec<PathBuf>) -> Vec<Finding> {
    let chunk = paths.len().div_ceil(THREADS).max(1);
    std::thread::scope(|s| {
        let handles: Vec<_> = paths
            .chunks(chunk)
            .map(|part| {
                s.spawn(move || part.iter().filter_map(|p| hit(iocs, p)).collect::<Vec<_>>())
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().unwrap_or_default())
            .collect()
    })
}

fn hit(iocs: &Iocs, path: &Path) -> Option<Finding> {
    let reason = check_file(iocs, path)?;
    Some(Finding {
        scanner: SCANNER,
        location: path.to_string_lossy().into_owned(),
        name: path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        target: path.to_string_lossy().into_owned(),
        severity: if reason == HASH_REASON {
            Severity::High
        } else {
            Severity::Suspicious
        },
        reason,
    })
}

const BUILTIN: &str = include_str!("../data/hashes.txt");

fn merge(a: &Iocs, b: &Iocs) -> Iocs {
    Iocs {
        hashes: a.hashes.union(&b.hashes).cloned().collect(),
        names: a.names.union(&b.names).cloned().collect(),
    }
}

/// Confere os processos em execução e os itens já achados por outros scanners, contra a lista embutida
/// (`data/hashes.txt`) somada à do usuário (`--ioc`).
pub fn check(iocs: &Iocs, findings: &[Finding]) -> Vec<Finding> {
    let all = merge(iocs, &Iocs::parse(BUILTIN).0);
    if all.is_empty() {
        return Vec::new();
    }
    check_paths(&all, candidates(findings))
}
#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY_SHA: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn parse_accepts_hashes_and_names_and_counts_garbage() {
        let text = format!(
            "# lista\nsha256:{EMPTY_SHA}\n{}\nnome: Evil.EXE # comentário\nnome:a\\b.exe\nlixo\n\n",
            EMPTY_SHA.to_uppercase()
        );
        let (iocs, ignored) = Iocs::parse(&text);
        assert_eq!(
            iocs.hashes.len(),
            1,
            "maiúsculas e minúsculas são o mesmo hash"
        );
        assert!(iocs.names.contains("evil.exe"));
        assert_eq!(ignored, 2, "nome com pasta e linha solta");
    }

    #[test]
    fn a_file_is_matched_by_content_or_by_name() {
        let dir = std::env::temp_dir().join(format!("oblivion-ioc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let empty = dir.join("qualquer.bin");
        std::fs::write(&empty, b"").unwrap();
        let other = dir.join("Evil.exe");
        std::fs::write(&other, b"abc").unwrap();

        let (iocs, _) = Iocs::parse(&format!("{EMPTY_SHA}\nnome:evil.exe\n"));
        assert_eq!(check_file(&iocs, &empty), Some(HASH_REASON));
        assert_eq!(check_file(&iocs, &other), Some(NAME_REASON));
        assert_eq!(check_file(&iocs, &dir.join("ausente.bin")), None);

        let found = check_paths(&iocs, vec![empty.clone(), other.clone()]);
        assert_eq!(found.len(), 2);
        let h = found.iter().find(|f| f.name == "qualquer.bin").unwrap();
        assert_eq!(h.severity, Severity::High);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_utf8_bom_on_the_first_line_is_tolerated() {
        let (iocs, ignored) = Iocs::parse(&format!("\u{feff}# lista\nsha256:{EMPTY_SHA}\n"));
        assert_eq!((iocs.hashes.len(), ignored), (1, 0));
        let (iocs, ignored) = Iocs::parse(&format!("\u{feff}sha256:{EMPTY_SHA}\n"));
        assert_eq!(
            (iocs.hashes.len(), ignored),
            (1, 0),
            "BOM colado no primeiro hash"
        );
    }

    #[test]
    fn the_embedded_list_parses_without_ignored_lines() {
        let (_, ignored) = Iocs::parse(BUILTIN);
        assert_eq!(ignored, 0);
    }

    #[test]
    fn merging_keeps_entries_from_both_lists() {
        let (a, _) = Iocs::parse(&format!("{EMPTY_SHA}\n"));
        let (b, _) = Iocs::parse("nome:x.exe\n");
        let m = merge(&a, &b);
        assert_eq!((m.hashes.len(), m.names.len()), (1, 1));
        assert!(merge(&Iocs::default(), &Iocs::default()).is_empty());
    }
}
