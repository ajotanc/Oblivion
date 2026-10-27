//! Sinais de ransomware nas pastas do usuário: bilhetes de resgate e muitos arquivos com a mesma extensão
//! incomum (o que sobra depois que arquivos foram criptografados e renomeados).
//!
//! LIMITE (importante): isto procura RASTROS, não impede nem desfaz nada. O Oblivion não decifra arquivos e não
//! detecta um ransomware enquanto ele ainda está criptografando. O que dá para fazer, se aparecer um sinal, é
//! parar de usar o computador, desligá-lo da rede, guardar o bilhete e procurar a família em nomoreransom.org.
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

use crate::finding::{Finding, Severity};

const SCANNER: &str = "ransomware";
const MAX_FILES: usize = 30_000;
const MIN_FILES: usize = 100;
const MIN_SAME_EXT: usize = 50;
/// Parte mínima (em %) do total que uma extensão incomum precisa ter para contar como "quase tudo renomeado".
const MIN_SHARE_PCT: usize = 25;

const NOTE_REASON: &str =
    "Arquivo com nome de bilhete de resgate de ransomware (pede pagamento para devolver arquivos)";
const NOTE_AND_EXT_REASON: &str = "Bilhete de resgate e muitos arquivos com a mesma extensão incomum: sinais fortes de arquivos criptografados";
const EXT_REASON: &str = "Muitos arquivos com a mesma extensão incomum (pode ser o que sobra de arquivos criptografados)";
const KNOWN_EXT_REASON: &str = "Muitos arquivos com uma extensão que ransomware conhecido usa";

/// Extensões que famílias conhecidas de ransomware acrescentam (lista curta; o que importa é o padrão em massa).
const RANSOM_EXTENSIONS: &[&str] = &[
    "wncry",
    "wnry",
    "wcry",
    "locky",
    "cerber",
    "crypt",
    "crypted",
    "locked",
    "encrypted",
    "enc",
    "lockbit",
    "ryk",
    "djvu",
    "stop",
    "petya",
    "zepto",
    "odin",
    "thor",
    "aesir",
    "zzzzz",
    "crypz",
    "cryptolocker",
];

/// Extensões comuns de documentos, mídia, código e programas: não são suspeitas por si.
const COMMON: &[&str] = &[
    "txt", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "odt", "ods", "odp", "rtf", "csv",
    "md", "json", "xml", "html", "htm", "css", "js", "ts", "py", "rs", "c", "h", "cpp", "java",
    "cs", "go", "php", "sql", "log", "jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "webp",
    "svg", "ico", "heic", "raw", "psd", "ai", "mp3", "wav", "flac", "aac", "ogg", "m4a", "mp4",
    "mkv", "avi", "mov", "wmv", "webm", "srt", "zip", "rar", "7z", "gz", "tar", "iso", "exe",
    "dll", "msi", "lnk", "url", "ini", "cfg", "conf", "bat", "cmd", "ps1", "vbs", "sh", "yml",
    "yaml", "toml", "lock", "db", "sqlite", "dat", "bin", "tmp", "bak", "pak", "sav", "ttf", "otf",
    "woff", "woff2", "epub", "mobi", "torrent", "apk", "jar", "dmp", "cache", "ldb", "map", "vue",
    "tsx", "jsx", "scss", "less", "obj", "mtl", "fbx", "blend", "dwg", "dxf", "stl", "gcode",
];

fn lower_ext(path: &Path) -> Option<String> {
    path.extension().map(|e| e.to_string_lossy().to_lowercase())
}

/// Nome de bilhete de resgate: fala em descriptografar/restaurar/recuperar arquivos, em formato de texto ou página.
pub fn is_ransom_note(file_name: &str) -> bool {
    let n = file_name.to_lowercase();
    let ext_ok = ["txt", "html", "htm", "hta", "rtf", "url"]
        .iter()
        .any(|e| n.ends_with(&format!(".{e}")));
    let simplified = n.replace(['_', '-', ' ', '@', '!'], "");
    let verb = ["decrypt", "restore", "recover", "unlock"]
        .iter()
        .any(|v| simplified.contains(v));
    let noun = ["files", "file", "instruction", "readme", "help", "data"]
        .iter()
        .any(|v| simplified.contains(v));
    // Nomes famosos de famílias específicas.
    let famous = [
        "pleasereadme",
        "wanadecryptor",
        "ryukreadme",
        "howtobackfiles",
        "helpinstructions",
    ]
    .iter()
    .any(|f| simplified.contains(f));
    famous || (ext_ok && verb && noun)
}

#[derive(Default)]
struct Survey {
    files: usize,
    by_ext: HashMap<String, usize>,
    notes: Vec<PathBuf>,
}

fn walk(dir: &Path, depth: u32, s: &mut Survey) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        if s.files >= MAX_FILES {
            return;
        }
        let Ok(kind) = e.file_type() else { continue };
        let path = e.path();
        if kind.is_dir() {
            if depth > 0 {
                walk(&path, depth - 1, s);
            }
        } else if kind.is_file() {
            s.files += 1;
            if is_ransom_note(&e.file_name().to_string_lossy()) {
                s.notes.push(path.clone());
            }
            if let Some(ext) = lower_ext(&path) {
                *s.by_ext.entry(ext).or_default() += 1;
            }
        }
    }
}

/// A extensão incomum que domina a pasta, se houver (nome e quantidade).
fn dominant_unusual_extension(s: &Survey) -> Option<(String, usize)> {
    if s.files < MIN_FILES {
        return None;
    }
    s.by_ext
        .iter()
        .filter(|(ext, n)| {
            !COMMON.contains(&ext.as_str())
                && **n >= MIN_SAME_EXT
                && **n * 100 / s.files >= MIN_SHARE_PCT
        })
        .max_by_key(|(_, n)| **n)
        .map(|(e, n)| (e.clone(), *n))
}

fn finding(
    location: &Path,
    name: String,
    target: String,
    severity: Severity,
    reason: &'static str,
) -> Finding {
    Finding {
        scanner: SCANNER,
        location: location.display().to_string(),
        name,
        target,
        severity,
        reason,
    }
}

/// Examina as pastas dadas (cada uma em até 3 níveis) e devolve os sinais.
pub fn scan_roots(roots: &[PathBuf]) -> Vec<Finding> {
    let mut out = Vec::new();
    for root in roots {
        let mut s = Survey::default();
        walk(root, 3, &mut s);
        let dominant = dominant_unusual_extension(&s);
        let known = dominant
            .as_ref()
            .is_some_and(|(e, _)| RANSOM_EXTENSIONS.contains(&e.as_str()));
        if let Some((ext, n)) = &dominant {
            let (severity, reason) = match (s.notes.is_empty(), known) {
                (false, _) => (Severity::High, NOTE_AND_EXT_REASON),
                (true, true) => (Severity::High, KNOWN_EXT_REASON),
                (true, false) => (Severity::Suspicious, EXT_REASON),
            };
            out.push(finding(
                root,
                format!("{n} arquivos .{ext}"),
                format!("{} ({n} de {} arquivos)", root.display(), s.files),
                severity,
                reason,
            ));
        }
        for note in s.notes.iter().take(5) {
            out.push(finding(
                note.parent().unwrap_or(root),
                note.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                note.display().to_string(),
                if dominant.is_some() {
                    Severity::High
                } else {
                    Severity::Suspicious
                },
                NOTE_REASON,
            ));
        }
    }
    out
}

fn roots() -> Vec<PathBuf> {
    let var = |n: &str| std::env::var_os(n).map(PathBuf::from);
    let mut r = Vec::new();
    if cfg!(windows) {
        if let Some(home) = var("USERPROFILE") {
            for d in [
                "Desktop",
                "Documents",
                "Pictures",
                "Downloads",
                "Videos",
                "Music",
            ] {
                r.push(home.join(d));
            }
        }
        r.extend(var("PUBLIC").map(|p| p.join("Documents")));
        r.push(PathBuf::from(r"C:\"));
    } else if let Some(home) = var("HOME") {
        r.push(home);
    }
    r.into_iter().filter(|p| p.is_dir()).collect()
}

pub fn scan() -> Vec<Finding> {
    // A raiz da unidade só conta o primeiro nível (a pasta do Windows e a de programas não entram).
    let all = roots();
    let (deep, shallow): (Vec<_>, Vec<_>) = all.into_iter().partition(|p| p.parent().is_some());
    let mut out = scan_roots(&deep);
    for root in shallow {
        let mut s = Survey::default();
        walk(&root, 0, &mut s);
        for note in s.notes.iter().take(5) {
            out.push(finding(
                &root,
                note.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                note.display().to_string(),
                Severity::Suspicious,
                NOTE_REASON,
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("oblivion-ransom-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(d.join("sub")).unwrap();
        d
    }

    fn fill(dir: &Path, count: usize, ext: &str) {
        for i in 0..count {
            fs::write(dir.join(format!("arquivo{i}.{ext}")), b"x").unwrap();
        }
    }

    #[test]
    fn ransom_note_names_are_recognized_and_ordinary_names_are_not() {
        for yes in [
            "HOW_TO_DECRYPT_FILES.txt",
            "RESTORE-MY-FILES.TXT",
            "@Please_Read_Me@.txt",
            "DECRYPT_INSTRUCTION.html",
            "RyukReadMe.txt",
            "Recover your files.hta",
        ] {
            assert!(is_ransom_note(yes), "{yes}");
        }
        for no in [
            "README.txt",
            "leiame.txt",
            "ajuda.txt",
            "recovery-plan.docx",
            "restore.exe",
            "notas de aula.txt",
            "files.zip",
        ] {
            assert!(!is_ransom_note(no), "{no}");
        }
    }

    #[test]
    fn many_files_with_one_unusual_extension_plus_a_note_is_high() {
        let d = scratch("a");
        fill(&d, 120, "locked");
        fs::write(d.join("sub").join("HOW_TO_DECRYPT_FILES.txt"), b"pague").unwrap();
        let found = scan_roots(std::slice::from_ref(&d));
        assert!(
            found
                .iter()
                .any(|f| f.severity == Severity::High && f.name.contains(".locked")),
            "{found:?}"
        );
        assert!(
            found
                .iter()
                .any(|f| f.reason == NOTE_REASON && f.severity == Severity::High)
        );
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn an_unknown_extension_in_bulk_without_a_note_is_only_suspicious() {
        let d = scratch("b");
        fill(&d, 150, "xyzabc");
        let found = scan_roots(std::slice::from_ref(&d));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].severity, Severity::Suspicious);
        // Uma extensão que ransomware conhecido usa já é ALTA, mesmo sem bilhete.
        let k = scratch("c");
        fill(&k, 150, "wncry");
        assert_eq!(
            scan_roots(std::slice::from_ref(&k))[0].severity,
            Severity::High
        );
        fs::remove_dir_all(&d).ok();
        fs::remove_dir_all(&k).ok();
    }

    #[test]
    fn normal_folders_do_not_raise_anything() {
        let d = scratch("d");
        fill(&d, 80, "jpg");
        fill(&d, 80, "docx");
        fill(&d.join("sub"), 80, "pdf");
        assert!(scan_roots(std::slice::from_ref(&d)).is_empty());
        // Poucos arquivos: nunca conclui nada.
        let few = scratch("e");
        fill(&few, 30, "qwerty");
        assert!(scan_roots(std::slice::from_ref(&few)).is_empty());
        fs::remove_dir_all(&d).ok();
        fs::remove_dir_all(&few).ok();
    }

    #[test]
    fn the_real_scan_runs_and_only_reports_its_own_kind() {
        for f in scan() {
            assert_eq!(f.scanner, SCANNER);
        }
    }
}
