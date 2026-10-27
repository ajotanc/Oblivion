//! Processos em execução. Procura o que se disfarça ou não deveria estar ali:
//! - Windows: nome de processo do Windows (`svchost.exe`, `lsass.exe`...) rodando de OUTRA pasta, ou um
//!   nome parecido (`svch0st.exe`); programa sem assinatura digital válida rodando de pasta do usuário.
//! - Linux: programa cujo arquivo foi apagado enquanto roda, sem arquivo (`memfd`) ou em pasta temporária.
//!
//! Sem administrador o sistema esconde o caminho do executável de muitos processos: eles não podem ser
//! julgados, e o relatório avisa quantos foram.
use std::{collections::HashSet, process, thread, time::Duration};

use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

use crate::finding::{Finding, Severity};

const SCANNER: &str = "processos";

/// Processos do Windows e a pasta (relativa à do Windows) de onde devem rodar. `explorer.exe` fica na
/// própria pasta do Windows; os demais em `System32` (ou `SysWOW64`, a versão de 32 bits).
const CRITICAL: &[&str] = &[
    "svchost.exe",
    "lsass.exe",
    "csrss.exe",
    "winlogon.exe",
    "services.exe",
    "smss.exe",
    "wininit.exe",
    "spoolsv.exe",
    "taskhostw.exe",
    "dllhost.exe",
    "conhost.exe",
    "runtimebroker.exe",
    "searchindexer.exe",
    "fontdrvhost.exe",
    "explorer.exe",
];

/// Distância de edição com troca de letras vizinhas (`svchsot` -> `svchost` = 1).
/// Nome de processo essencial do Windows (receitas nunca podem encerrá-lo).
pub(crate) fn is_critical(name: &str) -> bool {
    CRITICAL.contains(&name.to_lowercase().as_str())
}

fn distance(a: &str, b: &str) -> usize {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    let mut d = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            d[i][j] = (d[i - 1][j] + 1)
                .min(d[i][j - 1] + 1)
                .min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                d[i][j] = d[i][j].min(d[i - 2][j - 2] + 1);
            }
        }
    }
    d[a.len()][b.len()]
}

fn normalize(path: &str) -> String {
    path.replace('/', "\\").to_lowercase()
}

/// Dono legítimo do nome? `exe` está na pasta certa do Windows?
fn in_expected_dir(name: &str, exe: &str, system_root: &str) -> bool {
    let (exe, root) = (normalize(exe), normalize(system_root));
    let root = root.trim_end_matches('\\');
    let Some((dir, _)) = exe.rsplit_once('\\') else {
        return false;
    };
    let dir = format!("{dir}\\");
    if name == "explorer.exe" {
        dir == format!("{root}\\")
    } else {
        dir == format!("{root}\\system32\\") || dir == format!("{root}\\syswow64\\")
    }
}

/// Julga o nome e o caminho de um processo do Windows. `exe` desconhecido = não dá para julgar.
pub fn assess_windows(
    name: &str,
    exe: Option<&str>,
    system_root: &str,
) -> Option<(Severity, &'static str)> {
    let lower = name.to_lowercase();
    let exe = exe?;
    if CRITICAL.contains(&lower.as_str()) {
        return (!in_expected_dir(&lower, exe, system_root)).then_some((
            Severity::High,
            "Tem o nome de um processo do Windows, mas roda de outra pasta (disfarce)",
        ));
    }
    // Nome parecido com o de um processo do Windows (imitação) e fora da pasta do Windows.
    let base = lower.strip_suffix(".exe").unwrap_or(&lower);
    let outside = !normalize(exe).starts_with(&format!(
        "{}\\",
        normalize(system_root).trim_end_matches('\\')
    ));
    (outside
        && base.len() >= 5
        && CRITICAL
            .iter()
            .filter_map(|c| c.strip_suffix(".exe"))
            .any(|c| c != base && distance(base, c) == 1))
    .then_some((
        Severity::Suspicious,
        "Nome muito parecido com o de um processo do Windows (possível imitação)",
    ))
}

/// Julga o caminho de um processo no Linux. O núcleo do kernel mostra ` (deleted)` quando o arquivo sumiu.
pub fn assess_linux(exe: Option<&str>) -> Option<(Severity, &'static str)> {
    let exe = exe?;
    if exe.starts_with("/memfd:") {
        return Some((
            Severity::High,
            "Roda a partir da memória (memfd), sem arquivo no disco",
        ));
    }
    if exe.ends_with(" (deleted)") {
        return Some((
            Severity::High,
            "O arquivo do programa foi apagado enquanto ele roda (comum em malware)",
        ));
    }
    ["/tmp/", "/dev/shm/", "/var/tmp/"]
        .iter()
        .any(|d| exe.starts_with(d))
        .then_some((Severity::Suspicious, "Roda a partir de pasta temporária"))
}

/// Programas assinados rodando de pasta do usuário aparecem uma vez só (`Code.exe` tem dezenas de processos).
/// Os sem assinatura válida mantêm todas as linhas: cada PID precisa poder ser encerrado.
#[cfg(windows)]
fn drop_repeated_signed(
    out: &mut Vec<Finding>,
    entries: &[(String, usize)],
    signed: &HashSet<String>,
) {
    let mut seen = HashSet::new();
    let mut drop = HashSet::new();
    for (path, i) in entries {
        let key = path.to_lowercase();
        if signed.contains(&key) && !seen.insert(key) {
            drop.insert(*i);
        }
    }
    let mut i = 0;
    out.retain(|_| {
        i += 1;
        !drop.contains(&(i - 1))
    });
}

/// Mesmo critério do minerador: o próprio Oblivion e quem o iniciou não entram.
fn ancestors(start: Pid, parent_of: impl Fn(Pid) -> Option<Pid>) -> HashSet<Pid> {
    let mut set = HashSet::new();
    let mut cur = Some(start);
    while let Some(pid) = cur {
        if !set.insert(pid) {
            break;
        }
        cur = parent_of(pid);
    }
    set
}

pub fn scan() -> Vec<Finding> {
    let mut sys = System::new();
    let kind = ProcessRefreshKind::nothing()
        .with_memory()
        .with_cmd(UpdateKind::Always)
        .with_exe(UpdateKind::Always);
    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, kind);
    thread::sleep(Duration::from_millis(200));

    let skip = ancestors(Pid::from_u32(process::id()), |p| {
        sys.process(p).and_then(|x| x.parent())
    });
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let mut out = Vec::new();
    let mut unknown = 0usize;
    // Processos de pasta do usuário: o caminho e o índice do achado, para checar a assinatura depois.
    #[cfg(windows)]
    let mut from_user_folder: Vec<(String, usize)> = Vec::new();

    for (pid, p) in sys.processes() {
        if pid.as_u32() <= 4 || skip.contains(pid) {
            continue;
        }
        let name = p.name().to_string_lossy().into_owned();
        let exe = p.exe().map(|e| e.display().to_string());
        if exe.is_none() {
            unknown += 1;
            continue;
        }
        let verdict = if cfg!(windows) {
            assess_windows(&name, exe.as_deref(), &system_root)
        } else {
            assess_linux(exe.as_deref())
        };
        let cmdline = p
            .cmd()
            .iter()
            .map(|a| a.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ");
        let make = |severity, reason| Finding {
            scanner: SCANNER,
            location: format!("PID {} | RAM {} MB", pid, p.memory() / 1_048_576),
            name: name.clone(),
            target: if cmdline.is_empty() {
                exe.clone().unwrap_or_default()
            } else {
                cmdline.clone()
            },
            severity,
            reason,
        };
        if let Some((severity, reason)) = verdict {
            out.push(make(severity, reason));
        } else {
            #[cfg(windows)]
            if let Some(e) = exe.as_deref()
                && crate::clean::exec::is_user_location(std::path::Path::new(e))
            {
                // Entra como INFO; vira SUSPEITO se a assinatura não for válida (abaixo).
                from_user_folder.push((e.to_string(), out.len()));
                out.push(make(
                    Severity::Info,
                    "Roda de pasta do usuário com assinatura digital válida",
                ));
            }
        }
    }

    #[cfg(windows)]
    {
        let paths: Vec<String> = from_user_folder
            .iter()
            .map(|(p, _)| p.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        let signed = crate::trust::signed_paths(&paths);
        for (path, i) in &from_user_folder {
            if !signed.contains(&path.to_lowercase()) {
                out[*i].severity = Severity::Suspicious;
                out[*i].reason = "Roda de pasta do usuário sem assinatura digital válida";
            }
        }
        drop_repeated_signed(&mut out, &from_user_folder, &signed);
    }

    if unknown > 0 {
        out.push(Finding {
            scanner: SCANNER,
            location: "interno".into(),
            name: format!("{unknown} processo(s) NÃO verificados"),
            target: String::new(),
            severity: Severity::Info,
            reason: "O sistema escondeu o caminho do executável (rode como administrador/root para verificá-los)",
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = r"C:\Windows";

    #[test]
    fn a_windows_process_name_running_from_another_folder_is_a_disguise() {
        // O caso clássico: um "svchost.exe" no AppData.
        let (sev, why) = assess_windows(
            "svchost.exe",
            Some(r"C:\Users\x\AppData\Local\Temp\svchost.exe"),
            ROOT,
        )
        .unwrap();
        assert_eq!(sev, Severity::High);
        assert!(why.contains("disfarce"));
        assert_eq!(
            assess_windows("LSASS.EXE", Some(r"D:\malware\lsass.exe"), ROOT)
                .unwrap()
                .0,
            Severity::High
        );
        // Um programa com esse nome numa subpasta de System32 também não é o verdadeiro.
        assert!(
            assess_windows(
                "svchost.exe",
                Some(r"C:\Windows\System32\drivers\svchost.exe"),
                ROOT
            )
            .is_some()
        );
    }

    #[test]
    fn the_real_windows_processes_in_their_real_folders_are_fine() {
        for (n, p) in [
            ("svchost.exe", r"C:\Windows\System32\svchost.exe"),
            ("SVCHOST.EXE", r"c:\windows\system32\SVCHOST.EXE"),
            ("dllhost.exe", r"C:\Windows\SysWOW64\dllhost.exe"),
            ("explorer.exe", r"C:\Windows\explorer.exe"),
            ("conhost.exe", r"C:\WINDOWS\system32\conhost.exe"),
        ] {
            assert!(assess_windows(n, Some(p), ROOT).is_none(), "{n} {p}");
        }
        // O explorer.exe de System32 não é o verdadeiro (o real fica na pasta do Windows).
        assert!(
            assess_windows(
                "explorer.exe",
                Some(r"C:\Windows\System32\explorer.exe"),
                ROOT
            )
            .is_some()
        );
    }

    #[test]
    fn a_path_we_cannot_see_is_not_judged() {
        assert!(assess_windows("svchost.exe", None, ROOT).is_none());
    }

    #[test]
    fn lookalike_names_outside_the_windows_folder_are_suspicious() {
        for n in [
            "svch0st.exe",
            "scvhost.exe",
            "svchost1.exe",
            "lsasss.exe",
            "explore.exe",
            "csrss1.exe",
        ] {
            let v = assess_windows(n, Some(r"C:\Users\x\AppData\a.exe"), ROOT);
            assert_eq!(v.map(|x| x.0), Some(Severity::Suspicious), "{n}");
        }
    }

    #[test]
    fn ordinary_programs_and_short_names_are_not_flagged_as_lookalikes() {
        for n in [
            "chrome.exe",
            "notepad.exe",
            "code.exe",
            "dll.exe",
            "node.exe",
            "discord.exe",
            "steam.exe",
        ] {
            assert!(
                assess_windows(n, Some(r"C:\Users\x\AppData\a.exe"), ROOT).is_none(),
                "{n}"
            );
        }
        // Dentro da pasta do Windows um nome parecido não é julgado como imitação.
        assert!(
            assess_windows(
                "svchost1.exe",
                Some(r"C:\Windows\System32\svchost1.exe"),
                ROOT
            )
            .is_none()
        );
    }

    #[cfg(windows)]
    #[test]
    fn a_signed_program_with_many_processes_is_listed_once_but_unsigned_ones_keep_every_pid() {
        let row = |n: &str| Finding {
            scanner: SCANNER,
            location: String::new(),
            name: n.into(),
            target: String::new(),
            severity: Severity::Info,
            reason: "r",
        };
        let mut out = vec![row("a1"), row("a2"), row("b1"), row("b2"), row("a3")];
        let entries: Vec<(String, usize)> = [
            r"C:\u\Code.exe",
            r"C:\u\CODE.exe",
            r"C:\u\tool.exe",
            r"C:\u\tool.exe",
            r"C:\u\code.exe",
        ]
        .iter()
        .enumerate()
        .map(|(i, p)| (p.to_string(), i))
        .collect();
        let signed: HashSet<String> = [r"c:\u\code.exe".to_string()].into();
        drop_repeated_signed(&mut out, &entries, &signed);
        let names: Vec<_> = out.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["a1", "b1", "b2"],
            "assinado: 1 linha; sem assinatura: todas"
        );
    }

    #[test]
    fn edit_distance_counts_swaps_inserts_and_substitutions() {
        assert_eq!(distance("svchost", "svchost"), 0);
        assert_eq!(
            distance("svchsot", "svchost"),
            1,
            "troca de letras vizinhas"
        );
        assert_eq!(distance("svch0st", "svchost"), 1);
        assert_eq!(distance("svhost", "svchost"), 1);
        assert_eq!(distance("abc", "xyz"), 3);
        assert_eq!(distance("", "ab"), 2);
    }

    #[test]
    fn linux_processes_without_a_file_or_in_temp_folders_are_flagged() {
        assert_eq!(
            assess_linux(Some("/memfd:payload (deleted)")).unwrap().0,
            Severity::High
        );
        assert_eq!(
            assess_linux(Some("/tmp/.x/miner (deleted)")).unwrap().0,
            Severity::High
        );
        assert_eq!(
            assess_linux(Some("/tmp/miner")).unwrap().0,
            Severity::Suspicious
        );
        assert_eq!(
            assess_linux(Some("/dev/shm/a")).unwrap().0,
            Severity::Suspicious
        );
        assert!(assess_linux(Some("/usr/bin/bash")).is_none() && assess_linux(None).is_none());
    }

    #[test]
    fn the_real_scan_runs_and_never_flags_our_own_process_or_its_parents() {
        let own = std::env::current_exe().unwrap().display().to_string();
        let found = scan();
        for f in &found {
            assert_eq!(f.scanner, SCANNER);
            assert!(f.location.starts_with("PID ") || f.location == "interno");
        }
        assert!(
            !found
                .iter()
                .any(|f| f.target.contains(&own) && f.severity > Severity::Info)
        );
    }
}
