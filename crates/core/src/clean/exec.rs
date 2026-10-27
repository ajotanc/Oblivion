//! As ações de remoção em si. Cada uma: (1) confere que o item ainda é o mesmo do scan,
//! (2) guarda o que vai apagar na quarentena, (3) só então apaga, (4) confere o resultado.
use std::{
    fs, io,
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use serde_json::{Value, json};
use sysinfo::{Pid, ProcessRefreshKind, ProcessStatus, ProcessesToUpdate, System, UpdateKind};

use super::{Exec, Outcome, Plan};
use crate::finding::Finding;

fn skipped(why: &str) -> Exec {
    Exec {
        outcome: Outcome::Skipped(why.into()),
        note: String::new(),
        undo: Vec::new(),
    }
}

fn failed(why: String) -> Exec {
    Exec {
        outcome: Outcome::Failed(why),
        note: String::new(),
        undo: Vec::new(),
    }
}

/// Executa o plano de verdade (altera o sistema).
pub fn execute(plan: &Plan, f: &Finding, dir: &Path) -> Exec {
    match plan {
        Plan::Process { pid } => kill_process(*pid, f, dir),
        #[cfg(windows)]
        Plan::RunValue { hive, subkey, name } => win::run_value(hive, subkey, name, f, dir),
        #[cfg(windows)]
        Plan::Task { name } => win::task(name, f, dir),
        #[cfg(windows)]
        Plan::Startup { path } => win::startup(path, dir),
        _ => skipped("ação não disponível neste sistema"),
    }
}

// ---------- caminhos ----------

/// Minúsculas e `\` no Windows (onde o sistema de arquivos ignora maiúsculas); igual no Linux.
fn norm(p: &Path) -> String {
    let s = p.to_string_lossy();
    if cfg!(windows) {
        s.replace('/', "\\").to_lowercase()
    } else {
        s.into_owned()
    }
}

fn under_any(path: &Path, roots: &[PathBuf]) -> bool {
    let p = norm(path);
    let sep = if cfg!(windows) { '\\' } else { '/' };
    roots.iter().any(|r| {
        let r = norm(r);
        let r = r.trim_end_matches(sep);
        !r.is_empty() && p.starts_with(&format!("{r}{sep}"))
    })
}

#[cfg(windows)]
fn system_roots() -> Vec<PathBuf> {
    vec![std::env::var_os("SystemRoot").map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from)]
}

#[cfg(not(windows))]
fn system_roots() -> Vec<PathBuf> {
    ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/boot"]
        .map(PathBuf::from)
        .to_vec()
}

#[cfg(windows)]
fn user_roots() -> Vec<PathBuf> {
    [
        "LOCALAPPDATA",
        "APPDATA",
        "TEMP",
        "TMP",
        "ProgramData",
        "USERPROFILE",
        "PUBLIC",
    ]
    .iter()
    .filter_map(|v| std::env::var_os(v).map(PathBuf::from))
    .collect()
}

#[cfg(not(windows))]
fn user_roots() -> Vec<PathBuf> {
    ["/tmp", "/var/tmp", "/dev/shm", "/home", "/root"]
        .map(PathBuf::from)
        .to_vec()
}

/// Pastas do sistema: arquivos ali nunca são movidos.
pub(crate) fn is_system_path(p: &Path) -> bool {
    under_any(p, &system_roots())
}

/// Pastas onde o usuário (ou um malware rodando como ele) grava: só executáveis daqui são movidos.
pub(crate) fn is_user_location(p: &Path) -> bool {
    under_any(p, &user_roots())
}

/// Move um arquivo para `<quarentena>/<sub>/<nome>.quarantined`. Guarda o conteúdo intacto, sem
/// permissão de execução no Linux. Devolve onde ficou.
pub(crate) fn quarantine_file(src: &Path, dir: &Path, sub: &str) -> io::Result<PathBuf> {
    let folder = dir.join(sub);
    fs::create_dir_all(&folder)?;
    let name = src
        .file_name()
        .map_or_else(|| "item".to_string(), |n| n.to_string_lossy().into_owned());
    let mut dest = folder.join(format!("{name}.quarantined"));
    let mut n = 1;
    while dest.exists() {
        dest = folder.join(format!("{name}.{n}.quarantined"));
        n += 1;
    }
    if fs::rename(src, &dest).is_err() {
        // Outro volume: copia e só depois apaga o original; se não conseguir apagar, desfaz a cópia.
        fs::copy(src, &dest)?;
        if let Err(e) = fs::remove_file(src) {
            let _ = fs::remove_file(&dest);
            return Err(e);
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&dest, fs::Permissions::from_mode(0o600));
    }
    Ok(dest)
}

pub(crate) fn move_undo(dest: &Path, original: &Path) -> Value {
    json!({"kind": "move", "from": dest, "to": original})
}

// ---------- processo (Windows e Linux) ----------

fn kill_process(pid: u32, f: &Finding, dir: &Path) -> Exec {
    let spid = Pid::from_u32(pid);
    let kind = ProcessRefreshKind::nothing()
        .with_cmd(UpdateKind::Always)
        .with_exe(UpdateKind::Always);
    let mut sys = System::new();
    sys.refresh_processes_specifics(ProcessesToUpdate::Some(&[spid]), true, kind);
    let Some(p) = sys.process(spid) else {
        return skipped("o processo já não existe");
    };
    let name = p.name().to_string_lossy().into_owned();
    let cmd = p
        .cmd()
        .iter()
        .map(|a| a.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ");
    if name != f.name || cmd != f.target {
        return skipped("o processo mudou desde o scan (o PID pode ter sido reaproveitado)");
    }
    let exe = p.exe().map(Path::to_path_buf);
    if !p.kill() {
        return failed("não consegui encerrar o processo (permissão?)".into());
    }
    // O sistema leva um instante para liberar o arquivo do executável. No Linux, um processo morto
    // cujo pai ainda não recolheu o status vira "zumbi": já não executa nada, e conta como encerrado.
    let gone = |sys: &System| {
        sys.process(spid)
            .is_none_or(|p| p.status() == ProcessStatus::Zombie)
    };
    for _ in 0..30 {
        thread::sleep(Duration::from_millis(100));
        sys.refresh_processes_specifics(ProcessesToUpdate::Some(&[spid]), true, kind);
        if gone(&sys) {
            break;
        }
    }
    if !gone(&sys) {
        return failed("o processo continua vivo depois de encerrar".into());
    }

    let mut note = "Processo encerrado.".to_string();
    let mut undo = Vec::new();
    match exe {
        Some(e) if is_system_path(&e) => {
            note.push_str(" O executável está numa pasta do sistema e não foi movido.")
        }
        Some(e) if !is_user_location(&e) => {
            note.push_str(" O executável está fora das pastas do usuário e não foi movido (confira manualmente).");
        }
        Some(e) if e.is_file() => match quarantine_file(&e, dir, "files") {
            Ok(dest) => {
                note.push_str(&format!(" Executável movido para {}.", dest.display()));
                undo.push(move_undo(&dest, &e));
            }
            Err(err) => note.push_str(&format!(" Não consegui mover o executável: {err}.")),
        },
        _ => {}
    }
    Exec {
        outcome: Outcome::Done,
        note,
        undo,
    }
}

// ---------- Windows: valor Run, tarefa agendada, pasta Startup ----------

#[cfg(windows)]
mod win {
    use std::time::Duration;

    use winreg::{RegKey, RegValue, enums::*, types::FromRegValue};

    use super::*;
    use crate::scanners::tasks_win::{decode, parse_task, tasks_root};
    use crate::sys;

    pub(super) fn run_value(hive: &str, subkey: &str, name: &str, f: &Finding, dir: &Path) -> Exec {
        let root = match hive {
            "HKLM" => HKEY_LOCAL_MACHINE,
            "HKCU" => HKEY_CURRENT_USER,
            _ => return skipped("chave de registro desconhecida"),
        };
        let key = match RegKey::predef(root).open_subkey_with_flags(subkey, KEY_READ | KEY_WRITE) {
            Ok(k) => k,
            Err(e) => return failed(format!("não consegui abrir a chave (administrador?): {e}")),
        };
        let Ok(raw) = key.get_raw_value(name) else {
            return skipped("o valor já não existe");
        };
        let expand = raw.vtype == RegType::REG_EXPAND_SZ;
        let Ok(current) = String::from_reg_value(&raw) else {
            return skipped("o valor não é um texto");
        };
        if current != f.target {
            return skipped("o valor mudou desde o scan");
        }
        // Guarda ANTES de apagar: se algo falhar no meio, o conteúdo está salvo em disco.
        let undo = json!({"kind": "run_value", "hive": hive, "subkey": subkey, "name": name, "expand": expand, "data": current});
        let backup = dir.join("registry");
        if let Err(e) = fs::create_dir_all(&backup).and_then(|()| {
            fs::write(
                backup.join(format!("{}.json", name.replace(['\\', '/', ':'], "_"))),
                undo.to_string(),
            )
        }) {
            return failed(format!("não consegui guardar o valor na quarentena: {e}"));
        }
        if let Err(e) = key.delete_value(name) {
            return failed(format!("não consegui apagar o valor: {e}"));
        }
        if key.get_raw_value(name).is_ok() {
            return failed("o valor continua lá depois de apagar".into());
        }
        Exec {
            outcome: Outcome::Done,
            note: format!("Valor guardado em {}.", backup.display()),
            undo: vec![undo],
        }
    }

    pub(super) fn task(name: &str, f: &Finding, dir: &Path) -> Exec {
        // O nome vem do disco e vai para um comando: só aceita o formato de caminho relativo simples.
        if name.is_empty()
            || name.contains("..")
            || name.contains(':')
            || name.starts_with(['\\', '/'])
        {
            return skipped("nome de tarefa inválido");
        }
        let path = tasks_root().join(name);
        let Ok(bytes) = fs::read(&path) else {
            return skipped("a tarefa já não existe ou está sem acesso");
        };
        if !parse_task(&decode(&bytes)).contains(&f.target) {
            return skipped("a tarefa mudou desde o scan");
        }
        let saved = dir
            .join("tasks")
            .join(format!("{}.xml", name.replace(['\\', '/'], "__")));
        if let Err(e) =
            fs::create_dir_all(dir.join("tasks")).and_then(|()| fs::write(&saved, &bytes))
        {
            return failed(format!("não consegui guardar o XML da tarefa: {e}"));
        }
        let tn = format!("\\{name}");
        if sys::run(
            "schtasks",
            &["/Delete", "/TN", &tn, "/F"],
            None,
            Duration::from_secs(30),
        )
        .is_none()
        {
            return failed("o schtasks não conseguiu apagar a tarefa (administrador?)".into());
        }
        if path.exists() {
            return failed("a tarefa continua lá depois de apagar".into());
        }
        let undo = json!({"kind": "task", "name": name, "xml": saved});
        Exec {
            outcome: Outcome::Done,
            note: format!("XML guardado em {}.", saved.display()),
            undo: vec![undo],
        }
    }

    pub(super) fn startup(path: &Path, dir: &Path) -> Exec {
        let in_startup = path
            .parent()
            .is_some_and(|p| norm(p).ends_with(r"start menu\programs\startup"));
        if !in_startup {
            return skipped("o item não está numa pasta Startup");
        }
        if !path.is_file() {
            return skipped("o item já não existe");
        }
        match quarantine_file(path, dir, "startup") {
            Ok(dest) => Exec {
                outcome: Outcome::Done,
                note: format!("Movido para {}.", dest.display()),
                undo: vec![move_undo(&dest, path)],
            },
            Err(e) => failed(format!("não consegui mover: {e}")),
        }
    }

    /// Usado pelo `undo`: grava de volta o valor Run guardado.
    pub(crate) fn restore_run_value(entry: &serde_json::Value) -> Result<(), String> {
        let get = |k: &str| entry[k].as_str().ok_or_else(|| format!("registro sem {k}"));
        let (hive, subkey, name, data) = (get("hive")?, get("subkey")?, get("name")?, get("data")?);
        // O manifesto não é confiável: só recria valores nas chaves Run que o Oblivion sabe remover.
        if !crate::scanners::persistence_win::is_run_key(hive, subkey) {
            return Err("chave de registro fora das chaves Run: não recriei".into());
        }
        let root = match hive {
            "HKLM" => HKEY_LOCAL_MACHINE,
            "HKCU" => HKEY_CURRENT_USER,
            _ => return Err("chave desconhecida".into()),
        };
        let (key, _) = RegKey::predef(root)
            .create_subkey_with_flags(subkey, KEY_READ | KEY_WRITE)
            .map_err(|e| format!("não consegui abrir a chave: {e}"))?;
        if key.get_raw_value(name).is_ok() {
            return Err("já existe um valor com esse nome; não sobrescrevi".into());
        }
        let bytes: Vec<u8> = data
            .encode_utf16()
            .chain(Some(0))
            .flat_map(u16::to_le_bytes)
            .collect();
        let vtype = if entry["expand"].as_bool().unwrap_or(false) {
            RegType::REG_EXPAND_SZ
        } else {
            RegType::REG_SZ
        };
        key.set_raw_value(name, &RegValue { bytes, vtype })
            .map_err(|e| format!("não consegui gravar o valor: {e}"))
    }

    /// Usado pelo `undo`: recria a tarefa a partir do XML guardado.
    pub(crate) fn restore_task(dir: &Path, entry: &serde_json::Value) -> Result<(), String> {
        let name = entry["name"].as_str().ok_or("registro sem nome")?;
        let xml = entry["xml"].as_str().ok_or("registro sem XML")?;
        if name.contains("..") || name.contains(':') {
            return Err("nome de tarefa inválido".into());
        }
        let xml = dir.join(xml);
        if !crate::clean::secure::is_inside(dir, &xml)
            || xml
                .extension()
                .is_none_or(|e| !e.eq_ignore_ascii_case("xml"))
        {
            return Err("o XML não está dentro da quarentena: não recriei a tarefa".into());
        }
        // Sem /F: se já existir uma tarefa com esse nome, o schtasks recusa e nada é sobrescrito.
        sys::run(
            "schtasks",
            &[
                "/Create",
                "/XML",
                &xml.to_string_lossy(),
                "/TN",
                &format!("\\{name}"),
            ],
            None,
            Duration::from_secs(30),
        )
        .map(|_| ())
        .ok_or_else(|| {
            "o schtasks não recriou a tarefa (ela já existe, ou falta administrador)".into()
        })
    }
}

#[cfg(windows)]
pub(crate) use win::{restore_run_value, restore_task};

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("oblivion-exec-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn under_any_requires_a_whole_folder_not_a_prefix_of_a_name() {
        let roots = [PathBuf::from(if cfg!(windows) {
            r"C:\Users\x"
        } else {
            "/home/x"
        })];
        let inside = if cfg!(windows) {
            r"C:\Users\x\AppData\a.exe"
        } else {
            "/home/x/a.exe"
        };
        let lookalike = if cfg!(windows) {
            r"C:\Users\xyz\a.exe"
        } else {
            "/home/xyz/a.exe"
        };
        assert!(under_any(Path::new(inside), &roots));
        assert!(!under_any(Path::new(lookalike), &roots), "xyz não é x");
        assert!(
            !under_any(Path::new(inside), &[PathBuf::new()]),
            "raiz vazia não casa com tudo"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_directory_is_protected_and_appdata_is_a_user_location() {
        assert!(is_system_path(Path::new(r"C:\Windows\System32\cmd.exe")));
        assert!(is_system_path(Path::new(r"c:\WINDOWS\notepad.exe")));
        assert!(!is_system_path(Path::new(r"C:\Users\x\a.exe")));
        let appdata = std::env::var("LOCALAPPDATA").unwrap();
        assert!(is_user_location(Path::new(&format!(
            r"{appdata}\Temp\x.exe"
        ))));
        assert!(!is_user_location(Path::new(r"C:\Program Files\App\a.exe")));
        assert!(!is_user_location(Path::new(r"C:\Windows\System32\cmd.exe")));
    }

    #[cfg(unix)]
    #[test]
    fn unix_system_folders_are_protected_and_tmp_is_a_user_location() {
        assert!(
            is_system_path(Path::new("/usr/bin/ls")) && is_system_path(Path::new("/etc/passwd"))
        );
        assert!(!is_system_path(Path::new("/home/x/a")));
        assert!(
            is_user_location(Path::new("/tmp/x/miner"))
                && is_user_location(Path::new("/dev/shm/a"))
        );
        assert!(!is_user_location(Path::new("/opt/app/a")));
    }

    #[test]
    fn quarantine_moves_the_file_keeps_the_content_and_never_overwrites() {
        let dir = temp_dir("q");
        let src = dir.join("origem.bin");
        fs::write(&src, b"conteudo").unwrap();
        let dest = quarantine_file(&src, &dir.join("quarentena"), "files").unwrap();
        assert!(!src.exists());
        assert_eq!(fs::read(&dest).unwrap(), b"conteudo");
        assert!(dest.to_string_lossy().ends_with("origem.bin.quarantined"));

        fs::write(&src, b"outro").unwrap();
        let dest2 = quarantine_file(&src, &dir.join("quarentena"), "files").unwrap();
        assert_ne!(
            dest, dest2,
            "o segundo arquivo de mesmo nome não apaga o primeiro"
        );
        assert_eq!(fs::read(&dest).unwrap(), b"conteudo");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn quarantine_of_a_missing_file_fails_without_creating_a_phantom_copy() {
        let dir = temp_dir("qm");
        assert!(quarantine_file(&dir.join("nao-existe"), &dir.join("q"), "files").is_err());
        assert!(
            fs::read_dir(dir.join("q").join("files"))
                .unwrap()
                .next()
                .is_none()
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn move_undo_records_where_to_put_the_file_back() {
        let v = move_undo(Path::new("q/a.quarantined"), Path::new("orig/a"));
        assert_eq!(
            (v["kind"].as_str(), v["to"].as_str()),
            (Some("move"), Some("orig/a"))
        );
    }

    #[test]
    fn killing_a_pid_that_does_not_exist_is_skipped_not_an_error() {
        let f = Finding {
            scanner: "minerador",
            location: "PID 4000000000 | RAM 1 MB".into(),
            name: "x".into(),
            target: "x".into(),
            severity: crate::finding::Severity::High,
            reason: "r",
        };
        let e = execute(&Plan::Process { pid: 4_000_000_000 }, &f, Path::new("."));
        assert!(matches!(e.outcome, Outcome::Skipped(_)), "{:?}", e.outcome);
    }

    /// Processo de teste que dorme: cópia de um programa do sistema dentro de uma pasta temporária
    /// (uma "pasta do usuário", onde o executável pode ser movido).
    fn spawn_sleeper(dir: &Path) -> (std::process::Child, PathBuf, String) {
        let (src, args): (&str, &[&str]) = if cfg!(windows) {
            (r"C:\Windows\System32\ping.exe", &["-t", "127.0.0.1"])
        } else {
            ("/bin/sleep", &["300"])
        };
        let exe = dir.join(if cfg!(windows) {
            "minerador-t.exe"
        } else {
            "minerador-t"
        });
        fs::copy(src, &exe).unwrap();
        let child = std::process::Command::new(&exe)
            .args(args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        thread::sleep(Duration::from_millis(600));
        let target = format!("{} {}", exe.display(), args.join(" "));
        (child, exe, target)
    }

    fn process_finding(pid: u32, name: &str, target: &str) -> Finding {
        Finding {
            scanner: "minerador",
            location: format!("PID {pid} | RAM 1 MB"),
            name: name.into(),
            target: target.into(),
            severity: crate::finding::Severity::High,
            reason: crate::finding::MINER_STRONG_REASON,
        }
    }

    #[test]
    fn kills_the_exact_process_moves_its_executable_and_records_how_to_undo() {
        let dir = temp_dir("kill");
        let (mut child, exe, target) = spawn_sleeper(&dir);
        let name = exe.file_name().unwrap().to_string_lossy().into_owned();
        let e = execute(
            &Plan::Process { pid: child.id() },
            &process_finding(child.id(), &name, &target),
            &dir.join("q"),
        );
        let exited = (0..30).any(|_| {
            thread::sleep(Duration::from_millis(100));
            child.try_wait().unwrap().is_some()
        });
        let _ = child.kill();
        assert_eq!(e.outcome, Outcome::Done, "{e:?}");
        assert!(exited, "o processo tinha de ter sido encerrado");
        assert!(!exe.exists(), "o executável saiu do lugar");
        assert_eq!(e.undo.len(), 1);
        let stored = PathBuf::from(e.undo[0]["from"].as_str().unwrap());
        assert!(stored.is_file() && stored.to_string_lossy().ends_with(".quarantined"));
        assert_eq!(PathBuf::from(e.undo[0]["to"].as_str().unwrap()), exe);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_process_that_changed_since_the_scan_is_left_alone() {
        // O PID pode ter sido reaproveitado por outro programa: nome ou linha de comando diferentes.
        let dir = temp_dir("kill2");
        let (mut child, exe, target) = spawn_sleeper(&dir);
        let name = exe.file_name().unwrap().to_string_lossy().into_owned();
        let plan = Plan::Process { pid: child.id() };
        let wrong_name = execute(
            &plan,
            &process_finding(child.id(), "outro.exe", &target),
            &dir.join("q"),
        );
        let wrong_cmd = execute(
            &plan,
            &process_finding(child.id(), &name, "outra linha"),
            &dir.join("q"),
        );
        let still_alive = child.try_wait().unwrap().is_none();
        let _ = child.kill();
        let _ = child.wait();
        assert!(matches!(wrong_name.outcome, Outcome::Skipped(_)));
        assert!(matches!(wrong_cmd.outcome, Outcome::Skipped(_)));
        assert!(still_alive && exe.exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(windows)]
    mod win_tests {
        use serde_json::json;
        use winreg::{RegKey, RegValue, enums::*, types::FromRegValue};

        use super::*;

        const RUN: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";

        /// Valor de teste na chave Run do usuário atual; apagado ao sair, mesmo se o teste falhar.
        struct TestValue(String);

        impl TestValue {
            fn new(tag: &str, data: &str, expand: bool) -> Self {
                let name = format!("OblivionTeste-{tag}-{}", std::process::id());
                let key = RegKey::predef(HKEY_CURRENT_USER)
                    .open_subkey_with_flags(RUN, KEY_WRITE)
                    .unwrap();
                let bytes: Vec<u8> = data
                    .encode_utf16()
                    .chain(Some(0))
                    .flat_map(u16::to_le_bytes)
                    .collect();
                let vtype = if expand {
                    RegType::REG_EXPAND_SZ
                } else {
                    RegType::REG_SZ
                };
                key.set_raw_value(&name, &RegValue { bytes, vtype })
                    .unwrap();
                TestValue(name)
            }

            fn read(&self) -> Option<RegValue> {
                RegKey::predef(HKEY_CURRENT_USER)
                    .open_subkey(RUN)
                    .unwrap()
                    .get_raw_value(&self.0)
                    .ok()
            }
        }

        impl Drop for TestValue {
            fn drop(&mut self) {
                if let Ok(k) =
                    RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(RUN, KEY_WRITE)
                {
                    let _ = k.delete_value(&self.0);
                }
            }
        }

        fn run_finding(name: &str, target: &str) -> Finding {
            Finding {
                scanner: "persistencia",
                location: format!(r"HKCU\{RUN}"),
                name: name.into(),
                target: target.into(),
                severity: crate::finding::Severity::Suspicious,
                reason: "r",
            }
        }

        #[test]
        fn removes_a_run_value_backs_it_up_and_restores_it_exactly_once() {
            let data = r"C:\oblivion-teste\a.exe --f";
            let v = TestValue::new("a", data, false);
            let dir = temp_dir("reg-a");
            let e = win::run_value("HKCU", RUN, &v.0, &run_finding(&v.0, data), &dir);
            assert_eq!(e.outcome, Outcome::Done, "{e:?}");
            assert!(v.read().is_none(), "o valor foi apagado");
            let backup = dir.join("registry").join(format!("{}.json", v.0));
            let saved: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(&backup).unwrap()).unwrap();
            assert_eq!(saved["data"], data);

            win::restore_run_value(&e.undo[0]).unwrap();
            assert_eq!(String::from_reg_value(&v.read().unwrap()).unwrap(), data);
            assert!(
                win::restore_run_value(&e.undo[0])
                    .unwrap_err()
                    .contains("já existe"),
                "não sobrescreve"
            );
            fs::remove_dir_all(&dir).unwrap();
        }

        #[test]
        fn expand_string_values_keep_their_type_through_remove_and_restore() {
            let v = TestValue::new("b", r"%SystemRoot%\oblivion-teste.exe", true);
            let dir = temp_dir("reg-b");
            let e = win::run_value(
                "HKCU",
                RUN,
                &v.0,
                &run_finding(&v.0, r"%SystemRoot%\oblivion-teste.exe"),
                &dir,
            );
            assert_eq!(e.outcome, Outcome::Done, "{e:?}");
            win::restore_run_value(&e.undo[0]).unwrap();
            assert_eq!(v.read().unwrap().vtype, RegType::REG_EXPAND_SZ);
            fs::remove_dir_all(&dir).unwrap();
        }

        #[test]
        fn a_value_that_changed_or_vanished_since_the_scan_is_left_alone() {
            let v = TestValue::new("c", "novo.exe", false);
            let dir = temp_dir("reg-c");
            let changed = win::run_value(
                "HKCU",
                RUN,
                &v.0,
                &run_finding(&v.0, "valor-antigo.exe"),
                &dir,
            );
            assert!(matches!(changed.outcome, Outcome::Skipped(_)) && v.read().is_some());
            let gone = win::run_value(
                "HKCU",
                RUN,
                "OblivionTeste-nao-existe",
                &run_finding("x", "y"),
                &dir,
            );
            assert!(matches!(gone.outcome, Outcome::Skipped(_)));
            fs::remove_dir_all(&dir).ok();
        }

        #[test]
        fn restore_refuses_registry_keys_outside_run() {
            // O caso da auditoria: manifesto adulterado apontando para outra chave.
            let entry = json!({"kind": "run_value", "hive": "HKCU", "subkey": r"SOFTWARE\OblivionTesteFora", "name": "x", "data": "y", "expand": false});
            assert!(
                win::restore_run_value(&entry)
                    .unwrap_err()
                    .contains("fora das chaves Run")
            );
            assert!(
                RegKey::predef(HKEY_CURRENT_USER)
                    .open_subkey(r"SOFTWARE\OblivionTesteFora")
                    .is_err(),
                "nem criou a chave"
            );
        }

        #[test]
        fn moves_a_startup_item_only_from_a_startup_folder() {
            let root = temp_dir("startup");
            let folder = root.join(r"Microsoft\Windows\Start Menu\Programs\Startup");
            fs::create_dir_all(&folder).unwrap();
            let item = folder.join("Teste.lnk");
            fs::write(&item, b"x").unwrap();
            let e = win::startup(&item, &root.join("q"));
            assert_eq!(e.outcome, Outcome::Done, "{e:?}");
            assert!(!item.exists());
            assert_eq!(e.undo[0]["kind"], "move");

            let other = root.join("Documentos");
            fs::create_dir_all(&other).unwrap();
            let outside = other.join("a.lnk");
            fs::write(&outside, b"x").unwrap();
            assert!(matches!(
                win::startup(&outside, &root.join("q")).outcome,
                Outcome::Skipped(_)
            ));
            assert!(outside.exists(), "fora de uma pasta Startup nada é movido");
            assert!(
                matches!(
                    win::startup(&item, &root.join("q")).outcome,
                    Outcome::Skipped(_)
                ),
                "já não existe"
            );
            fs::remove_dir_all(&root).unwrap();
        }

        #[test]
        fn task_names_that_could_escape_the_tasks_folder_are_refused_before_anything_runs() {
            let f = run_finding("x", "y");
            let dir = temp_dir("task");
            for bad in [r"..\evil", r"a\..\..\b", r"C:\evil", r"\abs", "/abs", ""] {
                assert!(
                    matches!(win::task(bad, &f, &dir).outcome, Outcome::Skipped(_)),
                    "{bad}"
                );
            }
            assert!(matches!(
                win::task(r"Oblivion\NaoExiste", &f, &dir).outcome,
                Outcome::Skipped(_)
            ));
            assert!(!dir.join("tasks").exists(), "nada foi guardado");
            fs::remove_dir_all(&dir).ok();
        }
    }

    #[test]
    fn manual_plans_are_not_executable() {
        let f = Finding {
            scanner: "mbr",
            location: String::new(),
            name: String::new(),
            target: String::new(),
            severity: crate::finding::Severity::High,
            reason: "r",
        };
        assert!(matches!(
            execute(&Plan::Manual("x"), &f, Path::new(".")).outcome,
            Outcome::Skipped(_)
        ));
    }
}
