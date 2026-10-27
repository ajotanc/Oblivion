//! Persistência no Windows: tudo que faz um programa iniciar sozinho.
//! Equivale ao que RegScan.cmd e SuppScan.cmd do ComboFix faziam com swreg/swsc.
use std::{collections::HashMap, env, fs, path::Path, time::Duration};

use winreg::{HKEY, RegKey, enums::*};

use crate::classify::classify;
use crate::finding::{Finding, Severity};
use crate::sys;

const SCANNER: &str = "persistencia";

const RUN_KEYS: &[(&str, HKEY, &str)] = &[
    (
        "HKLM",
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    ),
    (
        "HKLM",
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    ),
    (
        "HKLM",
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    ),
    (
        "HKCU",
        HKEY_CURRENT_USER,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    ),
    (
        "HKCU",
        HKEY_CURRENT_USER,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    ),
    // Políticas (grupo de política ou malware): também executam o que estiver listado.
    (
        "HKLM",
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    ),
    (
        "HKLM",
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    ),
    (
        "HKLM",
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    ),
    (
        "HKCU",
        HKEY_CURRENT_USER,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    ),
];

/// A chave é uma das que o Oblivion lê como "Run"? A remoção só mexe nessas, nunca em outra chave.
pub(crate) fn is_run_key(hive: &str, subkey: &str) -> bool {
    RUN_KEYS
        .iter()
        .any(|(h, _, s)| h.eq_ignore_ascii_case(hive) && s.eq_ignore_ascii_case(subkey))
}

pub fn scan() -> Vec<Finding> {
    let mut out = Vec::new();
    scan_run_keys(&mut out);
    scan_other_users(&mut out);
    scan_winlogon(&mut out, "HKLM", HKEY_LOCAL_MACHINE);
    scan_winlogon(&mut out, "HKCU", HKEY_CURRENT_USER);
    scan_ifeo(&mut out);
    scan_appinit(&mut out);
    scan_startup_folders(&mut out);
    scan_services(&mut out);
    out
}

fn scan_run_keys(out: &mut Vec<Finding>) {
    for (hive_name, hive, subkey) in RUN_KEYS {
        let Ok(key) = RegKey::predef(*hive).open_subkey(subkey) else {
            continue;
        };
        for (name, _) in key.enum_values().flatten() {
            let Ok(target) = key.get_value::<String, _>(&name) else {
                continue;
            };
            let (severity, reason) = classify(&target);
            out.push(Finding {
                scanner: SCANNER,
                location: format!(r"{hive_name}\{subkey}"),
                name,
                target,
                severity,
                reason,
            });
        }
    }
}

/// Valor padrão do Windows. O `Userinit` é comparado com o caminho EXATO dentro da pasta do Windows:
/// só conferir o final do caminho aceitaria `C:\Users\x\system32\userinit.exe` como se fosse o padrão.
fn winlogon_is_default(name: &str, value: &str, system_root: &str) -> bool {
    let v = value.trim().to_lowercase();
    match name {
        "Shell" => v == "explorer.exe",
        _ => {
            let expected = format!(
                r"{}\system32\userinit.exe",
                system_root.trim_end_matches('\\')
            );
            v.trim_end_matches(',') == expected.to_lowercase()
        }
    }
}

/// Shell e Userinit são alvos clássicos: o Windows executa o que estiver neles no login.
fn scan_winlogon(out: &mut Vec<Finding>, hive_name: &str, hive: HKEY) {
    let subkey = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
    let Ok(key) = RegKey::predef(hive).open_subkey(subkey) else {
        return;
    };
    for name in ["Shell", "Userinit"] {
        let Ok(target) = key.get_value::<String, _>(name) else {
            continue;
        };
        let system_root = env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        if !winlogon_is_default(name, &target, &system_root) {
            out.push(Finding {
                scanner: SCANNER,
                location: format!(r"{hive_name}\{subkey}"),
                name: name.to_string(),
                target,
                severity: Severity::High,
                reason: "Valor do Winlogon diferente do padrão do Windows",
            });
        }
    }
}

fn scan_startup_folders(out: &mut Vec<Finding>) {
    let mut items = Vec::new(); // (pasta, nome, caminho)
    for var in ["APPDATA", "ProgramData"] {
        let Some(base) = env::var_os(var) else {
            continue;
        };
        let dir = Path::new(&base).join(r"Microsoft\Windows\Start Menu\Programs\Startup");
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.eq_ignore_ascii_case("desktop.ini") {
                items.push((dir.clone(), name, entry.path().display().to_string()));
            }
        }
    }

    let lnks: Vec<String> = items
        .iter()
        .filter(|(_, name, _)| name.to_lowercase().ends_with(".lnk"))
        .map(|(_, _, path)| path.clone())
        .collect();
    let resolved = resolve_shortcuts(&lnks);

    for (dir, name, path) in items {
        // Atalho resolvido: julga o que ele executa. Sem resolução, cai para o nome (menos preciso).
        let shortcut_target = resolved.get(&path.to_lowercase()).filter(|t| !t.is_empty());
        let (severity, reason) = classify(shortcut_target.unwrap_or(&name));
        out.push(Finding {
            scanner: SCANNER,
            location: dir.display().to_string(),
            name,
            target: shortcut_target.cloned().unwrap_or(path),
            severity,
            reason,
        });
    }
}

/// Destino e argumentos de cada atalho `.lnk` (chave: caminho do atalho em minúsculas).
fn resolve_shortcuts(paths: &[String]) -> HashMap<String, String> {
    if paths.is_empty() {
        return HashMap::new();
    }
    let script = "$sh = New-Object -ComObject WScript.Shell; $input | ForEach-Object { \
        if ($_) { $l = $sh.CreateShortcut($_); $_ + \"`t\" + $l.TargetPath + ' ' + $l.Arguments } }";
    sys::powershell(script, Some(&paths.join("\n")), Duration::from_secs(30))
        .map(|out| parse_shortcuts(&out))
        .unwrap_or_default()
}

/// Lê linhas `caminho-do-atalho<TAB>destino argumentos`.
fn parse_shortcuts(out: &str) -> HashMap<String, String> {
    out.lines()
        .filter_map(|l| l.split_once('\t'))
        .map(|(path, target)| (path.trim().to_lowercase(), target.trim().to_string()))
        .collect()
}

/// A DLL do serviço é o que o `svchost` carrega; é nela, e não no `svchost.exe`, que um malware se esconde.
fn is_svchost(image_path: &str) -> bool {
    image_path.to_lowercase().contains("svchost.exe")
}

/// Drivers do próprio Windows ficam em `System32\drivers` (são milhares): só os de fora interessam.
fn is_inbox_driver(path: &str) -> bool {
    path.to_lowercase()
        .replace('/', "\\")
        .contains(r"system32\drivers\")
}

/// Serviços Win32 automáticos, a `ServiceDll` dos serviços `svchost` e drivers de terceiros.
fn scan_services(out: &mut Vec<Finding>) {
    let subkey = r"SYSTEM\CurrentControlSet\Services";
    let Ok(root) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(subkey) else {
        return;
    };
    for name in root.enum_keys().flatten() {
        let Ok(svc) = root.open_subkey(&name) else {
            continue;
        };
        let start: u32 = svc.get_value("Start").unwrap_or(4);
        let kind: u32 = svc.get_value("Type").unwrap_or(0);
        let image = svc.get_value::<String, _>("ImagePath").ok();
        let win32 = kind & 0x30 != 0;

        if win32
            && start == 2
            && let Some(target) = image.clone()
        {
            let (severity, reason) = classify(&target);
            out.push(Finding {
                scanner: SCANNER,
                location: format!(r"HKLM\{subkey}"),
                name: name.clone(),
                target,
                severity,
                reason,
            });
        }
        if win32
            && (2..=3).contains(&start)
            && image.as_deref().is_some_and(is_svchost)
            && let Ok(dll) = svc
                .open_subkey("Parameters")
                .and_then(|p| p.get_value::<String, _>("ServiceDll"))
        {
            let (severity, reason) = classify(&dll);
            out.push(Finding {
                scanner: SCANNER,
                location: format!(r"HKLM\{subkey}\{name}\Parameters"),
                name: format!("{name} (ServiceDll)"),
                target: dll,
                severity,
                reason,
            });
        }
        // Drivers de kernel (1) e de sistema de arquivos (2) que iniciam com o Windows.
        if !win32
            && kind & 0x3 != 0
            && start <= 2
            && let Some(path) = image
            && !is_inbox_driver(&path)
        {
            let (severity, reason) = classify(&path);
            out.push(Finding {
                scanner: SCANNER,
                location: format!(r"HKLM\{subkey}"),
                name: format!("{name} (driver)"),
                target: path,
                severity,
                reason,
            });
        }
    }
}

/// Motivos específicos: a regra de "entrada órfã" não pode trocá-los por um texto genérico.
pub(crate) const IFEO_REASON: &str = "Debugger do IFEO: outro programa roda no lugar do original";
pub(crate) const APPINIT_REASON: &str =
    "AppInit_DLLs: a DLL é carregada em todo programa que usa a interface do Windows";

/// `Debugger` do IFEO (Image File Execution Options) faz o Windows rodar OUTRO programa no lugar do
/// original: truque clássico para sequestrar `taskmgr.exe`, antivírus, etc. Vazio não interessa.
fn ifeo_assess(debugger: &str) -> Option<(Severity, &'static str)> {
    let d = debugger.trim();
    if d.is_empty() {
        return None;
    }
    Some((classify(d).0.max(Severity::Suspicious), IFEO_REASON))
}

fn scan_ifeo(out: &mut Vec<Finding>) {
    // A chave de 32 bits é a mesma de 64 para o IFEO: sem isto o mesmo achado apareceria duas vezes.
    let mut seen = std::collections::HashSet::new();
    for base in [
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    ] {
        let Ok(root) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(base) else {
            continue;
        };
        for image in root.enum_keys().flatten() {
            let Ok(dbg) = root
                .open_subkey(&image)
                .and_then(|k| k.get_value::<String, _>("Debugger"))
            else {
                continue;
            };
            if !seen.insert((image.to_lowercase(), dbg.clone())) {
                continue;
            }
            if let Some((severity, reason)) = ifeo_assess(&dbg) {
                out.push(Finding {
                    scanner: SCANNER,
                    location: format!(r"HKLM\{base}\{image}"),
                    name: format!("{image} (Debugger)"),
                    target: dbg,
                    severity,
                    reason,
                });
            }
        }
    }
}

/// `AppInit_DLLs`: cada DLL listada é carregada em todo programa que usa a interface do Windows.
fn appinit_assess(value: &str) -> Option<(Severity, &'static str)> {
    if value.trim().is_empty() {
        return None;
    }
    Some((classify(value).0.max(Severity::Suspicious), APPINIT_REASON))
}

fn scan_appinit(out: &mut Vec<Finding>) {
    for base in [
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows",
    ] {
        let Ok(value) = RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey(base)
            .and_then(|k| k.get_value::<String, _>("AppInit_DLLs"))
        else {
            continue;
        };
        if let Some((severity, reason)) = appinit_assess(&value) {
            out.push(Finding {
                scanner: SCANNER,
                location: format!(r"HKLM\{base}"),
                name: "AppInit_DLLs".into(),
                target: value,
                severity,
                reason,
            });
        }
    }
}

/// Chave que identifica uma entrada Run, sem o nome da conta: serve para não repetir, nas contas
/// carregadas (`HKU`), o que o `HKCU` do usuário atual já mostrou (o `HKCU` é um espelho de uma delas).
fn mirror_key(subkey: &str, name: &str, target: &str) -> (String, String, String) {
    (subkey.to_lowercase(), name.to_string(), target.to_string())
}

/// Entradas Run das OUTRAS contas com perfil carregado (só com administrador; contas desligadas, cujo
/// perfil não está carregado, não são lidas). Fora do `HKCU` a remoção automática não vale: é instrução manual.
fn scan_other_users(out: &mut Vec<Finding>) {
    let mine: std::collections::HashSet<_> = out
        .iter()
        .filter_map(|f| {
            f.location
                .strip_prefix(r"HKCU\")
                .map(|sub| mirror_key(sub, &f.name, &f.target))
        })
        .collect();
    let hku = RegKey::predef(HKEY_USERS);
    for sid in hku
        .enum_keys()
        .flatten()
        .filter(|s| s.starts_with("S-1-5-21-") && !s.ends_with("_Classes"))
    {
        for (_, _, subkey) in RUN_KEYS.iter().filter(|(h, _, _)| *h == "HKCU") {
            let Ok(key) = hku.open_subkey(format!(r"{sid}\{subkey}")) else {
                continue;
            };
            for (name, _) in key.enum_values().flatten() {
                let Ok(target) = key.get_value::<String, _>(&name) else {
                    continue;
                };
                if mine.contains(&mirror_key(subkey, &name, &target)) {
                    continue;
                }
                let (severity, reason) = classify(&target);
                out.push(Finding {
                    scanner: SCANNER,
                    location: format!(r"HKU\{sid}\{subkey}"),
                    name,
                    target,
                    severity,
                    reason,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policies_and_wow64_run_keys_are_read_and_removable_like_the_others() {
        for (hive, key) in [
            (
                "HKLM",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            ),
            (
                "HKCU",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            ),
            (
                "HKLM",
                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
            ),
            (
                "hklm",
                r"software\wow6432node\microsoft\windows\currentversion\policies\explorer\run",
            ),
        ] {
            assert!(is_run_key(hive, key), "{hive}\\{key}");
        }
        assert!(!is_run_key(
            "HKLM",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        ));
        assert!(!is_run_key(
            "HKU",
            r"S-1-5-21-1\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        ));
    }

    #[test]
    fn an_ifeo_debugger_is_always_at_least_suspicious() {
        // O caso clássico: um programa aparece como "depurador" de outro e roda no lugar dele.
        let (sev, why) = ifeo_assess(r"C:\Users\x\AppData\evil.exe").unwrap();
        assert_eq!(sev, Severity::Suspicious);
        assert!(why.contains("IFEO"));
        assert_eq!(
            ifeo_assess("powershell -enc AAAA").unwrap().0,
            Severity::High
        );
        assert_eq!(
            ifeo_assess(r"C:\Windows\System32\notepad.exe").unwrap().0,
            Severity::Suspicious
        );
        assert!(ifeo_assess("").is_none() && ifeo_assess("   ").is_none());
    }

    #[test]
    fn appinit_dlls_are_reported_only_when_something_is_listed() {
        assert!(appinit_assess("").is_none() && appinit_assess(" ").is_none());
        assert_eq!(
            appinit_assess(r"C:\x\hook.dll").unwrap().0,
            Severity::Suspicious
        );
        assert_eq!(
            appinit_assess(r"C:\Users\x\AppData\Local\Temp\a.dll")
                .unwrap()
                .0,
            Severity::High
        );
    }

    #[test]
    fn only_svchost_services_and_non_inbox_drivers_get_the_extra_look() {
        assert!(
            is_svchost(r"C:\Windows\System32\svchost.exe -k netsvcs -p")
                && is_svchost(r"%SystemRoot%\system32\SVCHOST.EXE -k x")
        );
        assert!(!is_svchost(r"C:\Program Files\App\app.exe"));
        assert!(
            is_inbox_driver(r"\SystemRoot\System32\drivers\ntfs.sys")
                && is_inbox_driver(r"C:\Windows\System32\DRIVERS\x.sys")
        );
        assert!(
            !is_inbox_driver(r"C:\Program Files\Vendor\driver.sys")
                && !is_inbox_driver(r"C:\ProgramData\x\r.sys")
        );
    }

    #[test]
    fn other_users_entries_that_mirror_hkcu_are_not_repeated() {
        // O HKCU é um espelho de uma das contas em HKU: a mesma entrada não pode aparecer duas vezes.
        let mine = mirror_key(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "App",
            r"C:\a.exe",
        );
        assert_eq!(
            mine,
            mirror_key(
                r"software\microsoft\windows\currentversion\run",
                "App",
                r"C:\a.exe"
            )
        );
        assert_ne!(
            mine,
            mirror_key(
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "App",
                r"C:\outro.exe"
            )
        );
        assert_ne!(
            mine,
            mirror_key(
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "Outro",
                r"C:\a.exe"
            )
        );
    }

    #[test]
    fn winlogon_default_values_are_accepted_in_any_case_with_or_without_the_comma() {
        let root = r"C:\Windows";
        assert!(winlogon_is_default(
            "Userinit",
            r"C:\Windows\system32\userinit.exe,",
            root
        ));
        assert!(winlogon_is_default(
            "Userinit",
            r"c:\WINDOWS\System32\USERINIT.EXE",
            root
        ));
        assert!(winlogon_is_default("Shell", "explorer.exe", root));
        assert!(winlogon_is_default("Shell", "  Explorer.exe ", root));
    }

    #[test]
    fn winlogon_fake_path_or_extra_program_is_not_default() {
        let root = r"C:\Windows";
        // O caso da auditoria: pasta falsa que só TERMINA igual ao caminho padrão.
        assert!(!winlogon_is_default(
            "Userinit",
            r"C:\Users\x\system32\userinit.exe,",
            root
        ));
        assert!(!winlogon_is_default(
            "Userinit",
            r"C:\Windows\system32\userinit.exe,C:\evil.exe",
            root
        ));
        assert!(!winlogon_is_default(
            "Shell",
            "explorer.exe, evil.exe",
            root
        ));
        assert!(!winlogon_is_default("Shell", r"C:\evil\explorer.exe", root));
        assert!(!winlogon_is_default("Userinit", "", root));
    }

    #[test]
    fn winlogon_follows_a_windows_folder_on_another_drive() {
        assert!(winlogon_is_default(
            "Userinit",
            r"D:\WINDOWS\system32\userinit.exe,",
            r"D:\WINDOWS\"
        ));
        assert!(!winlogon_is_default(
            "Userinit",
            r"C:\Windows\system32\userinit.exe,",
            r"D:\WINDOWS"
        ));
    }

    #[test]
    fn parses_shortcut_lines_and_ignores_garbage() {
        let m = parse_shortcuts("C:\\S\\A.lnk\tC:\\x\\a.exe --f\nlixo sem tab\n");
        assert_eq!(m.len(), 1);
        assert_eq!(m[r"c:\s\a.lnk"], r"C:\x\a.exe --f");
    }

    #[test]
    fn no_shortcuts_means_no_powershell_call() {
        assert!(resolve_shortcuts(&[]).is_empty());
    }

    #[test]
    fn resolves_a_real_shortcut_with_accents_in_the_path() {
        let dir = std::env::temp_dir().join(format!("oblivion-lnk-ação-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let lnk = dir.join("teste.lnk");
        let make = format!(
            "$s = (New-Object -ComObject WScript.Shell).CreateShortcut('{}'); \
             $s.TargetPath = 'C:\\Windows\\System32\\notepad.exe'; $s.Arguments = '/a'; $s.Save(); 'ok'",
            lnk.display()
        );
        let made = sys::powershell(&make, None, Duration::from_secs(30));
        let resolved = resolve_shortcuts(&[lnk.display().to_string()]);
        fs::remove_dir_all(&dir).unwrap();

        assert_eq!(made.as_deref().map(str::trim), Some("ok"));
        let target = &resolved[&lnk.display().to_string().to_lowercase()];
        assert!(
            target.to_lowercase().contains("notepad.exe") && target.ends_with("/a"),
            "{target}"
        );
    }
}
