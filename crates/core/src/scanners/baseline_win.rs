//! Valores do Windows que têm um padrão conhecido e que malware costuma trocar para rodar cedo ou se
//! esconder: programas executados antes do login (BootExecute), shell do modo seguro, pacotes de
//! autenticação (LSA), extensões do Explorer (BHO, ShellExecuteHooks) e as linhas `load=`/`run=`/`shell=`
//! dos arquivos win.ini e system.ini. Fora do padrão = SUSPEITO (ou ALTO se o caminho já é típico de malware).
//!
//! Mudança legítima existe (leitor biométrico, software corporativo), por isso o achado é indício. Quando há
//! um valor padrão seguro, o `clean` consegue restaurá-lo (ver `repair`), com desfazer.
use winreg::{RegKey, enums::*};

use crate::classify::classify;
use crate::finding::{Finding, Severity};

const SCANNER: &str = "baseline";
const SESSION_MANAGER: &str = r"SYSTEM\CurrentControlSet\Control\Session Manager";
const LSA: &str = r"SYSTEM\CurrentControlSet\Control\Lsa";
const SAFEBOOT: &str = r"SYSTEM\CurrentControlSet\Control\SafeBoot";
const WINLOGON: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
const EXPLORER: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer";

/// Leitura do sistema, trocável nos testes.
pub struct Source<'a> {
    pub string: &'a dyn Fn(&str, &str) -> Option<String>,
    pub multi: &'a dyn Fn(&str, &str) -> Option<Vec<String>>,
    pub subkeys: &'a dyn Fn(&str) -> Vec<String>,
    pub values: &'a dyn Fn(&str) -> Vec<String>,
    /// DLL ou programa de uma classe COM.
    pub clsid: &'a dyn Fn(&str) -> Option<String>,
    pub file: &'a dyn Fn(&str) -> Option<String>,
    /// Valor binário do registro (o catálogo do Winsock guarda o caminho da DLL assim).
    pub binary: &'a dyn Fn(&str, &str) -> Option<Vec<u8>>,
}

/// Caminho de texto no começo de um valor binário (termina no primeiro byte zero).
fn leading_text(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn finding(
    location: String,
    name: &str,
    target: String,
    severity: Severity,
    reason: &'static str,
) -> Finding {
    Finding {
        scanner: SCANNER,
        location,
        name: name.to_string(),
        target,
        severity,
        reason,
    }
}

/// Fora do padrão é SUSPEITO; se o valor já parece malware, vale a classificação mais grave.
fn deviation(location: &str, name: &str, value: &str, reason: &'static str) -> Finding {
    let (sev, why) = classify(value);
    if sev == Severity::High {
        finding(location.to_string(), name, value.to_string(), sev, why)
    } else {
        finding(
            location.to_string(),
            name,
            value.to_string(),
            Severity::Suspicious,
            reason,
        )
    }
}

fn is_system_file(path: &str) -> bool {
    let p = path.trim_matches('"').replace('/', "\\").to_lowercase();
    p.contains(r"\windows\system32\")
        || p.contains(r"\windows\syswow64\")
        || p.starts_with("%systemroot%\\system32")
}

/// Linhas `chave=valor` de uma seção de um arquivo .ini (sem diferenciar maiúsculas).
fn ini_value(text: &str, section: &str, key: &str) -> Option<String> {
    let mut in_section = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_section = line.trim_matches(['[', ']']).eq_ignore_ascii_case(section);
        } else if in_section
            && let Some((k, v)) = line.split_once('=')
            && k.trim().eq_ignore_ascii_case(key)
        {
            return Some(v.trim().to_string());
        }
    }
    None
}

pub fn evaluate(src: &Source) -> Vec<Finding> {
    let mut out = Vec::new();

    // Programas que o Windows executa antes do login.
    if let Some(entries) = (src.multi)(&format!(r"HKLM\{SESSION_MANAGER}"), "BootExecute") {
        for e in entries.iter().filter(|e| !e.trim().is_empty()) {
            if !e.trim().to_lowercase().starts_with("autocheck autochk") {
                out.push(deviation(
                    &format!(r"HKLM\{SESSION_MANAGER}"),
                    "BootExecute",
                    e,
                    "Programa executado antes do login que não é a verificação de disco padrão",
                ));
            }
        }
    }
    if let Some(entries) = (src.multi)(&format!(r"HKLM\{SESSION_MANAGER}"), "SetupExecute") {
        for e in entries.iter().filter(|e| !e.trim().is_empty()) {
            out.push(deviation(
                &format!(r"HKLM\{SESSION_MANAGER}"),
                "SetupExecute",
                e,
                "Programa executado antes do login (esse valor costuma estar vazio)",
            ));
        }
    }

    // Shell do modo seguro e outros valores do Winlogon sem uso legítimo comum.
    if let Some(v) = (src.string)(&format!(r"HKLM\{SAFEBOOT}"), "AlternateShell")
        && !v.trim().eq_ignore_ascii_case("cmd.exe")
    {
        out.push(deviation(
            &format!(r"HKLM\{SAFEBOOT}"),
            "AlternateShell",
            &v,
            "O shell do modo seguro não é o cmd.exe padrão",
        ));
    }
    if let Some(v) = (src.string)(&format!(r"HKLM\{WINLOGON}"), "Taskman")
        && !v.trim().is_empty()
    {
        out.push(deviation(
            &format!(r"HKLM\{WINLOGON}"),
            "Taskman",
            &v,
            "Substitui o Gerenciador de Tarefas ao fazer login (valor sem uso legítimo comum)",
        ));
    }

    // Pacotes de autenticação (LSA): rodam dentro do processo mais protegido do Windows.
    const AUTH_OK: &[&str] = &["msv1_0"];
    const SECURITY_OK: &[&str] = &[
        "", "kerberos", "msv1_0", "schannel", "wdigest", "tspkg", "pku2u", "cloudap",
    ];
    const NOTIFY_OK: &[&str] = &["scecli", "rassfm"];
    for (name, ok) in [
        ("Authentication Packages", AUTH_OK),
        ("Security Packages", SECURITY_OK),
        ("Notification Packages", NOTIFY_OK),
    ] {
        if let Some(entries) = (src.multi)(&format!(r"HKLM\{LSA}"), name) {
            for e in entries
                .iter()
                .flat_map(|e| e.split([',', ' ']))
                .map(|e| e.trim().trim_matches('"'))
                .filter(|e| !e.is_empty())
            {
                if !ok.contains(&e.to_lowercase().as_str()) {
                    out.push(deviation(
                        &format!(r"HKLM\{LSA}"),
                        name,
                        e,
                        "Pacote de autenticação fora da lista padrão (carrega dentro do LSASS)",
                    ));
                }
            }
        }
    }

    // Extensões do Explorer. BHO é tecnologia do Internet Explorer: hoje quase só adware usa.
    for base in [
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects".to_string(),
        r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects".to_string(),
    ] {
        for id in (src.subkeys)(&base) {
            let dll = (src.clsid)(&id).unwrap_or_else(|| "(classe sem arquivo no registro)".into());
            out.push(deviation(&base, &id, &dll, "Browser Helper Object (extensão do Internet Explorer, hoje usada quase só por adware)"));
        }
    }
    let hooks = format!(r"HKLM\{EXPLORER}\ShellExecuteHooks");
    for id in (src.values)(&hooks) {
        let dll = (src.clsid)(&id).unwrap_or_default();
        out.push(deviation(
            &hooks,
            &id,
            &dll,
            "Hook que vê todo programa aberto pelo Explorer (uso legítimo é raro)",
        ));
    }
    let delay = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad";
    for name in (src.values)(delay) {
        let id = (src.string)(delay, &name).unwrap_or_default();
        if let Some(dll) = (src.clsid)(&id)
            && !is_system_file(&dll)
        {
            out.push(deviation(
                delay,
                &name,
                &dll,
                "Objeto carregado com o Explorer e fora da pasta do Windows",
            ));
        }
    }

    // Outros pontos de carga clássicos (lista do Autoruns e MITRE ATT&CK T1546/T1547/T1037/T1112):
    // valores que o Windows deixa vazios ou aponta para a pasta do sistema.
    let session = format!(r"HKLM\{SESSION_MANAGER}\AppCertDLLs");
    for name in (src.values)(&session) {
        let dll = (src.string)(&session, &name).unwrap_or_default();
        out.push(deviation(
            &session,
            &name,
            &dll,
            "DLL carregada em todo programa que cria processos (AppCertDLLs fica vazio no Windows)",
        ));
    }
    for (key, name, why) in [
        (
            r"HKLM\SOFTWARE\Microsoft\Command Processor",
            "AutoRun",
            "Comando executado toda vez que um cmd.exe abre (uso legítimo é raro)",
        ),
        (
            r"HKCU\SOFTWARE\Microsoft\Command Processor",
            "AutoRun",
            "Comando executado toda vez que um cmd.exe abre (uso legítimo é raro)",
        ),
        (
            r"HKCU\Environment",
            "UserInitMprLogonScript",
            "Script executado no login (técnica de persistência; uso legítimo é raro)",
        ),
    ] {
        if let Some(v) = (src.string)(key, name).filter(|v| !v.trim().is_empty()) {
            out.push(deviation(key, name, &v, why));
        }
    }
    let desktop = r"HKCU\Control Panel\Desktop";
    if let Some(v) =
        (src.string)(desktop, "SCRNSAVE.EXE").filter(|v| !v.trim().is_empty() && !is_system_file(v))
    {
        out.push(deviation(desktop, "SCRNSAVE.EXE", &v, "Protetor de tela fora da pasta do Windows (um .scr é um programa e roda sem o usuário pedir)"));
    }
    let times = r"HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders";
    for id in (src.subkeys)(times) {
        let key = format!(r"{times}\{id}");
        if let Some(dll) = (src.string)(&key, "DllName").filter(|d| !is_system_file(d)) {
            out.push(deviation(
                &key,
                "DllName",
                &dll,
                "Provedor de hora do Windows apontando para fora da pasta do sistema",
            ));
        }
    }
    // Monitores de impressão e ajudantes do netsh guardam só o nome da DLL (pasta do sistema);
    // um caminho completo fora dela é o desvio.
    let monitors = r"HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors";
    for id in (src.subkeys)(monitors) {
        let key = format!(r"{monitors}\{id}");
        if let Some(dll) =
            (src.string)(&key, "Driver").filter(|d| d.contains('\\') && !is_system_file(d))
        {
            out.push(deviation(
                &key,
                "Driver",
                &dll,
                "Monitor de impressão carregado de fora da pasta do Windows (roda como SYSTEM)",
            ));
        }
    }
    let netsh = r"HKLM\SOFTWARE\Microsoft\NetSh";
    for name in (src.values)(netsh) {
        let dll = (src.string)(netsh, &name).unwrap_or_default();
        if dll.contains('\\') && !is_system_file(&dll) {
            out.push(deviation(
                netsh,
                &name,
                &dll,
                "Ajudante do netsh carregado de fora da pasta do Windows",
            ));
        }
    }
    // Active Setup roda o StubPath uma vez por usuário; muito programa legítimo usa, então só o que já parece malware.
    let setup = r"HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components";
    for id in (src.subkeys)(setup) {
        let key = format!(r"{setup}\{id}");
        if let Some(v) = (src.string)(&key, "StubPath")
            && classify(&v).0 == Severity::High
        {
            out.push(deviation(
                &key,
                "StubPath",
                &v,
                "Active Setup executando um comando com padrão de malware",
            ));
        }
    }

    // SilentProcessExit: roda um programa quando outro termina (T1546.012).
    let spe = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit";
    for id in (src.subkeys)(spe) {
        let key = format!(r"{spe}\{id}");
        if let Some(v) = (src.string)(&key, "MonitorProcess").filter(|v| !v.trim().is_empty()) {
            out.push(deviation(&key, "MonitorProcess", &v, "Programa executado quando outro programa termina (técnica de persistência; uso legítimo é raro)"));
        }
    }

    // Sequestro de COM por usuário (T1546.015): o HKCU vale antes do HKLM, então basta apontar uma classe para uma DLL sua.
    let classes = r"HKCU\Software\Classes\CLSID";
    for id in (src.subkeys)(classes) {
        for server in ["InprocServer32", "LocalServer32"] {
            let key = format!(r"{classes}\{id}\{server}");
            if let Some(v) = (src.string)(&key, "").filter(|v| classify(v).0 != Severity::Info) {
                out.push(deviation(&key, &id, &v, "Classe COM do usuário apontando para um arquivo com padrão suspeito (pode substituir a classe do sistema)"));
            }
        }
    }

    // Suplementos do Office (T1137): o Perf do Office Test carrega uma DLL em todo Office; nada legítimo usa.
    let perf = r"HKCU\Software\Microsoft\Office Test\Special\Perf";
    if let Some(v) = (src.string)(perf, "").filter(|v| !v.trim().is_empty()) {
        out.push(deviation(perf, "(padrão)", &v, "DLL carregada em todo programa do Office (chave de teste da Microsoft, usada por malware)"));
    }
    for app in ["Word", "Excel", "Outlook", "PowerPoint"] {
        let base = format!(r"HKCU\Software\Microsoft\Office\{app}\Addins");
        for id in (src.subkeys)(&base) {
            let key = format!(r"{base}\{id}");
            let target = (src.string)(&key, "Manifest").or_else(|| (src.clsid)(&id));
            if let Some(v) = target.filter(|v| classify(v).0 != Severity::Info) {
                out.push(deviation(
                    &key,
                    &id,
                    &v,
                    "Suplemento do Office com padrão suspeito",
                ));
            }
        }
    }

    // Winsock: DLL carregada por todo programa que usa rede. Só o caminho fora da pasta do sistema é desvio,
    // mas antivírus e VPNs antigos também instalam LSP, então é indício e não veredito.
    let catalog = r"HKLM\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters";
    for id in (src.subkeys)(&format!(r"{catalog}\Protocol_Catalog9\Catalog_Entries")) {
        let key = format!(r"{catalog}\Protocol_Catalog9\Catalog_Entries\{id}");
        if let Some(bytes) = (src.binary)(&key, "PackedCatalogItem") {
            let dll = leading_text(&bytes);
            if !dll.is_empty() && !is_system_file(&dll) {
                out.push(deviation(&key, &id, &dll, "Provedor de serviço do Winsock (LSP) fora da pasta do Windows: vê o tráfego de rede de todos os programas"));
            }
        }
    }
    for id in (src.subkeys)(&format!(r"{catalog}\NameSpace_Catalog5\Catalog_Entries")) {
        let key = format!(r"{catalog}\NameSpace_Catalog5\Catalog_Entries\{id}");
        if let Some(dll) = (src.string)(&key, "LibraryPath").filter(|d| !is_system_file(d)) {
            out.push(deviation(
                &key,
                &id,
                &dll,
                "Provedor de nomes do Winsock fora da pasta do Windows",
            ));
        }
    }

    // Arquivos .ini herdados do Windows antigo: a seção [windows] load=/run= e o shell= do system.ini.
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    if let Some(ini) = (src.file)(&format!(r"{root}\win.ini")) {
        for key in ["load", "run"] {
            if let Some(v) = ini_value(&ini, "windows", key).filter(|v| !v.is_empty()) {
                out.push(deviation(&format!(r"{root}\win.ini [windows]"), key, &v, "Programa iniciado pelo win.ini (herança do Windows antigo; hoje só malware usa)"));
            }
        }
    }
    if let Some(ini) = (src.file)(&format!(r"{root}\system.ini"))
        && let Some(v) =
            ini_value(&ini, "boot", "shell").filter(|v| !v.eq_ignore_ascii_case("explorer.exe"))
    {
        out.push(deviation(
            &format!(r"{root}\system.ini [boot]"),
            "shell",
            &v,
            "O shell do system.ini não é o explorer.exe",
        ));
    }
    out
}

fn root_and_path(full: &str) -> (winreg::HKEY, &str) {
    match full.split_once('\\') {
        Some(("HKLM", p)) => (HKEY_LOCAL_MACHINE, p),
        Some((_, p)) => (HKEY_CURRENT_USER, p),
        None => (HKEY_LOCAL_MACHINE, full),
    }
}

pub fn scan() -> Vec<Finding> {
    let string = |key: &str, name: &str| {
        let (h, p) = root_and_path(key);
        RegKey::predef(h)
            .open_subkey(p)
            .ok()?
            .get_value::<String, _>(name)
            .ok()
    };
    let multi = |key: &str, name: &str| {
        let (h, p) = root_and_path(key);
        RegKey::predef(h)
            .open_subkey(p)
            .ok()?
            .get_value::<Vec<String>, _>(name)
            .ok()
    };
    let subkeys = |key: &str| {
        let (h, p) = root_and_path(key);
        RegKey::predef(h)
            .open_subkey(p)
            .map(|k| k.enum_keys().flatten().collect())
            .unwrap_or_default()
    };
    let values = |key: &str| {
        let (h, p) = root_and_path(key);
        RegKey::predef(h)
            .open_subkey(p)
            .map(|k| k.enum_values().flatten().map(|(n, _)| n).collect())
            .unwrap_or_default()
    };
    let binary = |key: &str, name: &str| {
        let (h, p) = root_and_path(key);
        RegKey::predef(h)
            .open_subkey(p)
            .ok()?
            .get_raw_value(name)
            .ok()
            .map(|v| v.bytes)
    };
    let file = |path: &str| {
        std::fs::read(path)
            .ok()
            .map(|b| String::from_utf8_lossy(&b).into_owned())
    };
    let mut found = evaluate(&Source {
        string: &string,
        multi: &multi,
        subkeys: &subkeys,
        values: &values,
        clsid: &super::tasks_win::resolve_clsid,
        file: &file,
        binary: &binary,
    });
    downgrade_extensions(&mut found);
    found
}

const SIGNED_REASON: &str = "Extensão do Explorer/navegador com assinatura digital válida";
const ORPHAN_CLASS_REASON: &str =
    "Registro de extensão sem arquivo (resto de um programa removido; inofensivo)";

fn is_extension(f: &Finding) -> bool {
    [
        "Browser Helper Objects",
        "ShellExecuteHooks",
        "ShellServiceObjectDelayLoad",
    ]
    .iter()
    .any(|k| f.location.contains(k))
}

/// Extensão assinada (Edge, Java...) deixa de ser suspeita; registro sem arquivo é só sobra.
/// O que continua sem assinatura segue SUSPEITO. Achado ALTO (padrão de malware) nunca é rebaixado.
fn downgrade_extensions(found: &mut [Finding]) {
    let paths: Vec<String> = found
        .iter()
        .filter(|f| is_extension(f) && f.severity == Severity::Suspicious)
        .filter_map(|f| crate::trust::exe_path(&f.target).map(str::to_string))
        .collect();
    let signed = crate::trust::signed_paths(&paths);
    for f in found
        .iter_mut()
        .filter(|f| is_extension(f) && f.severity == Severity::Suspicious)
    {
        if f.target.starts_with("(classe sem arquivo") {
            (f.severity, f.reason) = (Severity::Info, ORPHAN_CLASS_REASON);
        } else if let Some(p) = crate::trust::exe_path(&f.target)
            && signed.contains(&p.to_lowercase())
        {
            (f.severity, f.reason) = (Severity::Info, SIGNED_REASON);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[derive(Default)]
    struct Fake {
        strings: HashMap<(String, String), String>,
        multis: HashMap<(String, String), Vec<String>>,
        subkeys: HashMap<String, Vec<String>>,
        clsids: HashMap<String, String>,
        files: HashMap<String, String>,
        binaries: HashMap<(String, String), Vec<u8>>,
    }

    impl Fake {
        fn run(&self) -> Vec<Finding> {
            let k = |a: &str, b: &str| (a.to_string(), b.to_string());
            let string = |a: &str, b: &str| self.strings.get(&k(a, b)).cloned();
            let multi = |a: &str, b: &str| self.multis.get(&k(a, b)).cloned();
            let subkeys = |a: &str| self.subkeys.get(a).cloned().unwrap_or_default();
            let values = |_: &str| Vec::new();
            let clsid = |id: &str| self.clsids.get(id).cloned();
            let file = |p: &str| self.files.get(p).cloned();
            let binary = |a: &str, b: &str| self.binaries.get(&k(a, b)).cloned();
            evaluate(&Source {
                binary: &binary,
                string: &string,
                multi: &multi,
                subkeys: &subkeys,
                values: &values,
                clsid: &clsid,
                file: &file,
            })
        }
    }

    fn key(rest: &str, name: &str) -> (String, String) {
        (format!(r"HKLM\{rest}"), name.to_string())
    }

    #[test]
    fn a_default_system_has_no_findings() {
        let mut f = Fake::default();
        f.multis.insert(
            key(SESSION_MANAGER, "BootExecute"),
            vec!["autocheck autochk *".into()],
        );
        f.multis
            .insert(key(SESSION_MANAGER, "SetupExecute"), vec![]);
        f.strings
            .insert(key(SAFEBOOT, "AlternateShell"), "cmd.exe".into());
        f.multis
            .insert(key(LSA, "Authentication Packages"), vec!["msv1_0".into()]);
        f.multis
            .insert(key(LSA, "Notification Packages"), vec!["scecli".into()]);
        f.multis
            .insert(key(LSA, "Security Packages"), vec!["\"\"".replace('"', "")]);
        assert!(f.run().is_empty());
    }

    #[test]
    fn extra_boot_programs_shell_and_lsa_packages_are_reported() {
        let mut f = Fake::default();
        f.multis.insert(
            key(SESSION_MANAGER, "BootExecute"),
            vec![
                "autocheck autochk *".into(),
                r"C:\Users\x\AppData\evil.exe".into(),
            ],
        );
        f.strings
            .insert(key(SAFEBOOT, "AlternateShell"), "malware.exe".into());
        f.strings
            .insert(key(WINLOGON, "Taskman"), r"C:\ProgramData\tm.exe".into());
        f.multis.insert(
            key(LSA, "Notification Packages"),
            vec!["scecli".into(), "evilpkg".into()],
        );
        let found = f.run();
        let names: Vec<_> = found.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(
            names.iter().filter(|n| **n == "BootExecute").count(),
            1,
            "{names:?}"
        );
        for expected in ["AlternateShell", "Taskman", "Notification Packages"] {
            assert!(names.contains(&expected), "{expected}: {names:?}");
        }
        assert!(
            found
                .iter()
                .all(|x| x.severity >= Severity::Suspicious && x.scanner == SCANNER)
        );
    }

    #[test]
    fn extra_load_points_are_reported_and_defaults_are_not() {
        let mut f = Fake::default();
        let hk = |k: &str, n: &str| (k.to_string(), n.to_string());
        f.strings.insert(
            hk(r"HKLM\SOFTWARE\Microsoft\Command Processor", "AutoRun"),
            r"C:\Users\x\AppData\a.bat".into(),
        );
        f.strings.insert(
            hk(r"HKCU\Environment", "UserInitMprLogonScript"),
            "   ".into(),
        );
        f.strings.insert(
            hk(r"HKCU\Control Panel\Desktop", "SCRNSAVE.EXE"),
            r"C:\Windows\System32\Mystify.scr".into(),
        );
        let mon = r"HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors";
        f.subkeys
            .insert(mon.into(), vec!["Evil".into(), "Local Port".into()]);
        f.strings.insert(
            hk(&format!(r"{mon}\Evil"), "Driver"),
            r"C:\ProgramData\m.dll".into(),
        );
        f.strings.insert(
            hk(&format!(r"{mon}\Local Port"), "Driver"),
            "localspl.dll".into(),
        );
        let found = f.run();
        let names: Vec<_> = found.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(names, ["AutoRun", "Driver"], "{found:?}");
    }

    #[test]
    fn winsock_com_office_and_silent_exit_entries_are_reported() {
        let mut f = Fake::default();
        let hk = |k: &str, n: &str| (k.to_string(), n.to_string());
        let spe = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit";
        f.subkeys.insert(spe.into(), vec!["notepad.exe".into()]);
        f.strings.insert(
            hk(&format!(r"{spe}\notepad.exe"), "MonitorProcess"),
            r"C:\ProgramData\m.exe".into(),
        );
        let classes = r"HKCU\Software\Classes\CLSID";
        f.subkeys
            .insert(classes.into(), vec!["{AAAA}".into(), "{BBBB}".into()]);
        f.strings.insert(
            hk(&format!(r"{classes}\{{AAAA}}\InprocServer32"), ""),
            "powershell -enc AAAA".into(),
        );
        f.strings.insert(
            hk(&format!(r"{classes}\{{BBBB}}\InprocServer32"), ""),
            r"C:\Program Files\App\ok.dll".into(),
        );
        f.strings.insert(
            hk(r"HKCU\Software\Microsoft\Office Test\Special\Perf", ""),
            r"C:\Users\x\p.dll".into(),
        );
        let wsock = r"HKLM\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries";
        f.subkeys.insert(
            wsock.into(),
            vec!["000000000001".into(), "000000000002".into()],
        );
        f.binaries.insert(
            hk(&format!(r"{wsock}\000000000001"), "PackedCatalogItem"),
            b"%SystemRoot%\\system32\\mswsock.dll\0\0junk".to_vec(),
        );
        f.binaries.insert(
            hk(&format!(r"{wsock}\000000000002"), "PackedCatalogItem"),
            b"C:\\Users\\x\\lsp.dll\0junk".to_vec(),
        );
        let found = f.run();
        let mut names: Vec<_> = found.iter().map(|x| x.name.as_str()).collect();
        names.sort();
        assert_eq!(
            names,
            ["(padrão)", "000000000002", "MonitorProcess", "{AAAA}"],
            "{found:?}"
        );
    }

    #[test]
    fn browser_helper_objects_are_reported_with_their_dll() {
        let mut f = Fake::default();
        let base =
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects";
        f.subkeys.insert(base.into(), vec!["{AAAA}".into()]);
        f.clsids
            .insert("{AAAA}".into(), r"C:\Program Files\Toolbar\bho.dll".into());
        let found = f.run();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].target, r"C:\Program Files\Toolbar\bho.dll");
    }

    #[test]
    fn old_ini_files_are_checked_for_load_run_and_shell() {
        let mut f = Fake::default();
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        f.files.insert(
            format!(r"{root}\win.ini"),
            "[fonts]\n[windows]\nLOAD = c:\\x\\a.exe\nrun=\n".into(),
        );
        f.files.insert(
            format!(r"{root}\system.ini"),
            "[boot]\nshell=evil.exe\n".into(),
        );
        let found = f.run();
        assert_eq!(found.len(), 2, "{found:?}");
        let mut ok = Fake::default();
        ok.files.insert(
            format!(r"{root}\system.ini"),
            "[boot]\nShell=Explorer.exe\n".into(),
        );
        assert!(ok.run().is_empty());
    }

    #[test]
    fn ini_value_is_case_insensitive_and_scoped_to_its_section() {
        let text = "[other]\nload=x\n[Windows]\nLoad=y\n";
        assert_eq!(ini_value(text, "windows", "load").as_deref(), Some("y"));
        assert_eq!(ini_value(text, "boot", "load"), None);
    }

    #[test]
    fn the_real_scan_runs() {
        for f in scan() {
            assert_eq!(f.scanner, SCANNER);
            assert!(!f.reason.is_empty());
        }
    }
}
