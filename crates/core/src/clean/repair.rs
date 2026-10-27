//! Reparos: em vez de apagar, devolve ao PADRÃO um valor do sistema que foi adulterado (UAC, Gerenciador de
//! Tarefas, Defender, proxy, Winlogon, BootExecute...) ou neutraliza uma linha do arquivo hosts.
//!
//! Segurança: só mexe em pares (chave, valor) de uma lista fixa (`FIXES`); o `undo` usa a MESMA lista, então
//! um manifesto adulterado não consegue fazer o Oblivion gravar em outro lugar do registro. Antes de mudar,
//! guarda o valor antigo no manifesto e exporta a chave para um `.reg` na quarentena.
use std::path::{Path, PathBuf};

use crate::finding::Finding;

use super::Plan;

/// O que fazer com o valor para voltar ao padrão.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fix {
    /// O padrão é o valor não existir.
    Delete,
    Str(String),
    Multi(Vec<String>),
    Dword(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegFix {
    pub hive: &'static str,
    pub subkey: String,
    pub name: &'static str,
    pub fix: Fix,
    /// Só para serviços: o `ImagePath` visto no scan. Se mudou, o serviço não é mais o mesmo e nada é alterado.
    pub expect_image: Option<String>,
}

impl RegFix {
    /// Nome do serviço, se este reparo desativa um serviço (`Services\<nome>`, valor `Start`).
    pub fn service(&self) -> Option<&str> {
        self.subkey
            .strip_prefix(SERVICES_PREFIX)
            .filter(|_| self.name == "Start")
    }

    pub fn describe(&self) -> String {
        if let Some(svc) = self.service() {
            return format!(
                "Desativar o serviço \"{svc}\" (para de iniciar com o Windows e é parado agora; o valor antigo fica guardado e o `undo` devolve)"
            );
        }
        let to = match &self.fix {
            Fix::Delete => "removê-lo (o padrão é não existir)".to_string(),
            Fix::Str(s) => format!("\"{s}\""),
            Fix::Multi(v) => format!("\"{}\"", v.join(" ")),
            Fix::Dword(n) => n.to_string(),
        };
        format!(
            "Restaurar o valor \"{}\" de {}\\{} para o padrão: {to} (o valor atual fica guardado na quarentena)",
            self.name, self.hive, self.subkey
        )
    }
}

/// Serviços essenciais do Windows: desativar qualquer um deixaria o sistema sem iniciar ou sem rede.
const CRITICAL_SERVICES: &[&str] = &[
    "rpcss",
    "rpceptmapper",
    "dcomlaunch",
    "lsm",
    "samss",
    "eventlog",
    "plugplay",
    "power",
    "profsvc",
    "schedule",
    "winmgmt",
    "wininit",
    "lanmanworkstation",
    "lanmanserver",
    "dhcp",
    "dnscache",
    "nsi",
    "bfe",
    "mpssvc",
    "cryptsvc",
    "trustedinstaller",
    "wuauserv",
    "windefend",
    "wscsvc",
    "sens",
    "themes",
    "audiosrv",
    "audioendpointbuilder",
    "gpsvc",
    "usermanager",
    "tabletinputservice",
    "keyiso",
    "nlasvc",
    "netlogon",
    "seclogon",
    "sysmain",
    "time",
    "w32time",
    "browser",
    "bits",
];

const SERVICES_PREFIX: &str = r"SYSTEM\CurrentControlSet\Services\";

/// Reparo "desativar serviço": `Start = 4`. Só para nomes simples e fora da lista de serviços essenciais.
fn service_fix(hive: &str, subkey: &str, name: &str, image: Option<String>) -> Option<RegFix> {
    let svc = subkey
        .get(..SERVICES_PREFIX.len())
        .filter(|p| p.eq_ignore_ascii_case(SERVICES_PREFIX))
        .map(|_| &subkey[SERVICES_PREFIX.len()..])?;
    let plain = !svc.is_empty()
        && svc
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-.".contains(c));
    (hive.eq_ignore_ascii_case("HKLM")
        && name.eq_ignore_ascii_case("Start")
        && plain
        && !CRITICAL_SERVICES.contains(&svc.to_lowercase().as_str()))
    .then(|| RegFix {
        hive: "HKLM",
        subkey: format!("{SERVICES_PREFIX}{svc}"),
        name: "Start",
        fix: Fix::Dword(4),
        expect_image: image,
    })
}

const POLICIES_SYSTEM: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
const DEFENDER_RT: &str = r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection";
const FIREWALL: &str = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";
const INTERNET: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
const SESSION: &str = r"SYSTEM\CurrentControlSet\Control\Session Manager";
const WINLOGON: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";

/// (hive, chave, valor, correção). A lista inteira é a única coisa que o Oblivion reescreve fora das chaves Run.
fn table() -> Vec<(&'static str, String, &'static str, Fix)> {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let mut t: Vec<(&'static str, String, &'static str, Fix)> = vec![
        ("HKLM", POLICIES_SYSTEM.into(), "EnableLUA", Fix::Dword(1)),
        (
            "HKLM",
            POLICIES_SYSTEM.into(),
            "ConsentPromptBehaviorAdmin",
            Fix::Dword(5),
        ),
        (
            "HKLM",
            POLICIES_SYSTEM.into(),
            "DisableTaskMgr",
            Fix::Delete,
        ),
        (
            "HKCU",
            POLICIES_SYSTEM.into(),
            "DisableTaskMgr",
            Fix::Delete,
        ),
        (
            "HKLM",
            POLICIES_SYSTEM.into(),
            "DisableRegistryTools",
            Fix::Delete,
        ),
        (
            "HKCU",
            POLICIES_SYSTEM.into(),
            "DisableRegistryTools",
            Fix::Delete,
        ),
        (
            "HKCU",
            r"SOFTWARE\Policies\Microsoft\Windows\System".into(),
            "DisableCMD",
            Fix::Delete,
        ),
        (
            "HKCU",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer".into(),
            "NoFolderOptions",
            Fix::Delete,
        ),
        (
            "HKLM",
            r"SOFTWARE\Policies\Microsoft\Windows Defender".into(),
            "DisableAntiSpyware",
            Fix::Delete,
        ),
        (
            "HKLM",
            r"SOFTWARE\Microsoft\Windows Defender".into(),
            "DisableAntiSpyware",
            Fix::Delete,
        ),
        (
            "HKLM",
            DEFENDER_RT.into(),
            "DisableRealtimeMonitoring",
            Fix::Delete,
        ),
        (
            "HKLM",
            DEFENDER_RT.into(),
            "DisableBehaviorMonitoring",
            Fix::Delete,
        ),
        (
            "HKLM",
            DEFENDER_RT.into(),
            "DisableOnAccessProtection",
            Fix::Delete,
        ),
        (
            "HKLM",
            r"SOFTWARE\Policies\Microsoft\Windows\System".into(),
            "EnableSmartScreen",
            Fix::Delete,
        ),
        (
            "HKLM",
            r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU".into(),
            "NoAutoUpdate",
            Fix::Delete,
        ),
        ("HKCU", INTERNET.into(), "ProxyEnable", Fix::Dword(0)),
        ("HKCU", INTERNET.into(), "AutoConfigURL", Fix::Delete),
        (
            "HKLM",
            SESSION.into(),
            "BootExecute",
            Fix::Multi(vec!["autocheck autochk *".into()]),
        ),
        ("HKLM", SESSION.into(), "SetupExecute", Fix::Delete),
        (
            "HKLM",
            r"SYSTEM\CurrentControlSet\Control\SafeBoot".into(),
            "AlternateShell",
            Fix::Str("cmd.exe".into()),
        ),
        ("HKLM", WINLOGON.into(), "Taskman", Fix::Delete),
        (
            "HKLM",
            WINLOGON.into(),
            "Shell",
            Fix::Str("explorer.exe".into()),
        ),
        (
            "HKLM",
            WINLOGON.into(),
            "Userinit",
            Fix::Str(format!(r"{root}\system32\userinit.exe,")),
        ),
    ];
    for profile in ["StandardProfile", "DomainProfile", "PublicProfile"] {
        t.push((
            "HKLM",
            format!(r"{FIREWALL}\{profile}"),
            "EnableFirewall",
            Fix::Dword(1),
        ));
    }
    t
}

/// A correção prevista para este par, se ele estiver na lista fixa (sem diferenciar maiúsculas).
pub fn fix_for(hive: &str, subkey: &str, name: &str) -> Option<RegFix> {
    if let Some(svc) = service_fix(hive, subkey, name, None) {
        return Some(svc);
    }
    table().into_iter().find_map(|(h, s, n, fix)| {
        (h.eq_ignore_ascii_case(hive)
            && s.eq_ignore_ascii_case(subkey)
            && n.eq_ignore_ascii_case(name))
        .then_some(RegFix {
            hive: h,
            subkey: s,
            name: n,
            fix,
            expect_image: None,
        })
    })
}

/// O valor guardado no manifesto tem o tipo (e o tamanho) certo para o item? `vtype` é o número do registro
/// (1 texto, 2 texto expansível, 3 binário, 4 DWORD, 7 lista de textos). Serviço: `Start` só vai de 0 a 4.
pub fn restorable(fix: &RegFix, name: &str, vtype: u32, bytes: &[u8]) -> bool {
    let dword = || -> Option<u32> { Some(u32::from_le_bytes(bytes.try_into().ok()?)) };
    match &fix.fix {
        Fix::Dword(_) => vtype == 4 && dword().is_some_and(|d| name != "Start" || d <= 4),
        Fix::Multi(_) => vtype == 7,
        Fix::Str(_) => matches!(vtype, 1 | 2),
        // O padrão é o valor não existir: o que havia antes pode ser texto ou número.
        Fix::Delete => matches!(vtype, 1 | 2 | 4 | 7),
    }
}

/// O `undo` só restaura pares que o Oblivion poderia ter alterado.
pub fn is_allowed(hive: &str, subkey: &str, name: &str) -> bool {
    fix_for(hive, subkey, name).is_some()
}

/// Plano de reparo para um achado, se existir um padrão seguro para ele.
pub fn plan_for(f: &Finding) -> Option<Plan> {
    match f.scanner {
        "seguranca" | "baseline" | "persistencia" => {
            let (hive, subkey) = f.location.split_once('\\')?;
            // Serviço do Windows de início automático: desativa em vez de apagar (reversível).
            if f.scanner == "persistencia"
                && subkey.eq_ignore_ascii_case(r"SYSTEM\CurrentControlSet\Services")
                && !f.name.contains(' ')
            {
                let sub = format!("{SERVICES_PREFIX}{}", f.name);
                return service_fix(hive, &sub, "Start", Some(f.target.clone())).map(Plan::Repair);
            }
            // Em "persistencia" só o Winlogon entra aqui; as chaves Run seguem o plano de remoção.
            if f.scanner == "persistencia" && !subkey.eq_ignore_ascii_case(WINLOGON) {
                return None;
            }
            fix_for(hive, subkey, &f.name).map(Plan::Repair)
        }
        "rede" => {
            if f.name == "Entrada do hosts" {
                return Some(Plan::Hosts {
                    entry: f.target.clone(),
                });
            }
            let (hive, subkey) = f.location.split_once('\\')?;
            if !subkey.eq_ignore_ascii_case(INTERNET) {
                return None;
            }
            let name = if f.name == "Proxy ativado" {
                "ProxyEnable"
            } else {
                "AutoConfigURL"
            };
            fix_for(hive, subkey, name).map(Plan::Repair)
        }
        _ => None,
    }
}

// ---------- hosts (qualquer sistema) ----------

pub(crate) fn hosts_path() -> PathBuf {
    crate::scanners::hosts_path()
}

/// Comenta as linhas do hosts cujo "IP nome" é o `entry`. `None` se nenhuma linha casar.
/// Trabalha em BYTES: só as linhas que casam mudam; o resto do arquivo (fim de linha CRLF, acentos de outra
/// codificação, BOM) fica exatamente como estava.
pub fn comment_out(content: &[u8], entry: &str) -> Option<Vec<u8>> {
    let want: Vec<String> = entry.split_whitespace().map(str::to_lowercase).collect();
    if want.len() < 2 {
        return None;
    }
    let mut changed = false;
    let mut out = Vec::with_capacity(content.len() + 32);
    for raw in content.split_inclusive(|b| *b == b'\n') {
        let line = String::from_utf8_lossy(raw);
        let body = line.split('#').next().unwrap_or("");
        let toks: Vec<String> = body.split_whitespace().map(str::to_lowercase).collect();
        let hit = !line.trim_start().starts_with('#')
            && toks.len() >= 2
            && toks[0] == want[0]
            && toks[1..].iter().any(|h| *h == want[1]);
        if hit {
            changed = true;
            out.extend_from_slice(b"# [Oblivion] ");
        }
        out.extend_from_slice(raw);
    }
    changed.then_some(out)
}
/// Ordem do reparo do hosts: guarda o arquivo inteiro antes, reescreve, e confere.
pub(super) fn repair_hosts(entry: &str, dir: &Path) -> super::Exec {
    use super::{Exec, Outcome};
    use serde_json::json;
    let fail = |why: String| Exec {
        outcome: Outcome::Failed(why),
        note: String::new(),
        undo: Vec::new(),
    };
    let path = hosts_path();
    let Ok(bytes) = std::fs::read(&path) else {
        return Exec {
            outcome: Outcome::Skipped("não consegui ler o arquivo hosts".into()),
            note: String::new(),
            undo: Vec::new(),
        };
    };
    if entry.split_whitespace().count() < 2 {
        return Exec {
            outcome: Outcome::Skipped("entrada do hosts inválida".into()),
            note: String::new(),
            undo: Vec::new(),
        };
    }
    let Some(new) = comment_out(&bytes, entry) else {
        return Exec {
            outcome: Outcome::Skipped("a linha já não está no hosts".into()),
            note: String::new(),
            undo: Vec::new(),
        };
    };
    let folder = dir.join("files");
    let mut backup = folder.join("hosts.bak");
    let mut n = 1;
    if let Err(e) = std::fs::create_dir_all(&folder) {
        return fail(format!("não consegui criar a quarentena: {e}"));
    }
    while backup.exists() {
        backup = folder.join(format!("hosts.{n}.bak"));
        n += 1;
    }
    if let Err(e) = std::fs::write(&backup, &bytes) {
        return fail(format!("não consegui guardar o hosts na quarentena: {e}"));
    }
    if let Err(e) = std::fs::write(&path, &new) {
        let _ = std::fs::remove_file(&backup);
        return fail(format!("não consegui gravar o hosts (administrador?): {e}"));
    }
    Exec {
        outcome: Outcome::Done,
        note: format!(
            "Linha comentada no hosts; original guardado em {}.",
            backup.display()
        ),
        undo: vec![
            json!({"kind": "hosts", "from": backup, "to": path, "applied_sha256": sha256_hex(&new)}),
        ],
    }
}

/// Usado pelo `undo`: devolve o hosts guardado, só para o próprio arquivo hosts.
pub(crate) fn restore_hosts(dir: &Path, entry: &serde_json::Value) -> Result<(), String> {
    let from = Path::new(entry["from"].as_str().ok_or("registro sem origem")?);
    let to = Path::new(entry["to"].as_str().ok_or("registro sem destino")?);
    if to != hosts_path() {
        return Err("o destino não é o arquivo hosts: não restaurei".into());
    }
    if !super::secure::is_inside(dir, from) || !from.is_file() {
        return Err(
            "a cópia do hosts não está dentro da quarentena (manifesto adulterado?)".into(),
        );
    }
    let applied = entry["applied_sha256"]
        .as_str()
        .ok_or("registro sem o estado aplicado")?;
    restore_if_unchanged(from, to, applied)
}

/// Só devolve o arquivo se ele ainda é exatamente o que o Oblivion gravou; senão apagaria a edição de outra pessoa.
fn restore_if_unchanged(from: &Path, to: &Path, applied_sha256: &str) -> Result<(), String> {
    let current = std::fs::read(to).map_err(|e| format!("não consegui ler o hosts: {e}"))?;
    if sha256_hex(&current) != applied_sha256 {
        return Err("o hosts mudou depois da correção do Oblivion: não sobrescrevi".into());
    }
    std::fs::copy(from, to)
        .map(|_| ())
        .map_err(|e| format!("não consegui restaurar o hosts: {e}"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

// ---------- registro (Windows) ----------

#[cfg(windows)]
pub(super) use win::{repair_value, restore_reg_value};

#[cfg(windows)]
mod win {
    use std::path::Path;

    use serde_json::json;
    use winreg::{RegKey, RegValue, enums::*, types::ToRegValue};

    use super::{Fix, RegFix, fix_for, is_allowed, restorable};
    use crate::clean::{Exec, Outcome};

    fn root(hive: &str) -> Option<winreg::HKEY> {
        match hive {
            "HKLM" => Some(HKEY_LOCAL_MACHINE),
            "HKCU" => Some(HKEY_CURRENT_USER),
            _ => None,
        }
    }

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

    fn desired(fix: &Fix) -> Option<RegValue> {
        match fix {
            Fix::Delete => None,
            Fix::Str(s) => Some(s.as_str().to_reg_value()),
            Fix::Multi(v) => Some(v.to_reg_value()),
            Fix::Dword(n) => Some(n.to_reg_value()),
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn unhex(s: &str) -> Option<Vec<u8>> {
        if !s.len().is_multiple_of(2) {
            return None;
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
            .collect()
    }

    /// Exporta a chave para um .reg na quarentena (rede de segurança extra; o valor também fica no manifesto).
    fn export_key(hive: &str, subkey: &str, dir: &Path) -> Option<std::path::PathBuf> {
        let folder = dir.join("registry");
        std::fs::create_dir_all(&folder).ok()?;
        let mut file = folder.join("backup.reg");
        let mut n = 1;
        while file.exists() {
            file = folder.join(format!("backup.{n}.reg"));
            n += 1;
        }
        let reg = Path::new(&std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()))
            .join(r"System32\reg.exe");
        let ok = crate::sys::command(reg)
            .args(["export", &format!(r"{hive}\{subkey}")])
            .arg(&file)
            .arg("/y")
            .output()
            .is_ok_and(|o| o.status.success());
        ok.then_some(file)
    }

    pub(in crate::clean) fn repair_value(fix: &RegFix, dir: &Path) -> Exec {
        let Some(r) = root(fix.hive) else {
            return skipped("chave de registro desconhecida");
        };
        let key = match RegKey::predef(r).open_subkey_with_flags(&fix.subkey, KEY_READ | KEY_WRITE)
        {
            Ok(k) => k,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return skipped("a chave já não existe");
            }
            Err(e) => return failed(format!("não consegui abrir a chave (administrador?): {e}")),
        };
        // Serviço: confere que é o mesmo do scan (o ImagePath não pode ter mudado).
        if let Some(expected) = &fix.expect_image {
            let current: String = key.get_value("ImagePath").unwrap_or_default();
            if &current != expected {
                return skipped("o serviço mudou desde o scan");
            }
        }
        let old = key.get_raw_value(fix.name).ok();
        let want = desired(&fix.fix);
        match (&old, &want) {
            (None, None) => return skipped("o valor já não existe (já está no padrão)"),
            (Some(o), Some(w)) if o.bytes == w.bytes && o.vtype == w.vtype => {
                return skipped("o valor já está no padrão");
            }
            _ => {}
        }
        // Guarda ANTES de mexer: .reg exportado + o valor antigo no manifesto.
        let exported = export_key(fix.hive, &fix.subkey, dir);
        let undo = json!({
            "kind": "reg_value", "hive": fix.hive, "subkey": fix.subkey, "name": fix.name,
            "existed": old.is_some(),
            "vtype": old.as_ref().map(|o| o.vtype.clone() as u32),
            "data": old.as_ref().map(|o| hex(&o.bytes)),
            // O que o Oblivion deixou lá: o `undo` só desfaz se o valor ainda for exatamente este.
            "applied": want.as_ref().map(|w| hex(&w.bytes)),
        });
        let result = match &want {
            Some(w) => key.set_raw_value(fix.name, w),
            None => key.delete_value(fix.name),
        };
        if let Err(e) = result {
            return failed(format!("não consegui alterar o valor: {e}"));
        }
        let now = key.get_raw_value(fix.name).ok();
        let ok = match &want {
            Some(w) => now.is_some_and(|n| n.bytes == w.bytes),
            None => now.is_none(),
        };
        if !ok {
            return failed("o valor não ficou como esperado depois da alteração".into());
        }
        // Serviço: além de não iniciar mais, para a instância que está rodando agora (se não parar, o Start=4 já vale no próximo boot).
        let stopped = fix.service().map(|svc| {
            crate::sys::command("sc.exe")
                .args(["stop", svc])
                .output()
                .is_ok_and(|o| o.status.success())
        });
        let backup = exported.map_or("sem .reg (valor guardado no manifesto)".to_string(), |p| {
            format!("backup em {}", p.display())
        });
        let extra = match stopped {
            Some(true) => " Serviço parado.",
            Some(false) => {
                " O serviço não foi parado agora (não estava rodando ou exige reiniciar); não inicia mais no próximo boot."
            }
            None => "",
        };
        Exec {
            outcome: Outcome::Done,
            note: format!("Valor restaurado ao padrão; {backup}.{extra}"),
            undo: vec![undo],
        }
    }

    /// Usado pelo `undo`: devolve o valor antigo, só para pares da lista fixa.
    pub(crate) fn restore_reg_value(entry: &serde_json::Value) -> Result<(), String> {
        let get = |k: &str| entry[k].as_str().ok_or_else(|| format!("registro sem {k}"));
        let (hive, subkey, name) = (get("hive")?, get("subkey")?, get("name")?);
        if !is_allowed(hive, subkey, name) {
            return Err("esse valor não está entre os que o Oblivion altera: não restaurei".into());
        }
        let r = root(hive).ok_or("chave desconhecida")?;
        let (key, _) = RegKey::predef(r)
            .create_subkey_with_flags(subkey, KEY_READ | KEY_WRITE)
            .map_err(|e| format!("não consegui abrir a chave: {e}"))?;
        // Se alguém mexeu no valor depois da correção, desfazer sobrescreveria a mudança dele.
        let now = key.get_raw_value(name).ok();
        let still_ours = match (entry.get("applied"), &now) {
            (Some(serde_json::Value::String(a)), Some(n)) => unhex(a).is_some_and(|b| b == n.bytes),
            (Some(serde_json::Value::Null), None) => true,
            _ => false,
        };
        if !still_ours {
            return Err("o valor mudou depois da correção do Oblivion: não sobrescrevi".into());
        }
        if entry["existed"].as_bool().unwrap_or(false) {
            let vtype = entry["vtype"].as_u64().ok_or("registro sem tipo")? as u32;
            let bytes = unhex(entry["data"].as_str().ok_or("registro sem dados")?)
                .ok_or("dados inválidos")?;
            // O manifesto não é confiável: o tipo e o tamanho têm de ser os que esse valor tem de verdade.
            let fix = fix_for(hive, subkey, name).ok_or("valor fora da lista fixa")?;
            if !restorable(&fix, name, vtype, &bytes) {
                return Err(
                    "o valor guardado não tem o tipo esperado para esse item: não restaurei".into(),
                );
            }
            let vtype = match vtype {
                1 => REG_SZ,
                2 => REG_EXPAND_SZ,
                3 => REG_BINARY,
                4 => REG_DWORD,
                7 => REG_MULTI_SZ,
                _ => return Err("tipo de valor não suportado".into()),
            };
            key.set_raw_value(name, &RegValue { bytes, vtype })
                .map_err(|e| format!("não consegui gravar o valor: {e}"))
        } else {
            match key.delete_value(name) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(format!("não consegui remover o valor: {e}")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;

    fn finding(scanner: &'static str, location: &str, name: &str, target: &str) -> Finding {
        Finding {
            scanner,
            location: location.into(),
            name: name.into(),
            target: target.into(),
            severity: Severity::Suspicious,
            reason: "r",
        }
    }

    #[test]
    fn only_listed_pairs_have_a_fix_and_matching_ignores_case() {
        assert!(fix_for("hklm", &POLICIES_SYSTEM.to_lowercase(), "enablelua").is_some());
        assert!(fix_for("HKLM", r"SYSTEM\CurrentControlSet\Services", "ImagePath").is_none());
        assert!(!is_allowed(
            "HKCU",
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            "x"
        ));
    }

    #[test]
    fn findings_from_the_scanners_map_to_repairs() {
        let uac = finding(
            "seguranca",
            &format!(r"HKLM\{POLICIES_SYSTEM}"),
            "EnableLUA",
            "EnableLUA = 0",
        );
        assert!(matches!(plan_for(&uac), Some(Plan::Repair(r)) if r.fix == Fix::Dword(1)));
        let proxy = finding(
            "rede",
            &format!(r"HKCU\{INTERNET}"),
            "Proxy ativado",
            "1.2.3.4:80",
        );
        assert!(matches!(plan_for(&proxy), Some(Plan::Repair(r)) if r.name == "ProxyEnable"));
        let pac = finding(
            "rede",
            &format!(r"HKCU\{INTERNET}"),
            "Script de configuração automática do proxy",
            "http://x",
        );
        assert!(matches!(plan_for(&pac), Some(Plan::Repair(r)) if r.name == "AutoConfigURL"));
        let hosts = finding(
            "rede",
            "C:/Windows/hosts",
            "Entrada do hosts",
            "1.2.3.4 a.com",
        );
        assert!(matches!(plan_for(&hosts), Some(Plan::Hosts { .. })));
        // Chave Run continua com o plano de remoção, e valores fora da lista não ganham reparo.
        let run = finding(
            "persistencia",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "x",
            "c:\\a.exe",
        );
        assert!(plan_for(&run).is_none());
        let other = finding("seguranca", r"HKLM\SOFTWARE\Algo", "Qualquer", "x");
        assert!(plan_for(&other).is_none());
        let sh = finding(
            "persistencia",
            &format!(r"HKLM\{WINLOGON}"),
            "Shell",
            "evil.exe",
        );
        assert!(
            matches!(plan_for(&sh), Some(Plan::Repair(r)) if r.fix == Fix::Str("explorer.exe".into()))
        );
    }

    #[test]
    fn hosts_lines_are_commented_not_deleted_and_only_the_matching_ones() {
        let hosts = "127.0.0.1 localhost\n1.2.3.4 banco.com www.banco.com # x\n5.6.7.8 outro.com\n";
        let out =
            String::from_utf8(comment_out(hosts.as_bytes(), "1.2.3.4 banco.com").unwrap()).unwrap();
        assert!(out.contains("127.0.0.1 localhost\n"));
        assert!(out.contains("# [Oblivion] 1.2.3.4 banco.com www.banco.com # x"));
        assert!(out.contains("\n5.6.7.8 outro.com\n"));
        assert!(comment_out(hosts.as_bytes(), "9.9.9.9 nada.com").is_none());
        // Linha já comentada não conta.
        assert!(comment_out(b"# 1.2.3.4 banco.com\n", "1.2.3.4 banco.com").is_none());
    }

    #[test]
    fn the_rest_of_the_hosts_is_kept_byte_for_byte() {
        // CRLF, acento em outra codificação (0xE9 não é UTF-8 válido) e BOM nas outras linhas não podem mudar.
        let mut original =
            b"\xEF\xBB\xBF# coment\xE9rio\r\n127.0.0.1 localhost\r\n1.2.3.4 banco.com\r\n".to_vec();
        let out = comment_out(&original, "1.2.3.4 banco.com").unwrap();
        original.splice(
            original.len() - b"1.2.3.4 banco.com\r\n".len()..,
            b"# [Oblivion] 1.2.3.4 banco.com\r\n".iter().copied(),
        );
        assert_eq!(out, original);
    }

    #[test]
    fn a_suspicious_service_is_disabled_not_deleted_and_core_services_are_refused() {
        let svc = finding(
            "persistencia",
            r"HKLM\SYSTEM\CurrentControlSet\Services",
            "Updater3",
            r"C:\ProgramData\x\up.exe",
        );
        let Some(Plan::Repair(fix)) = plan_for(&svc) else {
            panic!("devia haver reparo para o serviço");
        };
        assert_eq!((fix.name, &fix.fix), ("Start", &Fix::Dword(4)));
        assert_eq!(fix.service(), Some("Updater3"));
        assert_eq!(
            fix.expect_image.as_deref(),
            Some(r"C:\ProgramData\x\up.exe")
        );
        assert!(fix.describe().contains("Desativar o serviço"));

        // Serviço essencial, nome com caminho e driver (nome com espaço) nunca ganham reparo.
        for name in ["RpcSs", "WinDefend", "a\\b", "Algo (driver)", "", "x y"] {
            let f = finding(
                "persistencia",
                r"HKLM\SYSTEM\CurrentControlSet\Services",
                name,
                "c:\\a.exe",
            );
            assert!(plan_for(&f).is_none(), "{name}");
        }
        // O undo só aceita o Start de um serviço comum.
        assert!(is_allowed(
            "HKLM",
            r"SYSTEM\CurrentControlSet\Services\Updater3",
            "Start"
        ));
        assert!(!is_allowed(
            "HKLM",
            r"SYSTEM\CurrentControlSet\Services\RpcSs",
            "Start"
        ));
        assert!(!is_allowed(
            "HKLM",
            r"SYSTEM\CurrentControlSet\Services\Updater3",
            "ImagePath"
        ));
        assert!(!is_allowed(
            "HKLM",
            r"SYSTEM\CurrentControlSet\Services\a\b",
            "Start"
        ));
    }

    #[test]
    fn the_hosts_is_restored_only_while_it_is_still_what_the_oblivion_wrote() {
        let dir = std::env::temp_dir().join(format!("oblivion-hosts-undo-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (backup, live) = (dir.join("hosts.bak"), dir.join("hosts"));
        std::fs::write(&backup, "original\n").unwrap();
        std::fs::write(&live, "# [Oblivion] corrigido\n").unwrap();
        let ours = sha256_hex(b"# [Oblivion] corrigido\n");

        // Alguém editou depois: não pode ser sobrescrito.
        std::fs::write(&live, "# [Oblivion] corrigido\n1.1.1.1 minha-linha.com\n").unwrap();
        assert!(
            restore_if_unchanged(&backup, &live, &ours)
                .unwrap_err()
                .contains("mudou")
        );
        assert!(
            std::fs::read_to_string(&live)
                .unwrap()
                .contains("minha-linha")
        );

        // Intacto: volta ao original.
        std::fs::write(&live, "# [Oblivion] corrigido\n").unwrap();
        restore_if_unchanged(&backup, &live, &ours).unwrap();
        assert_eq!(std::fs::read_to_string(&live).unwrap(), "original\n");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_tampered_manifest_cannot_restore_a_wrong_type_or_an_impossible_service_start() {
        let svc = fix_for(
            "HKLM",
            r"SYSTEM\CurrentControlSet\Services\Updater3",
            "Start",
        )
        .unwrap();
        assert!(restorable(&svc, "Start", 4, &2u32.to_le_bytes()));
        assert!(
            !restorable(&svc, "Start", 4, &9u32.to_le_bytes()),
            "Start de serviço só vai até 4"
        );
        assert!(!restorable(&svc, "Start", 1, b"2\0"), "tipo errado");
        assert!(!restorable(&svc, "Start", 4, &[1, 0]), "tamanho errado");
        let boot = fix_for("HKLM", POLICIES_SYSTEM, "EnableLUA").unwrap();
        assert!(restorable(&boot, "EnableLUA", 4, &0u32.to_le_bytes()));
        let multi = fix_for(
            "HKLM",
            r"SYSTEM\CurrentControlSet\Control\Session Manager",
            "BootExecute",
        )
        .unwrap();
        assert!(
            restorable(&multi, "BootExecute", 7, b"a\0\0\0")
                && !restorable(&multi, "BootExecute", 4, &[0; 4])
        );
    }

    #[test]
    fn describe_tells_what_will_be_set() {
        let r = fix_for("HKLM", POLICIES_SYSTEM, "EnableLUA").unwrap();
        assert!(r.describe().contains("EnableLUA") && r.describe().contains('1'));
        assert!(
            fix_for("HKLM", POLICIES_SYSTEM, "DisableTaskMgr")
                .unwrap()
                .describe()
                .contains("removê-lo")
        );
    }

    #[test]
    fn restoring_the_hosts_refuses_other_destinations_and_files_outside_quarantine() {
        let dir = std::env::temp_dir().join(format!("oblivion-hosts-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bak = dir.join("hosts.bak");
        std::fs::write(&bak, "x").unwrap();
        let elsewhere = serde_json::json!({"from": bak, "to": dir.join("outro")});
        assert!(
            restore_hosts(&dir, &elsewhere)
                .unwrap_err()
                .contains("não é o arquivo hosts")
        );
        let outside =
            serde_json::json!({"from": std::env::temp_dir().join("fora"), "to": hosts_path()});
        assert!(restore_hosts(&dir, &outside).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }
}
