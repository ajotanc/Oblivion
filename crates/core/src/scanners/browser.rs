//! Extensões de navegadores baseados em Chromium (Chrome, Edge, Brave, Vivaldi, Opera).
//! O manifest.json vem do disco e é tratado como não confiável (tamanho limitado, nada executado).
//! shortcut: sem Firefox (formato diferente) e sem Linux/macOS; a heurística olha só as permissões
//! do manifest, não verifica se a extensão veio da loja oficial.
use std::{
    fs,
    path::{Path, PathBuf},
};

use serde_json::Value;

use crate::finding::{Finding, Severity};

const SCANNER: &str = "extensoes";
const MAX_MANIFEST_BYTES: u64 = 2_000_000;
const MAX_LISTED: usize = 12;
const ALL_SITES: &[&str] = &["<all_urls>", "*://*/*", "http://*/*", "https://*/*"];
/// Permissões que, junto de acesso a todos os sites, dão controle sobre todo o tráfego ou páginas.
const POWERFUL: &[&str] = &["debugger", "proxy"];
/// IDs de extensões que o próprio navegador instala (componentes). Lista curta, aumente com evidência.
const BUILTIN_IDS: &[&str] = &["jifbgnmbgbdiedhdecealmlgmekpagde"]; // Opera AI

struct Extension {
    id: String,
    name: String,
    version: String,
    perms: Vec<String>,
    hosts: Vec<String>,
}

/// Pastas de dados dos navegadores no Windows (variável de ambiente, subpasta).
#[cfg(windows)]
fn bases() -> Vec<(&'static str, PathBuf)> {
    const BROWSERS: &[(&str, &str, &str)] = &[
        ("Chrome", "LOCALAPPDATA", r"Google\Chrome\User Data"),
        ("Edge", "LOCALAPPDATA", r"Microsoft\Edge\User Data"),
        (
            "Brave",
            "LOCALAPPDATA",
            r"BraveSoftware\Brave-Browser\User Data",
        ),
        ("Vivaldi", "LOCALAPPDATA", r"Vivaldi\User Data"),
        ("Opera", "APPDATA", r"Opera Software\Opera Stable"),
        ("Opera GX", "APPDATA", r"Opera Software\Opera GX Stable"),
    ];
    BROWSERS
        .iter()
        .filter_map(|(name, var, rel)| Some((*name, Path::new(&std::env::var_os(var)?).join(rel))))
        .collect()
}

#[cfg(not(windows))]
fn bases() -> Vec<(&'static str, PathBuf)> {
    Vec::new()
}

pub fn scan() -> Vec<Finding> {
    bases()
        .iter()
        .flat_map(|(browser, base)| scan_base(browser, base))
        .collect()
}

/// Cada perfil tem sua pasta `Extensions` (Chrome/Edge: `Default`, `Profile 1`...; Opera: na raiz).
fn scan_base(browser: &str, base: &Path) -> Vec<Finding> {
    let mut profiles = vec![base.to_path_buf()];
    if let Ok(entries) = fs::read_dir(base) {
        profiles.extend(
            entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.join("Extensions").is_dir()),
        );
    }

    let mut out = Vec::new();
    for profile in profiles {
        let Ok(ids) = fs::read_dir(profile.join("Extensions")) else {
            continue;
        };
        for id_dir in ids.flatten() {
            let id = id_dir.file_name().to_string_lossy().into_owned();
            let Some(ext) = newest_version(&id_dir.path()).and_then(|v| read_extension(&id, &v))
            else {
                continue;
            };
            let (severity, reason) = assess(&ext.id, &ext.perms, &ext.hosts);
            let profile_name = profile
                .file_name()
                .map_or(String::new(), |n| n.to_string_lossy().into_owned());
            out.push(Finding {
                scanner: SCANNER,
                location: format!("{browser} ({profile_name})"),
                name: ext.name.clone(),
                target: describe(&ext.id, &ext.version, &ext.perms, &ext.hosts),
                severity,
                reason,
            });
        }
    }
    out
}

/// Pasta da versão instalada mais recentemente (as antigas são sobras de atualização).
fn newest_version(ext_dir: &Path) -> Option<PathBuf> {
    fs::read_dir(ext_dir)
        .ok()?
        .flatten()
        .filter(|e| e.path().join("manifest.json").is_file())
        .max_by_key(|e| e.metadata().and_then(|m| m.modified()).ok())
        .map(|e| e.path())
}

fn strings(v: Option<&Value>) -> impl Iterator<Item = String> + '_ {
    v.and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
}

fn read_extension(id: &str, dir: &Path) -> Option<Extension> {
    let path = dir.join("manifest.json");
    if fs::metadata(&path).ok()?.len() > MAX_MANIFEST_BYTES {
        return None;
    }
    let text = fs::read_to_string(&path).ok()?;
    let manifest: Value = serde_json::from_str(text.trim_start_matches('\u{feff}')).ok()?;

    // Nos manifests antigos (v2) os sites também ficam em `permissions`; separa os dois tipos.
    let (mut hosts, mut perms) = (Vec::new(), Vec::new());
    for p in strings(manifest.get("permissions")).chain(strings(manifest.get("host_permissions"))) {
        if p == "<all_urls>" || p.contains("://") {
            hosts.push(p)
        } else {
            perms.push(p)
        }
    }
    for script in manifest
        .get("content_scripts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        hosts.extend(strings(script.get("matches")));
    }
    Some(Extension {
        id: id.to_string(),
        name: display_name(dir, &manifest).unwrap_or_else(|| id.to_string()),
        version: manifest
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or("?")
            .to_string(),
        perms,
        hosts,
    })
}

/// Nome da extensão; `__MSG_chave__` é buscado em `_locales/<idioma>/messages.json`.
fn display_name(dir: &Path, manifest: &Value) -> Option<String> {
    let raw = manifest.get("name")?.as_str()?;
    let Some(key) = raw
        .strip_prefix("__MSG_")
        .and_then(|r| r.strip_suffix("__"))
    else {
        return (!raw.is_empty()).then(|| raw.to_string());
    };
    let default = manifest
        .get("default_locale")
        .and_then(Value::as_str)
        .unwrap_or("en");
    [default, "en", "en_US"]
        .into_iter()
        // O idioma vem do manifest (não confiável) e entra num caminho: só letras, números, _ e -.
        .filter(|l| {
            !l.is_empty()
                && l.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        })
        .find_map(|locale| {
            let text =
                fs::read_to_string(dir.join("_locales").join(locale).join("messages.json")).ok()?;
            let messages: Value = serde_json::from_str(text.trim_start_matches('\u{feff}')).ok()?;
            let (_, entry) = messages
                .as_object()?
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(key))?;
            entry.get("message")?.as_str().map(str::to_string)
        })
}

/// Só permissão forte combinada com acesso a todos os sites vira SUSPEITO. Acesso a todos os sites,
/// sozinho, é comum (bloqueadores de anúncio, gerenciadores de senha) e fica como INFO.
pub fn assess(id: &str, perms: &[String], hosts: &[String]) -> (Severity, &'static str) {
    // APIs `...Private` só existem para componentes embutidos do próprio navegador. Mas o texto da
    // permissão vem do manifest, que o dono da extensão escreve: sozinho ele não prova nada, então
    // só vale junto de um ID de componente embutido conhecido.
    if BUILTIN_IDS.contains(&id) && perms.iter().any(|p| p.ends_with("Private")) {
        return (
            Severity::Info,
            "Componente interno do navegador (usa APIs privadas)",
        );
    }
    let all_sites = hosts.iter().any(|h| ALL_SITES.contains(&h.as_str()));
    let powerful = perms.iter().any(|p| POWERFUL.contains(&p.as_str()));
    match (all_sites, powerful) {
        (true, true) => (
            Severity::Suspicious,
            "Pode interceptar o tráfego ou controlar páginas (proxy/debugger) em todos os sites",
        ),
        (true, false) => (
            Severity::Info,
            "Acessa todos os sites (permissão sensível, comum em extensões legítimas)",
        ),
        _ => (
            Severity::Info,
            "Sem combinação de permissões de risco conhecida",
        ),
    }
}

pub(super) fn describe(id: &str, version: &str, perms: &[String], hosts: &[String]) -> String {
    let list = |v: &[String]| {
        let mut s = v
            .iter()
            .take(MAX_LISTED)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        if v.len() > MAX_LISTED {
            s.push_str(&format!(" (+{})", v.len() - MAX_LISTED));
        }
        if s.is_empty() {
            "nenhum".to_string()
        } else {
            s
        }
    };
    format!(
        "id {id} v{version} | permissões: {} | sites: {}",
        list(perms),
        list(hosts)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    /// Pasta temporária do teste (não cria nem apaga nada).
    fn fixture(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("oblivion-ext-{tag}-{}", std::process::id()))
    }

    /// Começa de uma pasta limpa, caso sobre lixo de uma execução anterior interrompida.
    fn clean(tag: &str) -> PathBuf {
        let dir = fixture(tag);
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn proxy_or_debugger_with_all_sites_is_suspicious() {
        assert_eq!(
            assess("x", &v(&["proxy"]), &v(&["<all_urls>"])).0,
            Severity::Suspicious
        );
        assert_eq!(
            assess("x", &v(&["debugger"]), &v(&["*://*/*"])).0,
            Severity::Suspicious
        );
    }

    #[test]
    fn known_builtin_component_is_info_even_with_proxy_and_all_sites() {
        let opera_ai = "jifbgnmbgbdiedhdecealmlgmekpagde";
        let (sev, why) = assess(
            opera_ai,
            &v(&["proxy", "operaBrowserPrivate"]),
            &v(&["<all_urls>"]),
        );
        assert_eq!(sev, Severity::Info);
        assert!(why.contains("interno"));
    }

    #[test]
    fn fake_private_permission_does_not_hide_a_risky_extension() {
        // O caso da auditoria: o dono da extensão escreve "operaBrowserPrivate" no manifest.
        let (sev, _) = assess(
            "idqualquerdeumaextensaodesconhecida",
            &v(&["proxy", "operaBrowserPrivate"]),
            &v(&["<all_urls>"]),
        );
        assert_eq!(sev, Severity::Suspicious);
        // E um ID conhecido SEM a permissão privada também não ganha a isenção.
        let (sev, _) = assess(
            "jifbgnmbgbdiedhdecealmlgmekpagde",
            &v(&["proxy"]),
            &v(&["<all_urls>"]),
        );
        assert_eq!(sev, Severity::Suspicious);
    }

    #[test]
    fn single_signals_are_only_info() {
        assert_eq!(assess("x", &v(&["proxy"]), &[]).0, Severity::Info);
        assert_eq!(
            assess("x", &v(&["storage"]), &v(&["<all_urls>"])).0,
            Severity::Info
        );
        assert_eq!(assess("x", &[], &[]).0, Severity::Info);
    }

    #[test]
    fn reads_permissions_hosts_and_localized_name() {
        let ext = clean("ok").join("abcdef").join("1.0_0");
        fs::create_dir_all(ext.join("_locales").join("pt_BR")).unwrap();
        fs::write(
            ext.join("manifest.json"),
            "\u{feff}{\"name\":\"__MSG_appName__\",\"version\":\"1.0\",\"default_locale\":\"pt_BR\",\
             \"permissions\":[\"proxy\",\"https://a.com/*\"],\"host_permissions\":[\"<all_urls>\"],\
             \"content_scripts\":[{\"matches\":[\"*://x.com/*\"]}]}",
        )
        .unwrap();
        fs::write(
            ext.join("_locales").join("pt_BR").join("messages.json"),
            "{\"APPNAME\":{\"message\":\"Minha Extensão\"}}",
        )
        .unwrap();

        let e = read_extension("abcdef", &ext).unwrap();
        fs::remove_dir_all(fixture("ok")).unwrap();

        assert_eq!(
            (e.name.as_str(), e.version.as_str()),
            ("Minha Extensão", "1.0")
        );
        assert_eq!(e.perms, v(&["proxy"]));
        assert_eq!(
            e.hosts,
            v(&["https://a.com/*", "<all_urls>", "*://x.com/*"])
        );
    }

    #[test]
    fn unresolvable_or_hostile_locale_falls_back_to_id() {
        let ext = clean("loc").join("idx").join("1");
        fs::create_dir_all(&ext).unwrap();
        fs::write(
            ext.join("manifest.json"),
            "{\"name\":\"__MSG_n__\",\"default_locale\":\"..\\\\..\\\\x\",\"version\":\"2\"}",
        )
        .unwrap();
        let e = read_extension("idx", &ext).unwrap();
        fs::remove_dir_all(fixture("loc")).unwrap();
        assert_eq!(e.name, "idx");
    }

    #[test]
    fn broken_or_missing_manifest_is_skipped_without_panic() {
        let ext = clean("bad").join("id1").join("1");
        fs::create_dir_all(&ext).unwrap();
        fs::write(ext.join("manifest.json"), "{ isto não é json").unwrap();
        assert!(read_extension("id1", &ext).is_none());
        assert!(read_extension("id1", &ext.join("nao-existe")).is_none());
        fs::write(ext.join("manifest.json"), "[1,2,3]").unwrap();
        assert!(read_extension("id1", &ext).is_some_and(|e| e.name == "id1"));
        fs::remove_dir_all(fixture("bad")).unwrap();
    }

    #[test]
    fn scan_base_finds_extensions_in_profiles_and_flags_risky_ones() {
        let base = clean("base");
        let ext = base
            .join("Default")
            .join("Extensions")
            .join("evil")
            .join("1_0");
        fs::create_dir_all(&ext).unwrap();
        fs::write(
            ext.join("manifest.json"),
            "{\"name\":\"VPN Rápida\",\"version\":\"1\",\"permissions\":[\"proxy\"],\"host_permissions\":[\"<all_urls>\"]}",
        )
        .unwrap();
        let found = scan_base("Chrome", &base);
        fs::remove_dir_all(&base).unwrap();

        assert_eq!(found.len(), 1);
        assert_eq!(
            (found[0].name.as_str(), found[0].severity),
            ("VPN Rápida", Severity::Suspicious)
        );
        assert_eq!(found[0].location, "Chrome (Default)");
        assert!(found[0].target.contains("id evil v1"));
    }

    #[test]
    fn missing_browser_folder_yields_nothing() {
        assert!(scan_base("Chrome", Path::new(r"C:\oblivion-pasta-que-nao-existe")).is_empty());
    }
}
