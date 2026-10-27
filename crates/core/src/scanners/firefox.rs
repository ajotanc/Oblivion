//! Extensões do Firefox: lidas de `extensions.json` em cada perfil (o arquivo vem do disco e é
//! tratado como não confiável: tamanho limitado, nada executado).
//! shortcut: só o usuário atual; sem macOS; a heurística é a mesma dos outros navegadores
//! (permissões) mais a assinatura da Mozilla, e não olha o código da extensão.
use std::{fs, path::PathBuf};

use serde_json::Value;

use super::browser::{assess, describe};
use crate::finding::{Finding, Severity};

const SCANNER: &str = "extensoes";
const MAX_FILE_BYTES: u64 = 5_000_000;
/// Origens que a própria Mozilla instala; não vêm do usuário nem de outros programas.
const MOZILLA_LOCATIONS: &[&str] = &[
    "app-builtin",
    "app-builtin-addons",
    "app-system-defaults",
    "app-system-addons",
];

/// Pastas que contêm os perfis do Firefox.
fn roots() -> Vec<PathBuf> {
    #[cfg(windows)]
    let roots = std::env::var_os("APPDATA")
        .map(|b| PathBuf::from(b).join(r"Mozilla\Firefox\Profiles"))
        .into_iter()
        .collect();
    #[cfg(not(windows))]
    let roots = std::env::var_os("HOME")
        .map(|h| {
            let h = PathBuf::from(h);
            [
                ".mozilla/firefox",
                "snap/firefox/common/.mozilla/firefox",
                ".var/app/org.mozilla.firefox/.mozilla/firefox",
            ]
            .map(|rel| h.join(rel))
            .to_vec()
        })
        .unwrap_or_default();
    roots
}

pub fn scan() -> Vec<Finding> {
    scan_roots(&roots())
}

fn scan_roots(roots: &[PathBuf]) -> Vec<Finding> {
    let mut out = Vec::new();
    for root in roots {
        let Ok(profiles) = fs::read_dir(root) else {
            continue;
        };
        for profile in profiles.flatten().map(|e| e.path()) {
            let file = profile.join("extensions.json");
            if fs::metadata(&file).map_or(true, |m| m.len() > MAX_FILE_BYTES) {
                continue;
            }
            let Ok(text) = fs::read_to_string(&file) else {
                continue;
            };
            let name = profile
                .file_name()
                .map_or(String::new(), |n| n.to_string_lossy().into_owned());
            out.extend(parse(&text, &name));
        }
    }
    out
}

fn strings(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}

/// Extensões ativas instaladas pelo usuário ou por outro programa (não as da Mozilla nem temas).
fn parse(text: &str, profile: &str) -> Vec<Finding> {
    let Ok(root) = serde_json::from_str::<Value>(text.trim_start_matches('\u{feff}')) else {
        return Vec::new();
    };
    root.get("addons")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|a| {
            let location = a.get("location").and_then(Value::as_str).unwrap_or("");
            let active = a.get("active").and_then(Value::as_bool).unwrap_or(false);
            let disabled = a
                .get("userDisabled")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if a.get("type").and_then(Value::as_str) != Some("extension")
                || !active
                || disabled
                || MOZILLA_LOCATIONS.contains(&location)
            {
                return None;
            }
            let id = a.get("id").and_then(Value::as_str)?;
            let name = a
                .pointer("/defaultLocale/name")
                .and_then(Value::as_str)
                .filter(|n| !n.is_empty())
                .unwrap_or(id);
            let version = a.get("version").and_then(Value::as_str).unwrap_or("?");
            let (perms, hosts) = (
                strings(a.pointer("/userPermissions/permissions")),
                strings(a.pointer("/userPermissions/origins")),
            );
            let signed = a.get("signedState").and_then(Value::as_i64).unwrap_or(0);
            let (severity, reason) = if location == "app-profile" && signed <= 0 {
                (
                    Severity::Suspicious,
                    "Instalada sem assinatura válida da Mozilla",
                )
            } else {
                assess(id, &perms, &hosts)
            };
            Some(Finding {
                scanner: SCANNER,
                location: format!("Firefox ({profile})"),
                name: name.to_string(),
                target: describe(id, version, &perms, &hosts),
                severity,
                reason,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addon(extra: &str) -> String {
        format!(
            "{{\"addons\":[{{\"id\":\"a@x\",\"type\":\"extension\",\"active\":true,\"userDisabled\":false,\
             \"location\":\"app-profile\",\"signedState\":2,\"version\":\"1.0\",\
             \"defaultLocale\":{{\"name\":\"Minha Ext\"}}{extra}}}]}}"
        )
    }

    #[test]
    fn reads_name_version_permissions_and_origins() {
        let f = parse(
            &addon(
                ",\"userPermissions\":{\"permissions\":[\"storage\"],\"origins\":[\"https://a.com/*\"]}",
            ),
            "p1",
        );
        assert_eq!(f.len(), 1);
        assert_eq!(
            (f[0].name.as_str(), f[0].severity),
            ("Minha Ext", Severity::Info)
        );
        assert_eq!(f[0].location, "Firefox (p1)");
        assert!(
            f[0].target.contains("a@x v1.0")
                && f[0].target.contains("storage")
                && f[0].target.contains("a.com")
        );
    }

    #[test]
    fn proxy_with_all_sites_is_suspicious() {
        let f = parse(
            &addon(
                ",\"userPermissions\":{\"permissions\":[\"proxy\"],\"origins\":[\"<all_urls>\"]}",
            ),
            "p",
        );
        assert_eq!(f[0].severity, Severity::Suspicious);
    }

    #[test]
    fn unsigned_profile_extension_is_suspicious() {
        let json = addon("").replace("\"signedState\":2", "\"signedState\":0");
        assert_eq!(parse(&json, "p")[0].severity, Severity::Suspicious);
    }

    #[test]
    fn skips_disabled_inactive_themes_and_mozilla_own() {
        for (from, to) in [
            ("\"userDisabled\":false", "\"userDisabled\":true"),
            ("\"active\":true", "\"active\":false"),
            ("\"type\":\"extension\"", "\"type\":\"theme\""),
            (
                "\"location\":\"app-profile\"",
                "\"location\":\"app-builtin\"",
            ),
            (
                "\"location\":\"app-profile\"",
                "\"location\":\"app-builtin-addons\"",
            ),
        ] {
            assert!(
                parse(&addon("").replace(from, to), "p").is_empty(),
                "{from}"
            );
        }
    }

    #[test]
    fn falls_back_to_id_when_name_is_missing() {
        let json = addon("").replace("\"defaultLocale\":{\"name\":\"Minha Ext\"}", "\"x\":1");
        assert_eq!(parse(&json, "p")[0].name, "a@x");
    }

    #[test]
    fn broken_json_or_unexpected_shapes_do_not_panic() {
        for json in [
            "",
            "{",
            "[]",
            "{\"addons\":5}",
            "{\"addons\":[1,null,{}]}",
            "{\"addons\":[{\"type\":\"extension\"}]}",
        ] {
            assert!(parse(json, "p").is_empty(), "{json}");
        }
    }

    #[test]
    fn scan_roots_reads_profile_folders_and_ignores_missing_ones() {
        let root = std::env::temp_dir().join(format!("oblivion-ff-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let profile = root.join("abc.default-release");
        fs::create_dir_all(&profile).unwrap();
        fs::create_dir_all(root.join("sem-extensions")).unwrap();
        fs::write(profile.join("extensions.json"), addon("")).unwrap();

        let found = scan_roots(&[root.clone(), PathBuf::from("/nao/existe-oblivion")]);
        fs::remove_dir_all(&root).unwrap();

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].location, "Firefox (abc.default-release)");
    }
}
