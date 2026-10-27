//! Tarefas agendadas: um dos lugares preferidos de malware para voltar depois de removido.
//! Lê os XML em `System32\Tasks` (direto do disco, sem rodar comando). Sem acesso a uma subpasta
//! ela é ignorada e o resto continua. Se nem a pasta raiz abre (sem administrador), o relatório
//! registra o aviso: silêncio seria pior, pois pareceria que as tarefas foram verificadas.
use std::{fs, path::Path};

use winreg::{RegKey, enums::HKEY_LOCAL_MACHINE};

use crate::classify::classify;
use crate::finding::{Finding, Severity};

const SCANNER: &str = "tarefas";
/// Limite de profundidade e de tamanho: o XML vem do disco e é tratado como não confiável.
const MAX_DEPTH: usize = 8;
const MAX_FILE_BYTES: u64 = 1_000_000;

/// Pasta onde o Windows guarda o XML de cada tarefa agendada.
pub(crate) fn tasks_root() -> std::path::PathBuf {
    Path::new(&std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into()))
        .join(r"System32\Tasks")
}

pub fn scan() -> Vec<Finding> {
    scan_root(&tasks_root())
}

fn scan_root(root: &Path) -> Vec<Finding> {
    if fs::read_dir(root).is_err() {
        return vec![Finding {
            scanner: SCANNER,
            location: root.display().to_string(),
            name: "Tarefas agendadas NÃO verificadas".into(),
            target: String::new(),
            severity: Severity::Info,
            reason: "Sem acesso à pasta de tarefas; rode como administrador para verificá-las",
        }];
    }
    let mut out = Vec::new();
    walk(root, root, 0, &mut out);
    out
}

fn walk(root: &Path, dir: &Path, depth: usize, out: &mut Vec<Finding>) {
    if depth > MAX_DEPTH {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = entry.metadata() else { continue };
        if meta.is_dir() {
            walk(root, &path, depth + 1, out);
        } else if meta.len() <= MAX_FILE_BYTES {
            let Ok(bytes) = fs::read(&path) else { continue };
            let name = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .display()
                .to_string();
            for command in parse_task(&decode(&bytes)) {
                let (severity, reason) = classify(&command);
                out.push(Finding {
                    scanner: SCANNER,
                    location: "Agendador de Tarefas".into(),
                    name: name.clone(),
                    target: command,
                    severity,
                    reason,
                });
            }
        }
    }
}

/// Os XML de tarefa costumam ser UTF-16 LE com BOM; aceita também UTF-8.
pub(crate) fn decode(bytes: &[u8]) -> String {
    match bytes {
        [0xFF, 0xFE, rest @ ..] => {
            let units: Vec<u16> = rest
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .collect();
            String::from_utf16_lossy(&units)
        }
        _ => String::from_utf8_lossy(bytes).into_owned(),
    }
}

/// A tarefa está desabilitada? Só vale o `<Enabled>` de `<Settings>`: cada gatilho também tem o seu,
/// e uma tarefa com um gatilho desligado e outro ligado continua ativa.
fn is_disabled(xml: &str) -> bool {
    xml.split_once("<Settings>")
        .and_then(|(_, rest)| rest.split_once("</Settings>"))
        .and_then(|(settings, _)| tag(settings, "Enabled"))
        .is_some_and(|v| v.eq_ignore_ascii_case("false"))
}

/// Comandos (`Command` + `Arguments`) de cada ação `<Exec>` de uma tarefa habilitada.
pub(crate) fn parse_task(xml: &str) -> Vec<String> {
    if is_disabled(xml) {
        return Vec::new();
    }
    let execs = xml.split("<Exec>").skip(1).filter_map(|block| {
        let block = block.split("</Exec>").next()?;
        let command = tag(block, "Command")?;
        let args = tag(block, "Arguments").unwrap_or_default();
        Some(format!("{command} {args}").trim().to_string())
    });
    let coms = com_class_ids(xml)
        .into_iter()
        .map(|id| match resolve_clsid(&id) {
            Some(dll) => format!("COM {id} -> {dll}"),
            None => format!("COM {id}"),
        });
    execs.chain(coms).collect()
}

/// `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`. Só esse formato entra no caminho do registro.
fn is_guid(s: &str) -> bool {
    s.len() == 38
        && s.starts_with('{')
        && s.ends_with('}')
        && s[1..37].chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// CLSIDs das ações `<ComHandler>`: a tarefa chama um objeto COM (uma DLL) em vez de um programa.
fn com_class_ids(xml: &str) -> Vec<String> {
    xml.split("<ComHandler>")
        .skip(1)
        .filter_map(|block| {
            let id = tag(block.split("</ComHandler>").next()?, "ClassId")?;
            is_guid(&id).then_some(id)
        })
        .collect()
}

/// A DLL (ou programa) que implementa a classe COM, lida do registro.
fn resolve_clsid(id: &str) -> Option<String> {
    let class = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(format!(r"SOFTWARE\Classes\CLSID\{id}"))
        .ok()?;
    ["InprocServer32", "LocalServer32"]
        .iter()
        .find_map(|server| {
            let value: String = class.open_subkey(server).ok()?.get_value("").ok()?;
            (!value.trim().is_empty()).then_some(value)
        })
}

fn tag(block: &str, name: &str) -> Option<String> {
    let start = block.find(&format!("<{name}>"))? + name.len() + 2;
    let end = start + block[start..].find(&format!("</{name}>"))?;
    Some(unescape(block[start..end].trim()))
}

fn unescape(s: &str) -> String {
    s.replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;

    const XML: &str = r#"<Task><Actions Context="Author"><Exec>
        <Command>"C:\Program Files\App\a.exe"</Command><Arguments>--run &amp; &quot;x&quot;</Arguments></Exec>
        <Exec><Command>cmd.exe</Command></Exec></Actions></Task>"#;

    #[test]
    fn parses_every_exec_action_and_unescapes() {
        assert_eq!(
            parse_task(XML),
            vec![
                r#""C:\Program Files\App\a.exe" --run & "x""#.to_string(),
                "cmd.exe".to_string()
            ]
        );
    }

    #[test]
    fn com_handler_tasks_are_listed_with_their_class_id() {
        // O caso da auditoria: tarefa que chama um objeto COM e nunca aparecia (só `<Exec>` era lido).
        let id = "{DEADBEEF-0000-4000-8000-0123456789AB}"; // não existe no registro
        let xml = format!(
            "<Task><Actions><ComHandler><ClassId>{id}</ClassId></ComHandler></Actions></Task>"
        );
        assert_eq!(parse_task(&xml), vec![format!("COM {id}")]);
        let both = format!(
            "<Task><Actions><Exec><Command>a.exe</Command></Exec><ComHandler><ClassId>{id}</ClassId></ComHandler></Actions></Task>"
        );
        assert_eq!(parse_task(&both).len(), 2);
    }

    #[test]
    fn a_class_id_outside_the_guid_format_is_ignored_and_never_reaches_the_registry() {
        for bad in [
            "",
            "{x}",
            r"..\..\evil",
            "{DEADBEEF-0000-4000-8000-0123456789AB",
            "{DEADBEEF-0000-4000-8000-0123456789AG}",
            "{DEADBEEF-0000-4000-8000-0123456789AB}\\x",
        ] {
            let xml = format!("<ComHandler><ClassId>{bad}</ClassId></ComHandler>");
            assert!(com_class_ids(&xml).is_empty(), "{bad}");
        }
        assert!(is_guid("{00000000-0000-0000-0000-000000000000}"));
    }

    #[test]
    fn a_real_windows_class_resolves_to_its_dll() {
        // `Scripting.FileSystemObject`: classe presente em todo Windows.
        let dll =
            resolve_clsid("{0D43FE01-F093-11CF-8940-00A0C9054228}").expect("classe do Windows");
        assert!(dll.to_lowercase().contains("scrrun.dll"), "{dll}");
        assert!(resolve_clsid("{DEADBEEF-0000-4000-8000-0123456789AB}").is_none());
    }

    #[test]
    fn one_disabled_trigger_does_not_hide_an_active_task() {
        // O caso da auditoria: um gatilho desligado, outro ligado, tarefa ativa.
        let xml = "<Task><Triggers><LogonTrigger><Enabled>false</Enabled></LogonTrigger>\
                   <BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>\
                   <Settings><Enabled>true</Enabled></Settings>\
                   <Actions><Exec><Command>evil.exe</Command></Exec></Actions></Task>";
        assert_eq!(parse_task(xml), vec!["evil.exe"]);
        let only_trigger = "<Task><Triggers><LogonTrigger><Enabled>false</Enabled></LogonTrigger></Triggers>\
                            <Actions><Exec><Command>evil.exe</Command></Exec></Actions></Task>";
        assert_eq!(
            parse_task(only_trigger),
            vec!["evil.exe"],
            "sem <Settings>, a tarefa conta como ativa"
        );
    }

    #[test]
    fn settings_level_disabled_is_skipped_in_any_case() {
        for flag in ["false", "FALSE", "False"] {
            let xml = format!(
                "<Task><Settings><Enabled>{flag}</Enabled></Settings><Actions><Exec><Command>a.exe</Command></Exec></Actions></Task>"
            );
            assert!(parse_task(&xml).is_empty(), "{flag}");
        }
    }

    #[test]
    fn disabled_task_is_skipped() {
        let xml = "<Task><Settings><Enabled>false</Enabled></Settings><Exec><Command>a.exe</Command></Exec></Task>";
        assert!(parse_task(xml).is_empty());
    }

    #[test]
    fn malformed_or_empty_xml_does_not_panic() {
        for xml in [
            "",
            "<Exec>",
            "<Exec><Command>",
            "<Exec></Exec>",
            "</Command><Command>",
            "<Exec><Command></Command",
        ] {
            let _ = parse_task(xml);
        }
    }

    #[test]
    fn decodes_utf16_with_bom_and_utf8() {
        let mut utf16 = vec![0xFF, 0xFE];
        utf16.extend("<Task>é</Task>".encode_utf16().flat_map(u16::to_le_bytes));
        assert_eq!(decode(&utf16), "<Task>é</Task>");
        assert_eq!(decode("<Task>é</Task>".as_bytes()), "<Task>é</Task>");
        assert_eq!(decode(&[]), "");
    }

    #[test]
    fn unreadable_root_reports_a_warning_instead_of_silence() {
        let f = scan_root(Path::new(r"C:\oblivion-pasta-que-nao-existe"));
        assert_eq!(f.len(), 1);
        assert!(f[0].name.contains("NÃO verificadas") && f[0].reason.contains("administrador"));
    }

    #[test]
    fn scans_nested_task_files_from_disk() {
        let root = std::env::temp_dir().join(format!("oblivion-tasks-{}", std::process::id()));
        let sub = root.join("Vendor").join("Sub");
        fs::create_dir_all(&sub).unwrap();
        fs::write(
            sub.join("Updater"),
            "<Task><Exec><Command>mshta.exe</Command></Exec></Task>",
        )
        .unwrap();
        fs::write(
            root.join("Off"),
            "<Task><Settings><Enabled>false</Enabled></Settings><Exec><Command>a.exe</Command></Exec></Task>",
        )
        .unwrap();
        fs::write(root.join("Broken"), [0xFF, 0xFE, 0x41]).unwrap();

        let f = scan_root(&root);
        fs::remove_dir_all(&root).unwrap();

        assert_eq!(f.len(), 1, "só a tarefa habilitada e válida: {f:?}");
        assert_eq!(f[0].name, r"Vendor\Sub\Updater");
        assert_eq!(f[0].severity, Severity::High);
    }

    #[test]
    fn task_command_goes_through_the_same_classifier() {
        let cmd = &parse_task(
            "<Exec><Command>powershell.exe</Command><Arguments>-enc AAAA</Arguments></Exec>",
        )[0];
        assert_eq!(classify(cmd).0, Severity::High);
    }
}
