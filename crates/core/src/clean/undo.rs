//! Desfazer uma limpeza: lê o `manifest.json` da quarentena e devolve cada item ao lugar.
//! Nunca sobrescreve: se algo já existe no destino, o item fica como está e o motivo é informado.
use std::{fs, path::Path};

use serde_json::Value;

use super::{exec::is_system_path, secure};

#[derive(Debug, Clone)]
pub struct UndoResult {
    pub description: String,
    pub result: Result<(), String>,
}

fn restore_move(dir: &Path, entry: &Value) -> Result<(), String> {
    let from = entry["from"].as_str().ok_or("registro sem origem")?;
    let to = entry["to"].as_str().ok_or("registro sem destino")?;
    let (from, to) = (Path::new(from), Path::new(to));
    if !from.is_file() {
        return Err("o arquivo da quarentena não existe mais".into());
    }
    // O manifesto não é confiável: o arquivo tem de estar na quarentena e o destino não pode ser a pasta do sistema.
    if !secure::is_inside(dir, from) {
        return Err("o arquivo não está dentro da quarentena (manifesto adulterado?)".into());
    }
    if is_system_path(to) {
        return Err("o destino fica numa pasta do sistema: não devolvi".into());
    }
    if to.exists() {
        return Err("já existe um arquivo no lugar original; não sobrescrevi".into());
    }
    if let Some(parent) = to.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("não consegui criar a pasta: {e}"))?;
    }
    if fs::rename(from, to).is_err() {
        fs::copy(from, to).map_err(|e| format!("não consegui copiar de volta: {e}"))?;
        fs::remove_file(from)
            .map_err(|e| format!("copiei, mas não consegui limpar a quarentena: {e}"))?;
    }
    Ok(())
}

fn describe(entry: &Value) -> String {
    match entry["kind"].as_str() {
        Some("move") => format!(
            "Devolver arquivo para {}",
            entry["to"].as_str().unwrap_or("?")
        ),
        Some("run_value") => format!(
            "Recriar o valor \"{}\" em {}\\{}",
            entry["name"].as_str().unwrap_or("?"),
            entry["hive"].as_str().unwrap_or("?"),
            entry["subkey"].as_str().unwrap_or("?")
        ),
        Some("reg_value") => format!(
            "Devolver o valor \"{}\" de {}\\{} ao que era antes",
            entry["name"].as_str().unwrap_or("?"),
            entry["hive"].as_str().unwrap_or("?"),
            entry["subkey"].as_str().unwrap_or("?")
        ),
        Some("hosts") => "Devolver o arquivo hosts ao que era antes".to_string(),
        Some("task") => format!(
            "Recriar a tarefa \"{}\"",
            entry["name"].as_str().unwrap_or("?")
        ),
        _ => "Item desconhecido".into(),
    }
}

fn restore_entry(dir: &Path, entry: &Value) -> Result<(), String> {
    match entry["kind"].as_str() {
        Some("move") => restore_move(dir, entry),
        #[cfg(windows)]
        Some("run_value") => super::exec::restore_run_value(entry),
        #[cfg(windows)]
        Some("task") => super::exec::restore_task(dir, entry),
        #[cfg(windows)]
        Some("reg_value") => super::repair::restore_reg_value(entry),
        Some("hosts") => super::repair::restore_hosts(dir, entry),
        _ => {
            let _ = dir;
            Err("tipo de item não suportado neste sistema".into())
        }
    }
}

/// Desfaz o que uma limpeza removeu. ANTES de ler o manifesto, confere que a pasta é privada: um
/// manifesto que outro usuário pudesse ter trocado seria obedecido como administrador.
pub fn undo(dir: &Path) -> Result<Vec<UndoResult>, String> {
    secure::verify_private(dir).map_err(|e| {
        format!("a quarentena não é privada ({e}); não desfaço para não obedecer um manifesto que outro usuário possa ter alterado")
    })?;
    undo_unchecked(dir)
}

/// Desfaz tudo o que o manifesto marca como feito. Itens já desfeitos ou que não puderam
/// ser desfeitos aparecem no resultado; o manifesto original não é alterado.
fn undo_unchecked(dir: &Path) -> Result<Vec<UndoResult>, String> {
    let text = fs::read_to_string(dir.join("manifest.json"))
        .map_err(|e| format!("não achei o manifest.json em {}: {e}", dir.display()))?;
    let manifest: Value = serde_json::from_str(text.trim_start_matches('\u{feff}'))
        .map_err(|e| format!("manifest.json inválido: {e}"))?;
    let records = manifest["registros"]
        .as_array()
        .ok_or("manifest.json sem registros")?;
    let mut out = Vec::new();
    for record in records.iter().filter(|r| r["resultado"] == "feito") {
        for entry in record["desfazer"].as_array().into_iter().flatten() {
            out.push(UndoResult {
                description: describe(entry),
                result: restore_entry(dir, entry),
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("oblivion-undo-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn write_manifest(dir: &Path, records: Value) {
        fs::write(
            dir.join("manifest.json"),
            json!({"registros": records}).to_string(),
        )
        .unwrap();
    }

    #[test]
    fn a_tampered_manifest_cannot_move_a_file_from_outside_the_quarantine() {
        // O caso da auditoria: o manifesto aponta `from` para um arquivo do atacante fora da quarentena.
        let dir = temp_dir("evil-from");
        let outside =
            std::env::temp_dir().join(format!("oblivion-undo-fora-{}", std::process::id()));
        fs::write(&outside, b"do atacante").unwrap();
        let target = dir.join("destino.exe");
        write_manifest(
            &dir,
            json!([{"resultado": "feito", "desfazer": [{"kind": "move", "from": outside, "to": target}]}]),
        );
        let r = undo_unchecked(&dir).unwrap();
        assert!(
            r[0].result
                .as_ref()
                .unwrap_err()
                .contains("dentro da quarentena"),
            "{r:?}"
        );
        assert!(outside.exists() && !target.exists());
        fs::remove_file(&outside).unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_tampered_manifest_cannot_drop_a_file_into_a_system_folder() {
        let dir = temp_dir("evil-to");
        let stored = dir.join("q.quarantined");
        fs::write(&stored, b"x").unwrap();
        let system_file = if cfg!(windows) {
            format!(
                r"{}\\oblivion-teste-nao-criar.dll",
                std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into())
            )
        } else {
            "/etc/oblivion-teste-nao-criar".to_string()
        };
        write_manifest(
            &dir,
            json!([{"resultado": "feito", "desfazer": [{"kind": "move", "from": stored, "to": system_file}]}]),
        );
        let r = undo_unchecked(&dir).unwrap();
        assert!(
            r[0].result
                .as_ref()
                .unwrap_err()
                .contains("pasta do sistema"),
            "{r:?}"
        );
        assert!(stored.exists() && !Path::new(&system_file).exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn dot_dot_cannot_escape_the_quarantine() {
        let dir = temp_dir("dotdot");
        let outside = dir
            .parent()
            .unwrap()
            .join(format!("oblivion-undo-escape-{}", std::process::id()));
        fs::write(&outside, b"x").unwrap();
        let sneaky = dir.join("..").join(outside.file_name().unwrap());
        write_manifest(
            &dir,
            json!([{"resultado": "feito", "desfazer": [{"kind": "move", "from": sneaky, "to": dir.join("a")}]}]),
        );
        let r = undo_unchecked(&dir).unwrap();
        assert!(r[0].result.is_err() && outside.exists());
        fs::remove_file(&outside).unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn undo_refuses_a_quarantine_folder_that_is_not_private() {
        let dir = temp_dir("notprivate");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();
        }
        write_manifest(&dir, json!([]));
        let e = undo(&dir).unwrap_err();
        assert!(e.contains("não é privada"), "{e}");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn moves_the_file_back_and_creates_missing_folders() {
        let dir = temp_dir("ok");
        let (stored, original) = (
            dir.join("q.quarantined"),
            dir.join("pasta-nova").join("a.exe"),
        );
        fs::write(&stored, b"x").unwrap();
        write_manifest(
            &dir,
            json!([{"resultado": "feito", "desfazer": [{"kind": "move", "from": stored, "to": original}]}]),
        );
        let r = undo_unchecked(&dir).unwrap();
        assert!(r.len() == 1 && r[0].result.is_ok(), "{r:?}");
        assert_eq!(fs::read(&original).unwrap(), b"x");
        assert!(!stored.exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn never_overwrites_an_existing_file() {
        let dir = temp_dir("over");
        let (stored, original) = (dir.join("q.quarantined"), dir.join("a.exe"));
        fs::write(&stored, b"quarentena").unwrap();
        fs::write(&original, b"novo").unwrap();
        write_manifest(
            &dir,
            json!([{"resultado": "feito", "desfazer": [{"kind": "move", "from": stored, "to": original}]}]),
        );
        let r = undo_unchecked(&dir).unwrap();
        assert!(
            r[0].result
                .as_ref()
                .unwrap_err()
                .contains("não sobrescrevi")
        );
        assert_eq!(fs::read(&original).unwrap(), b"novo");
        assert_eq!(fs::read(&stored).unwrap(), b"quarentena");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn only_items_marked_done_are_undone() {
        let dir = temp_dir("done");
        let stored = dir.join("q.quarantined");
        fs::write(&stored, b"x").unwrap();
        let entry = json!([{"kind": "move", "from": stored, "to": dir.join("a")}]);
        write_manifest(
            &dir,
            json!([
                {"resultado": "recusado", "desfazer": entry},
                {"resultado": "falhou: x", "desfazer": entry},
                {"resultado": "simulado", "desfazer": entry},
            ]),
        );
        assert!(undo_unchecked(&dir).unwrap().is_empty());
        assert!(stored.exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_manifest_saved_with_a_utf8_bom_is_still_read() {
        // O caso real do teste: o PowerShell 5 e o Bloco de Notas gravam `.json` com BOM.
        let dir = temp_dir("bom");
        let (stored, original) = (dir.join("q.quarantined"), dir.join("volta.exe"));
        fs::write(&stored, b"x").unwrap();
        let body = json!({"registros": [{"resultado": "feito", "desfazer": [{"kind": "move", "from": stored, "to": original}]}]});
        fs::write(dir.join("manifest.json"), format!("\u{feff}{body}")).unwrap();
        let r = undo_unchecked(&dir).unwrap();
        assert!(r.len() == 1 && r[0].result.is_ok(), "{r:?}");
        assert!(original.exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_or_broken_manifest_is_a_clear_error() {
        let dir = temp_dir("bad");
        assert!(undo_unchecked(&dir).unwrap_err().contains("manifest.json"));
        fs::write(dir.join("manifest.json"), "{ não é json").unwrap();
        assert!(undo_unchecked(&dir).unwrap_err().contains("inválido"));
        fs::write(dir.join("manifest.json"), "{}").unwrap();
        assert!(undo_unchecked(&dir).unwrap_err().contains("sem registros"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_quarantine_file_and_unknown_kinds_are_reported_not_panics() {
        let dir = temp_dir("miss");
        write_manifest(
            &dir,
            json!([{"resultado": "feito", "desfazer": [
                {"kind": "move", "from": dir.join("sumiu"), "to": dir.join("a")},
                {"kind": "inventado"},
                {"kind": "move"},
            ]}]),
        );
        let r = undo_unchecked(&dir).unwrap();
        assert_eq!(r.len(), 3);
        assert!(r.iter().all(|x| x.result.is_err()));
        fs::remove_dir_all(&dir).unwrap();
    }
}
