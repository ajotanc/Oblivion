//! Backend da interface do Oblivion. Princípios:
//! - A interface manda só NÚMEROS de achados; os achados ficam aqui (nunca confiamos em caminho ou
//!   comando vindos da tela).
//! - O texto que vai para a tela passa por `report::text::clean` (caracteres de controle e de inversão de sentido).
//! - Nada de rede. A remoção usa o mesmo núcleo do CLI: ponto de restauração, quarentena privada, desfazer.
use std::{
    path::{Path, PathBuf},
    sync::Mutex,
};

use oblivion_core::{
    clean::{self, Outcome, exec, undo},
    finding::{Finding, MINER_STRONG_REASON, Severity},
    privilege, report, restore,
    scanners::{self, Progress},
};
use serde::Serialize;
use tauri::{AppHandle, Emitter, State};

#[derive(Default)]
struct AppState {
    findings: Mutex<Vec<Finding>>,
}

fn safe(s: &str) -> String {
    report::text::clean(s)
}

fn severity_name(s: Severity) -> &'static str {
    match s {
        Severity::High => "high",
        Severity::Suspicious => "suspicious",
        Severity::Info => "info",
    }
}

#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
struct FindingDto {
    id: usize,
    severity: &'static str,
    scanner: &'static str,
    name: String,
    location: String,
    target: String,
    reason: String,
    /// O que a limpeza faria; `None` para INFO.
    action: Option<String>,
    /// Há uma ação automática (não só instrução manual).
    actionable: bool,
    /// Processo marcado só por sinais fracos (CPU/GPU): a tela avisa para conferir antes de encerrar.
    weak_signal: bool,
}

fn to_dto(id: usize, f: &Finding) -> FindingDto {
    let plan = clean::plan(f);
    FindingDto {
        id,
        severity: severity_name(f.severity),
        scanner: f.scanner,
        name: safe(&f.name),
        location: safe(&f.location),
        target: safe(&f.target),
        reason: safe(f.reason),
        actionable: plan.as_ref().is_some_and(|p| !p.is_manual()),
        weak_signal: f.scanner == "minerador"
            && f.severity > Severity::Info
            && f.reason != MINER_STRONG_REASON,
        action: plan.map(|p| safe(&p.describe())),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AppInfo {
    version: &'static str,
    elevated: bool,
    platform: &'static str,
    alert: &'static str,
}

#[tauri::command]
fn app_info() -> AppInfo {
    AppInfo {
        version: env!("CARGO_PKG_VERSION"),
        elevated: privilege::is_elevated(),
        platform: std::env::consts::OS,
        alert: privilege::alert(),
    }
}

#[derive(Serialize, Clone)]
struct ProgressDto {
    kind: &'static str,
    label: String,
    count: usize,
}

impl From<Progress<'_>> for ProgressDto {
    fn from(p: Progress<'_>) -> Self {
        match p {
            Progress::Started(l) => ProgressDto {
                kind: "started",
                label: l.into(),
                count: 0,
            },
            Progress::Finished { label, count } => ProgressDto {
                kind: "finished",
                label: label.into(),
                count,
            },
            Progress::Failed(l) => ProgressDto {
                kind: "failed",
                label: l.into(),
                count: 0,
            },
        }
    }
}

#[tauri::command]
async fn run_scan(app: AppHandle, state: State<'_, AppState>) -> Result<Vec<FindingDto>, String> {
    let handle = app.clone();
    let mut findings = tauri::async_runtime::spawn_blocking(move || {
        scanners::scan_all_with(&|p| {
            let _ = handle.emit("scan-progress", ProgressDto::from(p));
        })
    })
    .await
    .map_err(|e| e.to_string())?;
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    let dtos = findings
        .iter()
        .enumerate()
        .map(|(i, f)| to_dto(i, f))
        .collect();
    *state
        .findings
        .lock()
        .map_err(|_| "estado interno bloqueado")? = findings;
    Ok(dtos)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecordDto {
    name: String,
    severity: &'static str,
    target: String,
    action: String,
    outcome: &'static str,
    outcome_label: String,
    note: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CleanDto {
    dry_run: bool,
    restore: String,
    quarantine_dir: Option<String>,
    aborted: Option<String>,
    records: Vec<RecordDto>,
}

fn outcome_kind(o: &Outcome) -> &'static str {
    match o {
        Outcome::Done => "done",
        Outcome::DryRun => "dryRun",
        Outcome::Declined => "declined",
        Outcome::Manual => "manual",
        Outcome::Skipped(_) => "skipped",
        Outcome::Failed(_) => "failed",
    }
}

fn to_clean_dto(r: &clean::Report) -> CleanDto {
    CleanDto {
        dry_run: r.dry_run,
        restore: safe(&r.restore),
        quarantine_dir: (!r.dry_run).then(|| safe(&r.dir.display().to_string())),
        aborted: r.aborted.as_deref().map(safe),
        records: r
            .records
            .iter()
            .map(|rec| RecordDto {
                name: safe(&rec.finding.name),
                severity: severity_name(rec.finding.severity),
                target: safe(&rec.finding.target),
                action: safe(&rec.action),
                outcome: outcome_kind(&rec.outcome),
                outcome_label: safe(&rec.outcome.label()),
                note: safe(&rec.note),
            })
            .collect(),
    }
}

/// Os achados escolhidos, pelos números. Falha se algum número não existe (a lista mudou) ou se nenhum
/// tem ação automática.
fn select(findings: &[Finding], ids: &[usize]) -> Result<Vec<Finding>, String> {
    let mut chosen = Vec::new();
    for &id in ids {
        let f = findings
            .get(id)
            .ok_or("a lista mudou: faça a varredura de novo")?;
        if clean::plan(f).is_some_and(|p| !p.is_manual()) {
            chosen.push(f.clone());
        }
    }
    if chosen.is_empty() {
        return Err("nenhum dos itens escolhidos tem remoção automática".into());
    }
    Ok(chosen)
}

#[tauri::command]
async fn run_clean(
    state: State<'_, AppState>,
    ids: Vec<usize>,
    dry_run: bool,
) -> Result<CleanDto, String> {
    let chosen = select(
        &state
            .findings
            .lock()
            .map_err(|_| "estado interno bloqueado")?,
        &ids,
    )?;
    // O usuário já confirmou na tela, item a item; aqui a confirmação é sempre "sim".
    tauri::async_runtime::spawn_blocking(move || -> Result<CleanDto, String> {
        let opts = clean::Options {
            only: Vec::new(),
            dry_run,
            yes_for_safe: false,
        };
        if dry_run {
            let dir = clean::default_root().join("simulacao");
            let r = clean::run(
                &chosen,
                &opts,
                &dir,
                "não necessário (simulação)",
                &mut |_, _| true,
                &mut exec::execute,
            );
            return Ok(to_clean_dto(&r));
        }
        if !privilege::is_elevated() {
            return Err(format!(
                "A remoção exige administrador/root. {}",
                privilege::alert()
            ));
        }
        let restore_text = match restore::create() {
            Ok(r) => r.describe().to_string(),
            Err(e) => return Err(format!("Não removo nada sem ponto de restauração: {e}")),
        };
        let dir = clean::create_session(&clean::default_root())
            .map_err(|e| format!("Não consegui criar uma quarentena privada: {e}"))?;
        let r = clean::run(
            &chosen,
            &opts,
            &dir,
            &restore_text,
            &mut |_, _| true,
            &mut exec::execute,
        );
        let _ = std::fs::write(dir.join("report.html"), report::clean::html(&r));
        Ok(to_clean_dto(&r))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct QuarantineDto {
    name: String,
    path: String,
    items: usize,
    done: usize,
}

fn read_quarantine(dir: &Path) -> Option<QuarantineDto> {
    let text = std::fs::read_to_string(dir.join("manifest.json")).ok()?;
    let v: serde_json::Value = serde_json::from_str(text.trim_start_matches('\u{feff}')).ok()?;
    let records = v["registros"].as_array()?;
    Some(QuarantineDto {
        name: safe(&dir.file_name()?.to_string_lossy()),
        path: dir.display().to_string(),
        items: records.len(),
        done: records.iter().filter(|r| r["resultado"] == "feito").count(),
    })
}

#[tauri::command]
fn list_quarantines() -> Result<Vec<QuarantineDto>, String> {
    let root = clean::default_root();
    if !root.is_dir() {
        return Ok(Vec::new());
    }
    let entries = std::fs::read_dir(&root)
        .map_err(|e| format!("Sem acesso às quarentenas (administrador/root?): {e}"))?;
    let mut list: Vec<QuarantineDto> = entries
        .flatten()
        .filter_map(|e| read_quarantine(&e.path()))
        .collect();
    list.sort_by(|a, b| b.name.cmp(&a.name));
    Ok(list)
}

/// A pasta pedida pela tela tem de ser uma pasta DIRETAMENTE dentro da raiz das quarentenas.
fn quarantine_path(root: &Path, requested: &str) -> Result<PathBuf, String> {
    let dir = std::fs::canonicalize(requested).map_err(|_| "a quarentena não existe")?;
    let root = std::fs::canonicalize(root).map_err(|_| "a pasta das quarentenas não existe")?;
    if dir.parent() == Some(root.as_path()) && dir.is_dir() {
        Ok(dir)
    } else {
        Err("a pasta pedida não é uma quarentena do Oblivion".into())
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UndoDto {
    description: String,
    ok: bool,
    error: Option<String>,
}

#[tauri::command]
async fn undo_quarantine(path: String) -> Result<Vec<UndoDto>, String> {
    let dir = quarantine_path(&clean::default_root(), &path)?;
    let results = tauri::async_runtime::spawn_blocking(move || undo::undo(&dir))
        .await
        .map_err(|e| e.to_string())??;
    Ok(results
        .into_iter()
        .map(|r| UndoDto {
            description: safe(&r.description),
            ok: r.result.is_ok(),
            error: r.result.err().map(|e| safe(&e)),
        })
        .collect())
}

/// Grava o relatório HTML em `Documentos\Oblivion` e devolve o caminho.
#[tauri::command]
fn export_report(state: State<'_, AppState>) -> Result<String, String> {
    let findings = state
        .findings
        .lock()
        .map_err(|_| "estado interno bloqueado")?;
    let html = report::html::render(&findings, privilege::is_elevated());
    let home = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .ok_or("sem pasta do usuário")?;
    let dir = PathBuf::from(home).join("Documents").join("Oblivion");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let path = dir.join(format!("relatorio-{secs}.html"));
    std::fs::write(&path, html).map_err(|e| e.to_string())?;
    Ok(path.display().to_string())
}

/// Reabre o próprio programa pedindo administrador (o Windows mostra a janela do UAC; quem decide é o usuário).
#[tauri::command]
fn restart_as_admin(app: AppHandle) -> Result<(), String> {
    #[cfg(windows)]
    {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let exe = exe.display().to_string().replace('\'', "''");
        std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!("Start-Process -FilePath '{exe}' -Verb RunAs"),
            ])
            .spawn()
            .map_err(|e| e.to_string())?;
        app.exit(0);
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = app;
        Err("No Linux, abra o programa com sudo.".into())
    }
}

pub fn run() {
    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            app_info,
            run_scan,
            run_clean,
            list_quarantines,
            undo_quarantine,
            export_report,
            restart_as_admin
        ])
        .run(tauri::generate_context!())
        .expect("erro ao iniciar o Oblivion");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(name: &str, scanner: &'static str, location: &str, severity: Severity) -> Finding {
        Finding {
            scanner,
            location: location.into(),
            name: name.into(),
            target: format!("{name}.exe"),
            severity,
            reason: "motivo",
        }
    }

    #[test]
    fn dto_hides_hostile_characters_and_marks_what_can_be_removed() {
        let f = finding(
            "fatura\u{202E}fdp\x1b[2K",
            "minerador",
            "PID 7 | RAM 1 MB",
            Severity::High,
        );
        let dto = to_dto(3, &f);
        assert_eq!((dto.id, dto.severity), (3, "high"));
        assert_eq!(dto.name, "fatura?fdp?[2K");
        assert!(dto.actionable && dto.action.unwrap().contains("Encerrar o processo 7"));
    }

    #[test]
    fn only_miner_processes_flagged_by_weak_signals_get_the_warning() {
        let mut weak = finding(
            "editor.exe",
            "minerador",
            "PID 9 | RAM 1 MB",
            Severity::High,
        );
        weak.reason = "Mais de um sinal de mineração ao mesmo tempo";
        let mut strong = finding("xmrig.exe", "minerador", "PID 8 | RAM 1 MB", Severity::High);
        strong.reason = MINER_STRONG_REASON;
        let task = finding("t", "tarefas", "Agendador de Tarefas", Severity::High);
        assert!(to_dto(0, &weak).weak_signal);
        assert!(!to_dto(1, &strong).weak_signal && !to_dto(2, &task).weak_signal);
    }

    #[test]
    fn info_and_manual_findings_are_not_actionable() {
        let info = to_dto(
            0,
            &finding("a", "minerador", "PID 1 | RAM 1 MB", Severity::Info),
        );
        assert!(!info.actionable && info.action.is_none());
        let manual = to_dto(1, &finding("MBR", "mbr", "disco", Severity::High));
        assert!(
            !manual.actionable && manual.action.is_some(),
            "manual: mostra a instrução, sem remoção"
        );
    }

    #[test]
    fn selection_uses_server_side_findings_and_rejects_stale_or_empty_choices() {
        let list = vec![
            finding("a", "minerador", "PID 1 | RAM 1 MB", Severity::High),
            finding("mbr", "mbr", "disco", Severity::High),
        ];
        assert_eq!(select(&list, &[0]).unwrap().len(), 1);
        assert!(
            select(&list, &[5])
                .unwrap_err()
                .contains("varredura de novo")
        );
        assert!(
            select(&list, &[1]).unwrap_err().contains("nenhum"),
            "só manual: nada a fazer"
        );
        assert!(select(&list, &[]).is_err());
    }

    #[test]
    fn progress_maps_to_plain_events() {
        let p = ProgressDto::from(Progress::Finished {
            label: "X",
            count: 4,
        });
        assert_eq!((p.kind, p.label.as_str(), p.count), ("finished", "X", 4));
        assert_eq!(ProgressDto::from(Progress::Failed("Y")).kind, "failed");
    }

    #[test]
    fn undo_only_accepts_a_folder_directly_inside_the_quarantine_root() {
        let base = std::env::temp_dir().join(format!("oblivion-app-q-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("raiz");
        let inside = root.join("q1");
        let outside = base.join("fora");
        for d in [&inside, &outside, &root.join("q1").join("sub")] {
            std::fs::create_dir_all(d).unwrap();
        }
        assert!(quarantine_path(&root, &inside.display().to_string()).is_ok());
        for bad in [
            outside.display().to_string(),
            root.display().to_string(),
            root.join("q1").join("sub").display().to_string(),
            root.join("q1")
                .join("..")
                .join("..")
                .join("fora")
                .display()
                .to_string(),
            "C:\\nao-existe-oblivion".to_string(),
            String::new(),
        ] {
            assert!(quarantine_path(&root, &bad).is_err(), "{bad}");
        }
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn quarantine_listing_reads_the_manifest_counts() {
        let dir = std::env::temp_dir().join(format!("oblivion-app-m-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("manifest.json"),
            "\u{feff}{\"registros\":[{\"resultado\":\"feito\"},{\"resultado\":\"recusado\"}]}",
        )
        .unwrap();
        let q = read_quarantine(&dir).unwrap();
        assert_eq!((q.items, q.done), (2, 1));
        assert!(read_quarantine(&dir.join("nao-existe")).is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn app_info_exposes_the_workspace_version() {
        assert_eq!(app_info().version, env!("CARGO_PKG_VERSION"));
        assert!(!app_info().version.is_empty());
    }
}
