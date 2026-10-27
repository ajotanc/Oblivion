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
    allow,
    clean::{self, Outcome, exec, undo},
    explain,
    finding::{Finding, Severity},
    ioc, privilege, recent, recipe, report, restore,
    scanners::{self, Progress, ScanOptions},
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
    /// O que é, em linguagem simples.
    what: String,
    /// O que acontece se o item for tratado.
    impact: String,
    /// Sinal forte e ação reversível: o botão "Selecionar recomendados" marca estes.
    recommended: bool,
}

fn to_dto(id: usize, f: &Finding) -> FindingDto {
    let plan = clean::plan(f);
    let x = explain::explain(f);
    FindingDto {
        id,
        severity: severity_name(f.severity),
        scanner: f.scanner,
        name: safe(&f.name),
        location: safe(&f.location),
        target: safe(&f.target),
        reason: safe(f.reason),
        actionable: plan.as_ref().is_some_and(|p| !p.is_manual()),
        weak_signal: explain::is_weak_miner_signal(f),
        what: safe(&x.what),
        impact: safe(&x.impact),
        recommended: x.recommended,
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

/// O que a tela recebe de uma varredura (ou de uma receita): os itens e os avisos para mostrar ao usuário.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ScanDto {
    findings: Vec<FindingDto>,
    notes: Vec<String>,
}

fn store(
    state: &State<'_, AppState>,
    mut findings: Vec<Finding>,
    notes: Vec<String>,
) -> Result<ScanDto, String> {
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
    Ok(ScanDto {
        findings: dtos,
        notes: notes.iter().map(|n| safe(n)).collect(),
    })
}

/// Lê o texto colado/aberto na tela como as listas `--ioc` e `--allow` da CLI. Linha ruim vira aviso.
fn read_options(ioc_text: Option<&str>, allow_text: Option<&str>) -> (ScanOptions, Vec<String>) {
    let mut notes = Vec::new();
    let iocs = ioc_text
        .map(|t| {
            let (iocs, ignored) = ioc::Iocs::parse(t);
            if ignored > 0 {
                notes.push(format!(
                    "{ignored} linha(s) da lista de indicadores foram ignoradas (formato inválido)."
                ));
            }
            iocs
        })
        .unwrap_or_default();
    let allow = allow_text.map(allow::parse).unwrap_or_default();
    (ScanOptions { iocs, allow }, notes)
}

#[tauri::command]
async fn run_scan(
    app: AppHandle,
    state: State<'_, AppState>,
    ioc: Option<String>,
    allow: Option<String>,
) -> Result<ScanDto, String> {
    let (opts, notes) = read_options(ioc.as_deref(), allow.as_deref());
    let handle = app.clone();
    let findings = tauri::async_runtime::spawn_blocking(move || {
        scanners::scan_with(&opts, &|p| {
            let _ = handle.emit("scan-progress", ProgressDto::from(p));
        })
    })
    .await
    .map_err(|e| e.to_string())?;
    store(&state, findings, notes)
}

/// Receita: em vez de varrer, trata só o que o texto pede. Segue o mesmo caminho de revisão e limpeza.
#[tauri::command]
async fn load_recipe(state: State<'_, AppState>, text: String) -> Result<ScanDto, String> {
    let (findings, problems) = tauri::async_runtime::spawn_blocking(move || recipe::load(&text))
        .await
        .map_err(|e| e.to_string())?;
    store(&state, findings, problems)
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct RecentDto {
    name: String,
    path: String,
}

/// Arquivos novos nas pastas onde malware costuma se instalar (só diagnóstico).
#[tauri::command]
async fn recent_files(days: u32) -> Result<Vec<RecentDto>, String> {
    let found =
        tauri::async_runtime::spawn_blocking(move || recent::scan(u64::from(days.clamp(1, 365))))
            .await
            .map_err(|e| e.to_string())?;
    Ok(found
        .iter()
        .map(|f| RecentDto {
            name: safe(&f.name),
            path: safe(&f.target),
        })
        .collect())
}
#[derive(Serialize, Debug)]
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

#[derive(Serialize, Debug)]
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

/// Executa a limpeza (bloqueante). Fica fora do comando Tauri para poder ser testada sem a janela.
fn clean_blocking(chosen: Vec<Finding>, dry_run: bool) -> Result<CleanDto, String> {
    // O usuário já confirmou na tela, item a item; aqui a confirmação é sempre "sim".
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
    tauri::async_runtime::spawn_blocking(move || clean_blocking(chosen, dry_run))
        .await
        .map_err(|e| e.to_string())?
}
#[derive(Serialize, Debug)]
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

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct UndoDto {
    description: String,
    ok: bool,
    error: Option<String>,
}

/// Desfaz uma quarentena. Só aceita uma pasta diretamente dentro da raiz das quarentenas.
fn undo_dir(path: &str) -> Result<Vec<UndoDto>, String> {
    let dir = quarantine_path(&clean::default_root(), path)?;
    Ok(undo::undo(&dir)?
        .into_iter()
        .map(|r| UndoDto {
            description: safe(&r.description),
            ok: r.result.is_ok(),
            error: r.result.err().map(|e| safe(&e)),
        })
        .collect())
}

#[tauri::command]
async fn undo_quarantine(path: String) -> Result<Vec<UndoDto>, String> {
    tauri::async_runtime::spawn_blocking(move || undo_dir(&path))
        .await
        .map_err(|e| e.to_string())?
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

/// Comando do PowerShell que reabre o programa pedindo administrador. As aspas simples do caminho são
/// dobradas: sem isso um caminho com `'` terminaria o texto e o resto virava comando.
#[cfg_attr(not(windows), allow(dead_code))]
fn restart_command(exe: &str) -> String {
    format!(
        "Start-Process -FilePath '{}' -Verb RunAs",
        exe.replace('\'', "''")
    )
}

/// Reabre o próprio programa pedindo administrador (o Windows mostra a janela do UAC; quem decide é o usuário).
#[tauri::command]
fn restart_as_admin(app: AppHandle) -> Result<(), String> {
    #[cfg(windows)]
    {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &restart_command(&exe.display().to_string()),
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
            load_recipe,
            recent_files,
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
        strong.reason = oblivion_core::finding::MINER_STRONG_REASON;
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
    fn restart_command_quotes_the_path_so_it_cannot_inject_commands() {
        assert_eq!(
            restart_command(r"C:\Program Files\Oblivion\oblivion.exe"),
            r"Start-Process -FilePath 'C:\Program Files\Oblivion\oblivion.exe' -Verb RunAs"
        );
        // O caso perigoso: um caminho com aspa simples tentaria fechar o texto e rodar outro comando.
        let evil = restart_command("C:\\x'; Remove-Item C:\\ -Recurse; '.exe");
        assert!(evil.contains("x''; Remove-Item"), "{evil}");
        assert!(evil.starts_with("Start-Process -FilePath '") && evil.ends_with("' -Verb RunAs"));
    }

    #[test]
    fn undo_refuses_paths_that_are_not_quarantines() {
        for bad in [
            "",
            "..",
            r"C:\Windows",
            "/etc",
            r"C:\nao-existe-oblivion\q1",
        ] {
            assert!(undo_dir(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_non_elevated_real_clean_is_refused_before_touching_anything() {
        if privilege::is_elevated() {
            return; // sob administrador este teste não se aplica
        }
        let chosen = vec![finding(
            "x",
            "minerador",
            "PID 4000000000 | RAM 1 MB",
            Severity::High,
        )];
        let e = clean_blocking(chosen.clone(), false).unwrap_err();
        assert!(e.contains("exige administrador"), "{e}");
        // A simulação funciona sem administrador e não cria quarentena.
        let dry = clean_blocking(chosen, true).unwrap();
        assert!(dry.dry_run && dry.quarantine_dir.is_none());
    }

    /// Teste REAL da remoção pelo backend da interface. Altera o sistema (cria e remove itens de teste,
    /// cria uma quarentena e, se preciso, um ponto de restauração), por isso só roda quando pedido e
    /// elevado: `oblivion_app_lib --ignored real_clean`.
    #[cfg(windows)]
    #[test]
    #[ignore = "altera o sistema: rode só elevado, de propósito"]
    fn real_clean_and_undo_roundtrip_as_administrator() {
        use std::{process::Command, thread::sleep, time::Duration};
        use winreg::{RegKey, enums::*};

        struct Cleanup {
            value: String,
            dirs: Vec<std::path::PathBuf>,
            child: Option<std::process::Child>,
        }
        impl Drop for Cleanup {
            fn drop(&mut self) {
                if let Ok(k) = RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    KEY_WRITE,
                ) {
                    let _ = k.delete_value(&self.value);
                }
                if let Some(c) = self.child.as_mut() {
                    let _ = c.kill();
                    let _ = c.wait();
                }
                for d in &self.dirs {
                    let _ = std::fs::remove_dir_all(d);
                }
            }
        }

        assert!(privilege::is_elevated(), "este teste exige administrador");
        let pid = std::process::id();
        let value = format!("OblivionGuiE2E-{pid}");
        let work = std::env::temp_dir().join(format!("oblivion-gui-e2e-{pid}"));
        let mut guard = Cleanup {
            value: value.clone(),
            dirs: vec![work.clone()],
            child: None,
        };

        let run = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags(
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                KEY_ALL_ACCESS,
            )
            .unwrap();
        run.set_value(&value, &r"C:\oblivion-gui-e2e\gone.exe")
            .unwrap();
        std::fs::create_dir_all(&work).unwrap();
        let exe = work.join("xmrig-guie2e.exe");
        std::fs::copy(r"C:\Windows\System32\ping.exe", &exe).unwrap();
        guard.child = Some(
            Command::new(&exe)
                .args(["-t", "127.0.0.1"])
                .spawn()
                .unwrap(),
        );
        sleep(Duration::from_secs(2));

        // Só os itens de teste entram na escolha: nada do sistema real é tocado.
        let findings = scanners::scan_all();
        let ours: Vec<usize> = findings
            .iter()
            .enumerate()
            .filter(|(_, f)| {
                let n = f.name.to_lowercase();
                n.contains("oblivionguie2e") || n.contains("xmrig-guie2e")
            })
            .map(|(i, _)| i)
            .collect();
        assert_eq!(ours.len(), 2, "esperava o valor Run e o processo: {ours:?}");
        let chosen = select(&findings, &ours).unwrap();

        let dry = clean_blocking(chosen.clone(), true).unwrap();
        assert!(dry.records.iter().all(|r| r.outcome == "dryRun"));
        assert!(
            run.get_raw_value(&value).is_ok(),
            "a simulação não pode alterar nada"
        );

        let done = clean_blocking(chosen, false).unwrap();
        assert!(done.aborted.is_none(), "{:?}", done.aborted);
        assert!(
            done.records.iter().all(|r| r.outcome == "done"),
            "{:?}",
            done.records
                .iter()
                .map(|r| (&r.name, &r.outcome_label))
                .collect::<Vec<_>>()
        );
        assert!(
            run.get_raw_value(&value).is_err(),
            "o valor Run foi apagado"
        );
        sleep(Duration::from_millis(500));
        assert!(
            guard.child.as_mut().unwrap().try_wait().unwrap().is_some(),
            "o processo foi encerrado"
        );
        assert!(!exe.exists(), "o executável foi para a quarentena");

        let qdir = done.quarantine_dir.clone().expect("quarentena");
        guard.dirs.push(PathBuf::from(&qdir));
        assert!(
            list_quarantines()
                .unwrap()
                .iter()
                .any(|q| q.path == qdir && q.done == 2)
        );
        assert!(Path::new(&qdir).join("report.html").is_file());

        let undone = undo_dir(&qdir).unwrap();
        assert!(undone.iter().all(|u| u.ok), "{undone:?}");
        assert!(
            run.get_raw_value(&value).is_ok(),
            "o desfazer recriou o valor Run"
        );
        assert!(exe.exists(), "o desfazer devolveu o executável");
    }

    /// Serviço, assinatura do WMI e linha do hosts DE TESTE: remove/desativa, confere e desfaz. Só elevado.
    /// Tudo tem o marcador `oblivionbench`; o guarda desfaz mesmo se o teste falhar no meio.
    #[cfg(windows)]
    #[test]
    #[ignore = "altera serviços, WMI e o hosts: rode só elevado, de propósito"]
    fn real_service_wmi_and_hosts_roundtrip_as_administrator() {
        use std::process::Command;
        use winreg::{RegKey, enums::*};

        const SVC: &str = "OblivionBenchSvc";
        const WMI: &str = "OblivionBenchConsumer";
        const HOST: &str = "oblivionbench.invalid";

        fn ps(script: &str) -> String {
            let out = Command::new("powershell")
                .args(["-NoProfile", "-Command", script])
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }
        fn svc_start() -> Option<u32> {
            RegKey::predef(HKEY_LOCAL_MACHINE)
                .open_subkey(format!(r"SYSTEM\CurrentControlSet\Services\{SVC}"))
                .ok()?
                .get_value("Start")
                .ok()
        }
        fn wmi_exists() -> bool {
            ps(&format!(
                "(Get-WmiObject -Namespace root\\subscription -Class CommandLineEventConsumer | Where-Object {{ $_.Name -eq '{WMI}' }}) -ne $null"
            )) == "True"
        }

        struct Guard {
            hosts: Vec<u8>,
            dirs: Vec<PathBuf>,
        }
        impl Drop for Guard {
            fn drop(&mut self) {
                let _ = Command::new("sc.exe").args(["stop", SVC]).output();
                let _ = Command::new("sc.exe").args(["delete", SVC]).output();
                ps(&format!(
                    "$ns='root\\subscription'; \
                     Get-WmiObject -Namespace $ns -Class __FilterToConsumerBinding | Where-Object {{ $_.Consumer -like '*{WMI}*' }} | Remove-WmiObject; \
                     Get-WmiObject -Namespace $ns -Class CommandLineEventConsumer | Where-Object {{ $_.Name -eq '{WMI}' }} | Remove-WmiObject; \
                     Get-WmiObject -Namespace $ns -Class __EventFilter | Where-Object {{ $_.Name -eq '{WMI}' }} | Remove-WmiObject"
                ));
                let _ = std::fs::write(oblivion_core::scanners::hosts_file(), &self.hosts);
                for d in &self.dirs {
                    let _ = std::fs::remove_dir_all(d);
                }
            }
        }

        assert!(privilege::is_elevated(), "este teste exige administrador");
        let pid = std::process::id();
        let work = std::env::temp_dir().join(format!("oblivion-bench-svc-{pid}"));
        std::fs::create_dir_all(&work).unwrap();
        let exe = work.join("oblivionbench-svc.exe");
        std::fs::copy(r"C:\Windows\System32\ping.exe", &exe).unwrap();
        let hosts_path = oblivion_core::scanners::hosts_file();
        let original_hosts = std::fs::read(&hosts_path).unwrap();
        let mut guard = Guard {
            hosts: original_hosts.clone(),
            dirs: vec![work.clone()],
        };

        // 1) serviço automático apontando para um programa em Temp (nunca é iniciado de verdade)
        let created = Command::new("sc.exe")
            .args([
                "create",
                SVC,
                "binPath=",
                &exe.display().to_string(),
                "start=",
                "auto",
            ])
            .output()
            .unwrap();
        assert!(created.status.success(), "sc create falhou: {created:?}");
        assert_eq!(svc_start(), Some(2));
        // 2) assinatura do WMI (consumidor de linha de comando, filtro e vínculo)
        ps(&format!(
            "$ns='root\\subscription'; \
             $f = Set-WmiInstance -Namespace $ns -Class __EventFilter -Arguments @{{Name='{WMI}'; EventNamespace='root\\cimv2'; QueryLanguage='WQL'; Query='SELECT * FROM __InstanceModificationEvent WITHIN 600 WHERE TargetInstance ISA ''Win32_LocalTime'' AND TargetInstance.Hour=3 AND TargetInstance.Minute=33'}}; \
             $c = Set-WmiInstance -Namespace $ns -Class CommandLineEventConsumer -Arguments @{{Name='{WMI}'; CommandLineTemplate='cmd.exe /c rem oblivionbench'}}; \
             Set-WmiInstance -Namespace $ns -Class __FilterToConsumerBinding -Arguments @{{Filter=$f; Consumer=$c}} | Out-Null"
        ));
        assert!(wmi_exists(), "a assinatura de teste devia existir");
        // 3) linha suspeita no hosts
        let mut hosts = original_hosts.clone();
        hosts.extend_from_slice(format!("\r\n1.2.3.4 {HOST}\r\n").as_bytes());
        std::fs::write(&hosts_path, &hosts).unwrap();

        let findings = scanners::scan_all();
        let ours: Vec<usize> = findings
            .iter()
            .enumerate()
            .filter(|(_, f)| {
                f.name.contains(SVC) || f.name.contains(WMI) || f.target.contains(HOST)
            })
            .map(|(i, _)| i)
            .collect();
        assert_eq!(ours.len(), 3, "esperava serviço, WMI e hosts: {ours:?}");
        let chosen = select(&findings, &ours).unwrap();

        let done = clean_blocking(chosen, false).unwrap();
        assert!(done.aborted.is_none(), "{:?}", done.aborted);
        assert!(
            done.records.iter().all(|r| r.outcome == "done"),
            "{:?}",
            done.records
                .iter()
                .map(|r| (&r.name, &r.outcome_label, &r.note))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            svc_start(),
            Some(4),
            "o serviço foi desativado, não apagado"
        );
        assert!(!wmi_exists(), "a assinatura do WMI foi removida");
        let after = String::from_utf8_lossy(&std::fs::read(&hosts_path).unwrap()).into_owned();
        assert!(
            after.contains(&format!("# [Oblivion] 1.2.3.4 {HOST}")),
            "{after}"
        );

        let qdir = done.quarantine_dir.clone().expect("quarentena");
        guard.dirs.push(PathBuf::from(&qdir));
        let undone = undo_dir(&qdir).unwrap();
        assert!(undone.iter().all(|u| u.ok), "{undone:?}");
        assert_eq!(
            svc_start(),
            Some(2),
            "o desfazer devolveu o início automático"
        );
        assert!(wmi_exists(), "o desfazer recriou a assinatura do WMI");
        let restored = std::fs::read(&hosts_path).unwrap();
        assert_eq!(restored, hosts, "o desfazer devolveu o hosts");
    }

    #[test]
    fn every_dto_carries_a_plain_explanation_and_the_recommended_flag() {
        let strong = Finding {
            scanner: "minerador",
            location: "PID 7 | RAM 1 MB".into(),
            name: "xmrig.exe".into(),
            target: "x".into(),
            severity: Severity::High,
            reason: oblivion_core::finding::MINER_STRONG_REASON,
        };
        let dto = to_dto(0, &strong);
        assert!(dto.what.len() > 20 && !dto.impact.is_empty());
        assert!(dto.recommended);
        let info = Finding {
            severity: Severity::Info,
            ..strong
        };
        assert!(!to_dto(1, &info).recommended);
    }

    #[test]
    fn screen_options_are_read_like_the_command_line_lists() {
        let sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let (opts, notes) = read_options(
            Some(&format!("sha256:{sha}\nnome:x.exe\nlixo\n")),
            Some("# meu\nbackup.cmd\n"),
        );
        assert!(!opts.iocs.is_empty());
        assert_eq!(opts.allow, vec!["backup.cmd".to_string()]);
        assert_eq!(notes.len(), 1, "a linha inválida vira aviso: {notes:?}");
        let (empty, none) = read_options(None, None);
        assert!(empty.iocs.is_empty() && empty.allow.is_empty() && none.is_empty());
    }

    #[test]
    fn app_info_exposes_the_workspace_version() {
        assert_eq!(app_info().version, env!("CARGO_PKG_VERSION"));
        assert!(!app_info().version.is_empty());
    }
}
