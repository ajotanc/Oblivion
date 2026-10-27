//! Remoção opt-in de itens encontrados. O `scan` continua só leitura; nada aqui roda sem o usuário
//! pedir (`oblivion clean`). Regras de segurança:
//! - Só age em itens SUSPEITO ou ALTO; INFO nunca.
//! - Cada ação confere se o item ainda é o mesmo do scan (o valor, a tarefa, o processo) antes de agir.
//! - Antes de apagar, guarda o que apagou na quarentena (`manifest.json` + cópias), para `oblivion undo`.
//! - Só remove os tipos que sabe desfazer (valor Run, tarefa agendada, item da pasta Startup, processo
//!   e o executável dele). O resto (serviços, Winlogon, WMI, extensões, MBR) vira instrução manual.
//! - Com a confirmação do usuário, item a item. `--yes` cobre apenas ALTO e entradas órfãs.
pub mod exec;
pub mod secure;
pub mod undo;

use std::{
    fs, io,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::{Value, json};

use crate::finding::{Finding, MINER_STRONG_REASON, ORPHAN_REASON, Severity};

const MANUAL_SYSTEM: &str = "Serviços e chaves do sistema (ex.: Winlogon, cron, systemd) não são removidos automaticamente: confirme a origem e corrija manualmente.";

/// O que seria feito com um achado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    RunValue {
        hive: String,
        subkey: String,
        name: String,
    },
    Task {
        name: String,
    },
    Startup {
        path: PathBuf,
    },
    Process {
        pid: u32,
    },
    /// Não removemos sozinhos; o texto diz o que o usuário deve fazer.
    Manual(&'static str),
}

impl Plan {
    pub fn is_manual(&self) -> bool {
        matches!(self, Plan::Manual(_))
    }

    pub fn describe(&self) -> String {
        match self {
            Plan::RunValue { hive, subkey, name } => format!(
                "Apagar o valor \"{name}\" de {hive}\\{subkey} (o valor fica guardado na quarentena)"
            ),
            Plan::Task { name } => {
                format!("Apagar a tarefa agendada \"{name}\" (o XML fica guardado na quarentena)")
            }
            Plan::Startup { path } => format!("Mover \"{}\" para a quarentena", path.display()),
            Plan::Process { pid } => format!(
                "Encerrar o processo {pid} e mover o executável para a quarentena (se estiver numa pasta do usuário)"
            ),
            Plan::Manual(text) => (*text).to_string(),
        }
    }
}

/// `PID 123 | RAM 4 MB` -> 123.
fn pid_from_location(location: &str) -> Option<u32> {
    location
        .strip_prefix("PID ")?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

#[cfg_attr(not(windows), allow(unused_variables))]
fn persistence_plan(f: &Finding) -> Plan {
    #[cfg(windows)]
    {
        let location = f.location.replace('/', "\\").to_lowercase();
        if location.ends_with(r"start menu\programs\startup") {
            return Plan::Startup {
                path: PathBuf::from(&f.location).join(&f.name),
            };
        }
        if let Some((hive, subkey)) = f.location.split_once('\\')
            && crate::scanners::persistence_win::is_run_key(hive, subkey)
        {
            return Plan::RunValue {
                hive: hive.to_uppercase(),
                subkey: subkey.to_string(),
                name: f.name.clone(),
            };
        }
    }
    Plan::Manual(MANUAL_SYSTEM)
}

/// Plano para um achado, ou `None` se ele não pode ser alvo de remoção (INFO).
pub fn plan(f: &Finding) -> Option<Plan> {
    if f.severity == Severity::Info {
        return None;
    }
    Some(match f.scanner {
        "minerador" => pid_from_location(&f.location)
            .map_or(Plan::Manual("Encerre o processo manualmente."), |pid| {
                Plan::Process { pid }
            }),
        "tarefas" => Plan::Task {
            name: f.name.clone(),
        },
        "persistencia" => persistence_plan(f),
        "wmi" => Plan::Manual(
            "Remova o consumidor e o vínculo em root/subscription (Remove-CimInstance) depois de confirmar que não são de um programa seu.",
        ),
        "extensoes" => {
            Plan::Manual("Remova a extensão pelo próprio navegador (menu de extensões).")
        }
        "mbr" => Plan::Manual(
            "Não altere o MBR com ferramenta genérica: restaure o carregador de boot oficial ou use um disco de recuperação.",
        ),
        _ => Plan::Manual("Verifique manualmente."),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Done,
    /// Simulação (`--dry-run`): nada foi alterado.
    DryRun,
    Declined,
    /// Não removemos sozinhos este tipo de item.
    Manual,
    Skipped(String),
    Failed(String),
}

impl Outcome {
    pub fn label(&self) -> String {
        match self {
            Outcome::Done => "feito".into(),
            Outcome::DryRun => "simulado".into(),
            Outcome::Declined => "recusado".into(),
            Outcome::Manual => "manual".into(),
            Outcome::Skipped(why) => format!("ignorado: {why}"),
            Outcome::Failed(why) => format!("falhou: {why}"),
        }
    }
}

/// Resultado de executar uma ação: o que aconteceu e como desfazer.
#[derive(Debug, Clone)]
pub struct Exec {
    pub outcome: Outcome,
    pub note: String,
    pub undo: Vec<Value>,
}

#[derive(Debug, Clone)]
pub struct Record {
    pub finding: Finding,
    pub action: String,
    pub outcome: Outcome,
    pub note: String,
    pub undo: Vec<Value>,
}

#[derive(Debug, Clone)]
pub struct Report {
    pub dir: PathBuf,
    pub restore: String,
    pub dry_run: bool,
    pub records: Vec<Record>,
    /// Se não deu para gravar o registro do que foi feito, paramos: nunca agimos sem registro.
    pub aborted: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Só trata achados cujo nome ou alvo contém algum destes textos (sem diferenciar maiúsculas).
    pub only: Vec<String>,
    pub dry_run: bool,
    /// Dispensa a pergunta para ALTO e entradas órfãs. Os demais SUSPEITOS sempre perguntam.
    pub yes_for_safe: bool,
}

fn selected(f: &Finding, only: &[String]) -> bool {
    only.is_empty() || {
        let (name, target) = (f.name.to_lowercase(), f.target.to_lowercase());
        only.iter().any(|p| {
            let p = p.to_lowercase();
            name.contains(&p) || target.contains(&p)
        })
    }
}

/// Quantos achados selecionados têm uma ação automática (não só instrução manual). Serve para só
/// criar o ponto de restauração quando há mesmo algo a remover.
pub fn actionable_count(findings: &[Finding], only: &[String]) -> usize {
    findings
        .iter()
        .filter(|f| selected(f, only))
        .filter(|f| plan(f).is_some_and(|p| !p.is_manual()))
        .count()
}

/// O `--yes` só dispensa a pergunta quando o risco de errar é baixo. Encerrar um processo é mais
/// delicado: só vale pelo sinal forte (nome ou argumentos de minerador). CPU e GPU altas juntas também
/// descrevem um editor de vídeo ou um jogo, e esses sempre perguntam.
fn is_safe_to_auto_confirm(f: &Finding, plan: &Plan) -> bool {
    match plan {
        Plan::Process { .. } => f.reason == MINER_STRONG_REASON,
        _ => f.severity == Severity::High || f.reason == ORPHAN_REASON,
    }
}

fn manifest(restore: &str, records: &[Record]) -> Value {
    json!({
        "versao": 1,
        "ponto_de_restauracao": restore,
        "registros": records.iter().map(|r| json!({
            "nome": r.finding.name,
            "local": r.finding.location,
            "alvo": r.finding.target,
            "gravidade": r.finding.severity.label(),
            "motivo": r.finding.reason,
            "acao": r.action,
            "resultado": r.outcome.label(),
            "nota": r.note,
            "desfazer": r.undo,
        })).collect::<Vec<_>>(),
    })
}

fn write_manifest(dir: &Path, restore: &str, records: &[Record]) -> io::Result<()> {
    let text =
        serde_json::to_string_pretty(&manifest(restore, records)).map_err(io::Error::other)?;
    fs::write(dir.join("manifest.json"), text)
}

/// Primeira gravação: falha se já existe um manifesto, para nunca apagar o registro de outra limpeza.
fn write_first_manifest(dir: &Path, restore: &str) -> io::Result<()> {
    use io::Write;
    let text = serde_json::to_string_pretty(&manifest(restore, &[])).map_err(io::Error::other)?;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dir.join("manifest.json"))?
        .write_all(text.as_bytes())
}

/// Cria a pasta PRIVADA desta execução dentro de `root` (ver `secure`). O nome é o horário em segundos
/// (Unix); se já existe uma (duas limpezas no mesmo segundo), tenta `-1`, `-2`..., nunca reaproveita.
pub fn create_session(root: &Path) -> io::Result<PathBuf> {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    for n in 0..100 {
        let name = if n == 0 {
            format!("q{secs}")
        } else {
            format!("q{secs}-{n}")
        };
        let dir = root.join(name);
        match secure::create_private_dir(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::other(
        "não achei um nome livre para a pasta da quarentena",
    ))
}

/// Pasta padrão das quarentenas.
pub fn default_root() -> PathBuf {
    #[cfg(windows)]
    {
        std::env::var_os("ProgramData")
            .map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from)
            .join(r"Oblivion\Quarantine")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/var/lib/oblivion/quarantine")
    }
}

/// Percorre os achados (do mais grave ao menos grave) e age conforme as opções.
/// `confirm` pergunta ao usuário; `exec` faz a ação de verdade (injetável para testar sem tocar o sistema).
pub fn run(
    findings: &[Finding],
    opts: &Options,
    dir: &Path,
    restore: &str,
    confirm: &mut dyn FnMut(&Finding, &str) -> bool,
    exec: &mut dyn FnMut(&Plan, &Finding, &Path) -> Exec,
) -> Report {
    let mut report = Report {
        dir: dir.to_path_buf(),
        restore: restore.to_string(),
        dry_run: opts.dry_run,
        records: Vec::new(),
        aborted: None,
    };
    if !opts.dry_run
        && let Err(e) = fs::create_dir_all(dir).and_then(|()| write_first_manifest(dir, restore))
    {
        report.aborted = Some(format!(
            "não consegui criar a quarentena em {}: {e}",
            dir.display()
        ));
        return report;
    }
    let mut ordered: Vec<&Finding> = findings
        .iter()
        .filter(|f| selected(f, &opts.only))
        .collect();
    ordered.sort_by_key(|f| std::cmp::Reverse(f.severity));

    for f in ordered {
        let Some(plan) = plan(f) else { continue };
        let action = plan.describe();
        let (outcome, note, undo) = if plan.is_manual() {
            (Outcome::Manual, String::new(), Vec::new())
        } else if opts.dry_run {
            (Outcome::DryRun, String::new(), Vec::new())
        } else if (opts.yes_for_safe && is_safe_to_auto_confirm(f, &plan)) || confirm(f, &action) {
            let e = exec(&plan, f, dir);
            (e.outcome, e.note, e.undo)
        } else {
            (Outcome::Declined, String::new(), Vec::new())
        };
        report.records.push(Record {
            finding: f.clone(),
            action,
            outcome,
            note,
            undo,
        });
        if !opts.dry_run
            && let Err(e) = write_manifest(dir, restore, &report.records)
        {
            report.aborted = Some(format!(
                "não consegui gravar o registro em {}: {e}",
                dir.display()
            ));
            break;
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(
        scanner: &'static str,
        location: &str,
        name: &str,
        target: &str,
        severity: Severity,
    ) -> Finding {
        Finding {
            scanner,
            location: location.into(),
            name: name.into(),
            target: target.into(),
            severity,
            reason: "motivo",
        }
    }

    fn proc(name: &str, pid: u32, severity: Severity) -> Finding {
        finding(
            "minerador",
            &format!("PID {pid} | RAM 1 MB"),
            name,
            &format!("{name} --x"),
            severity,
        )
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("oblivion-clean-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    fn done() -> Exec {
        Exec {
            outcome: Outcome::Done,
            note: "ok".into(),
            undo: vec![json!({"kind": "teste"})],
        }
    }

    // ----- plano -----

    #[test]
    fn info_findings_are_never_planned() {
        assert_eq!(plan(&proc("a.exe", 1, Severity::Info)), None);
    }

    #[test]
    fn miner_process_plan_reads_the_pid_and_unreadable_pid_becomes_manual() {
        assert_eq!(
            plan(&proc("a.exe", 4242, Severity::High)),
            Some(Plan::Process { pid: 4242 })
        );
        let broken = finding("minerador", "sem pid", "a.exe", "a.exe", Severity::High);
        assert!(plan(&broken).unwrap().is_manual());
    }

    #[test]
    fn risky_or_unreversible_kinds_are_manual_only() {
        for scanner in ["wmi", "extensoes", "mbr", "desconhecido"] {
            let f = finding(scanner, "x", "n", "t", Severity::High);
            assert!(plan(&f).unwrap().is_manual(), "{scanner}");
        }
    }

    #[test]
    fn tasks_are_planned_by_name() {
        let f = finding(
            "tarefas",
            "Agendador de Tarefas",
            r"Vendor\Updater",
            "a.exe",
            Severity::Suspicious,
        );
        assert_eq!(
            plan(&f),
            Some(Plan::Task {
                name: r"Vendor\Updater".into()
            })
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_persistence_plans_only_known_run_keys_and_the_startup_folder() {
        let run = finding(
            "persistencia",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "Valor",
            "x.exe",
            Severity::High,
        );
        assert_eq!(
            plan(&run),
            Some(Plan::RunValue {
                hive: "HKCU".into(),
                subkey: r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run".into(),
                name: "Valor".into()
            })
        );
        let startup = finding(
            "persistencia",
            r"C:\Users\x\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
            "a.lnk",
            "x.exe",
            Severity::Suspicious,
        );
        assert!(matches!(plan(&startup), Some(Plan::Startup { .. })));
        // Winlogon e serviços NUNCA são removidos automaticamente (quebrariam o login).
        for location in [
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            r"HKLM\SYSTEM\CurrentControlSet\Services",
            r"HKCU\SOFTWARE\Qualquer\Outra\Chave",
        ] {
            let f = finding(
                "persistencia",
                location,
                "Shell",
                "evil.exe",
                Severity::High,
            );
            assert!(plan(&f).unwrap().is_manual(), "{location}");
        }
    }

    #[test]
    fn describe_names_what_will_happen() {
        assert!(
            Plan::Process { pid: 7 }
                .describe()
                .contains("Encerrar o processo 7")
        );
        assert!(
            Plan::Task { name: "T".into() }
                .describe()
                .contains("quarentena")
        );
        assert_eq!(Plan::Manual("faça X").describe(), "faça X");
    }

    // ----- run: regras de decisão (sem tocar o sistema) -----

    #[test]
    fn dry_run_never_asks_never_executes_and_writes_nothing() {
        let dir = temp_dir("dry");
        let mut asked = 0;
        let mut ran = 0;
        let r = run(
            &[proc("a.exe", 1, Severity::High)],
            &Options {
                dry_run: true,
                ..Options::default()
            },
            &dir,
            "teste",
            &mut |_, _| {
                asked += 1;
                true
            },
            &mut |_, _, _| {
                ran += 1;
                done()
            },
        );
        assert_eq!((asked, ran), (0, 0));
        assert_eq!(r.records[0].outcome, Outcome::DryRun);
        assert!(!dir.exists(), "simulação não cria a quarentena");
    }

    #[test]
    fn declined_items_are_not_executed() {
        let dir = temp_dir("decl");
        let mut ran = 0;
        let r = run(
            &[proc("a.exe", 1, Severity::High)],
            &Options::default(),
            &dir,
            "teste",
            &mut |_, _| false,
            &mut |_, _, _| {
                ran += 1;
                done()
            },
        );
        fs::remove_dir_all(&dir).unwrap();
        assert_eq!(ran, 0);
        assert_eq!(r.records[0].outcome, Outcome::Declined);
    }

    #[test]
    fn manual_and_info_items_are_never_executed_even_if_the_user_says_yes() {
        let dir = temp_dir("man");
        let mut ran = 0;
        let r = run(
            &[
                finding("mbr", "disco", "MBR", "x", Severity::High),
                proc("info.exe", 2, Severity::Info),
            ],
            &Options {
                yes_for_safe: true,
                ..Options::default()
            },
            &dir,
            "teste",
            &mut |_, _| true,
            &mut |_, _, _| {
                ran += 1;
                done()
            },
        );
        fs::remove_dir_all(&dir).unwrap();
        assert_eq!(ran, 0);
        assert_eq!(r.records.len(), 1, "INFO nem entra");
        assert_eq!(r.records[0].outcome, Outcome::Manual);
    }

    fn task(name: &str, severity: Severity, reason: &'static str) -> Finding {
        let mut f = finding("tarefas", "Agendador de Tarefas", name, "a.exe", severity);
        f.reason = reason;
        f
    }

    #[test]
    fn yes_covers_high_and_orphans_but_other_suspicious_items_still_ask() {
        let dir = temp_dir("yes");
        let mut asked = Vec::new();
        let r = run(
            &[
                task("alto-task", Severity::High, "motivo"),
                task("orfa-task", Severity::Suspicious, ORPHAN_REASON),
                task("duvida-task", Severity::Suspicious, "motivo"),
            ],
            &Options {
                yes_for_safe: true,
                ..Options::default()
            },
            &dir,
            "teste",
            &mut |f, _| {
                asked.push(f.name.clone());
                false
            },
            &mut |_, _, _| done(),
        );
        fs::remove_dir_all(&dir).unwrap();
        assert_eq!(asked, vec!["duvida-task"]);
        let outcome = |n: &str| {
            r.records
                .iter()
                .find(|x| x.finding.name == n)
                .unwrap()
                .outcome
                .clone()
        };
        assert_eq!(outcome("alto-task"), Outcome::Done);
        assert_eq!(outcome("orfa-task"), Outcome::Done);
        assert_eq!(outcome("duvida-task"), Outcome::Declined);
    }

    #[test]
    fn yes_kills_a_process_only_for_the_strong_signal_never_for_cpu_plus_gpu() {
        // O caso da auditoria: editor de vídeo (CPU alta + GPU) vira ALTO por dois sinais fracos.
        let dir = temp_dir("yesproc");
        let mut strong = proc("minerador.exe", 1, Severity::High);
        strong.reason = MINER_STRONG_REASON;
        let mut weak = proc("editor-de-video.exe", 2, Severity::High);
        weak.reason = "Mais de um sinal de mineração ao mesmo tempo";
        let mut asked = Vec::new();
        let r = run(
            &[strong, weak],
            &Options {
                yes_for_safe: true,
                ..Options::default()
            },
            &dir,
            "teste",
            &mut |f, _| {
                asked.push(f.name.clone());
                false
            },
            &mut |_, _, _| done(),
        );
        fs::remove_dir_all(&dir).unwrap();
        assert_eq!(
            asked,
            vec!["editor-de-video.exe"],
            "o sinal fraco pergunta, mesmo com --yes"
        );
        let outcome = |n: &str| {
            r.records
                .iter()
                .find(|x| x.finding.name == n)
                .unwrap()
                .outcome
                .clone()
        };
        assert_eq!(outcome("minerador.exe"), Outcome::Done);
        assert_eq!(outcome("editor-de-video.exe"), Outcome::Declined);
    }

    #[test]
    fn only_filter_limits_the_items_and_the_most_severe_go_first() {
        let dir = temp_dir("only");
        let mut order = Vec::new();
        let r = run(
            &[
                proc("outro.exe", 9, Severity::High),
                proc("meu-teste-1.exe", 1, Severity::Suspicious),
                proc("MEU-TESTE-2.exe", 2, Severity::High),
            ],
            &Options {
                only: vec!["meu-teste".into()],
                ..Options::default()
            },
            &dir,
            "teste",
            &mut |f, _| {
                order.push(f.name.clone());
                true
            },
            &mut |_, _, _| done(),
        );
        fs::remove_dir_all(&dir).unwrap();
        assert_eq!(order, vec!["MEU-TESTE-2.exe", "meu-teste-1.exe"]);
        assert_eq!(r.records.len(), 2);
    }

    #[test]
    fn manifest_records_everything_that_was_done_with_the_undo_data() {
        let dir = temp_dir("man2");
        let _ = run(
            &[proc("a.exe", 1, Severity::High)],
            &Options::default(),
            &dir,
            "Ponto criado",
            &mut |_, _| true,
            &mut |_, _, _| done(),
        );
        let text = fs::read_to_string(dir.join("manifest.json")).unwrap();
        fs::remove_dir_all(&dir).unwrap();
        let v: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["ponto_de_restauracao"], "Ponto criado");
        assert_eq!(v["registros"][0]["resultado"], "feito");
        assert_eq!(v["registros"][0]["desfazer"][0]["kind"], "teste");
        assert_eq!(v["registros"][0]["nome"], "a.exe");
    }

    #[test]
    fn nothing_is_executed_if_the_record_cannot_be_written() {
        // O "diretório" é um arquivo comum: não dá para criar a quarentena nem o registro.
        let file =
            std::env::temp_dir().join(format!("oblivion-clean-arquivo-{}", std::process::id()));
        fs::write(&file, "x").unwrap();
        let mut ran = 0;
        let r = run(
            &[proc("a.exe", 1, Severity::High)],
            &Options::default(),
            &file.join("sub"),
            "teste",
            &mut |_, _| true,
            &mut |_, _, _| {
                ran += 1;
                done()
            },
        );
        fs::remove_file(&file).unwrap();
        assert_eq!(ran, 0);
        assert!(r.aborted.is_some() && r.records.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn two_sessions_in_the_same_second_get_different_private_folders() {
        // O caso da auditoria: duas limpezas no mesmo segundo apagavam o desfazer da primeira.
        let root = temp_dir("sess");
        let a = create_session(&root).unwrap();
        let b = create_session(&root).unwrap();
        assert_ne!(a, b);
        assert!(a.starts_with(&root) && b.starts_with(&root));
        assert!(a.file_name().unwrap().to_string_lossy().starts_with('q'));
        fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn without_administrator_no_session_folder_is_created_as_if_it_were_private() {
        if !crate::privilege::is_elevated() {
            let root = temp_dir("sessw");
            assert!(create_session(&root).is_err());
            let _ = fs::remove_dir_all(&root);
        }
    }

    #[test]
    fn a_second_run_in_the_same_folder_never_overwrites_the_first_manifest() {
        let dir = temp_dir("again");
        let opts = Options::default();
        let first = run(
            &[proc("a.exe", 1, Severity::High)],
            &opts,
            &dir,
            "primeira",
            &mut |_, _| true,
            &mut |_, _, _| done(),
        );
        assert!(first.aborted.is_none());
        let second = run(
            &[proc("b.exe", 2, Severity::High)],
            &opts,
            &dir,
            "segunda",
            &mut |_, _| true,
            &mut |_, _, _| done(),
        );
        assert!(
            second.aborted.is_some() && second.records.is_empty(),
            "a segunda recusa seguir"
        );
        let text = fs::read_to_string(dir.join("manifest.json")).unwrap();
        fs::remove_dir_all(&dir).unwrap();
        assert!(text.contains("primeira") && text.contains("a.exe") && !text.contains("b.exe"));
    }

    #[test]
    fn outcome_labels_explain_themselves() {
        assert_eq!(Outcome::Done.label(), "feito");
        assert!(Outcome::Failed("x".into()).label().contains("falhou: x"));
        assert!(Outcome::Skipped("y".into()).label().contains("ignorado: y"));
    }
}
