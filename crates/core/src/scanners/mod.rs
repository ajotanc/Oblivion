mod browser;
mod firefox;
mod mbr;
mod miner;
mod persistence_linux;
#[cfg(windows)]
pub(crate) mod persistence_win;
#[cfg(windows)]
pub(crate) mod tasks_win;
#[cfg(windows)]
mod wmi_win;

use std::thread;

use crate::finding::{Finding, Severity};

/// Andamento do scan, para a interface mostrar um log ao vivo (o CLI ignora).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Progress<'a> {
    Started(&'a str),
    Finished {
        label: &'a str,
        count: usize,
    },
    /// O scanner parou por erro interno; essa parte NÃO foi verificada.
    Failed(&'a str),
}

/// (nome para o usuário, scanner, trabalho)
type Job = (
    &'static str,
    &'static str,
    Box<dyn FnOnce() -> Vec<Finding> + Send>,
);

/// Um scanner que parou por erro interno não pode simplesmente sumir do relatório: vira um aviso,
/// para ninguém achar que aquela parte do sistema foi verificada.
fn failed_scanner(scanner: &'static str, label: &str) -> Finding {
    Finding {
        scanner,
        location: "interno".into(),
        name: format!("Scanner \"{label}\" falhou"),
        target: String::new(),
        severity: Severity::Info,
        reason: "O scanner parou por um erro interno; essa parte NÃO foi verificada",
    }
}

/// Roda os scanners ao mesmo tempo (o do minerador sozinho leva ~5 s medindo a CPU) e junta os achados.
fn run_parallel(jobs: Vec<Job>, on_progress: &(dyn Fn(Progress) + Sync)) -> Vec<Finding> {
    thread::scope(|s| {
        let handles: Vec<_> = jobs
            .into_iter()
            .map(|(label, scanner, job)| {
                let handle = s.spawn(move || {
                    on_progress(Progress::Started(label));
                    let found = job();
                    on_progress(Progress::Finished {
                        label,
                        count: found.len(),
                    });
                    found
                });
                (label, scanner, handle)
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|(label, scanner, h)| {
                h.join().unwrap_or_else(|_| {
                    on_progress(Progress::Failed(label));
                    vec![failed_scanner(scanner, label)]
                })
            })
            .collect()
    })
}

/// Persistência do Windows: depois de reunir tudo, as evidências sobre os executáveis (arquivo que
/// sumiu, assinatura digital, script em System32) ajustam a gravidade.
#[cfg(windows)]
fn startup_windows() -> Vec<Finding> {
    use crate::trust;
    let mut startup = persistence_win::scan();
    startup.extend(tasks_win::scan());
    // Órfãos antes da assinatura: arquivo que sumiu não tem o que verificar.
    trust::flag_orphans(&mut startup);
    trust::downgrade_signed(&mut startup);
    trust::downgrade_system_scripts(&mut startup);
    startup
}

/// Roda todos os scanners da plataforma atual e devolve os achados, do mais grave ao menos grave.
pub fn scan_all() -> Vec<Finding> {
    scan_all_with(&|_| {})
}

/// Igual a `scan_all`, avisando o andamento (para a interface mostrar um log ao vivo).
pub fn scan_all_with(on_progress: &(dyn Fn(Progress) + Sync)) -> Vec<Finding> {
    let mut jobs: Vec<Job> = vec![
        (
            "Extensões do Chromium",
            "extensoes",
            Box::new(browser::scan),
        ),
        ("Extensões do Firefox", "extensoes", Box::new(firefox::scan)),
        ("Setor de boot (MBR)", "mbr", Box::new(mbr::scan)),
        (
            "Mineradores (CPU, GPU e rede)",
            "minerador",
            Box::new(miner::scan),
        ),
    ];
    #[cfg(windows)]
    {
        jobs.push((
            "Persistência, serviços e tarefas agendadas",
            "persistencia",
            Box::new(startup_windows),
        ));
        jobs.push(("WMI", "wmi", Box::new(wmi_win::scan)));
    }
    #[cfg(unix)]
    jobs.push((
        "Persistência (systemd, cron, autostart)",
        "persistencia",
        Box::new(persistence_linux::scan),
    ));

    let mut findings = run_parallel(jobs, on_progress);
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    findings
}

#[cfg(test)]
mod tests {
    use std::{
        sync::Mutex,
        time::{Duration, Instant},
    };

    use super::*;

    fn finding(name: &str) -> Finding {
        Finding {
            scanner: "t",
            location: "l".into(),
            name: name.into(),
            target: String::new(),
            severity: Severity::Suspicious,
            reason: "r",
        }
    }

    fn sleeper(name: &'static str) -> Job {
        (
            name,
            "t",
            Box::new(move || {
                thread::sleep(Duration::from_millis(400));
                vec![finding(name)]
            }),
        )
    }

    #[test]
    fn scanners_run_at_the_same_time_not_one_after_another() {
        let start = Instant::now();
        let found = run_parallel(vec![sleeper("a"), sleeper("b"), sleeper("c")], &|_| {});
        let took = start.elapsed();
        assert_eq!(found.len(), 3);
        assert!(
            took < Duration::from_millis(1000),
            "levou {took:?}; em fila seriam 1200 ms"
        );
    }

    #[test]
    fn a_scanner_that_panics_is_reported_and_the_others_survive() {
        // O caso da auditoria: sem isso um erro interno faria uma parte do sistema sumir do relatório.
        let jobs: Vec<Job> = vec![
            ("Bom", "bom", Box::new(|| vec![finding("ok")])),
            ("Quebrado", "quebrado", Box::new(|| panic!("erro de teste"))),
        ];
        let found = run_parallel(jobs, &|_| {});
        assert_eq!(found.len(), 2);
        assert!(found.iter().any(|f| f.name == "ok"));
        let warn = found.iter().find(|f| f.scanner == "quebrado").unwrap();
        assert!(warn.name.contains("falhou") && warn.reason.contains("NÃO foi verificada"));
    }

    #[test]
    fn progress_reports_every_start_and_finish_and_failures() {
        let events = Mutex::new(Vec::<String>::new());
        let jobs: Vec<Job> = vec![
            ("A", "a", Box::new(|| vec![finding("1"), finding("2")])),
            ("B", "b", Box::new(|| panic!("falha"))),
        ];
        run_parallel(jobs, &|p| {
            events.lock().unwrap().push(match p {
                Progress::Started(l) => format!("começou {l}"),
                Progress::Finished { label, count } => format!("terminou {label} {count}"),
                Progress::Failed(l) => format!("falhou {l}"),
            });
        });
        let mut got = events.into_inner().unwrap();
        got.sort();
        assert_eq!(
            got,
            vec!["começou A", "começou B", "falhou B", "terminou A 2"]
        );
    }

    #[test]
    fn no_jobs_means_no_findings() {
        assert!(run_parallel(Vec::new(), &|_| {}).is_empty());
    }
}
