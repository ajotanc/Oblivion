//! Visão cruzada de processos: compara duas formas independentes de listar o que está rodando. Um rootkit
//! de modo usuário esconde o processo de UMA delas (a que o Gerenciador de Tarefas usa), mas dificilmente
//! das duas. No Windows: a lista direta do sistema contra o WMI. No Linux: a listagem de /proc contra o
//! teste direto de cada PID.
//!
//! LIMITE (importante): isto NÃO detecta rootkits de kernel, que enganam todas as visões ao mesmo tempo.
//! Diferença entre as listas é indício, não veredito: um processo curtíssimo pode aparecer só numa delas,
//! por isso cada PID só é apontado se continuar sumido numa segunda conferência.
use std::collections::{BTreeMap, BTreeSet};

use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};

use crate::finding::{Finding, Severity};

const SCANNER: &str = "rootkit";
const REASON: &str = "Aparece numa forma de listar processos e some da outra (possível ocultação por rootkit; confira)";

fn api_pids() -> BTreeSet<u32> {
    let mut sys = System::new();
    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, ProcessRefreshKind::nothing());
    sys.processes().keys().map(|p| p.as_u32()).collect()
}

/// PIDs vistos por `other` e por nenhuma das duas amostras da lista direta.
pub fn only_in_other(
    direct_before: &BTreeSet<u32>,
    direct_after: &BTreeSet<u32>,
    other: &BTreeMap<u32, String>,
) -> Vec<u32> {
    other
        .keys()
        .copied()
        .filter(|pid| *pid != 0 && !direct_before.contains(pid) && !direct_after.contains(pid))
        .collect()
}

fn finding(pid: u32, name: &str) -> Finding {
    Finding {
        scanner: SCANNER,
        location: format!("PID {pid}"),
        name: name.to_string(),
        target: name.to_string(),
        severity: Severity::Suspicious,
        reason: REASON,
    }
}

/// Lista pelo WMI (outro caminho no sistema). `None` se o PowerShell/WMI falhar: sem visão, sem comparação.
#[cfg(windows)]
fn other_view() -> Option<BTreeMap<u32, String>> {
    use std::time::Duration;
    let script =
        r#"Get-CimInstance Win32_Process | ForEach-Object { "$($_.ProcessId)|$($_.Name)" }"#;
    let out = crate::sys::powershell(script, None, Duration::from_secs(30))?;
    let map: BTreeMap<u32, String> = out
        .lines()
        .filter_map(|l| {
            let (pid, name) = l.split_once('|')?;
            Some((pid.trim().parse().ok()?, name.trim().to_string()))
        })
        .collect();
    // Lista vazia = o WMI não respondeu direito; comparar assim apontaria tudo como escondido.
    (!map.is_empty()).then_some(map)
}

/// No Linux, "a outra visão" é perguntar por cada PID possível, sem usar a listagem de /proc.
#[cfg(unix)]
fn other_view() -> Option<BTreeMap<u32, String>> {
    let max: u32 = std::fs::read_to_string("/proc/sys/kernel/pid_max")
        .ok()?
        .trim()
        .parse()
        .ok()?;
    let mut map = BTreeMap::new();
    for pid in 2..=max.min(4_194_304) {
        let dir = format!("/proc/{pid}");
        if std::path::Path::new(&dir).exists() {
            let name = std::fs::read_to_string(format!("{dir}/comm")).unwrap_or_default();
            map.insert(pid, name.trim().to_string());
        }
    }
    Some(map)
}

pub fn scan() -> Vec<Finding> {
    let before = api_pids();
    let Some(other) = other_view() else {
        return vec![Finding {
            scanner: SCANNER,
            location: "interno".into(),
            name: "Visão cruzada de processos NÃO feita".into(),
            target: String::new(),
            severity: Severity::Info,
            reason: "A segunda forma de listar processos não respondeu; essa checagem não foi feita",
        }];
    };
    let after = api_pids();
    let mut candidates = only_in_other(&before, &after, &other);
    if !candidates.is_empty() {
        // Segunda conferência: processo efêmero já terá sumido das duas listas; ocultação continua.
        let (b2, o2) = (api_pids(), other_view().unwrap_or_default());
        let a2 = api_pids();
        let still = only_in_other(&b2, &a2, &o2);
        candidates.retain(|pid| still.contains(pid));
        return candidates
            .into_iter()
            .map(|pid| finding(pid, &o2[&pid]))
            .collect();
    }
    Vec::new()
}
#[cfg(test)]
mod tests {
    use super::*;

    fn set(v: &[u32]) -> BTreeSet<u32> {
        v.iter().copied().collect()
    }

    fn map(v: &[(u32, &str)]) -> BTreeMap<u32, String> {
        v.iter().map(|(p, n)| (*p, n.to_string())).collect()
    }

    #[test]
    fn identical_views_report_nothing() {
        assert!(
            only_in_other(&set(&[4, 8]), &set(&[4, 8]), &map(&[(4, "a"), (8, "b")])).is_empty()
        );
    }

    #[test]
    fn a_pid_missing_from_both_direct_samples_is_reported() {
        let hidden = only_in_other(
            &set(&[4, 8]),
            &set(&[4, 8]),
            &map(&[(4, "a"), (8, "b"), (1234, "x")]),
        );
        assert_eq!(hidden, vec![1234]);
    }

    #[test]
    fn a_process_that_appeared_between_the_samples_is_not_reported() {
        // Apareceu depois da primeira lista direta: a segunda já o vê, então não é ocultação.
        assert!(
            only_in_other(&set(&[4]), &set(&[4, 99]), &map(&[(4, "a"), (99, "novo")])).is_empty()
        );
    }

    #[test]
    fn pid_zero_is_ignored() {
        assert!(only_in_other(&set(&[]), &set(&[]), &map(&[(0, "Idle")])).is_empty());
    }

    #[test]
    fn a_real_machine_has_matching_views() {
        // Máquina comum, sem rootkit: o scan roda e não aponta mais que ruído de processos efêmeros.
        let found = scan();
        assert!(found.len() <= 3, "{found:?}");
        assert!(found.iter().all(|f| f.scanner == SCANNER));
    }
}
