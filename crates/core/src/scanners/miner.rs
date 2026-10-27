//! Mineradores de criptomoeda: combina sinais de nome, linha de comando, CPU, GPU e rede.
//! Só detecta e reporta; nunca encerra processo.
use std::{
    collections::{HashMap, HashSet},
    process, thread,
    time::Duration,
};

use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

use crate::finding::{Finding, MINER_STRONG_REASON, Severity};
use crate::sys;

const SCANNER: &str = "minerador";
/// Amostras de CPU, 1 s entre elas: o uso precisa ficar alto em todas (sustentado).
const SAMPLES: usize = 4;
/// Percentual do total de CPUs lógicas.
const CPU_THRESHOLD: f32 = 40.0;

// Em minúsculas. Sinais fortes: nomes de mineradores conhecidos e argumentos típicos de pool.
const MINER_NAMES: &[&str] = &[
    "xmrig",
    "nbminer",
    "t-rex",
    "phoenixminer",
    "lolminer",
    "gminer",
    "ethminer",
    "cgminer",
    "bfgminer",
    "cpuminer",
    "minerd",
    "nanominer",
    "teamredminer",
    "srbminer",
    "claymore",
];
const MINER_ARGS: &[&str] = &["stratum", "--donate-level", "cryptonight"];

/// Portas comuns de pools. Também são usadas por outros serviços, por isso é só sinal fraco.
const POOL_PORTS: &[u16] = &[3333, 4444, 5555, 7777, 14433, 14444, 45560, 45700];

/// Sinais fracos: cada um sozinho é comum em programas legítimos.
#[derive(Debug, Default, Clone, Copy)]
pub struct Signals {
    pub cpu_high: bool,
    pub gpu_compute: bool,
    pub pool_connection: bool,
}

/// O processo e todos os seus ancestrais, do mais novo ao mais antigo.
fn ancestors(start: Pid, parent_of: impl Fn(Pid) -> Option<Pid>) -> HashSet<Pid> {
    let mut set = HashSet::new();
    let mut cur = Some(start);
    while let Some(pid) = cur {
        if !set.insert(pid) {
            break; // ciclo: nunca deveria acontecer, mas não trava
        }
        cur = parent_of(pid);
    }
    set
}

/// Um sinal forte basta para ALTO; um sinal fraco é SUSPEITO; dois ou mais fracos são ALTO.
pub fn assess(name: &str, cmdline: &str, signals: Signals) -> Option<(Severity, &'static str)> {
    let (name, cmd) = (name.to_lowercase(), cmdline.to_lowercase());
    if MINER_NAMES.iter().any(|m| name.contains(m)) || MINER_ARGS.iter().any(|a| cmd.contains(a)) {
        return Some((Severity::High, MINER_STRONG_REASON));
    }
    let weak = [
        (signals.cpu_high, "Uso de CPU alto e contínuo"),
        (signals.gpu_compute, "Usa a GPU para computação"),
        (
            signals.pool_connection,
            "Conexão a porta típica de pool de mineração",
        ),
    ];
    let mut active = weak.iter().filter(|(on, _)| *on);
    match (active.next(), active.next()) {
        (Some(&(_, reason)), None) => Some((Severity::Suspicious, reason)),
        (Some(_), Some(_)) => Some((
            Severity::High,
            "Mais de um sinal de mineração ao mesmo tempo",
        )),
        _ => None,
    }
}

pub fn scan() -> Vec<Finding> {
    let mut sys = System::new();
    let kind = ProcessRefreshKind::nothing()
        .with_cpu()
        .with_memory()
        .with_cmd(UpdateKind::Always);
    let cpus = thread::available_parallelism().map_or(1, |n| n.get()) as f32;

    // A 1ª leitura só cria a base de comparação; o uso de CPU vem das leituras seguintes.
    // Guarda o menor uso visto por processo e em quantas amostras ele apareceu.
    let mut lowest: HashMap<Pid, (f32, usize)> = HashMap::new();
    for i in 0..=SAMPLES {
        thread::sleep(Duration::from_secs(1));
        sys.refresh_processes_specifics(ProcessesToUpdate::All, true, kind);
        if i > 0 {
            for (pid, p) in sys.processes() {
                let e = lowest.entry(*pid).or_insert((f32::MAX, 0));
                *e = (e.0.min(p.cpu_usage() / cpus), e.1 + 1);
            }
        }
    }

    let gpu_pids = gpu_compute_pids();
    let pool_pids = pool_connection_pids();
    // Pula o próprio Oblivion e quem o iniciou (terminal, `sudo`): a linha de comando deles pode conter
    // o texto que o usuário digitou (`--only xmrig`) e eles seriam marcados como minerador por engano.
    let skip = ancestors(Pid::from_u32(process::id()), |p| {
        sys.process(p).and_then(|x| x.parent())
    });
    let mut out = Vec::new();
    for (pid, p) in sys.processes() {
        if pid.as_u32() == 0 || skip.contains(pid) {
            continue;
        }
        let signals = Signals {
            cpu_high: lowest
                .get(pid)
                .is_some_and(|&(min, n)| n == SAMPLES && min >= CPU_THRESHOLD),
            gpu_compute: gpu_pids.contains(&pid.as_u32()),
            pool_connection: pool_pids.contains(&pid.as_u32()),
        };
        let name = p.name().to_string_lossy().into_owned();
        let cmdline = p
            .cmd()
            .iter()
            .map(|a| a.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ");
        let Some((severity, reason)) = assess(&name, &cmdline, signals) else {
            continue;
        };
        out.push(Finding {
            scanner: SCANNER,
            location: format!("PID {} | RAM {} MB", pid, p.memory() / 1_048_576),
            name,
            target: cmdline,
            severity,
            reason,
        });
    }
    out
}

/// PIDs com carga de computação na GPU agora (NVIDIA, AMD e Intel), via contadores do Windows.
/// shortcut: uma única amostra e só Windows; no Linux usar nvidia-smi/rocm-smi quando chegar a hora.
#[cfg(windows)]
fn gpu_compute_pids() -> HashSet<u32> {
    let script = "Get-CimInstance Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine | \
        Where-Object { $_.UtilizationPercentage -gt 20 -and $_.Name -match 'engtype_(Compute|Cuda)' } | \
        ForEach-Object { $_.Name }";
    sys::powershell(script, None, Duration::from_secs(30))
        .map(|out| out.lines().filter_map(parse_gpu_pid).collect())
        .unwrap_or_default()
}

/// PIDs com conexão TCP estabelecida para portas típicas de pools.
/// shortcut: só IPv4/IPv6 em TCP via netstat e só Windows; no Linux usar `ss -tnp`.
#[cfg(windows)]
fn pool_connection_pids() -> HashSet<u32> {
    sys::run(
        "netstat",
        &["-ano", "-p", "tcp"],
        None,
        Duration::from_secs(15),
    )
    .map(|out| parse_pool_pids(&out))
    .unwrap_or_default()
}

/// PIDs usando a GPU para computação, via `nvidia-smi` (vem com o driver NVIDIA).
/// shortcut: só NVIDIA; AMD (`rocm-smi`) e Intel ainda não. Sem o programa, devolve vazio.
#[cfg(not(windows))]
fn gpu_compute_pids() -> HashSet<u32> {
    sys::run(
        "nvidia-smi",
        &["--query-compute-apps=pid", "--format=csv,noheader"],
        None,
        Duration::from_secs(15),
    )
    .map(|out| parse_nvidia_pids(&out))
    .unwrap_or_default()
}

/// PIDs com conexão TCP estabelecida para portas típicas de pools, via `ss`.
/// shortcut: sem root, o `ss` só mostra o processo dos sockets do próprio usuário.
#[cfg(not(windows))]
fn pool_connection_pids() -> HashSet<u32> {
    sys::run(
        "ss",
        &["-tnpH", "state", "established"],
        None,
        Duration::from_secs(15),
    )
    .map(|out| parse_ss_pids(&out))
    .unwrap_or_default()
}

/// Uma linha por PID (`1234`); mensagens como `[Not Found]` são ignoradas.
#[cfg_attr(windows, allow(dead_code))]
fn parse_nvidia_pids(out: &str) -> HashSet<u32> {
    out.lines().filter_map(|l| l.trim().parse().ok()).collect()
}

/// Linhas `Recv-Q Send-Q Local:porta Remoto:porta users:(("nome",pid=123,fd=4))`.
#[cfg_attr(windows, allow(dead_code))]
fn parse_ss_pids(out: &str) -> HashSet<u32> {
    out.lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            // Sem a 5ª coluna o `ss` não mostrou o processo (falta de permissão).
            let (remote, process) = (f.get(3)?, f.get(4)?);
            let port: u16 = remote.rsplit(':').next()?.parse().ok()?;
            POOL_PORTS.contains(&port).then(|| {
                process
                    .split("pid=")
                    .skip(1)
                    .filter_map(|r| r.split(|c: char| !c.is_ascii_digit()).next()?.parse().ok())
                    .collect::<Vec<u32>>()
            })
        })
        .flatten()
        .collect()
}

/// Extrai o PID de nomes como `pid_1234_luid_0x..._engtype_Compute_0`.
#[cfg(windows)]
fn parse_gpu_pid(line: &str) -> Option<u32> {
    let rest = line.split_once("pid_")?.1;
    rest.split('_').next()?.parse().ok()
}

/// Lê linhas `TCP  local  remoto  ESTABLISHED  pid` e devolve os PIDs com porta de pool no destino.
#[cfg(windows)]
fn parse_pool_pids(netstat: &str) -> HashSet<u32> {
    netstat
        .lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() != 5 || f[0] != "TCP" || f[3] != "ESTABLISHED" {
                return None;
            }
            let port: u16 = f[2].rsplit(':').next()?.parse().ok()?;
            if POOL_PORTS.contains(&port) {
                f[4].parse().ok()
            } else {
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const QUIET: Signals = Signals {
        cpu_high: false,
        gpu_compute: false,
        pool_connection: false,
    };

    #[test]
    fn ancestors_walk_the_whole_parent_chain_and_survive_cycles() {
        let parent = |p: Pid| match p.as_u32() {
            30 => Some(Pid::from_u32(20)),
            20 => Some(Pid::from_u32(10)),
            _ => None,
        };
        let set = ancestors(Pid::from_u32(30), parent);
        assert_eq!(
            set,
            HashSet::from([Pid::from_u32(30), Pid::from_u32(20), Pid::from_u32(10)])
        );
        // Ciclo 1 -> 2 -> 1.
        let cyc = |p: Pid| Some(Pid::from_u32(3 - p.as_u32()));
        assert_eq!(ancestors(Pid::from_u32(1), cyc).len(), 2);
        assert_eq!(ancestors(Pid::from_u32(7), |_| None).len(), 1);
    }

    #[test]
    fn the_real_parent_of_this_test_process_is_an_ancestor() {
        let own = Pid::from_u32(process::id());
        let mut sys = System::new();
        sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing(),
        );
        let set = ancestors(own, |p| sys.process(p).and_then(|x| x.parent()));
        assert!(set.contains(&own));
        if let Some(parent) = sys.process(own).and_then(|p| p.parent()) {
            assert!(
                set.contains(&parent),
                "o processo que iniciou o teste tem de estar na lista"
            );
        }
    }

    #[test]
    fn a_parent_whose_command_line_holds_a_miner_argument_word_is_skipped_not_flagged() {
        // `sudo oblivion clean --yes --only stratum`: o `assess` compara o NOME do processo com os nomes de
        // minerador, mas a LINHA DE COMANDO com `stratum`, `--donate-level` e `cryptonight`. O `sudo`
        // aparece com `stratum` na linha de comando e seria marcado, por isso os ancestrais são pulados.
        let (sev, _) = assess(
            "sudo",
            "sudo oblivion clean --yes --only stratum",
            Signals::default(),
        )
        .unwrap();
        assert_eq!(sev, Severity::High);
        // Só o NOME de minerador na linha de comando de outro programa não marca (este é o caso comum).
        assert!(
            assess(
                "sudo",
                "sudo oblivion clean --yes --only xmrig",
                Signals::default()
            )
            .is_none()
        );
        let (sudo, me) = (Pid::from_u32(5), Pid::from_u32(6));
        let skip = ancestors(me, |p| (p == me).then_some(sudo));
        assert!(skip.contains(&sudo) && skip.contains(&me));
    }

    #[test]
    fn known_miner_name_is_high() {
        assert_eq!(assess("xmrig.exe", "", QUIET).unwrap().0, Severity::High);
    }

    #[test]
    fn miner_name_matches_regardless_of_case() {
        assert_eq!(assess("XMRig.EXE", "", QUIET).unwrap().0, Severity::High);
    }

    #[test]
    fn pool_argument_is_high() {
        assert_eq!(
            assess("svc.exe", "-o stratum+tcp://pool:3333", QUIET)
                .unwrap()
                .0,
            Severity::High
        );
    }

    #[test]
    fn each_weak_signal_alone_is_suspicious() {
        for s in [
            Signals {
                cpu_high: true,
                ..QUIET
            },
            Signals {
                gpu_compute: true,
                ..QUIET
            },
            Signals {
                pool_connection: true,
                ..QUIET
            },
        ] {
            assert_eq!(assess("a.exe", "", s).unwrap().0, Severity::Suspicious);
        }
    }

    #[test]
    fn two_or_more_weak_signals_are_high() {
        let two = Signals {
            cpu_high: true,
            pool_connection: true,
            ..QUIET
        };
        let three = Signals {
            cpu_high: true,
            gpu_compute: true,
            pool_connection: true,
        };
        assert_eq!(assess("a.exe", "", two).unwrap().0, Severity::High);
        assert_eq!(assess("a.exe", "", three).unwrap().0, Severity::High);
    }

    #[test]
    fn quiet_process_is_ignored() {
        assert!(assess("notepad.exe", "", QUIET).is_none());
        assert!(assess("", "", QUIET).is_none());
    }

    #[test]
    fn parses_nvidia_compute_pids_and_ignores_messages() {
        assert_eq!(
            parse_nvidia_pids("1234\n 5678 \n[Not Found]\nNo running processes found\n\n"),
            HashSet::from([1234, 5678])
        );
        assert!(parse_nvidia_pids("").is_empty());
    }

    #[test]
    fn parses_ss_pool_connections_with_one_or_more_processes() {
        let out = "0 0 10.0.0.5:50123 1.2.3.4:3333 users:((\"xmrig\",pid=4321,fd=5))\n\
                   0 0 10.0.0.5:50124 1.2.3.4:443 users:((\"curl\",pid=1111,fd=5))\n\
                   0 0 [::1]:50126 [::1]:14444 users:((\"a\",pid=7,fd=3),(\"b\",pid=8,fd=3))\n\
                   0 0 10.0.0.5:50127 1.2.3.4:3333\n\
                   linha invalida";
        assert_eq!(parse_ss_pids(out), HashSet::from([4321, 7, 8]));
    }

    #[cfg(windows)]
    #[test]
    fn parses_pid_from_counter_name() {
        assert_eq!(
            parse_gpu_pid("pid_1234_luid_0x00000000_0x0000D1F6_phys_0_eng_2_engtype_Compute"),
            Some(1234)
        );
        assert_eq!(parse_gpu_pid("sem pid"), None);
        assert_eq!(parse_gpu_pid("pid_abc_x"), None);
    }

    #[cfg(windows)]
    #[test]
    fn parses_pool_connections_from_netstat() {
        let out = "  TCP    10.0.0.5:50123    1.2.3.4:3333    ESTABLISHED    4321\n\
                   TCP    10.0.0.5:50124    1.2.3.4:443     ESTABLISHED    1111\n\
                   TCP    10.0.0.5:50125    1.2.3.4:3333    TIME_WAIT      2222\n\
                   TCP    [::1]:50126       [::1]:14444     ESTABLISHED    5555\n\
                   linha invalida";
        assert_eq!(parse_pool_pids(out), HashSet::from([4321, 5555]));
    }
}
