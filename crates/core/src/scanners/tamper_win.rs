//! Adulteração das defesas do Windows: o que um malware desliga ou esconde para se proteger.
//! Antivírus e firewall desligados, UAC desativado, Gerenciador de Tarefas e Editor de Registro bloqueados,
//! e exclusões do Windows Defender (pastas, extensões e programas que ele deixa de verificar).
//!
//! Tudo isso também pode ser configuração legítima (empresa, outro antivírus): por isso é SUSPEITO, nunca
//! ALTO, e a correção é manual: o Oblivion mostra o que achou e deixa a decisão com você.
use winreg::{RegKey, enums::*};

use crate::classify::classify;
use crate::finding::{Finding, Severity};

const SCANNER: &str = "seguranca";

struct Check {
    hive: &'static str,
    key: &'static str,
    value: &'static str,
    /// Valor que indica adulteração.
    bad: u32,
    reason: &'static str,
}

const DEFENDER_POLICY: &str = r"SOFTWARE\Policies\Microsoft\Windows Defender";
const POLICIES_SYSTEM: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
const FIREWALL: &str = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";

const CHECKS: &[Check] = &[
    Check {
        hive: "HKLM",
        key: DEFENDER_POLICY,
        value: "DisableAntiSpyware",
        bad: 1,
        reason: "Windows Defender desligado por política",
    },
    Check {
        hive: "HKLM",
        key: r"SOFTWARE\Microsoft\Windows Defender",
        value: "DisableAntiSpyware",
        bad: 1,
        reason: "Windows Defender desligado (configuração antiga)",
    },
    Check {
        hive: "HKLM",
        key: r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
        value: "DisableRealtimeMonitoring",
        bad: 1,
        reason: "Proteção em tempo real do Defender desligada por política",
    },
    Check {
        hive: "HKLM",
        key: r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
        value: "DisableBehaviorMonitoring",
        bad: 1,
        reason: "Monitoramento de comportamento do Defender desligado por política",
    },
    Check {
        hive: "HKLM",
        key: r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
        value: "DisableOnAccessProtection",
        bad: 1,
        reason: "Verificação de arquivos ao abrir do Defender desligada por política",
    },
    Check {
        hive: "HKLM",
        key: POLICIES_SYSTEM,
        value: "EnableLUA",
        bad: 0,
        reason: "Controle de Conta de Usuário (UAC) desativado",
    },
    Check {
        hive: "HKLM",
        key: POLICIES_SYSTEM,
        value: "ConsentPromptBehaviorAdmin",
        bad: 0,
        reason: "Administrador eleva privilégios sem pedir confirmação (UAC mudo)",
    },
    Check {
        hive: "HKLM",
        key: POLICIES_SYSTEM,
        value: "DisableTaskMgr",
        bad: 1,
        reason: "Gerenciador de Tarefas bloqueado (esconde processos do usuário)",
    },
    Check {
        hive: "HKCU",
        key: POLICIES_SYSTEM,
        value: "DisableTaskMgr",
        bad: 1,
        reason: "Gerenciador de Tarefas bloqueado (esconde processos do usuário)",
    },
    Check {
        hive: "HKLM",
        key: POLICIES_SYSTEM,
        value: "DisableRegistryTools",
        bad: 1,
        reason: "Editor de Registro bloqueado",
    },
    Check {
        hive: "HKCU",
        key: POLICIES_SYSTEM,
        value: "DisableRegistryTools",
        bad: 1,
        reason: "Editor de Registro bloqueado",
    },
    Check {
        hive: "HKCU",
        key: r"SOFTWARE\Policies\Microsoft\Windows\System",
        value: "DisableCMD",
        bad: 1,
        reason: "Prompt de comando bloqueado",
    },
    Check {
        hive: "HKCU",
        key: r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        value: "NoFolderOptions",
        bad: 1,
        reason: "Opções de pasta escondidas (impede mostrar arquivos ocultos)",
    },
    Check {
        hive: "HKLM",
        key: r"SOFTWARE\Policies\Microsoft\Windows\System",
        value: "EnableSmartScreen",
        bad: 0,
        reason: "SmartScreen desligado por política",
    },
    Check {
        hive: "HKLM",
        key: r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
        value: "NoAutoUpdate",
        bad: 1,
        reason: "Atualizações automáticas do Windows desligadas por política",
    },
];

const FIREWALL_PROFILES: &[(&str, &str)] = &[
    ("StandardProfile", "Firewall desligado no perfil Privado"),
    ("DomainProfile", "Firewall desligado no perfil de Domínio"),
    ("PublicProfile", "Firewall desligado no perfil Público"),
];

/// Leitor de valor DWORD, para o avaliador poder ser testado sem o registro de verdade.
type Reader<'a> = &'a dyn Fn(&str, &str, &str) -> Option<u32>;

fn finding(location: String, name: &str, target: String, reason: &'static str) -> Finding {
    Finding {
        scanner: SCANNER,
        location,
        name: name.to_string(),
        target,
        severity: Severity::Suspicious,
        reason,
    }
}

/// Aplica todas as verificações de valor, usando `read` para ler o registro.
fn evaluate(read: Reader) -> Vec<Finding> {
    let mut out = Vec::new();
    for c in CHECKS {
        if read(c.hive, c.key, c.value) == Some(c.bad) {
            out.push(finding(
                format!(r"{}\{}", c.hive, c.key),
                c.value,
                format!("{} = {}", c.value, c.bad),
                c.reason,
            ));
        }
    }
    for (profile, reason) in FIREWALL_PROFILES {
        let key = format!(r"{FIREWALL}\{profile}");
        if read("HKLM", &key, "EnableFirewall") == Some(0) {
            out.push(finding(
                format!(r"HKLM\{key}"),
                "EnableFirewall",
                "EnableFirewall = 0".into(),
                reason,
            ));
        }
    }
    out
}

fn read_dword(hive: &str, key: &str, value: &str) -> Option<u32> {
    let root = match hive {
        "HKLM" => HKEY_LOCAL_MACHINE,
        _ => HKEY_CURRENT_USER,
    };
    RegKey::predef(root)
        .open_subkey(key)
        .ok()?
        .get_value::<u32, _>(value)
        .ok()
}

/// Exclusão do Defender: extensão de programa ou unidade inteira é muito suspeito; pasta ou programa em local do
/// usuário/temporário também. Exclusão de uma pasta comum de desenvolvimento é só informativa.
pub fn assess_exclusion(kind: &str, value: &str) -> (Severity, &'static str) {
    let v = value.trim().to_lowercase();
    match kind {
        "Extensions" => {
            let risky = ["exe", "dll", "bat", "cmd", "ps1", "vbs", "js", "scr", "msi"];
            if risky.contains(&v.trim_start_matches('.')) {
                (
                    Severity::Suspicious,
                    "O Defender não verifica arquivos desse tipo de programa (exclusão por extensão)",
                )
            } else {
                (Severity::Info, "Exclusão por extensão no Defender")
            }
        }
        _ => {
            let is_drive_root = v.len() <= 3
                && v.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
                && v[1..].starts_with(':');
            if is_drive_root {
                (
                    Severity::Suspicious,
                    "O Defender não verifica uma unidade inteira",
                )
            } else if classify(value).0 > Severity::Info {
                (
                    Severity::Suspicious,
                    "O Defender deixa de verificar um local típico de malware (pasta temporária ou do usuário)",
                )
            } else {
                (Severity::Info, "Exclusão do Defender (confira se foi você)")
            }
        }
    }
}

fn scan_exclusions(out: &mut Vec<Finding>) {
    let base = r"SOFTWARE\Microsoft\Windows Defender\Exclusions";
    let root = RegKey::predef(HKEY_LOCAL_MACHINE);
    let mut unreadable = false;
    for kind in ["Paths", "Extensions", "Processes"] {
        let key = format!(r"{base}\{kind}");
        match root.open_subkey(&key) {
            Ok(k) => {
                for (name, _) in k.enum_values().flatten() {
                    let (severity, reason) = assess_exclusion(kind, &name);
                    out.push(Finding {
                        scanner: SCANNER,
                        location: format!(r"HKLM\{key}"),
                        name: format!("Exclusão do Defender ({kind})"),
                        target: name,
                        severity,
                        reason,
                    });
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => unreadable = true,
            Err(_) => {}
        }
    }
    if unreadable {
        out.push(Finding {
            scanner: SCANNER,
            location: format!(r"HKLM\{base}"),
            name: "Exclusões do Defender NÃO verificadas".into(),
            target: String::new(),
            severity: Severity::Info,
            reason: "Sem acesso às exclusões do Defender; rode como administrador para verificá-las",
        });
    }
}

pub fn scan() -> Vec<Finding> {
    let mut out = evaluate(&read_dword);
    scan_exclusions(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn fake(values: &[(&str, &str, &str, u32)]) -> impl Fn(&str, &str, &str) -> Option<u32> {
        let map: HashMap<(String, String, String), u32> = values
            .iter()
            .map(|(h, k, v, n)| ((h.to_string(), k.to_lowercase(), v.to_string()), *n))
            .collect();
        move |h, k, v| {
            map.get(&(h.to_string(), k.to_lowercase(), v.to_string()))
                .copied()
        }
    }

    #[test]
    fn a_clean_system_has_no_findings() {
        assert!(evaluate(&fake(&[])).is_empty());
        // Valores que existem mas estão no estado normal não contam.
        let normal = fake(&[
            ("HKLM", POLICIES_SYSTEM, "EnableLUA", 1),
            ("HKLM", POLICIES_SYSTEM, "DisableTaskMgr", 0),
            ("HKLM", DEFENDER_POLICY, "DisableAntiSpyware", 0),
        ]);
        assert!(evaluate(&normal).is_empty());
    }

    #[test]
    fn disabled_defenses_are_reported_with_their_own_reason() {
        let tampered = fake(&[
            ("HKLM", DEFENDER_POLICY, "DisableAntiSpyware", 1),
            ("HKLM", POLICIES_SYSTEM, "EnableLUA", 0),
            ("HKCU", POLICIES_SYSTEM, "DisableTaskMgr", 1),
            (
                "HKLM",
                r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile",
                "EnableFirewall",
                0,
            ),
        ]);
        let found = evaluate(&tampered);
        assert_eq!(found.len(), 4);
        let reasons: Vec<_> = found.iter().map(|f| f.reason).collect();
        assert!(reasons.iter().any(|r| r.contains("Defender desligado")));
        assert!(reasons.iter().any(|r| r.contains("UAC")));
        assert!(reasons.iter().any(|r| r.contains("Gerenciador de Tarefas")));
        assert!(reasons.iter().any(|r| r.contains("perfil Público")));
        assert!(
            found
                .iter()
                .all(|f| f.severity == Severity::Suspicious && f.scanner == SCANNER)
        );
    }

    #[test]
    fn a_wrong_value_in_the_wrong_hive_is_not_reported() {
        // DisableTaskMgr em HKCU só vale na verificação de HKCU, e vice-versa.
        let only_hkcu = fake(&[("HKCU", DEFENDER_POLICY, "DisableAntiSpyware", 1)]);
        assert!(evaluate(&only_hkcu).is_empty());
    }

    #[test]
    fn defender_exclusions_of_programs_drives_and_temp_folders_are_suspicious() {
        assert_eq!(
            assess_exclusion("Extensions", ".exe").0,
            Severity::Suspicious
        );
        assert_eq!(
            assess_exclusion("Extensions", "PS1").0,
            Severity::Suspicious
        );
        assert_eq!(assess_exclusion("Extensions", ".log").0, Severity::Info);
        assert_eq!(assess_exclusion("Paths", r"C:\").0, Severity::Suspicious);
        assert_eq!(assess_exclusion("Paths", "d:").0, Severity::Suspicious);
        assert_eq!(
            assess_exclusion("Paths", r"C:\Users\x\AppData\Local\Temp").0,
            Severity::Suspicious
        );
        assert_eq!(
            assess_exclusion("Paths", r"D:\Apps\Projeto").0,
            Severity::Info,
            "pasta de desenvolvimento comum"
        );
        assert_eq!(
            assess_exclusion("Processes", r"C:\Users\x\AppData\Roaming\a.exe").0,
            Severity::Suspicious
        );
    }

    #[test]
    fn the_real_scan_runs_and_only_reports_known_reasons() {
        for f in scan() {
            assert_eq!(f.scanner, SCANNER);
            assert!(!f.reason.is_empty() && !f.name.is_empty());
        }
    }
}
