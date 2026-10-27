//! Rede: arquivo hosts, proxy do Windows e servidores DNS fixos. Malware usa isso para bloquear antivírus e
//! atualizações, redirecionar sites e desviar o tráfego. Correção sempre manual (a decisão é sua).
use std::net::IpAddr;

use crate::finding::{Finding, Severity};

const SCANNER: &str = "rede";

/// Sites de antivírus e de atualização: bloquear ou redirecionar qualquer um deles é sinal forte.
const SECURITY_DOMAINS: &[&str] = &[
    "windowsupdate.com",
    "update.microsoft.com",
    "defender.microsoft.com",
    "virustotal.com",
    "malwarebytes.com",
    "kaspersky.com",
    "avast.com",
    "avg.com",
    "eset.com",
    "symantec.com",
    "norton.com",
    "mcafee.com",
    "bitdefender.com",
    "sophos.com",
    "avira.com",
    "trendmicro.com",
    "f-secure.com",
];

const LOCAL_NAMES: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-allhosts",
];

/// DNS públicos conhecidos e confiáveis (Cloudflare, Google, Quad9, OpenDNS).
#[cfg_attr(not(windows), allow(dead_code))] // só o Windows usa
const KNOWN_DNS: &[&str] = &[
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "149.112.112.112",
    "208.67.222.222",
    "208.67.220.220",
];

fn finding(
    location: &str,
    name: String,
    target: String,
    severity: Severity,
    reason: &'static str,
) -> Finding {
    Finding {
        scanner: SCANNER,
        location: location.to_string(),
        name,
        target,
        severity,
        reason,
    }
}

fn is_security_domain(host: &str) -> bool {
    let h = host.to_lowercase();
    SECURITY_DOMAINS
        .iter()
        .any(|d| h == *d || h.ends_with(&format!(".{d}")))
}

/// Analisa o conteúdo de um arquivo hosts.
pub fn assess_hosts(content: &str, location: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut blocked = 0usize;
    for line in content.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let mut parts = line.split_whitespace();
        let (Some(ip), Some(first)) = (parts.next(), parts.next()) else {
            continue;
        };
        let Ok(addr) = ip.parse::<IpAddr>() else {
            continue;
        };
        let sink = addr.is_loopback() || addr.is_unspecified();
        for host in std::iter::once(first).chain(parts) {
            let lower = host.to_lowercase();
            // O Docker Desktop grava esses nomes apontando para o IP da própria máquina na rede local.
            let docker = lower.ends_with(".docker.internal") && is_private_or_loopback(&addr);
            if LOCAL_NAMES.contains(&lower.as_str()) || docker {
                continue;
            }
            let target = format!("{ip} {host}");
            if is_security_domain(host) {
                let reason = if sink {
                    "Bloqueia um site de antivírus ou de atualização do Windows"
                } else {
                    "Redireciona um site de antivírus ou de atualização do Windows para outro endereço"
                };
                out.push(finding(
                    location,
                    "Entrada do hosts".into(),
                    target,
                    Severity::High,
                    reason,
                ));
            } else if sink {
                blocked += 1;
            } else {
                out.push(finding(
                    location,
                    "Entrada do hosts".into(),
                    target,
                    Severity::Suspicious,
                    "Redireciona um site para outro endereço (confira se foi você)",
                ));
            }
        }
    }
    if blocked > 0 {
        out.push(finding(
            location,
            format!("{blocked} site(s) bloqueado(s) no hosts"),
            String::new(),
            Severity::Info,
            "Lista de bloqueio no hosts (comum em bloqueadores de anúncios)",
        ));
    }
    out
}

/// Proxy do Windows: tráfego passando por um servidor que você talvez não escolheu.
#[cfg_attr(not(windows), allow(dead_code))] // só o Windows usa
pub fn assess_proxy(enabled: bool, server: &str, pac: &str) -> Vec<(String, String, &'static str)> {
    let mut out = Vec::new();
    if enabled && !server.trim().is_empty() {
        out.push((
            "Proxy ativado".to_string(),
            server.trim().to_string(),
            "Todo o tráfego do navegador passa por esse proxy (confira se foi você ou sua empresa)",
        ));
    }
    if !pac.trim().is_empty() {
        out.push((
            "Script de configuração automática do proxy".to_string(),
            pac.trim().to_string(),
            "Um script remoto decide por onde o tráfego passa (confira se foi você ou sua empresa)",
        ));
    }
    out
}

fn is_private_or_loopback(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Servidores DNS fixos que não são de rede local nem DNS público conhecido.
#[cfg_attr(not(windows), allow(dead_code))] // só o Windows usa
pub fn assess_dns(name_server: &str) -> Vec<String> {
    name_server
        .split([',', ' ', ';'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter(|s| match s.parse::<IpAddr>() {
            Ok(ip) => !is_private_or_loopback(&ip) && !KNOWN_DNS.contains(s),
            Err(_) => true,
        })
        .map(str::to_string)
        .collect()
}

fn hosts_path() -> std::path::PathBuf {
    if cfg!(windows) {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        std::path::PathBuf::from(root).join(r"System32\drivers\etc\hosts")
    } else {
        "/etc/hosts".into()
    }
}

#[cfg(windows)]
fn scan_windows(out: &mut Vec<Finding>) {
    use winreg::{RegKey, enums::*};
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok(k) = hkcu.open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
    {
        let enabled = k.get_value::<u32, _>("ProxyEnable").unwrap_or(0) == 1;
        let server: String = k.get_value("ProxyServer").unwrap_or_default();
        let pac: String = k.get_value("AutoConfigURL").unwrap_or_default();
        for (name, target, reason) in assess_proxy(enabled, &server, &pac) {
            out.push(finding(
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                name,
                target,
                Severity::Suspicious,
                reason,
            ));
        }
    }
    let interfaces = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";
    if let Ok(k) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(interfaces) {
        for guid in k.enum_keys().flatten() {
            let Ok(iface) = k.open_subkey(&guid) else {
                continue;
            };
            let ns: String = iface.get_value("NameServer").unwrap_or_default();
            for server in assess_dns(&ns) {
                out.push(finding(
                    &format!(r"HKLM\{interfaces}\{guid}"),
                    "Servidor DNS fixo".into(),
                    server,
                    Severity::Suspicious,
                    "DNS configurado à mão que não é de rede local nem um DNS público conhecido (pode desviar sites)",
                ));
            }
        }
    }
}

pub fn scan() -> Vec<Finding> {
    let mut out = Vec::new();
    let path = hosts_path();
    // O hosts é leitura pública; se não existir, não há o que avaliar.
    if let Ok(bytes) = std::fs::read(&path) {
        out.extend(assess_hosts(
            &String::from_utf8_lossy(&bytes),
            &path.to_string_lossy(),
        ));
    }
    #[cfg(windows)]
    scan_windows(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_default_hosts_file_has_no_findings() {
        let hosts =
            "# Copyright\n127.0.0.1 localhost\n::1 localhost\n\n255.255.255.255 broadcasthost\n";
        assert!(assess_hosts(hosts, "hosts").is_empty());
    }

    #[test]
    fn blocking_or_redirecting_security_sites_is_high() {
        let hosts = "127.0.0.1 update.microsoft.com\n0.0.0.0 www.malwarebytes.com\n6.6.6.6 download.windowsupdate.com # x\n";
        let found = assess_hosts(hosts, "hosts");
        assert_eq!(found.len(), 3);
        assert!(found.iter().all(|f| f.severity == Severity::High));
        assert!(found.iter().any(|f| f.reason.contains("Bloqueia")));
        assert!(found.iter().any(|f| f.reason.contains("Redireciona")));
    }

    #[test]
    fn redirecting_another_site_is_suspicious_and_blocklists_are_only_counted() {
        let hosts = "1.2.3.4 banco.example.com\n0.0.0.0 ads.example.com tracker.example.com\n";
        let found = assess_hosts(hosts, "hosts");
        let sus: Vec<_> = found
            .iter()
            .filter(|f| f.severity == Severity::Suspicious)
            .collect();
        assert_eq!(sus.len(), 1);
        assert_eq!(sus[0].target, "1.2.3.4 banco.example.com");
        let info = found.iter().find(|f| f.severity == Severity::Info).unwrap();
        assert!(info.name.starts_with("2 site(s)"));
    }

    #[test]
    fn lookalike_domains_are_not_treated_as_security_sites() {
        // "notavast.com" não é subdomínio de avast.com.
        let found = assess_hosts("0.0.0.0 notavast.com\n", "hosts");
        assert!(found.iter().all(|f| f.severity == Severity::Info));
    }

    #[test]
    fn docker_desktop_entries_on_the_local_network_are_not_reported() {
        let ok = "192.168.1.104 host.docker.internal\n127.0.0.1 kubernetes.docker.internal\n";
        assert!(
            assess_hosts(ok, "hosts")
                .iter()
                .all(|f| f.severity == Severity::Info)
        );
        // Mesmo nome apontando para a internet continua suspeito.
        let bad = assess_hosts("8.8.4.4 host.docker.internal\n", "hosts");
        assert_eq!(bad[0].severity, Severity::Suspicious);
    }

    #[test]
    fn garbage_lines_are_ignored() {
        assert!(assess_hosts("isso nao e ip host\nsó-uma-coluna\n\t\n", "hosts").is_empty());
    }

    #[test]
    fn proxy_is_reported_only_when_on_or_scripted() {
        assert!(assess_proxy(false, "1.2.3.4:80", "").is_empty());
        assert!(assess_proxy(true, "  ", "").is_empty());
        assert_eq!(assess_proxy(true, "1.2.3.4:8080", "").len(), 1);
        assert_eq!(assess_proxy(true, "a:1", "http://x/p.pac").len(), 2);
    }

    #[test]
    fn dns_accepts_local_and_well_known_servers_only() {
        assert!(assess_dns("").is_empty());
        assert!(assess_dns("192.168.0.1,8.8.8.8 1.1.1.1").is_empty());
        assert!(assess_dns("fe80::1").is_empty());
        assert_eq!(assess_dns("8.8.8.8,45.67.89.10"), vec!["45.67.89.10"]);
        assert_eq!(assess_dns("nao-e-ip"), vec!["nao-e-ip"]);
    }

    #[test]
    fn the_real_scan_runs() {
        for f in scan() {
            assert_eq!(f.scanner, SCANNER);
            assert!(!f.reason.is_empty());
        }
    }
}
