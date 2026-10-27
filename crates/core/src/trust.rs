//! Evidência sobre o executável de uma entrada de inicialização: se existe e se tem assinatura.
//!
//! Assinatura digital (Authenticode): programa assinado e íntegro em local fora do padrão
//! (AppData, ProgramData) é quase sempre legítimo. Substitui uma lista de permissão manual.
//! Limite: malware também pode ser assinado (certificado roubado), por isso só rebaixa suspeita
//! baseada em LOCAL, nunca sinais fortes, scripts ou comandos de rede.
use std::{collections::HashSet, path::Path, time::Duration};

use crate::classify::{is_location_only, is_system_script};
use crate::finding::{Finding, ORPHAN_REASON, Severity};
use crate::sys;

/// Extrai o caminho do executável de um comando, com ou sem aspas. `None` se não houver `.exe`
/// ou se o caminho usar variável de ambiente (`%...%`), que não é expandida aqui.
pub fn exe_path(command: &str) -> Option<&str> {
    let c = command.trim();
    let path = if let Some(rest) = c.strip_prefix('"') {
        rest.split('"').next()?
    } else {
        let lower = c.to_ascii_lowercase();
        let end = [".exe", ".dll", ".sys"]
            .iter()
            .filter_map(|ext| lower.find(ext).map(|i| i + ext.len()))
            .min()?;
        &c[..end]
    };
    (!path.is_empty() && !path.contains('%')).then_some(path)
}

/// Caminhos (em minúsculas) com assinatura válida. Falha do PowerShell = nenhum confiável (seguro).
pub(crate) fn signed_paths(paths: &[String]) -> HashSet<String> {
    let script = "$input | ForEach-Object { Get-AuthenticodeSignature -LiteralPath $_ } | \
        Where-Object { $_.Status -eq 'Valid' } | ForEach-Object { $_.Path }";
    let Some(out) = sys::powershell(script, Some(&paths.join("\n")), Duration::from_secs(30))
    else {
        return HashSet::new();
    };
    out.lines()
        .map(|l| l.trim().to_lowercase())
        .filter(|l| !l.is_empty())
        .collect()
}

/// Rebaixa para INFO os suspeitos só por local cujo executável tem assinatura válida.
pub fn downgrade_signed(findings: &mut [Finding]) {
    let candidates: Vec<(usize, String)> = findings
        .iter()
        .enumerate()
        .filter(|(_, f)| f.severity == Severity::Suspicious && is_location_only(&f.target))
        .filter_map(|(i, f)| exe_path(&f.target).map(|p| (i, p.to_string())))
        .collect();
    if candidates.is_empty() {
        return;
    }
    let paths: Vec<String> = candidates.iter().map(|(_, p)| p.clone()).collect();
    let signed = signed_paths(&paths);
    for (i, path) in candidates {
        if signed.contains(&path.to_lowercase()) {
            findings[i].severity = Severity::Info;
            findings[i].reason =
                "Assinatura digital válida; local fora do padrão, mas o arquivo é assinado";
        }
    }
}

/// Rebaixa para INFO os suspeitos que são só scripts dentro de System32 (pasta protegida).
pub fn downgrade_system_scripts(findings: &mut [Finding]) {
    for f in findings
        .iter_mut()
        .filter(|f| f.severity == Severity::Suspicious && is_system_script(&f.target))
    {
        f.severity = Severity::Info;
        f.reason = "Script dentro de System32, pasta protegida do Windows";
    }
}

/// Verdadeiro se o comando aponta, por caminho absoluto, para um executável que não existe.
/// Caminhos relativos ou com variáveis `%X%` não são julgados (evita falso positivo).
pub fn is_orphan(command: &str, exists: impl Fn(&Path) -> bool) -> bool {
    exe_path(command).map(Path::new).is_some_and(|p| {
        p.is_absolute() && !is_remote(p) && drive_is_present(p, &exists) && !exists(p)
    })
}

/// Caminho de rede (`\\servidor\pasta`): não é julgado (acessar a rede pode travar e o servidor pode estar fora).
fn is_remote(p: &Path) -> bool {
    p.to_string_lossy().starts_with(r"\\")
}

/// A unidade do arquivo existe agora? Um terminal elevado (UAC) não enxerga as unidades de rede
/// mapeadas na sessão normal, e um pendrive desconectado some: nesses casos o arquivo "não existir"
/// não prova que o programa foi removido.
fn drive_is_present(p: &Path, exists: &impl Fn(&Path) -> bool) -> bool {
    p.ancestors().last().is_some_and(exists)
}

/// Marca como SUSPEITO as entradas de baixa gravidade cujo executável sumiu. Quem já é ALTO não muda.
pub fn flag_orphans(findings: &mut [Finding]) {
    use crate::scanners::persistence_win::{APPINIT_REASON, IFEO_REASON};
    for f in findings
        .iter_mut()
        .filter(|f| f.severity <= Severity::Suspicious)
        // IFEO e AppInit têm motivo próprio: um `Debugger` que aponta para arquivo inexistente continua
        // sendo um sinal de sequestro, e não uma "sobra de programa removido".
        .filter(|f| f.reason != IFEO_REASON && f.reason != APPINIT_REASON)
    {
        if is_orphan(&f.target, |p| p.exists()) {
            f.severity = Severity::Suspicious;
            f.reason = ORPHAN_REASON;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(target: &str, severity: Severity) -> Finding {
        Finding {
            scanner: "t",
            location: String::new(),
            name: String::new(),
            target: target.into(),
            severity,
            reason: "original",
        }
    }

    #[test]
    fn system32_scripts_are_downgraded_but_other_scripts_are_not() {
        let mut f = vec![
            finding(
                r"cmd.exe /c %systemroot%\system32\t.cmd",
                Severity::Suspicious,
            ),
            finding(r"cmd.exe /c D:\x\t.cmd", Severity::Suspicious),
            finding(
                r"cmd.exe /c %systemroot%\system32\t.cmd -enc A",
                Severity::High,
            ),
        ];
        downgrade_system_scripts(&mut f);
        assert_eq!(f[0].severity, Severity::Info);
        assert_eq!(f[1].severity, Severity::Suspicious);
        assert_eq!(f[2].severity, Severity::High);
    }

    #[test]
    fn missing_absolute_exe_is_orphan() {
        // Só a raiz da unidade (`C:\`) existe: o arquivo sumiu de uma unidade que está aqui.
        assert!(is_orphan(r"C:\x\a.exe --f", |p| p.parent().is_none()));
        assert!(!is_orphan(r"C:\x\a.exe --f", |_| true));
    }

    #[test]
    fn a_file_on_a_missing_drive_or_a_network_path_is_not_an_orphan() {
        // O caso da auditoria: unidade de rede mapeada que o terminal elevado não enxerga, ou pendrive fora.
        assert!(!is_orphan(r"Z:\ferramentas\x.exe", |_| false));
        assert!(!is_orphan(r"\\servidor\pasta\x.exe", |p| p
            .parent()
            .is_none()));
    }

    #[test]
    fn relative_env_or_non_exe_commands_are_not_judged() {
        assert!(!is_orphan(r"system32\a.exe", |_| false));
        assert!(!is_orphan(r"%SystemRoot%\a.exe", |_| false));
        assert!(!is_orphan(r"C:\x\run.bat", |_| false));
        assert!(!is_orphan("", |_| false));
    }

    #[test]
    fn an_ifeo_debugger_pointing_to_a_missing_file_keeps_its_own_reason() {
        // O caso do teste real: o Debugger apontava para um arquivo inexistente e o motivo virava "órfã".
        let mut f = vec![
            finding(r"C:\oblivion-nao-existe\dbg.exe", Severity::Suspicious),
            finding(r"C:\oblivion-nao-existe\hook.dll", Severity::Suspicious),
            finding(r"C:\oblivion-nao-existe\outro.exe", Severity::Suspicious),
        ];
        f[0].reason = crate::scanners::persistence_win::IFEO_REASON;
        f[1].reason = crate::scanners::persistence_win::APPINIT_REASON;
        flag_orphans(&mut f);
        assert_eq!(f[0].reason, crate::scanners::persistence_win::IFEO_REASON);
        assert_eq!(
            f[1].reason,
            crate::scanners::persistence_win::APPINIT_REASON
        );
        assert_eq!(
            f[2].reason, ORPHAN_REASON,
            "os demais continuam sendo órfãos"
        );
    }

    #[test]
    fn flag_orphans_marks_missing_files_but_keeps_high() {
        let mut f = vec![
            finding(r"C:\oblivion-nao-existe\a.exe", Severity::Info),
            finding(r"C:\oblivion-nao-existe\b.exe -enc AAAA", Severity::High),
            finding(r"C:\Windows\System32\notepad.exe", Severity::Info),
        ];
        flag_orphans(&mut f);
        assert_eq!(
            (f[0].severity, f[0].reason),
            (Severity::Suspicious, ORPHAN_REASON)
        );
        assert_eq!((f[1].severity, f[1].reason), (Severity::High, "original"));
        assert_eq!(f[2].severity, Severity::Info);
    }

    #[test]
    fn exe_path_also_finds_dlls_and_drivers() {
        assert_eq!(
            exe_path(r"C:\ProgramData\x\svc.dll"),
            Some(r"C:\ProgramData\x\svc.dll")
        );
        assert_eq!(exe_path(r"C:\Drivers\a.sys"), Some(r"C:\Drivers\a.sys"));
        // O primeiro que aparece vale; o que vem depois é argumento.
        assert_eq!(
            exe_path(r"C:\x\a.exe --lib C:\y\b.dll"),
            Some(r"C:\x\a.exe")
        );
    }

    #[test]
    fn exe_path_quoted() {
        assert_eq!(
            exe_path(r#""C:\Users\x\AppData\Local\app\a.exe" --flag"#),
            Some(r"C:\Users\x\AppData\Local\app\a.exe")
        );
    }

    #[test]
    fn exe_path_unquoted_with_args() {
        assert_eq!(
            exe_path(r"C:\ProgramData\x\d.exe --checkInstall"),
            Some(r"C:\ProgramData\x\d.exe")
        );
    }

    #[test]
    fn exe_path_rejects_env_vars_and_non_exe() {
        assert_eq!(exe_path(r"%APPDATA%\a.exe"), None);
        assert_eq!(exe_path(r"C:\x\script.vbs"), None);
        assert_eq!(exe_path(""), None);
    }

    #[test]
    fn microsoft_signed_binary_is_trusted() {
        // Alguns ambientes (runners de CI) não conseguem validar assinaturas por catálogo. Testa vários
        // binários do Windows: se NENHUM validar, o ambiente não verifica assinatura e o teste não se aplica.
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let candidates: Vec<String> = [
            "notepad.exe",
            "explorer.exe",
            "System32\\cmd.exe",
            "System32\\kernel32.dll",
        ]
        .iter()
        .map(|n| format!(r"{root}\{n}"))
        .collect();
        let trusted = signed_paths(&candidates);
        if trusted.is_empty() {
            eprintln!("ambiente sem verificação de assinatura: teste ignorado");
            return;
        }
        assert!(
            candidates
                .iter()
                .any(|c| trusted.contains(&c.to_lowercase()))
        );
    }

    #[test]
    fn unsigned_file_is_not_trusted() {
        let unsigned = r"C:\Windows\System32\drivers\etc\hosts".to_string();
        assert!(signed_paths(&[unsigned]).is_empty());
    }

    #[test]
    fn strong_signals_are_never_downgraded() {
        let mut f = vec![Finding {
            scanner: "t",
            location: String::new(),
            name: String::new(),
            target: r"C:\Windows\System32\notepad.exe -enc AAAA".into(),
            severity: Severity::High,
            reason: "x",
        }];
        downgrade_signed(&mut f);
        assert_eq!(f[0].severity, Severity::High);
    }
}
