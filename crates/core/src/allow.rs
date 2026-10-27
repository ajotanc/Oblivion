//! Lista de permissão do usuário: itens que ele reconhece (ex.: seus scripts de backup).
//! Um padrão por linha, `#` começa comentário. Só rebaixa SUSPEITO; nunca esconde ALTO.
//!
//! O padrão precisa ser IGUAL ao nome ou à linha de comando inteira do achado (copie o "alvo" do
//! relatório), sem diferenciar maiúsculas nem espaços repetidos. Um `*` no fim vale como prefixo.
//! Casar por "contém" deixaria um malware escapar só incluindo o seu texto como argumento.
use crate::finding::{Finding, Severity};

const ALLOWED_REASON: &str = "Permitido pela sua lista (--allow)";
/// Padrão curto demais (sem contar o `*`) casaria com quase tudo e apagaria achados por engano.
const MIN_PATTERN_LEN: usize = 4;

/// Minúsculas e espaços repetidos viram um só: "A   b" e "a b" são o mesmo comando.
fn normalize(s: &str) -> String {
    s.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

pub fn parse(text: &str) -> Vec<String> {
    text.lines()
        .map(normalize)
        .filter(|l| {
            !l.is_empty() && !l.starts_with('#') && l.trim_end_matches('*').len() >= MIN_PATTERN_LEN
        })
        .collect()
}

fn matches(pattern: &str, value: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => value.starts_with(prefix),
        None => value == pattern,
    }
}

/// Rebaixa para INFO os suspeitos cujo nome ou alvo casa com algum padrão.
pub fn apply(findings: &mut [Finding], patterns: &[String]) {
    for f in findings
        .iter_mut()
        .filter(|f| f.severity == Severity::Suspicious)
    {
        let (name, target) = (normalize(&f.name), normalize(&f.target));
        if patterns
            .iter()
            .any(|p| matches(p, &name) || matches(p, &target))
        {
            f.severity = Severity::Info;
            f.reason = ALLOWED_REASON;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(name: &str, target: &str, severity: Severity) -> Finding {
        Finding {
            scanner: "t",
            location: String::new(),
            name: name.into(),
            target: target.into(),
            severity,
            reason: "original",
        }
    }

    fn severity_after(patterns: &str, name: &str, target: &str) -> Severity {
        let mut f = vec![finding(name, target, Severity::Suspicious)];
        apply(&mut f, &parse(patterns));
        f[0].severity
    }

    #[test]
    fn parse_skips_comments_blank_and_too_short_lines() {
        let p = parse("# comentário\n\n  D:\\Apps\\Docker  \nab\n***\nabc*\nabcd*\n");
        assert_eq!(p, vec!["d:\\apps\\docker", "abcd*"]);
    }

    #[test]
    fn exact_target_or_exact_name_is_allowed_ignoring_case_and_extra_spaces() {
        let target = r#"powershell.exe -NoProfile -File "D:\Apps\Docker\backup-all.ps1""#;
        assert_eq!(
            severity_after(&target.to_lowercase().replace(' ', "  "), "x", target),
            Severity::Info
        );
        assert_eq!(
            severity_after("Appwrite-Weekly-Backup", "appwrite-weekly-backup", "y"),
            Severity::Info
        );
    }

    #[test]
    fn prefix_pattern_needs_the_star() {
        let target = r"d:\apps\docker\backup-all.ps1 --extra";
        assert_eq!(
            severity_after(r"d:\apps\docker\*", "x", target),
            Severity::Info
        );
        assert_eq!(
            severity_after(r"d:\apps\docker", "x", target),
            Severity::Suspicious
        );
    }

    #[test]
    fn appending_an_allowed_text_to_another_command_does_not_hide_it() {
        // O caso da auditoria: o malware cita o caminho permitido como argumento.
        let sneaky = r"C:\Users\x\AppData\malware.exe d:\apps\docker\backup-all.ps1";
        assert_eq!(
            severity_after(r"d:\apps\docker\backup-all.ps1", "backup", sneaky),
            Severity::Suspicious
        );
        assert_eq!(
            severity_after(
                r"d:\apps\docker\backup-all.ps1",
                "tarefa d:\\apps\\docker\\backup-all.ps1",
                "z"
            ),
            Severity::Suspicious
        );
    }

    #[test]
    fn never_hides_high_findings() {
        let mut f = vec![finding("x", r"D:\Apps\a.exe -enc AAAA", Severity::High)];
        apply(&mut f, &parse(r"d:\apps\a.exe -enc aaaa"));
        assert_eq!(f[0].severity, Severity::High);
    }

    #[test]
    fn empty_pattern_list_changes_nothing() {
        let mut f = vec![finding("x", "y", Severity::Suspicious)];
        apply(&mut f, &[]);
        assert_eq!(f[0].severity, Severity::Suspicious);
    }

    #[test]
    fn unmatched_findings_keep_their_original_reason() {
        let mut f = vec![finding("outro", "z", Severity::Suspicious)];
        apply(&mut f, &parse("algum-padrao"));
        assert_eq!(
            (f[0].severity, f[0].reason),
            (Severity::Suspicious, "original")
        );
    }
}
