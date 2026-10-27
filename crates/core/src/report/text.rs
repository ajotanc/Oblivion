use std::fmt::Write;

use crate::finding::{Finding, Severity};

/// Caracteres que não aparecem mas mudam o que o olho lê: inversão de sentido (`fatura<RLO>fdp.exe` parece
/// um PDF), marcas de direção e espaços de largura zero.
fn is_invisible_or_bidi(c: char) -> bool {
    matches!(
        c,
        '\u{200B}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}'
    )
}

/// Troca caracteres de controle e invisíveis por `?`. Nomes, caminhos e comandos vêm do sistema (dado hostil):
/// uma sequência `ESC[...` poderia apagar linhas já impressas ou forjar a linha de resumo, e um caractere de
/// inversão poderia fazer um `.exe` parecer outra coisa.
pub fn clean(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control() || is_invisible_or_bidi(c) {
                '?'
            } else {
                c
            }
        })
        .collect()
}

/// Mostra só o que merece atenção; os itens INFO entram apenas contados (use o HTML para ver tudo).
pub fn render(findings: &[Finding]) -> String {
    let count = |s| findings.iter().filter(|f| f.severity == s).count();
    let mut out = String::new();
    for f in findings.iter().filter(|f| f.severity > Severity::Info) {
        let _ = writeln!(
            out,
            "[{}] {}\n    local:  {}\n    alvo:   {}\n    motivo: {}\n",
            f.severity.label(),
            clean(&f.name),
            clean(&f.location),
            clean(&f.target),
            clean(f.reason)
        );
    }
    let _ = writeln!(
        out,
        "Resumo: {} alto, {} suspeito, {} info. Achados são indícios para análise, não veredito.",
        count(Severity::High),
        count(Severity::Suspicious),
        count(Severity::Info)
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(name: &str, target: &str, severity: Severity) -> Finding {
        Finding {
            scanner: "t",
            location: "local".into(),
            name: name.into(),
            target: target.into(),
            severity,
            reason: "motivo",
        }
    }

    #[test]
    fn control_characters_cannot_reach_the_terminal() {
        // O caso da auditoria: nome com "apagar linha" e "subir o cursor" para esconder o achado.
        let evil = finding(
            "tarefa\x1b[2K\x1b[2A\r\u{7}fim",
            "alvo\nResumo: 0 alto\u{0}",
            Severity::High,
        );
        let text = render(&[evil]);
        for c in text.chars() {
            assert!(
                !c.is_control() || c == '\n',
                "caractere de controle {c:?} passou"
            );
        }
        assert_eq!(
            text.matches("Resumo:").count(),
            2,
            "a linha falsa fica visível como texto, não como linha nova"
        );
        assert!(text.contains("tarefa?[2K?[2A??fim"));
    }

    #[test]
    fn right_to_left_override_cannot_disguise_an_executable() {
        // O caso clássico: "fatura" + RLO + "fdp.exe" é exibido como "faturaexe.pdf".
        assert_eq!(clean("fatura\u{202E}fdp.exe"), "fatura?fdp.exe");
        assert_eq!(clean("a\u{200B}b\u{2066}c\u{FEFF}"), "a?b?c?");
    }

    #[test]
    fn normal_text_and_accents_are_untouched() {
        assert_eq!(clean("Instalação  é\tok"), "Instalação  é?ok");
        assert_eq!(clean("ação ü ç"), "ação ü ç");
    }

    #[test]
    fn info_findings_are_counted_but_not_listed() {
        let text = render(&[
            finding("segredo-info", "alvo-info", Severity::Info),
            finding("visivel", "alvo", Severity::Suspicious),
        ]);
        assert!(!text.contains("segredo-info") && text.contains("visivel"));
        assert!(text.contains("1 suspeito, 1 info."));
    }

    #[test]
    fn empty_input_still_prints_the_summary() {
        assert!(render(&[]).starts_with("Resumo: 0 alto, 0 suspeito, 0 info."));
    }
}
