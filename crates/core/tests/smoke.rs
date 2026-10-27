//! Testes de integração: rodam os scanners de verdade (só leitura) na máquina atual.
use oblivion_core::{privilege, report, scanners};

#[test]
fn scan_all_is_sorted_by_severity_and_reports_render() {
    let findings = scanners::scan_all();

    assert!(
        findings.windows(2).all(|w| w[0].severity >= w[1].severity),
        "achados devem vir do mais grave ao menos grave"
    );
    for f in &findings {
        assert!(
            !f.name.is_empty() || !f.target.is_empty(),
            "achado sem nome nem alvo: {f:?}"
        );
        assert!(!f.reason.is_empty());
    }

    let text = report::text::render(&findings);
    let elevated = privilege::is_elevated();
    let html = report::html::render(&findings, elevated);
    assert_eq!(
        html.contains("role=\"alert\""),
        !elevated,
        "o aviso aparece só sem privilégios elevados"
    );
    assert!(text.contains("Resumo:"));
    assert!(html.starts_with("<!doctype html>") && html.ends_with("</html>"));
    assert_eq!(
        html.matches("<td class=\"sev").count(),
        findings.len(),
        "uma linha de tabela por achado"
    );
}
