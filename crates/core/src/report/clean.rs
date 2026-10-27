//! Relatório do que a limpeza fez (ou faria, na simulação): terminal e HTML.
use std::fmt::Write;

use super::{
    html::{STYLE, escape},
    text::clean,
};
use crate::clean::{Outcome, Report};

struct Counts {
    done: usize,
    dry: usize,
    declined: usize,
    manual: usize,
    skipped: usize,
    failed: usize,
}

fn counts(r: &Report) -> Counts {
    let n = |f: fn(&Outcome) -> bool| r.records.iter().filter(|x| f(&x.outcome)).count();
    Counts {
        done: n(|o| *o == Outcome::Done),
        dry: n(|o| *o == Outcome::DryRun),
        declined: n(|o| *o == Outcome::Declined),
        manual: n(|o| *o == Outcome::Manual),
        skipped: n(|o| matches!(o, Outcome::Skipped(_))),
        failed: n(|o| matches!(o, Outcome::Failed(_))),
    }
}

fn summary(c: &Counts, dry_run: bool) -> String {
    if dry_run {
        format!(
            "Simulação: {} item(ns) seriam tratados, {} exigem ação manual. Nada foi alterado.",
            c.dry, c.manual
        )
    } else {
        format!(
            "Resumo: {} removido(s), {} recusado(s), {} manual(is), {} ignorado(s), {} falha(s).",
            c.done, c.declined, c.manual, c.skipped, c.failed
        )
    }
}

fn undo_line(r: &Report) -> String {
    format!("Para desfazer: oblivion undo \"{}\"", r.dir.display())
}

pub fn text(r: &Report) -> String {
    let mut out = String::from("=== Relatório da limpeza ===\n");
    let _ = writeln!(
        out,
        "Modo: {}",
        if r.dry_run {
            "SIMULAÇÃO (nada foi alterado)"
        } else {
            "REAL"
        }
    );
    let _ = writeln!(out, "Ponto de restauração: {}", clean(&r.restore));
    if !r.dry_run {
        let _ = writeln!(out, "Quarentena: {}", clean(&r.dir.display().to_string()));
        let _ = writeln!(out, "{}", clean(&undo_line(r)));
    }
    if let Some(why) = &r.aborted {
        let _ = writeln!(out, "\n[!] INTERROMPIDO: {}", clean(why));
    }
    out.push('\n');
    for rec in &r.records {
        let _ = writeln!(
            out,
            "[{}] {}  ->  {}\n    alvo: {}\n    ação: {}",
            rec.finding.severity.label(),
            clean(&rec.finding.name),
            clean(&rec.outcome.label()),
            clean(&rec.finding.target),
            clean(&rec.action)
        );
        if !rec.note.is_empty() {
            let _ = writeln!(out, "    nota: {}", clean(&rec.note));
        }
        out.push('\n');
    }
    let _ = writeln!(out, "{}", summary(&counts(r), r.dry_run));
    out
}

pub fn html(r: &Report) -> String {
    let c = counts(r);
    let mut h = String::new();
    let _ = write!(
        h,
        r##"<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Relatório da limpeza</title><style>{STYLE}</style></head><body><main>
<h1>Relatório da limpeza</h1>
<p class="note">Modo: <strong>{mode}</strong>. Ponto de restauração: {restore}</p>
"##,
        mode = if r.dry_run {
            "simulação, nada foi alterado"
        } else {
            "real"
        },
        restore = escape(&r.restore),
    );
    if !r.dry_run {
        let _ = writeln!(
            h,
            "<p>Quarentena: <code>{}</code><br>{}</p>",
            escape(&r.dir.display().to_string()),
            escape(&undo_line(r))
        );
    }
    if let Some(why) = &r.aborted {
        let _ = writeln!(
            h,
            r#"<div class="alert" role="alert"><strong>Interrompido:</strong> {}</div>"#,
            escape(why)
        );
    }
    let _ = write!(
        h,
        r#"<p>{}</p><div class="scroll" tabindex="0" role="region" aria-label="Itens tratados">
<table><caption class="note" style="text-align:left;padding:8px 12px">O que foi encontrado e o que foi feito</caption>
<thead><tr><th scope="col">Gravidade</th><th scope="col">Nome</th><th scope="col">Alvo</th><th scope="col">Ação</th><th scope="col">Resultado</th><th scope="col">Nota</th></tr></thead><tbody>
"#,
        escape(&summary(&c, r.dry_run))
    );
    for rec in &r.records {
        let _ = writeln!(
            h,
            "<tr><td class=\"sev\">{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            rec.finding.severity.label(),
            escape(&rec.finding.name),
            escape(&rec.finding.target),
            escape(&rec.action),
            escape(&rec.outcome.label()),
            escape(&rec.note)
        );
    }
    h.push_str("</tbody></table></div></main></body></html>");
    h
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::clean::Record;
    use crate::finding::{Finding, Severity};

    fn record(name: &str, outcome: Outcome) -> Record {
        Record {
            finding: Finding {
                scanner: "t",
                location: "l".into(),
                name: name.into(),
                target: "alvo".into(),
                severity: Severity::High,
                reason: "r",
            },
            action: "ação".into(),
            outcome,
            note: "nota".into(),
            undo: Vec::new(),
        }
    }

    fn report(dry_run: bool, records: Vec<Record>) -> Report {
        Report {
            dir: PathBuf::from("C:/q/q1"),
            restore: "Ponto criado".into(),
            dry_run,
            records,
            aborted: None,
        }
    }

    #[test]
    fn real_run_shows_quarantine_undo_command_and_counts() {
        let r = report(
            false,
            vec![
                record("a", Outcome::Done),
                record("b", Outcome::Declined),
                record("c", Outcome::Failed("x".into())),
                record("d", Outcome::Manual),
                record("e", Outcome::Skipped("y".into())),
            ],
        );
        let t = text(&r);
        assert!(t.contains("Modo: REAL") && t.contains("oblivion undo \"C:/q/q1\""));
        assert!(
            t.contains("1 removido(s), 1 recusado(s), 1 manual(is), 1 ignorado(s), 1 falha(s)")
        );
        assert!(t.contains("falhou: x") && t.contains("ignorado: y"));
    }

    #[test]
    fn dry_run_says_nothing_was_changed_and_hides_the_undo_command() {
        let t = text(&report(true, vec![record("a", Outcome::DryRun)]));
        assert!(t.contains("SIMULAÇÃO") && t.contains("Nada foi alterado"));
        assert!(!t.contains("oblivion undo") && !t.contains("Quarentena:"));
    }

    #[test]
    fn hostile_names_are_neutralized_in_both_formats() {
        let r = report(
            false,
            vec![record("<img src=x onerror=alert(1)>\x1b[2K", Outcome::Done)],
        );
        let t = text(&r);
        assert!(!t.chars().any(|c| c.is_control() && c != '\n'));
        let h = html(&r);
        assert!(!h.contains("<img") && h.contains("&lt;img"));
        assert!(!h.contains("<script"));
    }

    #[test]
    fn aborted_run_is_loud_in_both_formats() {
        let mut r = report(false, vec![]);
        r.aborted = Some("sem espaço".into());
        assert!(text(&r).contains("INTERROMPIDO: sem espaço"));
        assert!(html(&r).contains(r#"role="alert""#));
    }

    #[test]
    fn html_is_self_contained_and_lists_each_record() {
        let h = html(&report(
            false,
            vec![record("a", Outcome::Done), record("b", Outcome::Declined)],
        ));
        assert_eq!(h.matches("<td class=\"sev\">").count(), 2);
        assert!(
            h.contains("default-src 'none'") && !h.contains("http://") && !h.contains("https://")
        );
        assert!(h.starts_with("<!doctype html>") && h.ends_with("</html>"));
    }

    #[test]
    fn empty_report_still_renders() {
        assert!(text(&report(true, vec![])).contains("0 item(ns)"));
        assert!(html(&report(false, vec![])).contains("0 removido(s)"));
    }
}
