use std::{collections::BTreeSet, fmt::Write};

use crate::finding::{Finding, Severity};
use crate::privilege;

// Valores vêm do registro e de nomes de arquivo, então são dados não confiáveis: sempre escapar.
pub(crate) fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub(crate) const STYLE: &str = r#"
:root{--bg:#f7f7f9;--fg:#1b1b1f;--card:#fff;--line:#d9d9e0;--muted:#55555f;--high:#b3261e;--susp:#8a5a00;--info:#2f5d9e}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#121216;--fg:#ececf1;--card:#1c1c22;--line:#34343e;--muted:#a6a6b3;--high:#ff8a80;--susp:#ffcc66;--info:#8ab4f8}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif}
main{max-width:1200px;margin:0 auto;padding:16px}h1{font-size:1.5rem;margin:.5rem 0}
[hidden]{display:none!important}
.skip{position:absolute;left:-999px}.skip:focus{left:8px;top:8px;background:var(--card);padding:8px}
.summary{display:flex;flex-wrap:wrap;gap:12px;margin:16px 0;padding:0;list-style:none}
.summary li{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 16px;min-width:130px}
.summary b{display:block;font-size:1.6rem}.note{color:var(--muted)}
.alert{margin:16px 0;padding:12px 16px;background:var(--card);border:2px solid var(--susp);border-radius:8px}
.filters{display:flex;flex-wrap:wrap;gap:16px;align-items:end;margin:16px 0}
.filters label,.filters legend{font-weight:600;font-size:.9rem}
.filters input[type=search],.filters select{display:block;min-height:44px;padding:8px 12px;font:inherit;color:var(--fg);background:var(--card);border:1px solid var(--line);border-radius:8px}
.filters fieldset{border:0;padding:0;margin:0;display:flex;gap:12px;align-items:center}
.filters fieldset label{display:inline-flex;align-items:center;gap:6px;min-height:44px;font-weight:400}
.scroll{overflow-x:auto;border:1px solid var(--line);border-radius:8px;background:var(--card)}
table{border-collapse:collapse;width:100%;min-width:820px}th,td{text-align:left;padding:8px 12px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}
th{color:var(--muted);font-weight:600}.sev{font-weight:700;white-space:nowrap}
.high{color:var(--high)}.susp{color:var(--susp)}.info{color:var(--info)}
:focus-visible{outline:3px solid var(--info);outline-offset:2px}
"#;

// Sem o JavaScript a tabela continua completa; o script só esconde linhas (nada é enviado).
const SCRIPT: &str = r#"
(function(){
var q=document.getElementById('q'),s=document.getElementById('origem'),
boxes=document.querySelectorAll('input[name=sev]'),
rows=document.querySelectorAll('tbody tr'),out=document.getElementById('contagem');
function apply(){
var term=q.value.trim().toLowerCase(),sevs={},n=0;
boxes.forEach(function(b){if(b.checked)sevs[b.value]=1});
rows.forEach(function(r){
var ok=sevs[r.dataset.sev]&&(!s.value||r.dataset.scanner===s.value)&&(!term||r.textContent.toLowerCase().indexOf(term)>-1);
r.hidden=!ok;if(ok)n++});
out.textContent='Mostrando '+n+' de '+rows.length+' achados';}
q.addEventListener('input',apply);s.addEventListener('change',apply);
boxes.forEach(function(b){b.addEventListener('change',apply)});apply();
})();
"#;

fn class(s: Severity) -> &'static str {
    match s {
        Severity::High => "high",
        Severity::Suspicious => "susp",
        Severity::Info => "info",
    }
}

/// `elevated`: se o scan rodou como administrador/root; senão o relatório abre com um aviso.
pub fn render(findings: &[Finding], elevated: bool) -> String {
    let count = |s| findings.iter().filter(|f| f.severity == s).count();
    let alert = if elevated {
        String::new()
    } else {
        format!(
            r#"<div class="alert" role="alert"><strong>Execução sem privilégios elevados.</strong> {}</div>"#,
            escape(privilege::alert())
        )
    };
    let scanners: BTreeSet<&str> = findings.iter().map(|f| f.scanner).collect();
    let options: String = scanners
        .iter()
        .map(|s| format!(r#"<option value="{0}">{0}</option>"#, escape(s)))
        .collect();
    let mut h = String::new();
    let _ = write!(
        h,
        r##"<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="description" content="Relatório local gerado pelo Oblivion com os itens encontrados no sistema.">
<title>Relatório Oblivion</title><style>{STYLE}</style></head><body>
<a class="skip" href="#achados">Pular para os achados</a><main>
<h1>Relatório Oblivion</h1>{alert}
<p class="note">Os achados são indícios para análise, não um veredito. Tudo foi gerado localmente; nada foi enviado.</p>
<ul class="summary" aria-label="Resumo">
<li><b class="high">{}</b>Alto</li><li><b class="susp">{}</b>Suspeito</li><li><b class="info">{}</b>Info</li></ul>
<div class="filters" role="search" aria-label="Filtrar achados">
<div><label for="q">Buscar</label><input type="search" id="q" autocomplete="off" placeholder="nome, alvo, local ou motivo"></div>
<div><label for="origem">Origem</label><select id="origem"><option value="">Todas</option>{options}</select></div>
<fieldset><legend>Gravidade</legend>
<label><input type="checkbox" name="sev" value="high" checked> Alto</label>
<label><input type="checkbox" name="sev" value="susp" checked> Suspeito</label>
<label><input type="checkbox" name="sev" value="info" checked> Info</label></fieldset>
</div>
<p class="note" id="contagem" role="status" aria-live="polite">{} achados</p>
<div class="scroll" tabindex="0" role="region" aria-label="Tabela de achados" id="achados">
<table><caption class="note" style="text-align:left;padding:8px 12px">Itens encontrados pelos scanners do Oblivion</caption>
<thead><tr><th scope="col">Gravidade</th><th scope="col">Nome</th><th scope="col">Alvo</th><th scope="col">Local</th><th scope="col">Origem</th><th scope="col">Motivo</th></tr></thead><tbody>
"##,
        count(Severity::High),
        count(Severity::Suspicious),
        count(Severity::Info),
        findings.len()
    );
    for f in findings {
        let c = class(f.severity);
        let _ = writeln!(
            h,
            r#"<tr data-sev="{c}" data-scanner="{sc}"><td class="sev {c}">{}</td><td>{}</td><td>{}</td><td>{}</td><td>{sc}</td><td>{}</td></tr>"#,
            f.severity.label(),
            escape(&f.name),
            escape(&f.target),
            escape(&f.location),
            escape(f.reason),
            sc = escape(f.scanner)
        );
    }
    let _ = write!(
        h,
        "</tbody></table></div><script>{SCRIPT}</script></main></body></html>"
    );
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(scanner: &'static str, name: &str, severity: Severity) -> Finding {
        Finding {
            scanner,
            location: "local".into(),
            name: name.into(),
            target: "alvo".into(),
            severity,
            reason: "motivo",
        }
    }

    #[test]
    fn escapes_untrusted_values() {
        let payload = "<script>alert(1)</script>";
        let mut f = finding("t", payload, Severity::Info);
        f.target = "\"><img src=x onerror=alert(1)>".into();
        let html = render(&[f], true);
        assert!(!html.contains(payload) && !html.contains("<img"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        // O único <script> do documento é o nosso, no fim.
        assert_eq!(html.matches("<script>").count(), 1);
    }

    #[test]
    fn one_row_per_finding_with_filter_attributes() {
        let html = render(
            &[
                finding("persistencia", "a", Severity::High),
                finding("minerador", "b", Severity::Info),
            ],
            true,
        );
        assert_eq!(html.matches("<td class=\"sev").count(), 2);
        assert!(html.contains(r#"data-sev="high" data-scanner="persistencia""#));
        assert!(html.contains(r#"data-sev="info" data-scanner="minerador""#));
    }

    #[test]
    fn origin_filter_lists_each_scanner_once_in_order() {
        let html = render(
            &[
                finding("wmi", "a", Severity::Info),
                finding("minerador", "b", Severity::Info),
                finding("wmi", "c", Severity::Info),
            ],
            true,
        );
        let m = html.find(r#"<option value="minerador">"#).unwrap();
        let w = html.find(r#"<option value="wmi">"#).unwrap();
        assert!(m < w);
        assert_eq!(html.matches(r#"<option value="wmi">"#).count(), 1);
    }

    #[test]
    fn alert_banner_appears_only_without_elevation_and_before_the_findings() {
        let without = render(&[], false);
        assert!(
            without.contains(r#"role="alert""#)
                && without.contains("Execução sem privilégios elevados")
        );
        assert!(without.contains(&escape(privilege::alert())));
        assert!(
            without.find(r#"role="alert""#).unwrap() < without.find(r#"id="achados""#).unwrap(),
            "o aviso vem antes da tabela"
        );
        assert!(!render(&[], true).contains(r#"role="alert""#));
    }

    #[test]
    fn page_is_self_contained_and_accessible() {
        let html = render(&[], true);
        assert!(html.contains("lang=\"pt-BR\"") && html.contains("Content-Security-Policy"));
        assert!(
            html.contains("default-src 'none'"),
            "bloqueia qualquer acesso à rede"
        );
        assert!(
            !html.contains("http://") && !html.contains("https://"),
            "sem recurso externo"
        );
        for needed in [
            "for=\"q\"",
            "for=\"origem\"",
            "role=\"status\"",
            "aria-live=\"polite\"",
            "<legend>Gravidade</legend>",
        ] {
            assert!(html.contains(needed), "{needed}");
        }
        assert!(html.starts_with("<!doctype html>") && html.ends_with("</html>"));
    }
}
