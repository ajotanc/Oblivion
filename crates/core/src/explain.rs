//! Explicações em linguagem simples: o que o achado significa, o que acontece se for tratado e se vale
//! a pena selecioná-lo sem pensar muito ("recomendado"). A CLI e a interface usam este mesmo texto.
//!
//! O texto técnico (`reason`) continua existindo para quem quer detalhes; aqui é para quem não é do ramo.
//! "Recomendado" nunca é prova de que é malware: só quer dizer que o sinal é forte e que dá para desfazer.
use crate::{
    clean::{self, Plan},
    finding::{Finding, MINER_STRONG_REASON, ORPHAN_REASON, Severity},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Explanation {
    /// O que é, em uma ou duas frases.
    pub what: String,
    /// O que acontece se o Oblivion tratar o item.
    pub impact: String,
    /// Sinal forte e ação reversível: a tela pode pré-selecionar.
    pub recommended: bool,
}

/// Processo marcado só por sinais fracos (CPU/GPU): pode ser um jogo ou um editor de vídeo.
pub fn is_weak_miner_signal(f: &Finding) -> bool {
    f.scanner == "minerador" && f.severity > Severity::Info && f.reason != MINER_STRONG_REASON
}

fn what(f: &Finding, plan: Option<&Plan>) -> String {
    let base = match (f.scanner, plan) {
        (_, Some(Plan::RunValue { .. })) => {
            "Um programa está configurado para iniciar sozinho toda vez que você liga o computador ou entra na sua conta."
        }
        (_, Some(Plan::Startup { .. })) => {
            "Um item da pasta de inicialização abre sozinho quando você entra no Windows."
        }
        (_, Some(Plan::Task { .. })) => {
            "Existe uma tarefa agendada que executa um programa sozinha, em certos horários ou eventos."
        }
        (_, Some(Plan::Process { .. })) => "Este programa está rodando agora.",
        (_, Some(Plan::Wmi { .. })) => {
            "Uma regra escondida do Windows (WMI) executa um comando quando acontece um evento, sem deixar arquivo à vista."
        }
        (_, Some(Plan::Hosts { .. })) => {
            "O arquivo \"hosts\" manda um site para outro endereço. Isso é usado para bloquear antivírus ou desviar sites."
        }
        (_, Some(Plan::Repair(fix))) if fix.service().is_some() => {
            "Um serviço do Windows inicia sozinho e roda em segundo plano, sem janela."
        }
        (_, Some(Plan::Repair(_))) => {
            "Uma configuração de segurança ou de inicialização do Windows foi alterada em relação ao padrão."
        }
        ("persistencia", _) => {
            "Um programa, serviço ou driver está configurado para iniciar sozinho com o Windows."
        }
        ("tarefas", _) => "Existe uma tarefa agendada que executa um programa sozinha.",
        ("wmi", _) => {
            "Uma regra escondida do Windows (WMI) executa algo quando acontece um evento."
        }
        ("minerador", _) => {
            "Um programa usa o processador ou a placa de vídeo de forma típica de mineração de criptomoeda."
        }
        ("processos", _) => "Um programa em execução tem sinais de disfarce.",
        ("extensoes", _) => {
            "Uma extensão do navegador tem permissões amplas, como ver ou mudar o que você acessa."
        }
        ("mbr", _) => {
            "O setor de boot do disco (o primeiro código que roda ao ligar) tem algo diferente do esperado."
        }
        ("rede", _) => {
            "Uma configuração de rede (proxy, DNS ou hosts) pode estar desviando o seu tráfego."
        }
        ("seguranca", _) => {
            "Uma proteção do Windows (como antivírus, firewall ou controle de contas) está desligada ou enfraquecida."
        }
        ("baseline", _) => {
            "Uma configuração que quase nunca muda no Windows está diferente do padrão."
        }
        ("conhecidos", _) => {
            "Há um programa instalado que consta numa lista de programas indesejados conhecidos (falso antivírus ou adware)."
        }
        ("atalhos", _) => {
            "Um atalho foi alterado para abrir outra coisa além do programa que o nome mostra."
        }
        ("ads", _) => {
            "Existe um programa ou script escondido dentro de outro arquivo, onde o Explorer não mostra."
        }
        ("rootkit", _) => {
            "Um processo aparece numa forma de listar e some da outra, o que pode indicar que algo está se escondendo."
        }
        ("ioc", _) => "Um arquivo bate com a sua lista de indicadores de ameaça.",
        ("ransomware", _) => {
            "Há sinais de ransomware: programa que criptografa arquivos e pede resgate."
        }
        _ => "O Oblivion encontrou algo que merece sua atenção.",
    };
    let confidence = match f.severity {
        Severity::High => " O sinal é forte.",
        Severity::Suspicious => " Pode ser legítimo: veja se você reconhece o nome e o caminho.",
        Severity::Info => " É só informativo.",
    };
    format!("{base}{confidence}")
}

fn impact(plan: Option<&Plan>) -> String {
    match plan {
        None => "É só informação: o Oblivion não faz nada com este item.".into(),
        Some(Plan::RunValue { .. }) => "O programa deixa de iniciar com o Windows e o arquivo dele vai para a quarentena. Dá para desfazer.".into(),
        Some(Plan::Startup { .. }) => "O item sai da pasta de inicialização e vai para a quarentena. Dá para desfazer.".into(),
        Some(Plan::Task { .. }) => "A tarefa é apagada (uma cópia fica guardada) e o programa dela vai para a quarentena. Dá para desfazer.".into(),
        Some(Plan::Process { .. }) => "O programa é fechado agora e o arquivo dele vai para a quarentena. Trabalho não salvo nele pode ser perdido.".into(),
        Some(Plan::Wmi { .. }) => "A regra é removida (fica guardada). Dá para desfazer.".into(),
        Some(Plan::Hosts { .. }) => "A linha é comentada, não apagada, e o site volta ao endereço normal. Dá para desfazer.".into(),
        Some(Plan::Repair(fix)) if fix.service().is_some() => "O serviço para de iniciar sozinho e é parado agora. Se algum programa seu dependia dele, pode parar de funcionar. Dá para desfazer.".into(),
        Some(Plan::Repair(_)) => "A configuração volta ao valor padrão do Windows. Se foi você ou sua empresa que a mudou de propósito, não corrija. Dá para desfazer.".into(),
        Some(Plan::Manual(_)) => "O Oblivion não altera isto sozinho (é arriscado automatizar). Siga a orientação mostrada.".into(),
    }
}

/// Selecionável sem pensar muito: ação automática, reversível e sinal forte (ALTO ou entrada órfã).
/// Processo marcado só por sinal fraco nunca entra: pode ser um jogo.
pub fn is_recommended(f: &Finding) -> bool {
    let Some(plan) = clean::plan(f) else {
        return false;
    };
    !plan.is_manual()
        && !is_weak_miner_signal(f)
        && (f.severity == Severity::High || f.reason == ORPHAN_REASON)
}

pub fn explain(f: &Finding) -> Explanation {
    let plan = clean::plan(f);
    Explanation {
        what: what(f, plan.as_ref()),
        impact: impact(plan.as_ref()),
        recommended: is_recommended(f),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(
        scanner: &'static str,
        location: &str,
        name: &str,
        reason: &'static str,
        severity: Severity,
    ) -> Finding {
        Finding {
            scanner,
            location: location.into(),
            name: name.into(),
            target: r"C:\Users\x\AppData\a.exe".into(),
            severity,
            reason,
        }
    }

    #[test]
    fn every_scanner_gets_a_plain_explanation_and_an_impact() {
        for scanner in [
            "persistencia",
            "tarefas",
            "wmi",
            "minerador",
            "processos",
            "extensoes",
            "mbr",
            "rede",
            "seguranca",
            "baseline",
            "conhecidos",
            "atalhos",
            "ads",
            "rootkit",
            "ioc",
            "ransomware",
        ] {
            let e = explain(&finding(scanner, "loc", "n", "r", Severity::Suspicious));
            assert!(
                e.what.len() > 30 && !e.what.contains("merece sua atenção"),
                "{scanner}: {}",
                e.what
            );
            assert!(!e.impact.is_empty(), "{scanner}");
        }
    }

    #[test]
    fn info_is_never_recommended_and_says_nothing_will_be_done() {
        let e = explain(&finding("persistencia", "loc", "n", "r", Severity::Info));
        assert!(!e.recommended);
        assert!(e.impact.contains("só informação"));
    }

    #[test]
    fn a_strong_miner_process_is_recommended_but_a_weak_one_never_is() {
        let strong = finding(
            "minerador",
            "PID 7 | RAM 1 MB",
            "xmrig.exe",
            MINER_STRONG_REASON,
            Severity::High,
        );
        let weak = finding(
            "minerador",
            "PID 8 | RAM 1 MB",
            "jogo.exe",
            "CPU e GPU altas",
            Severity::High,
        );
        assert!(is_recommended(&strong));
        assert!(!is_recommended(&weak) && is_weak_miner_signal(&weak));
        assert!(explain(&weak).impact.contains("Trabalho não salvo"));
    }

    #[test]
    fn manual_items_are_not_recommended_even_when_high() {
        let mbr = finding("mbr", "disco", "MBR", "r", Severity::High);
        let e = explain(&mbr);
        assert!(!e.recommended && e.impact.contains("não altera isto sozinho"));
    }

    #[test]
    fn suspicious_items_tell_the_user_to_check_before_acting() {
        let e = explain(&finding(
            "conhecidos",
            "loc",
            "n",
            "r",
            Severity::Suspicious,
        ));
        assert!(e.what.contains("Pode ser legítimo"));
        assert!(!e.recommended);
    }

    #[test]
    fn an_orphan_entry_is_recommended_because_nothing_is_lost() {
        let f = finding(
            "persistencia",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "Velho",
            ORPHAN_REASON,
            Severity::Suspicious,
        );
        assert!(is_recommended(&f) == cfg!(windows));
    }
}
