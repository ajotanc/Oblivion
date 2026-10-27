//! Leitura estrita dos argumentos: opção desconhecida, valor faltando e valor que parece outra opção
//! são erros, em vez de serem ignorados em silêncio (ex.: `--htm` não pode "funcionar" sem gerar nada).

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Switch,
    Value,
    /// Pode aparecer mais de uma vez.
    Repeat,
}

use Kind::{Repeat, Switch, Value};

/// Opções aceitas por comando. `None` = comando desconhecido.
fn spec(command: &str) -> Option<&'static [(&'static str, Kind)]> {
    Some(match command {
        "scan" => &[("--html", Value), ("--allow", Value), ("--ioc", Value)],
        "clean" => &[
            ("--allow", Value),
            ("--ioc", Value),
            ("--recipe", Value),
            ("--only", Repeat),
            ("--dry-run", Switch),
            ("--yes", Switch),
            ("--no-restore-point", Switch),
            ("--report", Value),
            ("--quarantine-dir", Value),
        ],
        "recent" => &[("--days", Value)],
        "undo" | "restore-point" => &[],
        _ => return None,
    })
}

#[derive(Debug, Default)]
pub struct Parsed {
    pub command: String,
    values: Vec<(String, String)>,
    switches: Vec<String>,
    pub positional: Vec<String>,
}

impl Parsed {
    pub fn value(&self, flag: &str) -> Option<&str> {
        self.values
            .iter()
            .find(|(f, _)| f == flag)
            .map(|(_, v)| v.as_str())
    }

    pub fn values(&self, flag: &str) -> Vec<&str> {
        self.values
            .iter()
            .filter(|(f, _)| f == flag)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    pub fn has(&self, flag: &str) -> bool {
        self.switches.iter().any(|f| f == flag)
    }
}

/// `--version` ou `-V` como primeiro argumento: mostrar a versão e sair com sucesso.
pub fn wants_version(args: &[String]) -> bool {
    matches!(args.first().map(String::as_str), Some("--version" | "-V"))
}

/// `--help`, `-h` ou `help` como primeiro argumento: mostrar o uso e sair com sucesso.
pub fn wants_help(args: &[String]) -> bool {
    matches!(
        args.first().map(String::as_str),
        Some("--help" | "-h" | "help")
    )
}

pub fn parse(args: &[String]) -> Result<Parsed, String> {
    let command = args.first().ok_or("faltou o comando")?;
    let options = spec(command).ok_or_else(|| format!("comando desconhecido: {command}"))?;
    let mut parsed = Parsed {
        command: command.clone(),
        ..Parsed::default()
    };

    let mut rest = args[1..].iter();
    while let Some(arg) = rest.next() {
        if !arg.starts_with("--") {
            parsed.positional.push(arg.clone());
            continue;
        }
        let kind = options
            .iter()
            .find(|(name, _)| name == arg)
            .map(|(_, k)| *k)
            .ok_or_else(|| format!("opção desconhecida para \"{command}\": {arg}"))?;
        match kind {
            Switch => {
                if parsed.has(arg) {
                    return Err(format!("a opção {arg} foi repetida"));
                }
                parsed.switches.push(arg.clone());
            }
            Value | Repeat => {
                let value = rest
                    .next()
                    .ok_or_else(|| format!("a opção {arg} precisa de um valor"))?;
                if value.starts_with("--") {
                    return Err(format!(
                        "a opção {arg} precisa de um valor, mas recebeu \"{value}\""
                    ));
                }
                if kind == Value && parsed.value(arg).is_some() {
                    return Err(format!("a opção {arg} foi repetida"));
                }
                parsed.values.push((arg.clone(), value.clone()));
            }
        }
    }

    let wanted = usize::from(command == "undo");
    if parsed.positional.len() != wanted {
        return Err(match wanted {
            1 => "informe a pasta da quarentena: oblivion undo PASTA".to_string(),
            _ => format!("argumento inesperado: {}", parsed.positional[0]),
        });
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_str(s: &str) -> Result<Parsed, String> {
        parse(&s.split_whitespace().map(String::from).collect::<Vec<_>>())
    }

    #[test]
    fn scan_reads_values() {
        let p = parse_str("scan --html r.html --allow lista.txt").unwrap();
        assert_eq!(
            (p.value("--html"), p.value("--allow")),
            (Some("r.html"), Some("lista.txt"))
        );
        assert_eq!(p.value("--nada"), None);
    }

    #[test]
    fn typos_are_errors_not_silently_ignored() {
        // O caso da auditoria: `--htm` era aceito e nenhum relatório era gerado.
        assert!(
            parse_str("scan --htm r.html")
                .unwrap_err()
                .contains("opção desconhecida")
        );
        assert!(
            parse_str("scan --dry-run").is_err(),
            "opção de outro comando"
        );
    }

    #[test]
    fn a_value_that_looks_like_an_option_is_rejected() {
        // O caso da auditoria: `--html --allow x` gravava um arquivo chamado "--allow".
        let e = parse_str("scan --html --allow lista.txt").unwrap_err();
        assert!(e.contains("--html") && e.contains("--allow"));
    }

    #[test]
    fn missing_value_and_repeated_options_are_errors() {
        assert!(
            parse_str("scan --html")
                .unwrap_err()
                .contains("precisa de um valor")
        );
        assert!(
            parse_str("scan --html a --html b")
                .unwrap_err()
                .contains("repetida")
        );
        assert!(
            parse_str("clean --yes --yes")
                .unwrap_err()
                .contains("repetida")
        );
    }

    #[test]
    fn clean_accepts_switches_and_repeated_only() {
        let p = parse_str(
            "clean --dry-run --only abc --only xyz --yes --report r.html --quarantine-dir q",
        )
        .unwrap();
        assert!(p.has("--dry-run") && p.has("--yes") && !p.has("--no-restore-point"));
        assert_eq!(p.values("--only"), vec!["abc", "xyz"]);
        assert_eq!(
            (p.value("--report"), p.value("--quarantine-dir")),
            (Some("r.html"), Some("q"))
        );
    }

    #[test]
    fn undo_needs_exactly_one_folder() {
        assert_eq!(
            parse_str("undo C:/q/q1").unwrap().positional,
            vec!["C:/q/q1"]
        );
        assert!(
            parse_str("undo")
                .unwrap_err()
                .contains("pasta da quarentena")
        );
        assert!(parse_str("undo a b").is_err());
    }

    #[test]
    fn other_commands_reject_stray_arguments() {
        assert!(parse_str("scan extra").unwrap_err().contains("inesperado"));
        assert!(parse_str("restore-point agora").is_err());
        assert!(parse_str("restore-point").is_ok());
    }

    #[test]
    fn version_is_recognized_only_as_the_first_argument() {
        let a = |s: &str| s.split_whitespace().map(String::from).collect::<Vec<_>>();
        assert!(wants_version(&a("--version")) && wants_version(&a("-V")));
        assert!(
            !wants_version(&a("scan --version")) && !wants_version(&a("-v")) && !wants_version(&[])
        );
    }

    #[test]
    fn help_is_recognized_only_as_the_first_argument() {
        let a = |s: &str| s.split_whitespace().map(String::from).collect::<Vec<_>>();
        assert!(wants_help(&a("--help")) && wants_help(&a("-h")) && wants_help(&a("help")));
        assert!(!wants_help(&a("scan --help")) && !wants_help(&[]));
    }

    #[test]
    fn unknown_or_missing_command_is_an_error() {
        assert!(
            parse_str("apagar-tudo")
                .unwrap_err()
                .contains("comando desconhecido")
        );
        assert!(parse(&[]).unwrap_err().contains("faltou o comando"));
    }
}
