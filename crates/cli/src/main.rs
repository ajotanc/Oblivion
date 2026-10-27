mod args;

use std::{
    env, fs,
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
};

use args::Parsed;
use oblivion_core::{
    allow,
    clean::{self, Outcome, exec, undo},
    finding::Finding,
    privilege, report, restore, scanners,
};

const USAGE: &str = concat!(
    "Oblivion ",
    env!("CARGO_PKG_VERSION"),
    "\n\nUso:
  oblivion scan [--html ARQUIVO] [--allow ARQUIVO]
      Varre o sistema e mostra o que encontrou. SOMENTE LEITURA: nada é alterado.

  oblivion clean [--dry-run] [--only TEXTO]... [--yes] [--report ARQUIVO] [--allow ARQUIVO]
                 [--no-restore-point] [--quarantine-dir PASTA]
      Procura e REMOVE o que for encontrado, com a sua confirmação item a item. Antes cria um
      ponto de restauração e guarda tudo o que apagou em uma quarentena (dá para desfazer).
      Exige administrador/root. --dry-run só mostra o que seria feito. --only limita aos itens
      cujo nome ou alvo contém o texto. --yes dispensa a pergunta só para itens ALTOS e entradas
      órfãs; os demais SUSPEITOS sempre perguntam.

  oblivion undo PASTA_DA_QUARENTENA
      Devolve ao lugar o que uma limpeza removeu.

  oblivion restore-point
      Cria um ponto de restauração (administrador).

--allow: arquivo de texto com um padrão por linha (# comenta). O padrão deve ser IGUAL ao nome ou à
linha de comando inteira do achado (copie o \"alvo\" do relatório); um `*` no fim vale como prefixo.
Itens SUSPEITOS que casam passam a INFO. Itens ALTOS nunca são escondidos."
);

fn main() -> ExitCode {
    let raw: Vec<String> = env::args().skip(1).collect();
    if args::wants_version(&raw) {
        println!("oblivion {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    if args::wants_help(&raw) {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let parsed = match args::parse(&raw) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Erro: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match parsed.command.as_str() {
        "scan" => scan(&parsed),
        "clean" => clean_command(&parsed),
        "undo" => undo_command(&parsed),
        _ => restore_point(),
    }
}

fn restore_point() -> ExitCode {
    match restore::create() {
        Ok(r) => {
            println!("{}", r.describe());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Não foi possível criar o ponto de restauração: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Lê a lista `--allow`. Um arquivo ilegível aborta: não pode ser ignorado em silêncio.
fn read_allow(p: &Parsed) -> Result<Vec<String>, ExitCode> {
    match p.value("--allow").map(fs::read_to_string).transpose() {
        Ok(text) => Ok(text.map(|t| allow::parse(&t)).unwrap_or_default()),
        Err(e) => {
            eprintln!("Falha ao ler a lista --allow: {e}");
            Err(ExitCode::from(2))
        }
    }
}

fn scan(p: &Parsed) -> ExitCode {
    let patterns = match read_allow(p) {
        Ok(v) => v,
        Err(code) => return code,
    };

    // Avisa antes de varrer (o scan leva alguns segundos), em stderr para não sujar a saída redirecionada.
    let elevated = privilege::is_elevated();
    if !elevated {
        eprintln!("\n[!] {}\n", privilege::alert());
    }

    let mut findings = scanners::scan_all();
    allow::apply(&mut findings, &patterns);
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    print!("{}", report::text::render(&findings));

    if let Some(path) = p.value("--html") {
        if let Err(e) = fs::write(path, report::html::render(&findings, elevated)) {
            eprintln!("Falha ao gravar {path}: {e}");
            return ExitCode::FAILURE;
        }
        println!("Relatório HTML: {path}");
    }
    if !elevated {
        // Lembrete no fim: o aviso do início pode ter rolado para fora da tela.
        eprintln!(
            "[!] Resultado incompleto: o scan rodou sem privilégios elevados (veja o aviso acima)."
        );
    }
    ExitCode::SUCCESS
}

/// Pergunta ao usuário, mostrando o que será feito. Sem resposta clara (ou sem entrada), é "não".
fn ask(f: &Finding, action: &str) -> bool {
    use report::text::clean as safe;
    println!(
        "\n[{}] {}\n    alvo:   {}\n    motivo: {}\n    ação:   {}",
        f.severity.label(),
        safe(&f.name),
        safe(&f.target),
        safe(f.reason),
        safe(action)
    );
    print!("Executar? [s/N] ");
    let _ = io::stdout().flush();
    let mut line = String::new();
    io::stdin().read_line(&mut line).is_ok_and(|n| n > 0)
        && matches!(
            line.trim().to_lowercase().as_str(),
            "s" | "sim" | "y" | "yes"
        )
}

fn clean_command(p: &Parsed) -> ExitCode {
    let dry_run = p.has("--dry-run");
    let patterns = match read_allow(p) {
        Ok(v) => v,
        Err(code) => return code,
    };
    if !privilege::is_elevated() {
        eprintln!("\n[!] {}\n", privilege::alert());
        if !dry_run {
            eprintln!(
                "A remoção exige privilégios elevados. Rode como administrador/root, ou use --dry-run para só ver o que seria feito."
            );
            return ExitCode::from(2);
        }
    }

    eprintln!("Procurando (leva alguns segundos)...");
    let mut findings = scanners::scan_all();
    allow::apply(&mut findings, &patterns);

    let only: Vec<String> = p.values("--only").into_iter().map(String::from).collect();
    let restore_text = if dry_run {
        "não necessário (simulação)".to_string()
    } else if clean::actionable_count(&findings, &only) == 0 {
        "não necessário (nada a remover)".to_string()
    } else if p.has("--no-restore-point") {
        "NÃO criado (--no-restore-point): só a quarentena protege".to_string()
    } else {
        match restore::create() {
            Ok(r) => r.describe().to_string(),
            Err(e) => {
                eprintln!(
                    "Não removo nada sem ponto de restauração: {e}\nSe quiser seguir mesmo assim, use --no-restore-point (por sua conta e risco)."
                );
                return ExitCode::FAILURE;
            }
        }
    };

    let root = p
        .value("--quarantine-dir")
        .map_or_else(clean::default_root, PathBuf::from);
    // A pasta da quarentena é criada PRIVADA (só administrador/root) e com nome novo. Em simulação nada é criado.
    let dir = if dry_run {
        root.join("simulacao")
    } else {
        match clean::create_session(&root) {
            Ok(dir) => dir,
            Err(e) => {
                eprintln!(
                    "Não consegui criar uma quarentena privada em {}: {e}\nNão removo nada sem ela.",
                    root.display()
                );
                return ExitCode::FAILURE;
            }
        }
    };
    let opts = clean::Options {
        only,
        dry_run,
        yes_for_safe: p.has("--yes"),
    };
    let result = clean::run(
        &findings,
        &opts,
        &dir,
        &restore_text,
        &mut ask,
        &mut exec::execute,
    );

    print!("{}", report::clean::text(&result));
    let html = report::clean::html(&result);
    if !dry_run && dir.is_dir() {
        // O relatório do que foi feito fica junto da quarentena, para quem precisar desfazer depois.
        let _ = fs::write(dir.join("report.html"), &html);
    }
    if let Some(path) = p.value("--report") {
        match fs::write(path, &html) {
            Ok(()) => println!("Relatório HTML: {path}"),
            Err(e) => {
                eprintln!("Falha ao gravar {path}: {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    let failed = result
        .records
        .iter()
        .any(|r| matches!(r.outcome, Outcome::Failed(_)));
    if failed || result.aborted.is_some() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn undo_command(p: &Parsed) -> ExitCode {
    if !privilege::is_elevated() {
        eprintln!("\n[!] {}\n", privilege::alert());
    }
    let results = match undo::undo(&PathBuf::from(&p.positional[0])) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Não foi possível desfazer: {e}");
            return ExitCode::FAILURE;
        }
    };
    if results.is_empty() {
        println!("Nada para desfazer nesta quarentena.");
    }
    for r in &results {
        match &r.result {
            Ok(()) => println!("[ok] {}", report::text::clean(&r.description)),
            Err(e) => println!(
                "[não desfeito] {}: {}",
                report::text::clean(&r.description),
                report::text::clean(e)
            ),
        }
    }
    if results.iter().any(|r| r.result.is_err()) {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
