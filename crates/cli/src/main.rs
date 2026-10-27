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
    ioc, privilege, recent, recipe, report, restore, scanners,
};

const USAGE: &str = concat!(
    "Oblivion ",
    env!("CARGO_PKG_VERSION"),
    "\n\nUso:
  oblivion scan [--html ARQUIVO] [--allow ARQUIVO] [--ioc ARQUIVO]
      Varre o sistema e mostra o que encontrou. SOMENTE LEITURA: nada é alterado.

  oblivion clean [--dry-run] [--only TEXTO]... [--yes] [--report ARQUIVO] [--allow ARQUIVO] [--ioc ARQUIVO]
                 [--recipe ARQUIVO]
                 [--no-restore-point] [--quarantine-dir PASTA]
      Procura e REMOVE o que for encontrado, com a sua confirmação item a item. Antes cria um
      ponto de restauração e guarda tudo o que apagou em uma quarentena (dá para desfazer).
      Exige administrador/root. --dry-run só mostra o que seria feito. --only limita aos itens
      cujo nome ou alvo contém o texto. --yes dispensa a pergunta só para itens ALTOS e entradas
      órfãs; os demais SUSPEITOS sempre perguntam.

  oblivion recent [--days N]
      Lista executáveis e scripts criados ou alterados nos últimos N dias (padrão 7) nas pastas onde
      malware costuma se instalar. Só diagnóstico, como o Find3M: nada é alterado nem julgado.

  oblivion undo PASTA_DA_QUARENTENA
      Devolve ao lugar o que uma limpeza removeu.

  oblivion restore-point
      Cria um ponto de restauração (administrador).

--allow: arquivo de texto com um padrão por linha (# comenta). O padrão deve ser IGUAL ao nome ou à
linha de comando inteira do achado (copie o \"alvo\" do relatório); um `*` no fim vale como prefixo.
Itens SUSPEITOS que casam passam a INFO. Itens ALTOS nunca são escondidos.
--recipe: em vez de varrer, remove SÓ o que o seu arquivo pede (uma linha por item: `valor: CHAVE_RUN | Nome`,
`inicializacao: arquivo.lnk`, `processo: nome.exe`; # comenta). Sempre pergunta item a item (--yes não vale),
e usa ponto de restauração, quarentena e undo. Não aceita caminho livre nem processos do Windows.
--ioc: sua lista de indicadores, um por linha: `sha256:<64 hex>` ou `nome:<arquivo.exe>` (# comenta). Confere
os processos em execução e os itens achados; casou pelo conteúdo = ALTO. O Oblivion não traz lista pronta."
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
        "recent" => recent_command(&parsed),
        _ => restore_point(),
    }
}

fn recent_command(p: &Parsed) -> ExitCode {
    let days = match p.value("--days").map(str::parse::<u64>).transpose() {
        Ok(d) => d.unwrap_or(7).clamp(1, 365),
        Err(_) => {
            eprintln!("--days precisa de um número inteiro (1 a 365)");
            return ExitCode::from(2);
        }
    };
    let found = recent::scan(days);
    // O relatório comum esconde INFO; aqui a lista é o próprio resultado (limpa de caracteres de controle).
    for f in &found {
        println!(
            "{}\n    {}",
            report::text::clean(&f.name),
            report::text::clean(&f.target)
        );
    }
    println!(
        "\n{} arquivo(s) nos últimos {days} dia(s). Diagnóstico, não veredito.",
        found.len()
    );
    ExitCode::SUCCESS
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

/// Lê a lista `--ioc` e avisa das linhas ignoradas. Arquivo ilegível aborta, como no `--allow`.
fn read_ioc(p: &Parsed) -> Result<ioc::Iocs, ExitCode> {
    let Some(path) = p.value("--ioc") else {
        return Ok(ioc::Iocs::default());
    };
    match fs::read_to_string(path) {
        Ok(text) => {
            let (iocs, ignored) = ioc::Iocs::parse(&text);
            if ignored > 0 {
                eprintln!("[!] {ignored} linha(s) inválida(s) ignorada(s) em {path}");
            }
            Ok(iocs)
        }
        Err(e) => {
            eprintln!("Falha ao ler a lista --ioc: {e}");
            Err(ExitCode::from(2))
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
    let iocs = match read_ioc(p) {
        Ok(v) => v,
        Err(code) => return code,
    };

    // Avisa antes de varrer (o scan leva alguns segundos), em stderr para não sujar a saída redirecionada.
    let elevated = privilege::is_elevated();
    if !elevated {
        eprintln!("\n[!] {}\n", privilege::alert());
    }

    let mut findings = scanners::scan_all();
    let extra = ioc::check(&iocs, &findings);
    findings.extend(extra);
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
    let iocs = match read_ioc(p) {
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

    let mut findings = if let Some(path) = p.value("--recipe") {
        let text = match fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("Falha ao ler a receita: {e}");
                return ExitCode::from(2);
            }
        };
        let (found, problems) = recipe::load(&text);
        for problem in &problems {
            eprintln!("[!] receita, {problem}");
        }
        found
    } else {
        eprintln!("Procurando (leva alguns segundos)...");
        let mut found = scanners::scan_all();
        let extra = ioc::check(&iocs, &found);
        found.extend(extra);
        found
    };
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
