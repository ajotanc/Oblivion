/// Gravidade do achado. A ordem das variantes define a ordenação (maior = mais grave).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Suspicious,
    High,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Suspicious => "SUSPEITO",
            Severity::High => "ALTO",
        }
    }
}

/// Motivo dos itens cujo arquivo sumiu. Compartilhado: a remoção trata esses itens como seguros de limpar.
pub const ORPHAN_REASON: &str =
    "O arquivo não existe mais (entrada órfã, sobra de programa removido)";

/// Motivo do minerador pelo sinal FORTE (nome ou argumentos de pool). Só este permite o `--yes` encerrar um processo.
pub const MINER_STRONG_REASON: &str = "Nome ou linha de comando típicos de minerador";

/// Um item encontrado por um scanner. É só um indício para análise, nunca um veredito.
#[derive(Debug, Clone)]
pub struct Finding {
    pub scanner: &'static str,
    /// Onde foi encontrado (chave de registro, pasta, serviço).
    pub location: String,
    pub name: String,
    /// Comando ou caminho que seria executado.
    pub target: String,
    pub severity: Severity,
    pub reason: &'static str,
}
