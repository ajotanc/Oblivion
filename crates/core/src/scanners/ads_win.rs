//! Fluxos alternativos de dados (ADS) do NTFS: um arquivo pode carregar outro "dentro" dele (`a.txt:oculto`),
//! que não aparece no Explorer nem em `dir`. Malware usa isso para esconder programas e scripts.
//! O fluxo `Zone.Identifier` (marca de "veio da internet") e alguns outros são normais e ignorados.
//!
//! Só olha as pastas onde malware costuma se instalar, em poucos níveis, para o scan não ficar lento.
use std::{env, path::PathBuf, time::Duration};

use crate::finding::{Finding, Severity};
use crate::sys;

const SCANNER: &str = "ads";
const PE_REASON: &str = "Programa escondido dentro de outro arquivo (fluxo alternativo de dados com cabeçalho de executável)";
const STREAM_REASON: &str =
    "Script escondido dentro de outro arquivo (fluxo alternativo de dados que começa como script)";
const BENIGN: &[&str] = &[
    "zone.identifier",
    "smartscreen",
    "encryptable",
    "afp_afpinfo",
    "afp_resource",
    "com.dropbox.attrs",
    "oecustomproperty",
    "favicon",
];

// Uma linha por fluxo: `caminho<TAB>nome-do-fluxo<TAB>tamanho<TAB>tipo`, com tipo `MZ` (executável do Windows),
// `SCRIPT` (começa como script) ou `-` (dados comuns: programas como AnyDesk e Chocolatey usam fluxos assim).
const SCRIPT: &str = "$ErrorActionPreference='SilentlyContinue'; $t=\"`t\"; \
    $input | ForEach-Object { if ($_) { \
        Get-ChildItem -LiteralPath $_ -File -Force -Recurse -Depth 2 | ForEach-Object { \
            Get-Item -LiteralPath $_.FullName -Stream * | Where-Object { $_.Stream -ne ':$DATA' -and $_.Length -gt 0 } | ForEach-Object { \
                $kind = '-'; try { $b = Get-Content -LiteralPath $_.FileName -Stream $_.Stream -Encoding Byte -TotalCount 96; \
                    if ($b.Count -ge 2 -and $b[0] -eq 77 -and $b[1] -eq 90) { $kind = 'MZ' } \
                    elseif ([Text.Encoding]::ASCII.GetString($b) -match '(?i)^\\s*(@echo|powershell|cmd /|wscript|cscript|mshta|<script|#!/)') { $kind = 'SCRIPT' } } catch {}; \
                $_.FileName + $t + $_.Stream + $t + $_.Length + $t + $kind } } } }";
fn roots() -> Vec<String> {
    let var = |n: &str| env::var_os(n).map(PathBuf::from);
    let mut r: Vec<PathBuf> = Vec::new();
    r.extend(var("APPDATA").map(|p| p.join(r"Microsoft\Windows\Start Menu\Programs\Startup")));
    r.extend(var("ProgramData").map(|p| p.join(r"Microsoft\Windows\Start Menu\Programs\Startup")));
    r.extend(var("TEMP"));
    r.extend(var("USERPROFILE").map(|p| p.join("Downloads")));
    r.extend(var("PUBLIC"));
    r.extend(var("ProgramData"));
    r.into_iter()
        .filter(|p| p.is_dir())
        .map(|p| p.display().to_string())
        .collect()
}

pub fn scan() -> Vec<Finding> {
    let roots = roots();
    if roots.is_empty() {
        return Vec::new();
    }
    let Some(out) = sys::powershell(SCRIPT, Some(&roots.join("\n")), Duration::from_secs(90))
    else {
        return vec![Finding {
            scanner: SCANNER,
            location: "interno".into(),
            name: "Fluxos alternativos NÃO verificados".into(),
            target: String::new(),
            severity: Severity::Info,
            reason: "A verificação demorou demais ou falhou; essa parte não foi verificada",
        }];
    };
    parse(&out)
}

fn parse(out: &str) -> Vec<Finding> {
    out.lines()
        .filter_map(|l| {
            let mut p = l.split('\t');
            let (file, stream, size, mz) = (p.next()?, p.next()?, p.next()?, p.next()?.trim());
            if BENIGN.contains(&stream.to_lowercase().as_str()) {
                return None;
            }
            let (severity, reason) = match mz {
                "MZ" => (Severity::High, PE_REASON),
                "SCRIPT" => (Severity::Suspicious, STREAM_REASON),
                // Dado comum: não é achado.
                _ => return None,
            };
            Some(Finding {
                scanner: SCANNER,
                location: std::path::Path::new(file)
                    .parent()
                    .map(|d| d.display().to_string())
                    .unwrap_or_default(),
                name: format!(
                    "{}:{stream}",
                    std::path::Path::new(file).file_name()?.to_string_lossy()
                ),
                target: format!("{file}:{stream} ({size} bytes)"),
                severity,
                reason,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_streams_are_ignored_and_hidden_programs_are_high() {
        let out = "C:\\Users\\x\\Downloads\\a.zip\tZone.Identifier\t55\t-\n\
                   C:\\Users\\x\\Downloads\\b.txt\toculto\t8192\tMZ\n\
                   C:\\Users\\x\\Downloads\\c.txt\tdados\t10\t-\n\
                   C:\\ProgramData\\AnyDesk\\ad.trace\t4834988E71\t900\t-\n\
                   C:\\Users\\x\\Downloads\\d.txt\tcmd\t30\tSCRIPT\n";
        let f = parse(out);
        assert_eq!(f.len(), 2, "dado comum não conta; MZ e script sim");
        assert_eq!(
            (f[0].name.as_str(), f[0].severity),
            ("b.txt:oculto", Severity::High)
        );
        assert_eq!(f[1].severity, Severity::Suspicious);
        assert!(f[1].name.ends_with(":cmd"));
        assert!(f[0].target.contains("8192 bytes"));
    }

    #[test]
    fn garbage_lines_are_ignored() {
        assert!(parse("sem tabs\n\t\t\n").is_empty());
    }

    #[test]
    fn the_script_is_valid_powershell() {
        let probe = "$s = [Console]::In.ReadToEnd(); $null = [scriptblock]::Create($s); 'OK'";
        let out = sys::powershell(probe, Some(SCRIPT), Duration::from_secs(30));
        assert_eq!(out.as_deref().map(str::trim), Some("OK"));
    }

    /// Cria um fluxo escondido de verdade, com cabeçalho `MZ`, e confere que o scan o acha.
    #[test]
    fn a_real_hidden_stream_is_found() {
        let dir = std::env::temp_dir().join(format!("oblivion-ads-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("base.txt");
        std::fs::write(&file, "x").unwrap();
        let hidden = format!("{}:escondido", file.display());
        std::fs::write(&hidden, b"MZ\x90\x00 conteudo falso").unwrap();
        let out = sys::powershell(
            SCRIPT,
            Some(&dir.display().to_string()),
            Duration::from_secs(60),
        )
        .unwrap();
        let found = parse(&out);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            found
                .iter()
                .any(|f| f.name == "base.txt:escondido" && f.severity == Severity::High),
            "{out}"
        );
    }
}
