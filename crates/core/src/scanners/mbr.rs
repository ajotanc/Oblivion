//! Setor de boot (MBR): primeiros 512 bytes do disco. Bootkits antigos gravam código aqui para
//! rodar antes do sistema. Leitura crua do disco, exige administrador/root e é só leitura.
//! Limite: sem base de assinaturas, só reconhece o INÍCIO do código de boot (Windows/DOS e GRUB).
//! Um bootkit poderia copiar esse início; código desconhecido também pode ser um gerenciador de
//! boot legítimo incomum. Por isso o resultado é indício, e o byte inicial vai no relatório.
use std::{
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
};

use crate::finding::{Finding, Severity};

const SCANNER: &str = "mbr";
const SECTOR: usize = 512;
/// Bytes 0..440 são código de boot; 440..444 são a assinatura do disco e 444..446 ficam reservados.
const CODE_LEN: usize = 440;
const PARTITION_TABLE: usize = 446;

/// Início do código de boot do Windows/DOS (`xor ax,ax; mov ss,ax; mov sp,0x7C00`, com ou sem `cli`).
const WINDOWS_PROLOGUES: &[&[u8]] = &[
    &[0x33, 0xC0, 0x8E, 0xD0, 0xBC, 0x00, 0x7C],
    &[0xFA, 0x33, 0xC0, 0x8E, 0xD0, 0xBC, 0x00, 0x7C],
];
/// GRUB (`jmp short` + `nop`).
const GRUB_PROLOGUES: &[&[u8]] = &[&[0xEB, 0x63, 0x90], &[0xEB, 0x48, 0x90]];

#[cfg(windows)]
fn devices() -> Vec<PathBuf> {
    (0..4)
        .map(|n| PathBuf::from(format!(r"\\.\PhysicalDrive{n}")))
        .collect()
}

#[cfg(not(windows))]
fn devices() -> Vec<PathBuf> {
    ["/dev/sda", "/dev/vda", "/dev/nvme0n1", "/dev/mmcblk0"]
        .map(PathBuf::from)
        .to_vec()
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Avalia um setor de boot. Devolve gravidade, motivo e um resumo para estudo; `None` se curto demais.
pub fn analyze(sector: &[u8]) -> Option<(Severity, &'static str, String)> {
    let sector = sector.get(..SECTOR)?;
    let types: Vec<u8> = (0..4)
        .map(|i| sector[PARTITION_TABLE + i * 16 + 4])
        .collect();
    let non_zero = sector[..CODE_LEN].iter().filter(|&&b| b != 0).count();
    // Dados para estudo: o que decide a gravidade e o que um analista olharia primeiro.
    let detail = format!(
        "início do código: {} | bytes de código não zero: {non_zero} de {CODE_LEN} | tipos de partição: {}",
        hex(&sector[..16]),
        hex(&types)
    );
    if sector.iter().all(|&b| b == 0) {
        return Some((
            Severity::Info,
            "Setor vazio (sem MBR): normal em disco sem sistema",
            detail,
        ));
    }
    if sector[510..] != [0x55, 0xAA] {
        return Some((
            Severity::Suspicious,
            "Assinatura 55AA ausente: setor de boot inválido ou adulterado",
            detail,
        ));
    }
    // Cada entrada de partição começa com 0x00 (inativa) ou 0x80 (ativa); outro valor é inválido.
    let flags: Vec<u8> = (0..4).map(|i| sector[PARTITION_TABLE + i * 16]).collect();
    if flags.iter().any(|&f| f != 0x00 && f != 0x80) {
        return Some((Severity::Suspicious, "Tabela de partições inválida", detail));
    }
    if flags.iter().filter(|&&f| f == 0x80).count() > 1 {
        return Some((
            Severity::Suspicious,
            "Mais de uma partição marcada como ativa",
            detail,
        ));
    }
    let code = &sector[..CODE_LEN];
    let starts_with = |list: &[&[u8]]| list.iter().any(|p| code.starts_with(p));
    let (severity, reason) = if code.iter().all(|&b| b == 0) {
        (
            Severity::Info,
            "Sem código de boot (comum em discos GPT/UEFI)",
        )
    } else if starts_with(WINDOWS_PROLOGUES) {
        (
            Severity::Info,
            "Início do código de boot compatível com Windows/DOS (só o início foi comparado)",
        )
    } else if starts_with(GRUB_PROLOGUES) {
        (
            Severity::Info,
            "Início do código de boot compatível com o GRUB (só o início foi comparado)",
        )
    } else if types.contains(&0xEE) {
        // Tipo 0xEE = MBR protetor de um disco GPT. Em boot UEFI esse código nunca executa.
        // shortcut: não detecta se o PC inicia em BIOS legado (aí o código executaria); checar o firmware depois.
        (
            Severity::Info,
            "Disco GPT (MBR protetor): o código de boot é ignorado em boot UEFI; confirme que o PC inicia em UEFI",
        )
    } else {
        (
            Severity::Suspicious,
            "Código de boot não reconhecido (pode ser um gerenciador de boot incomum ou um bootkit)",
        )
    };
    Some((severity, reason, detail))
}

pub fn scan() -> Vec<Finding> {
    scan_devices(&devices())
}

/// Lê 4096 bytes de uma vez: o Windows só aceita leitura de disco cru em múltiplos do tamanho do setor
/// (512 ou 4096), e 4096 serve para os dois. Depois só os 512 primeiros são analisados.
fn read_boot_sector(path: &Path) -> io::Result<Vec<u8>> {
    let mut buf = [0u8; 4096];
    let n = File::open(path)?.read(&mut buf)?;
    if n < SECTOR {
        return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
    }
    Ok(buf[..SECTOR].to_vec())
}

fn scan_devices(paths: &[PathBuf]) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut warned = false;
    for path in paths {
        match read_boot_sector(path) {
            Ok(sector) => {
                if let Some((severity, reason, detail)) = analyze(&sector) {
                    out.push(Finding {
                        scanner: SCANNER,
                        location: path.display().to_string(),
                        name: "Setor de boot (MBR)".into(),
                        target: detail,
                        severity,
                        reason,
                    });
                }
            }
            // Disco inexistente: não há o que verificar.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            // Qualquer outra falha (normalmente falta de permissão) avisa uma vez, em vez de silenciar.
            Err(_) if warned => {}
            Err(_) => {
                warned = true;
                out.push(Finding {
                    scanner: SCANNER,
                    location: path.display().to_string(),
                    name: "Setor de boot (MBR) NÃO verificado".into(),
                    target: String::new(),
                    severity: Severity::Info,
                    reason: "Sem acesso ao disco; rode como administrador (ou root) para verificá-lo",
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Setor válido: código inicial + tabela vazia + assinatura 55AA.
    fn sector(code: &[u8]) -> [u8; SECTOR] {
        let mut s = [0u8; SECTOR];
        s[..code.len()].copy_from_slice(code);
        s[510] = 0x55;
        s[511] = 0xAA;
        s
    }

    #[test]
    fn windows_and_grub_prologues_are_info() {
        for code in [
            WINDOWS_PROLOGUES[0],
            WINDOWS_PROLOGUES[1],
            GRUB_PROLOGUES[0],
        ] {
            assert_eq!(
                analyze(&sector(code)).unwrap().0,
                Severity::Info,
                "{code:02X?}"
            );
        }
    }

    #[test]
    fn unknown_boot_code_is_suspicious_and_shows_the_first_bytes() {
        let (sev, why, detail) = analyze(&sector(&[0xE9, 0x10, 0x20, 0xDE, 0xAD])).unwrap();
        assert_eq!(sev, Severity::Suspicious);
        assert!(
            why.contains("não reconhecido")
                && detail.starts_with("início do código: E9 10 20 DE AD")
        );
    }

    #[test]
    fn gpt_protective_mbr_with_odd_code_is_info_but_the_same_code_without_it_is_not() {
        let mut gpt = sector(&[0x00, 0x00, 0x00, 0x7C, 0xDE]);
        gpt[PARTITION_TABLE + 4] = 0xEE;
        let (sev, why, detail) = analyze(&gpt).unwrap();
        assert_eq!(sev, Severity::Info);
        assert!(why.contains("GPT") && why.contains("UEFI"));
        assert!(detail.contains("tipos de partição: EE 00 00 00") && detail.contains("de 440"));

        assert_eq!(
            analyze(&sector(&[0x00, 0x00, 0x00, 0x7C, 0xDE])).unwrap().0,
            Severity::Suspicious
        );
    }

    #[test]
    fn disk_signature_is_not_counted_as_boot_code() {
        // Caso real: disco GPT cujo único conteúdo não zero antes da tabela é a assinatura do disco.
        let mut s = sector(&[]);
        s[440..444].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        let (sev, why, detail) = analyze(&s).unwrap();
        assert_eq!(sev, Severity::Info);
        assert!(why.contains("Sem código de boot"), "{why}");
        assert!(detail.contains("bytes de código não zero: 0 de 440"));
    }

    #[test]
    fn empty_sector_and_gpt_without_boot_code_are_info() {
        assert_eq!(analyze(&[0u8; SECTOR]).unwrap().0, Severity::Info);
        assert_eq!(analyze(&sector(&[])).unwrap().0, Severity::Info);
    }

    #[test]
    fn missing_signature_is_suspicious() {
        let mut s = sector(WINDOWS_PROLOGUES[0]);
        s[511] = 0x00;
        assert!(analyze(&s).unwrap().1.contains("55AA"));
    }

    #[test]
    fn invalid_or_double_active_partition_table_is_suspicious() {
        let mut bad_flag = sector(WINDOWS_PROLOGUES[0]);
        bad_flag[PARTITION_TABLE] = 0x42;
        assert!(analyze(&bad_flag).unwrap().1.contains("inválida"));

        let mut two_active = sector(WINDOWS_PROLOGUES[0]);
        two_active[PARTITION_TABLE] = 0x80;
        two_active[PARTITION_TABLE + 16] = 0x80;
        assert!(
            analyze(&two_active).unwrap().1.contains("mais de uma")
                || analyze(&two_active).unwrap().1.contains("Mais de uma")
        );
    }

    #[test]
    fn one_active_partition_is_fine() {
        let mut s = sector(WINDOWS_PROLOGUES[0]);
        s[PARTITION_TABLE] = 0x80;
        assert_eq!(analyze(&s).unwrap().0, Severity::Info);
    }

    #[test]
    fn short_input_is_not_analyzed() {
        assert!(analyze(&[0x55, 0xAA]).is_none());
        assert!(analyze(&[]).is_none());
    }

    #[test]
    fn a_4096_byte_read_still_analyzes_only_the_first_512_bytes() {
        // Disco de setor 4K: a leitura precisa ser de 4096 bytes; o MBR é o início.
        let dir = std::env::temp_dir().join(format!("oblivion-mbr-4k-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let mut disk = vec![0xAAu8; 8192];
        disk[..SECTOR].copy_from_slice(&sector(WINDOWS_PROLOGUES[0]));
        let path = dir.join("disco4k");
        fs::write(&path, &disk).unwrap();
        let read = read_boot_sector(&path).unwrap();
        assert_eq!(read.len(), SECTOR);
        let found = scan_devices(&[path]);
        fs::remove_dir_all(&dir).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].severity, Severity::Info, "{found:?}");
    }

    #[test]
    fn scan_devices_reads_files_skips_missing_and_warns_once_on_failure() {
        let dir = std::env::temp_dir().join(format!("oblivion-mbr-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let good = dir.join("disk0");
        let short = dir.join("disk1");
        let short2 = dir.join("disk2");
        fs::write(&good, sector(&[0xE9, 1, 2])).unwrap();
        fs::write(&short, [1, 2, 3]).unwrap();
        fs::write(&short2, [4]).unwrap();

        let found = scan_devices(&[good, dir.join("nao-existe"), short, short2]);
        fs::remove_dir_all(&dir).unwrap();

        assert_eq!(found.len(), 2, "{found:?}");
        assert_eq!(found[0].severity, Severity::Suspicious);
        assert!(
            found[1].name.contains("NÃO verificado") && found[1].reason.contains("administrador")
        );
    }
}
