//! Privilégios do processo: o Oblivion funciona sem elevação, mas com cobertura reduzida.
//! Tarefas agendadas, setor de boot (MBR) e ponto de restauração exigem administrador (Windows);
//! crontabs de usuários e o MBR exigem root (Linux).

/// Verdadeiro se roda como administrador (Windows) ou root (Linux).
#[cfg(windows)]
pub fn is_elevated() -> bool {
    // shortcut: usa a abertura do disco cru como teste (é o que o MBR precisa) em vez de ler o token
    // de elevação, que exigiria `unsafe`; se um dia precisar do token exato, usar a API do Windows.
    std::fs::File::open(r"\\.\PhysicalDrive0").is_ok()
}

#[cfg(unix)]
pub fn is_elevated() -> bool {
    use std::os::unix::fs::MetadataExt;
    // O dono de /proc/self é o usuário do processo; evita `unsafe` e a dependência de libc.
    std::fs::metadata("/proc/self").is_ok_and(|m| m.uid() == 0)
}

#[cfg(not(any(windows, unix)))]
pub fn is_elevated() -> bool {
    false
}

/// Aviso mostrado quando o programa roda sem privilégios elevados.
pub fn alert() -> &'static str {
    if cfg!(windows) {
        "ATENÇÃO: o Oblivion está rodando SEM privilégios de administrador, então o resultado ficará \
         incompleto: tarefas agendadas, setor de boot (MBR) e ponto de restauração exigem administrador. \
         Para a funcionalidade total, feche e abra o terminal com \"Executar como administrador\"."
    } else {
        "ATENÇÃO: o Oblivion está rodando SEM root, então o resultado ficará incompleto: crontabs de \
         usuários, setor de boot (MBR) e detalhes de rede de outros usuários exigem root. \
         Para a funcionalidade total, rode com sudo (por exemplo: sudo oblivion scan)."
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alert_names_the_right_elevation_for_the_platform() {
        let a = alert();
        assert!(a.starts_with("ATENÇÃO") && a.contains("incompleto") && a.contains("MBR"));
        if cfg!(windows) {
            assert!(a.contains("administrador") && !a.contains("sudo"));
        } else {
            assert!(a.contains("sudo") && !a.contains("administrador"));
        }
    }

    #[test]
    fn detection_does_not_panic_and_is_stable() {
        assert_eq!(is_elevated(), is_elevated());
    }
}
