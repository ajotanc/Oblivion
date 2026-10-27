//! Quarentena privada: só administradores/SYSTEM (Windows) ou o dono (Linux) leem e gravam.
//!
//! Por quê: a pasta guarda malware e um manifesto que o `undo` obedece como administrador. A pasta
//! padrão fica em `ProgramData`, onde usuários comuns conseguem CRIAR pastas e arquivos; se um deles
//! criasse a pasta antes, trocasse o manifesto ou colocasse uma junção (link de pasta), o administrador
//! acabaria gravando ou movendo arquivos para onde o atacante quisesse.
use std::{
    fs, io,
    path::{Path, PathBuf},
};

fn err(msg: impl Into<String>) -> io::Error {
    io::Error::other(msg.into())
}

/// Cria `dir` e as pastas acima que faltarem, todas privadas, e confere o resultado.
/// `dir` NÃO pode existir: se existir, devolve `AlreadyExists` (quem chama tenta outro nome).
pub fn create_private_dir(dir: &Path) -> io::Result<()> {
    let mut missing: Vec<PathBuf> = Vec::new();
    let mut cur = dir;
    while !cur.exists() {
        missing.push(cur.to_path_buf());
        match cur.parent() {
            Some(p) => cur = p,
            None => break,
        }
    }
    if !missing.iter().any(|p| p == dir) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "a pasta já existe",
        ));
    }
    for p in missing.iter().rev() {
        create_one(p)?;
        harden(p)?;
    }
    verify_private(dir)
}

#[cfg(unix)]
fn create_one(p: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(p)
}

#[cfg(not(unix))]
fn create_one(p: &Path) -> io::Result<()> {
    fs::create_dir(p)
}

/// No Linux o modo `0700` já vale na criação.
#[cfg(unix)]
fn harden(_: &Path) -> io::Result<()> {
    Ok(())
}

/// No Windows: dono vira Administradores e só Administradores e SYSTEM mantêm acesso (SIDs fixos,
/// que não dependem do idioma do sistema). Quem não for administrador falha aqui, e tudo bem:
/// a limpeza exige administrador.
#[cfg(windows)]
fn harden(p: &Path) -> io::Result<()> {
    use std::time::Duration;

    use crate::sys;
    let path = p.to_string_lossy().into_owned();
    let t = Duration::from_secs(30);
    sys::run("icacls", &[&path, "/setowner", "*S-1-5-32-544"], None, t).ok_or_else(|| {
        err(format!(
            "não consegui definir o dono de {path} (administrador?)"
        ))
    })?;
    sys::run(
        "icacls",
        &[
            &path,
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
        ],
        None,
        t,
    )
    .map(|_| ())
    .ok_or_else(|| err(format!("não consegui restringir o acesso a {path}")))
}

#[cfg(not(any(unix, windows)))]
fn harden(_: &Path) -> io::Result<()> {
    Ok(())
}

/// `p` está DENTRO de `dir` (depois de resolver `..` e links)? Falso se algum dos dois não existe.
pub(crate) fn is_inside(dir: &Path, p: &Path) -> bool {
    match (fs::canonicalize(dir), fs::canonicalize(p)) {
        (Ok(d), Ok(p)) => p.starts_with(d),
        _ => false,
    }
}

/// A pasta e a pasta pai não são links, pertencem a quem executa e ninguém mais pode gravar nelas.
pub fn verify_private(dir: &Path) -> io::Result<()> {
    let parent = dir
        .parent()
        .ok_or_else(|| err("a pasta não tem pasta pai"))?;
    verify_two(dir, parent)
}

#[cfg(unix)]
fn verify_two(dir: &Path, parent: &Path) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let me = fs::metadata("/proc/self")?.uid();
    for p in [dir, parent] {
        let m = fs::symlink_metadata(p)?;
        if m.file_type().is_symlink() || !m.is_dir() {
            return Err(err(format!(
                "{} não é uma pasta comum (é um link?)",
                p.display()
            )));
        }
        if m.uid() != me {
            return Err(err(format!("{} pertence a outro usuário", p.display())));
        }
        if m.mode() & 0o022 != 0 {
            return Err(err(format!("{} permite gravação por outros", p.display())));
        }
    }
    Ok(())
}

/// Mesma conferência no Windows, pelo dono e pela lista de permissões (por SID, sem depender de idioma).
/// 852310 = gravar dados, acrescentar, atributos estendidos, apagar itens, atributos, apagar, mudar
/// permissões e tomar posse.
#[cfg(windows)]
fn verify_two(dir: &Path, parent: &Path) -> io::Result<()> {
    use std::time::Duration;

    use crate::sys;
    const SCRIPT: &str = "$adm = @('S-1-5-18','S-1-5-32-544'); \
        $input | ForEach-Object { $p = $_; \
          $i = Get-Item -LiteralPath $p -Force; \
          if ($i.Attributes -band [IO.FileAttributes]::ReparsePoint) { \"ERRO: $p é um link (junção ou symlink)\"; return }; \
          $acl = Get-Acl -LiteralPath $p; \
          $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value; \
          if ($adm -notcontains $owner) { \"ERRO: $p pertence a outro usuário ($owner)\"; return }; \
          foreach ($a in $acl.Access) { \
            if ($a.AccessControlType -ne 'Allow') { continue }; \
            try { $sid = $a.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { $sid = $a.IdentityReference.Value }; \
            if (($adm -notcontains $sid) -and (([int]$a.FileSystemRights -band 852310) -ne 0)) { \"ERRO: $p dá permissão de escrita a $sid\"; return } }; \
          'OK' }";
    let input = format!("{}\n{}", dir.display(), parent.display());
    let out = sys::powershell(SCRIPT, Some(&input), Duration::from_secs(30))
        .ok_or_else(|| err("não consegui verificar as permissões da quarentena"))?;
    if let Some(line) = out.lines().map(str::trim).find(|l| l.starts_with("ERRO:")) {
        return Err(err(line.trim_start_matches("ERRO:").trim().to_string()));
    }
    if out.lines().filter(|l| l.trim() == "OK").count() != 2 {
        return Err(err("a verificação das permissões não terminou"));
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn verify_two(_: &Path, _: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("oblivion-secure-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[cfg(unix)]
    #[test]
    fn creates_private_dirs_with_mode_700_and_never_reuses_an_existing_one() {
        use std::os::unix::fs::PermissionsExt;
        let root = temp_root("ok");
        let dir = root.join("Quarentena").join("q1");
        create_private_dir(&dir).unwrap();
        for p in [&dir, dir.parent().unwrap(), &root] {
            assert_eq!(
                fs::metadata(p).unwrap().permissions().mode() & 0o777,
                0o700,
                "{}",
                p.display()
            );
        }
        let again = create_private_dir(&dir).unwrap_err();
        assert_eq!(again.kind(), io::ErrorKind::AlreadyExists);
        fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_folders_others_can_write_and_symlinks() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let root = temp_root("bad");
        fs::create_dir_all(&root).unwrap();
        let open = root.join("aberta");
        fs::create_dir_all(open.join("q")).unwrap();
        fs::set_permissions(&open, fs::Permissions::from_mode(0o777)).unwrap();
        let e = verify_private(&open.join("q")).unwrap_err().to_string();
        assert!(e.contains("gravação por outros"), "{e}");

        let real = root.join("real");
        fs::create_dir_all(&real).unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
        symlink(&real, root.join("elo")).unwrap();
        let e = verify_private(&root.join("elo")).unwrap_err().to_string();
        assert!(e.contains("link"), "{e}");
        fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn a_normal_user_folder_is_not_private_and_cannot_be_hardened_without_admin() {
        // A pasta temporária do usuário dá escrita a ele (e, para o processo comum, a ninguém mais é
        // administrador): nunca passa como privada.
        let root = temp_root("win");
        let dir = root.join("q1");
        fs::create_dir_all(&dir).unwrap();
        assert!(verify_private(&dir).is_err());
        fs::remove_dir_all(&root).unwrap();
        if !crate::privilege::is_elevated() {
            assert!(
                create_private_dir(&temp_root("win2").join("q1")).is_err(),
                "sem administrador não cria"
            );
            let _ = fs::remove_dir_all(temp_root("win2"));
        }
    }
}
