use std::{
    io::{Read, Write},
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::Duration,
};

/// `Command` que não abre janela de console: sem isso, cada chamada pisca uma janela quando o programa é a interface.
pub(crate) fn command(program: impl AsRef<std::ffi::OsStr>) -> Command {
    #[allow(unused_mut)]
    let mut cmd = Command::new(program);
    #[cfg(windows)]
    std::os::windows::process::CommandExt::creation_flags(&mut cmd, 0x0800_0000); // CREATE_NO_WINDOW
    cmd
}

/// Roda um programa externo e devolve o que ele escreveu na saída padrão.
/// Devolve `None` se não iniciar, passar do tempo-limite (e o processo é encerrado) ou terminar com
/// código de saída diferente de zero: um scanner nunca pode travar por causa de um comando do sistema,
/// e uma falha não pode parecer "saída vazia = tudo limpo".
pub(crate) fn run(
    program: &str,
    args: &[&str],
    input: Option<&str>,
    timeout: Duration,
) -> Option<String> {
    let mut child = command(program)
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    if let (Some(text), Some(mut stdin)) = (input, child.stdin.take()) {
        // shortcut: entrada pequena (lista de caminhos); com entrada grande a escrita poderia bloquear.
        let _ = stdin.write_all(text.as_bytes());
    }
    let mut stdout = child.stdout.take()?;
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        let _ = tx.send(buf);
    });
    match rx.recv_timeout(timeout) {
        Ok(buf) => {
            let status = child.wait().ok()?;
            status
                .success()
                .then(|| String::from_utf8_lossy(&buf).into_owned())
        }
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait(); // evita processo zumbi no Linux
            None
        }
    }
}

/// Roda um script PowerShell trocando a codificação da saída para UTF-8.
/// Sem isso o PowerShell usa a página de código do console (ex.: 850) e acentos viram `�`.
/// A entrada vai em hexadecimal (ASCII puro) e é decodificada como UTF-8 dentro do PowerShell: mudar
/// `[Console]::InputEncoding` no script não vale para a entrada redirecionada, que já foi aberta com a
/// página de código do console. O script enxerga as linhas em `$input`, como antes.
/// O `exit 0` no fim separa erro não fatal (ex.: um arquivo que não existe, o script segue) de falha
/// real (erro de sintaxe ou erro fatal: o `exit 0` não é alcançado e o código de saída é 1).
#[cfg(windows)]
pub(crate) fn powershell(script: &str, input: Option<&str>, timeout: Duration) -> Option<String> {
    let out_enc = "[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false);";
    let full = if input.is_some() {
        format!(
            "{out_enc} $hex = [Console]::In.ReadToEnd().Trim(); \
             $bytes = [byte[]]::new($hex.Length / 2); \
             for ($i = 0; $i -lt $bytes.Length; $i++) {{ $bytes[$i] = [Convert]::ToByte($hex.Substring(2 * $i, 2), 16) }}; \
             [Text.Encoding]::UTF8.GetString($bytes) -split \"`r?`n\" | & {{\n{script}\n}}\nexit 0"
        )
    } else {
        format!("{out_enc} {script}\nexit 0")
    };
    let hex = input.map(|t| t.bytes().map(|b| format!("{b:02x}")).collect::<String>());
    run(
        "powershell",
        &["-NoProfile", "-Command", &full],
        hex.as_deref(),
        timeout,
    )
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn nonzero_exit_code_is_a_failure_not_an_empty_answer() {
        // O caso da auditoria: comando que falha e não escreve nada.
        assert!(run("cmd", &["/c", "exit 3"], None, Duration::from_secs(10)).is_none());
        assert_eq!(
            run("cmd", &["/c", "exit 0"], None, Duration::from_secs(10)).as_deref(),
            Some("")
        );
    }

    #[test]
    fn powershell_syntax_or_fatal_errors_are_failures() {
        assert!(powershell("if (", None, Duration::from_secs(20)).is_none());
        assert!(powershell("throw 'x'", None, Duration::from_secs(20)).is_none());
    }

    #[test]
    fn powershell_non_fatal_errors_do_not_hide_the_output() {
        let out = powershell(
            "Get-Item 'C:\\oblivion-nao-existe-xyz' -ErrorAction SilentlyContinue; 'resto'",
            None,
            Duration::from_secs(20),
        );
        assert_eq!(out.as_deref().map(str::trim), Some("resto"));
        let noisy = powershell(
            "Get-Item 'C:\\oblivion-nao-existe-xyz'; 'resto'",
            None,
            Duration::from_secs(20),
        );
        assert_eq!(
            noisy.as_deref().map(str::trim),
            Some("resto"),
            "erro não fatal não derruba o resultado"
        );
    }

    #[test]
    fn powershell_output_keeps_accents() {
        let out = powershell("'ação é ü'", None, Duration::from_secs(20)).unwrap();
        assert_eq!(out.trim(), "ação é ü");
    }

    #[test]
    fn powershell_input_keeps_accents() {
        let out = powershell("$input", Some("C:\\José\\ç.exe"), Duration::from_secs(20)).unwrap();
        assert_eq!(out.trim(), "C:\\José\\ç.exe");
    }

    #[test]
    fn powershell_input_arrives_as_one_item_per_line() {
        let out = powershell(
            "$input | ForEach-Object { \"[$_]\" }",
            Some(
                "a ç
b",
            ),
            Duration::from_secs(20),
        )
        .unwrap();
        assert_eq!(
            out.lines().map(str::trim).collect::<Vec<_>>(),
            ["[a ç]", "[b]"]
        );
    }

    #[test]
    fn returns_output() {
        let out = run("cmd", &["/c", "echo", "oi"], None, Duration::from_secs(10)).unwrap();
        assert!(out.contains("oi"));
    }

    #[test]
    fn passes_stdin() {
        let out = run(
            "findstr",
            &["abc"],
            Some("abc\nxyz\n"),
            Duration::from_secs(10),
        )
        .unwrap();
        assert!(out.contains("abc") && !out.contains("xyz"));
    }

    #[test]
    fn times_out_and_returns_none() {
        assert!(
            run(
                "cmd",
                &["/c", "ping -n 6 127.0.0.1 >nul"],
                None,
                Duration::from_millis(300)
            )
            .is_none()
        );
    }

    #[test]
    fn missing_program_returns_none() {
        assert!(
            run(
                "programa-que-nao-existe-oblivion",
                &[],
                None,
                Duration::from_secs(2)
            )
            .is_none()
        );
    }
}
