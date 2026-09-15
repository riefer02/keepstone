//! Developer task runner: `cargo xtask <task>`.
//!
//! Tasks: `fmt`, `fmt-check`, `clippy`, `test`, `ci`, `demo`.
#![allow(
    clippy::print_stdout,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::thread;
use std::time::Duration;

fn run(args: &[&str]) -> bool {
    println!("$ cargo {}", args.join(" "));
    Command::new("cargo")
        .args(args)
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn bin_path() -> PathBuf {
    let mut path = std::env::current_dir().expect("cwd");
    path.push("target");
    path.push("debug");
    path.push("keepstone");
    path
}

/// Run the reference client against `data_dir`, returning its stdout.
fn client(bin: &Path, data_dir: &Path, args: &[&str]) -> String {
    let output = Command::new(bin)
        .arg("--data-dir")
        .arg(data_dir)
        .args(args)
        .output()
        .expect("run keepstone");
    if !output.status.success() {
        eprintln!(
            "keepstone {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn field(output: &str, label: &str) -> Option<String> {
    output
        .lines()
        .find_map(|line| line.trim().strip_prefix(label))
        .map(|value| value.trim().to_owned())
}

fn serve_in_background(bin: &Path, data_dir: &Path, listen: &str) -> Child {
    Command::new(bin)
        .arg("--data-dir")
        .arg(data_dir)
        .args(["serve", "--listen", listen])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn relay")
}

fn demo() -> bool {
    println!("=== Keepstone end-to-end demo ===\n");
    if !run(&["build", "-p", "keepstone-cli"]) {
        return false;
    }
    let bin = bin_path();
    let root = std::env::temp_dir().join(format!("keepstone-demo-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let alice = root.join("alice");
    let bob = root.join("bob");
    let relay = root.join("relay");
    for dir in [&alice, &bob, &relay] {
        fs::create_dir_all(dir).expect("create data dir");
    }

    client(&bin, &alice, &["keygen"]);
    client(&bin, &bob, &["keygen"]);
    client(&bin, &relay, &["keygen"]);
    println!("[1/6] generated identities for alice, bob, and a relay");

    let bob_id = client(&bin, &bob, &["id"]);
    let bob_signing = field(&bob_id, "signing:").expect("bob signing");
    let bob_ecdh = field(&bob_id, "ecdh:").expect("bob ecdh");
    let bob_hybrid = field(&bob_id, "hybrid:").expect("bob hybrid");
    client(
        &bin,
        &alice,
        &["contact-add", "bob", &bob_signing, &bob_ecdh, &bob_hybrid],
    );
    println!("[2/6] alice added bob (out-of-band key exchange)");

    let created = client(
        &bin,
        &alice,
        &[
            "drop-create",
            "--to",
            "bob",
            "--suite",
            "hybrid",
            "--lat",
            "51.5007",
            "--lng",
            "-0.1246",
            "--message",
            "meet at the old oak at dusk",
        ],
    );
    let id = field(&created, "id:").expect("drop id");
    println!("[3/6] alice created a post-quantum drop {id}");

    let mut relay_child = serve_in_background(&bin, &relay, "127.0.0.1:7799");
    thread::sleep(Duration::from_millis(800));
    client(&bin, &alice, &["push", "127.0.0.1:7799", &id]);
    println!("[4/6] alice pushed ciphertext to the relay (relay holds no keys)");

    let fetched = client(&bin, &bob, &["fetch", "127.0.0.1:7799", &id]);
    print!("{fetched}");
    println!("[5/6] bob fetched the envelope and chunks from the relay");

    let opened = client(&bin, &bob, &["drop-open", &id]);
    let verify = client(&bin, &bob, &["log-verify", &id]);
    println!("[6/6] bob opened the drop: {}", opened.trim());
    for line in verify.lines().take(2) {
        println!("      {line}");
    }
    let _ = relay_child.kill();
    let _ = relay_child.wait();

    let ok = opened.contains("meet at the old oak at dusk")
        && verify.contains("signature:   ok")
        && verify.contains("inclusion:   ok");
    println!("\nresult: {}", if ok { "PASS" } else { "FAIL" });
    let _ = fs::remove_dir_all(&root);
    ok
}

fn main() -> ExitCode {
    let task = std::env::args().nth(1).unwrap_or_else(|| "help".to_owned());

    let commands: Vec<Vec<&str>> = match task.as_str() {
        "fmt" => vec![vec!["fmt", "--all"]],
        "fmt-check" => vec![vec!["fmt", "--all", "--", "--check"]],
        "clippy" => vec![vec![
            "clippy",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ]],
        "test" => vec![vec!["test", "--workspace"]],
        "deny" => vec![vec!["deny", "check"]],
        "ci" => vec![
            vec!["fmt", "--all", "--", "--check"],
            vec![
                "clippy",
                "--workspace",
                "--all-targets",
                "--",
                "-D",
                "warnings",
            ],
            vec!["test", "--workspace"],
        ],
        "demo" => {
            return if demo() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            };
        }
        _ => {
            println!("tasks: fmt | fmt-check | clippy | test | ci | demo | deny");
            return ExitCode::SUCCESS;
        }
    };

    for command in &commands {
        if !run(command) {
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}
