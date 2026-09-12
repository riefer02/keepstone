//! Developer task runner: `cargo xtask <task>`.
//!
//! Tasks: `fmt`, `fmt-check`, `clippy`, `test`, `ci`.
#![allow(clippy::print_stdout, clippy::unwrap_used, clippy::expect_used)]

use std::process::{Command, ExitCode};

fn run(args: &[&str]) -> bool {
    println!("$ cargo {}", args.join(" "));
    Command::new("cargo")
        .args(args)
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
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
        _ => {
            println!("tasks: fmt | fmt-check | clippy | test | ci");
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
