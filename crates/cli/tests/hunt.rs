//! Integration tests for the CLI and the hunt (pilot) flow.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_keepstone")
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("keepstone-cli-test-{}-{tag}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(data_dir: &Path, args: &[&str]) -> String {
    let output = Command::new(bin())
        .arg("--data-dir")
        .arg(data_dir)
        .args(args)
        .output()
        .expect("run keepstone");
    assert!(
        output.status.success(),
        "keepstone {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn field(output: &str, label: &str) -> String {
    output
        .lines()
        .find_map(|line| line.trim().strip_prefix(label))
        .unwrap_or_else(|| panic!("missing {label} in:\n{output}"))
        .trim()
        .to_owned()
}

/// `(signing, ecdh, hybrid)` for a data dir that has run `keygen`.
fn keys(data_dir: &Path) -> (String, String, String) {
    let id = run(data_dir, &["id"]);
    (
        field(&id, "signing:"),
        field(&id, "ecdh:"),
        field(&id, "hybrid:"),
    )
}

fn add_contact(organizer: &Path, name: &str, keys: &(String, String, String)) {
    run(organizer, &["contact-add", name, &keys.0, &keys.1, &keys.2]);
}

fn extract_id(line_with_id: &str) -> Option<String> {
    let start = line_with_id.find("id=")? + 3;
    let rest = &line_with_id[start..];
    let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
    Some(rest[..end].to_owned())
}

#[test]
fn hunt_pilot_flow() {
    let root = temp_dir("hunt");
    let org = root.join("organizer");
    let alice = root.join("alice");
    let bob = root.join("bob");
    for dir in [&org, &alice, &bob] {
        fs::create_dir_all(dir).unwrap();
        run(dir, &["keygen"]);
    }
    add_contact(&org, "alice", &keys(&alice));
    add_contact(&org, "bob", &keys(&bob));

    run(&org, &["hunt", "create", "demo"]);
    run(&org, &["hunt", "add-participant", "demo", "alice"]);
    run(&org, &["hunt", "add-participant", "demo", "bob"]);
    run(
        &org,
        &[
            "hunt",
            "add-drop",
            "demo",
            "--lat",
            "51.5007",
            "--lng",
            "-0.1246",
            "--suite",
            "hybrid",
            "Find the lion statue",
        ],
    );
    run(&org, &["hunt", "seed", "demo"]);

    let shown = run(&org, &["hunt", "show", "demo"]);
    let id_line = shown.lines().find(|l| l.contains("id=")).unwrap();
    let id = extract_id(id_line).expect("drop id");

    // The MAP renders and the standalone verifier accepts the drop file.
    let map = root.join("map.html");
    run(
        &org,
        &["hunt", "map", "demo", "--out", map.to_str().unwrap()],
    );
    assert!(fs::read_to_string(&map).unwrap().contains("Hunt: demo"));

    let drop_file = org.join("drops").join(format!("{id}.signed"));
    let verified = run(&org, &["verify", drop_file.to_str().unwrap()]);
    assert!(verified.contains("signature:  ok"));
    assert!(verified.contains("hybrid (Ed25519 + ML-DSA-65)"));
    assert!(verified.contains("pow:        ok"));

    // Both participants can open the drop once they have the ciphertext.
    for participant in [&alice, &bob] {
        for sub in ["drops", "chunks"] {
            let source = org.join(sub);
            let target = participant.join(sub);
            fs::create_dir_all(&target).unwrap();
            for entry in fs::read_dir(&source).unwrap().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let dest = target.join(path.file_name().unwrap());
                    fs::create_dir_all(&dest).unwrap();
                    for chunk in fs::read_dir(&path).unwrap().flatten() {
                        fs::copy(chunk.path(), dest.join(chunk.file_name())).unwrap();
                    }
                } else {
                    fs::copy(&path, target.join(path.file_name().unwrap())).unwrap();
                }
            }
        }
        let opened = run(participant, &["drop-open", &id]);
        assert_eq!(opened.trim(), "Find the lion statue");
    }

    // A third party is refused.
    let carol = root.join("carol");
    fs::create_dir_all(&carol).unwrap();
    run(&carol, &["keygen"]);
    for sub in ["drops", "chunks"] {
        let target = carol.join(sub);
        fs::create_dir_all(&target).unwrap();
        for entry in fs::read_dir(org.join(sub)).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                let dest = target.join(path.file_name().unwrap());
                fs::create_dir_all(&dest).unwrap();
                for chunk in fs::read_dir(&path).unwrap().flatten() {
                    fs::copy(chunk.path(), dest.join(chunk.file_name())).unwrap();
                }
            } else {
                fs::copy(&path, target.join(path.file_name().unwrap())).unwrap();
            }
        }
    }
    let output = Command::new(bin())
        .arg("--data-dir")
        .arg(&carol)
        .args(["drop-open", &id])
        .output()
        .unwrap();
    assert!(!output.status.success());

    let _ = fs::remove_dir_all(&root);
}
