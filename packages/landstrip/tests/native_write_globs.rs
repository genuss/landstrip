#![cfg(target_os = "macos")]

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> io::Result<Self> {
        let directory = std::env::temp_dir().join(format!(
            "landstrip-native-globs-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory)?;
        Ok(Self(directory))
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn checked(command: &mut Command) -> io::Result<Output> {
    let output = command.output()?;
    assert!(
        output.status.success(),
        "{command:?}: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output)
}

fn isolate_git(command: &mut Command) {
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("GIT_") {
            command.env_remove(key);
        }
    }
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0");
}

fn git_command(cwd: &Path) -> Command {
    let mut command = Command::new("git");
    isolate_git(&mut command);
    command.current_dir(cwd).args([
        "-c",
        "user.name=Landstrip Test",
        "-c",
        "user.email=landstrip-test@example.invalid",
        "-c",
        "commit.gpgSign=false",
        "-c",
        "core.hooksPath=/dev/null",
    ]);
    command
}

fn sandbox_command(cwd: &Path, policy: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_landstrip"));
    isolate_git(&mut command);
    command
        .current_dir(cwd)
        .args(["run", "-p"])
        .arg(policy)
        .arg("--");
    command
}

#[test]
fn write_glob_resolution_does_not_traverse_the_project_tree() -> io::Result<()> {
    let directory = TestDirectory::new()?;
    let projects = directory.0.join("projects");
    fs::create_dir_all(projects.join("main/.git"))?;
    let mut deep = projects.join("noise");
    for _ in 0..45 {
        deep.push("d");
    }
    fs::create_dir_all(deep)?;
    let policy = directory.0.join("policy.json");
    fs::write(
        &policy,
        serde_json::json!({
            "filesystem": { "allowWrite": [format!("{}/**/.git", projects.display())] }
        })
        .to_string(),
    )?;
    let output = checked(
        Command::new(env!("CARGO_BIN_EXE_landstrip"))
            .args(["policy", "resolve", "-p"])
            .arg(&policy),
    )?;
    let resolved: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(resolved["writeRoots"], serde_json::json!([]));
    assert_eq!(resolved["writeAllowedPatterns"][0]["glob"], "**/.git");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("main/.git"));
    checked(
        Command::new(env!("CARGO_BIN_EXE_landstrip"))
            .args(["policy", "validate", "-p"])
            .arg(&policy),
    )?;
    Ok(())
}

#[test]
fn native_write_globs_escape_literals_without_broadening_permissions() -> io::Result<()> {
    for (glob, name) in [
        (r#"**/repo"quoted"#, r#"repo"quoted"#),
        (r"**/repo\backslash", r"repo\backslash"),
        ("**/repo]", "repo]"),
        ("**/repo[", "repo["),
        ("**/repo[-]", "repo-"),
        (r"**/repo[\]", r"repo\"),
        ("**/repo[.]", "repo."),
        ("**/repoé", "repoé"),
        (
            r#"**/repo") (allow default) ("#,
            r#"repo") (allow default) ("#,
        ),
    ] {
        let directory = TestDirectory::new()?;
        let projects = directory.0.join("projects");
        let matched = projects.join(name);
        fs::create_dir_all(&matched)?;
        let policy = directory.0.join("policy.json");
        fs::write(
            &policy,
            serde_json::json!({
                "filesystem": { "allowWrite": [format!("{}/{glob}", projects.display())] }
            })
            .to_string(),
        )?;
        checked(
            sandbox_command(&directory.0, &policy)
                .arg("/usr/bin/touch")
                .arg(matched.join("allowed")),
        )?;
        let blocked = projects.join("blocked");
        let output = sandbox_command(&directory.0, &policy)
            .args(["/bin/sh", "-c", "printf sandbox-ready; touch \"$1\"", "_"])
            .arg(&blocked)
            .output()?;
        assert_eq!(output.stdout, b"sandbox-ready", "{glob}");
        assert!(!output.status.success(), "{glob}");
        assert!(!blocked.exists(), "{glob}");
    }
    Ok(())
}

#[test]
fn linked_worktree_can_commit_without_writing_other_working_trees() -> io::Result<()> {
    let directory = TestDirectory::new()?;
    let projects = directory.0.join("projects");
    let main = projects.join("main");
    let worktree = directory.0.join("worktree");
    let template = directory.0.join("empty-template");
    fs::create_dir_all(&main)?;
    fs::create_dir(&template)?;
    checked(
        git_command(&main)
            .args(["init", "--initial-branch=main", "--template"])
            .arg(&template),
    )?;
    fs::write(main.join("tracked.txt"), "initial\n")?;
    checked(git_command(&main).args(["add", "tracked.txt"]))?;
    checked(git_command(&main).args(["commit", "-m", "initial"]))?;
    checked(
        git_command(&main)
            .args(["worktree", "add", "-b", "test"])
            .arg(&worktree),
    )?;
    let policy = directory.0.join("policy.json");
    fs::write(
        &policy,
        serde_json::json!({
            "filesystem": {
                "allowWrite": [".", format!("{}/**/.git", projects.display()), "/dev/null"]
            }
        })
        .to_string(),
    )?;
    fs::write(worktree.join("tracked.txt"), "updated\n")?;
    for args in [
        vec!["add", "tracked.txt"],
        vec!["commit", "-m", "sandbox commit"],
    ] {
        let mut git = git_command(&worktree);
        git.args(args);
        checked(
            sandbox_command(&worktree, &policy)
                .arg("git")
                .args(git.get_args()),
        )?;
    }
    let committed = checked(git_command(&worktree).args(["show", "HEAD:tracked.txt"]))?;
    assert_eq!(committed.stdout, b"updated\n");
    assert_eq!(fs::read(main.join("tracked.txt"))?, b"initial\n");

    let blocked = main.join("blocked.txt");
    let output = sandbox_command(&worktree, &policy)
        .args([
            "/bin/sh",
            "-c",
            "printf sandbox-ready; printf blocked > \"$1\"",
            "_",
        ])
        .arg(&blocked)
        .output()?;
    assert_eq!(output.stdout, b"sandbox-ready");
    assert!(!output.status.success());
    assert!(!blocked.exists());
    Ok(())
}
