//! End-to-end test against a real kernel, driven through `cargo test`.
//!
//! The exporter runs unmodified in a throwaway user + network namespace, where
//! an unprivileged user holds `CAP_NET_ADMIN` over a network stack of its own:
//! real conntrack events over real netlink, decoded from the real UDP export.
//! See `tests/e2e/` for the harness.
//!
//! It is `#[ignore]`d because it takes about a minute and spawns namespaces,
//! which is more than `cargo test` should do on every inner-loop run:
//!
//!     cargo test -- --ignored          # run it
//!     ./tests/e2e/run-netns.sh         # one configuration, faster
//!     ./tests/e2e/run-netns.sh --all   # the same matrix, outside cargo
//!
//! On a host that cannot provide the namespaces — no unprivileged user
//! namespaces, or `nf_conntrack` not loaded — the harness exits 77 and this
//! skips rather than reporting a failure it cannot do anything about.

use std::path::PathBuf;
use std::process::Command;

/// The harness's "this host cannot run the test" exit code.
const SKIP: i32 = 77;

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
#[ignore = "spawns namespaces and takes about a minute; run with --ignored"]
fn every_configuration_exports_real_conntrack_nat_events() {
    let script = repository_root().join("tests/e2e/run-netns.sh");
    assert!(script.is_file(), "missing harness: {}", script.display());

    let output = Command::new("bash")
        .arg(&script)
        .arg("--all")
        // The binary cargo just built for this test run, rather than whatever
        // happens to be sitting in target/.
        .env("EXPORTER_BIN", env!("CARGO_BIN_EXE_conntrack_exporter"))
        .output()
        .expect("failed to run the end-to-end harness");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if output.status.code() == Some(SKIP) {
        eprintln!("skipping end-to-end test: {}", stderr.trim());
        return;
    }

    assert!(
        output.status.success(),
        "the end-to-end test failed\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );

    // Printed only for a failing run, but worth keeping accurate.
    eprintln!("{}", stdout.trim());
}
