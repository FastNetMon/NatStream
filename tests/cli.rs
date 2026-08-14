//! Integration tests that drive the real binary.
//!
//! These cover the configuration checks the exporter makes before it touches
//! anything on the system, so they need no privileges: a bad flag has to be
//! reported as a bad flag rather than as whatever fails next.

use std::io::Read;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const EXPORTER: &str = env!("CARGO_BIN_EXE_conntrack_exporter");

/// A run that is expected to exit on its own. The deadline is a backstop: a
/// configuration that was supposed to be refused would otherwise sit in the
/// event loop and hang the test run.
fn run(args: &[&str]) -> Output {
    let mut child = Command::new(EXPORTER)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn the exporter");

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match child.try_wait().expect("failed to wait for the exporter") {
            Some(status) => {
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                child.stdout.take().unwrap().read_to_end(&mut stdout).ok();
                child.stderr.take().unwrap().read_to_end(&mut stderr).ok();
                return Output {
                    status,
                    stdout,
                    stderr,
                };
            }
            None if Instant::now() >= deadline => {
                child.kill().ok();
                child.wait().ok();
                panic!("the exporter did not exit within 10s for args {args:?}");
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    }
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Run with a configuration that is invalid, and return what the operator sees.
fn expect_refused(args: &[&str]) -> String {
    let output = run(args);
    assert!(
        !output.status.success(),
        "{args:?} was accepted; stderr: {}",
        stderr_of(&output)
    );
    stderr_of(&output)
}

// ---- Configuration the exporter refuses ----

#[test]
fn a_counter_width_other_than_four_or_eight_is_refused() {
    for width in ["0", "1", "2", "3", "5", "6", "7", "9", "16", "255"] {
        let stderr = expect_refused(&["-c", "127.0.0.1:4739", "--counter-width", width]);
        assert!(
            stderr.contains("counter width must be 4 or 8"),
            "width {width} was refused unhelpfully: {stderr}"
        );
    }
}

/// Template IDs below 256 collide with the set / FlowSet identifiers.
#[test]
fn a_template_id_below_the_reserved_range_is_refused() {
    for id in ["0", "1", "2", "255"] {
        let stderr = expect_refused(&["-c", "127.0.0.1:4739", "--template-id", id]);
        assert!(
            stderr.contains("template ID must be at least 256"),
            "template id {id} was refused unhelpfully: {stderr}"
        );
    }
}

/// A zero interval would retransmit the template on every pass of the loop.
#[test]
fn a_zero_template_interval_is_refused() {
    let stderr = expect_refused(&["-c", "127.0.0.1:4739", "--template-interval", "0"]);
    assert!(
        stderr.contains("--template-interval must be at least 1 second"),
        "unhelpful error: {stderr}"
    );
}

#[test]
fn the_collector_is_required() {
    let stderr = expect_refused(&[]);
    assert!(
        stderr.contains("--collector"),
        "the missing flag should be named: {stderr}"
    );
}

#[test]
fn a_collector_without_a_port_is_refused() {
    let stderr = expect_refused(&["--collector", "203.0.113.10"]);
    assert!(
        stderr.contains("collector"),
        "the bad flag should be named: {stderr}"
    );
}

#[test]
fn an_unsupported_protocol_is_refused() {
    let stderr = expect_refused(&["-c", "127.0.0.1:4739", "--protocol", "netflow5"]);
    assert!(
        stderr.contains("netflow9") && stderr.contains("ipfix"),
        "the supported values should be listed: {stderr}"
    );
}

#[test]
fn an_unknown_flag_is_refused() {
    let stderr = expect_refused(&["-c", "127.0.0.1:4739", "--collect-everything"]);
    assert!(stderr.contains("--collect-everything"), "{stderr}");
}

/// The configuration is validated before the exporter touches the sysctls or
/// opens a socket, so a bad flag is reported as a bad flag. If this regressed,
/// the message below would be about permissions instead.
#[test]
fn configuration_is_validated_before_the_system_is_touched() {
    let stderr = expect_refused(&[
        "-c",
        "127.0.0.1:4739",
        "--counter-width",
        "5",
        // Both of these would fail first if the order were wrong.
        "--recv-buf",
        "999999999999",
    ]);

    assert!(stderr.contains("counter width must be 4 or 8"), "{stderr}");
    assert!(
        !stderr.contains("sysctl") && !stderr.contains("netlink"),
        "the system was touched before the flags were checked: {stderr}"
    );
}

// ---- Usage output ----

#[test]
fn help_lists_every_documented_option() {
    let output = run(&["--help"]);
    assert!(output.status.success(), "{}", stderr_of(&output));
    let help = stdout_of(&output);

    for flag in [
        "--collector",
        "--protocol",
        "--profile",
        "--counter-width",
        "--template-id",
        "--template-interval",
        "--domain-id",
        "--recv-buf",
        "--send-buf",
        "--verbose",
        "--daemon",
        "--log-file",
        "--no-sysctl",
    ] {
        assert!(help.contains(flag), "{flag} is missing from --help:\n{help}");
    }
}

#[test]
fn version_reports_the_crate_version() {
    let output = run(&["--version"]);
    assert!(output.status.success(), "{}", stderr_of(&output));
    assert!(
        stdout_of(&output).contains(env!("CARGO_PKG_VERSION")),
        "{}",
        stdout_of(&output)
    );
}

// ---- Startup without privileges ----

/// Joining the conntrack netlink group needs `CAP_NET_ADMIN`, as does setting
/// the sysctls. Without them the exporter must fail loudly at startup instead
/// of sitting in its event loop reporting nothing, which is indistinguishable
/// from a quiet network.
#[test]
fn a_run_without_the_needed_privileges_fails_loudly() {
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipping: running as root, which has the privileges this checks for");
        return;
    }

    let stderr = expect_refused(&["-c", "127.0.0.1:4739"]);

    // Which one comes first depends on whether the sysctls are already set on
    // the host, so accept either — the point is that it stops and says why.
    assert!(
        stderr.contains("conntrack event delivery") || stderr.contains("netlink"),
        "the failure should name what it could not do: {stderr}"
    );
}

/// `--no-sysctl` exists for hosts where the sysctls are already configured, but
/// it must not paper over the missing capability the netlink socket needs.
#[test]
fn no_sysctl_does_not_silence_a_missing_capability() {
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipping: running as root, which has the privileges this checks for");
        return;
    }

    let stderr = expect_refused(&["-c", "127.0.0.1:4739", "--no-sysctl"]);
    assert!(
        stderr.contains("netlink"),
        "the netlink failure should be reported: {stderr}"
    );
}
