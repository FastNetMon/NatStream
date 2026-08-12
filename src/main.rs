mod event;
mod ipfix;
mod netlink;
mod signals;

use std::io;
use std::ffi::CString;
use std::fs;
use std::net::{SocketAddr, UdpSocket};
use std::thread;
use std::time::Instant;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use log::{debug, error, info, warn};

use ipfix::IpfixEncoder;
use netlink::constants::{DEFAULT_RECV_BUF_SIZE, DEFAULT_SEND_BUF_SIZE};
use netlink::{parse_conntrack_messages, NetlinkSocket};
use signals::SignalFd;

/// How long the supervisor waits for the worker to exit on its own after
/// SIGTERM before escalating to SIGKILL.
const WORKER_STOP_GRACE: Duration = Duration::from_secs(10);

#[derive(Parser, Debug)]
#[command(name = "conntrack_exporter", about = "Conntrack NAT event IPFIX exporter")]
struct Args {
    /// IPFIX collector address (host:port)
    #[arg(short, long, default_value = "10.168.120.66:4739")]
    collector: SocketAddr,

    /// Netlink receive buffer size in bytes
    #[arg(long, default_value_t = DEFAULT_RECV_BUF_SIZE)]
    recv_buf: usize,

    /// UDP send buffer size in bytes
    #[arg(long, default_value_t = DEFAULT_SEND_BUF_SIZE)]
    send_buf: usize,

    /// IPFIX observation domain ID
    #[arg(long, default_value_t = 0)]
    domain_id: u32,

    /// Enable verbose (debug) logging
    #[arg(short, long)]
    verbose: bool,

    /// Run as a background daemon with self-supervision
    #[arg(long)]
    daemon: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Init logger
    let log_level = if args.verbose { "debug" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level))
        .format_timestamp_millis()
        .init();

    if args.daemon {
        return run_supervisor(&args);
    }

    run_worker(&args)
}

fn run_worker(args: &Args) -> Result<()> {
    info!("Starting conntrack_exporter worker, collector={}", args.collector);
    apply_conntrack_sysctl_settings()?;

    // Consume shutdown signals through a descriptor so they are observed by the
    // same poll() that waits for netlink data, with no EINTR races.
    let signals = SignalFd::new(&[libc::SIGTERM, libc::SIGINT])
        .context("Failed to set up signal handling")?;

    // Create UDP socket for IPFIX export
    let udp_socket = UdpSocket::bind("0.0.0.0:0").context("Failed to bind UDP socket")?;
    udp_socket
        .connect(args.collector)
        .context("Failed to connect UDP socket to collector")?;

    // Set UDP send buffer
    set_send_buf(&udp_socket, args.send_buf);

    // Create netlink socket
    let nl_socket =
        NetlinkSocket::open(args.recv_buf).context("Failed to open netlink socket")?;

    // Create IPFIX encoder
    let mut encoder = IpfixEncoder::new(args.domain_id);

    // Send initial template
    let mut include_template = true;
    let mut last_template_time = Instant::now();
    let mut message_active = false;

    // Flush timeout: if we have pending records and no new data arrives
    // within this period, send what we have.
    const FLUSH_TIMEOUT_MS: i32 = 100;

    // Drop/error stats — reported every 10 seconds
    const STATS_INTERVAL_SECS: u64 = 10;
    let mut last_stats_time = Instant::now();
    let mut prev_nl_drops: u64 = nl_socket.get_drops();
    let mut send_errors: u64 = 0;
    let mut prev_send_errors: u64 = 0;

    // Receive buffer (64KB)
    let mut recv_buf = vec![0u8; 65536];

    info!("Listening for conntrack NAT events...");

    let mut running = true;
    while running {
        // Check if template retransmit is due
        let now = Instant::now();
        if now.duration_since(last_template_time).as_secs()
            >= ipfix::constants::TEMPLATE_RETRANSMIT_INTERVAL
        {
            include_template = true;
        }

        // Report drop stats every 10 seconds
        if now.duration_since(last_stats_time).as_secs() >= STATS_INTERVAL_SECS {
            let nl_drops = nl_socket.get_drops();
            let new_nl_drops = nl_drops - prev_nl_drops;
            let new_send_errors = send_errors - prev_send_errors;
            if new_nl_drops > 0 || new_send_errors > 0 {
                warn!(
                    "drops: nl_recv={} udp_send={} (total: nl_recv={} udp_send={})",
                    new_nl_drops, new_send_errors, nl_drops, send_errors,
                );
            }
            prev_nl_drops = nl_drops;
            prev_send_errors = send_errors;
            last_stats_time = now;
        }

        // Poll: use flush timeout if we have pending records, otherwise block
        let timeout = if message_active { FLUSH_TIMEOUT_MS } else { -1 };
        let (ready, signalled) = match nl_socket.poll_with(signals.as_raw_fd(), timeout) {
            Ok(state) => state,
            Err(e) => {
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e).context("poll() on netlink socket failed");
            }
        };

        if signalled {
            for sig in signals.read_pending().context("failed to read signalfd")? {
                info!("Received signal {}, shutting down", sig);
                running = false;
            }
            if !running {
                break;
            }
        }

        if !ready {
            // Timeout — flush pending records
            if message_active && encoder.has_records() {
                let (data, count) = encoder.finalize();
                if let Err(e) = udp_socket.send(data) {
                    send_errors += 1;
                    warn!("sendto() failed: {}", e);
                }
                debug!("Sent IPFIX message with {} records (flush)", count);
                message_active = false;
            }
            continue;
        }

        // Receive netlink messages
        let n = match nl_socket.recv(&mut recv_buf) {
            Ok(n) => n,
            Err(e) => {
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                error!("recv() failed: {}", e);
                continue;
            }
        };

        if n == 0 {
            continue;
        }

        // Ensure we have an active message
        if !message_active {
            encoder.begin_message(include_template);
            if include_template {
                include_template = false;
                last_template_time = Instant::now();
            }
            message_active = true;
        }

        // Parse all conntrack messages and encode into IPFIX
        parse_conntrack_messages(&recv_buf, n, |event| {
            debug!("{}", event);

            if !encoder.add_record(&event) {
                // Message full — finalize and send, then start a new one
                let (data, count) = encoder.finalize();
                if let Err(e) = udp_socket.send(data) {
                    send_errors += 1;
                    warn!("sendto() failed: {}", e);
                }
                debug!("Sent IPFIX message with {} records", count);

                encoder.begin_message(include_template);
                if include_template {
                    include_template = false;
                    last_template_time = Instant::now();
                }
                if !encoder.add_record(&event) {
                    error!("BUG: failed to add record to fresh message");
                }
            }
        });
    }

    // Flush remaining records on shutdown
    if message_active && encoder.has_records() {
        let (data, count) = encoder.finalize();
        if let Err(e) = udp_socket.send(data) {
            warn!("sendto() failed: {}", e);
        }
        debug!("Sent IPFIX message with {} records (shutdown)", count);
    }

    info!("Worker shutting down.");
    Ok(())
}

fn run_supervisor(args: &Args) -> Result<()> {
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(anyhow::anyhow!("fork() failed: {}", io::Error::last_os_error()));
    }
    if pid > 0 {
        info!("Daemon started, supervisor pid={}", pid);
        return Ok(());
    }

    if unsafe { libc::setsid() } < 0 {
        return Err(anyhow::anyhow!("setsid() failed: {}", io::Error::last_os_error()));
    }
    redirect_stdio_to_devnull()?;

    // SIGCHLD is included so a worker exit wakes the poll() below, letting the
    // supervisor wait on signals and child status through one descriptor.
    let signals = SignalFd::new(&[libc::SIGTERM, libc::SIGINT, libc::SIGCHLD])
        .context("Failed to set up signal handling")?;

    info!("Supervisor started, pid={}", std::process::id());
    loop {
        let child_pid = unsafe { libc::fork() };
        if child_pid < 0 {
            return Err(anyhow::anyhow!(
                "supervisor fork() failed: {}",
                io::Error::last_os_error()
            ));
        }

        if child_pid == 0 {
            // The child must not share the supervisor's signalfd or its
            // inherited signal mask.
            signals.close_in_child();
            let rc = match signals::unblock_all().context("Failed to reset signal mask") {
                Err(e) => {
                    error!("{:#}", e);
                    1
                }
                Ok(()) => match run_worker(args) {
                    Ok(()) => 0,
                    Err(e) => {
                        error!("Worker exited with error: {:#}", e);
                        1
                    }
                },
            };
            unsafe { libc::_exit(rc) };
        }

        match supervise_child(&signals, child_pid)? {
            Supervision::ShutdownRequested => break,
            Supervision::Exited(status) => {
                if !should_restart(status) {
                    info!("Worker exited cleanly; supervisor stopping");
                    break;
                }
                warn!("Worker terminated (status=0x{:x}); restarting in 1s", status);
                thread::sleep(Duration::from_secs(1));
            }
        }
    }

    info!("Supervisor shutting down.");
    Ok(())
}

enum Supervision {
    /// The worker exited on its own with this wait status.
    Exited(libc::c_int),
    /// A shutdown signal arrived; the worker has been stopped and reaped.
    ShutdownRequested,
}

/// Wait for the worker to exit, or for a shutdown signal — in which case the
/// signal is forwarded to the worker and we wait for it to go away.
fn supervise_child(signals: &SignalFd, child_pid: libc::pid_t) -> Result<Supervision> {
    let mut shutting_down = false;
    let mut kill_deadline: Option<Instant> = None;

    loop {
        if let Some(status) = try_reap(child_pid)? {
            return Ok(if shutting_down {
                Supervision::ShutdownRequested
            } else {
                Supervision::Exited(status)
            });
        }

        let timeout = match kill_deadline {
            Some(deadline) => ms_until(deadline, Instant::now()),
            None => -1,
        };

        let ready = match signals::poll_readable(signals.as_raw_fd(), timeout) {
            Ok(ready) => ready,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e).context("poll() on signalfd failed"),
        };

        if ready {
            // SIGCHLD needs no handling beyond waking us for the reap above.
            for sig in signals
                .read_pending()
                .context("failed to read signalfd")?
                .into_iter()
                .filter(|&sig| sig != libc::SIGCHLD)
            {
                if !shutting_down {
                    info!("Received signal {}, stopping worker pid={}", sig, child_pid);
                    shutting_down = true;
                    unsafe { libc::kill(child_pid, libc::SIGTERM) };
                    kill_deadline = Some(Instant::now() + WORKER_STOP_GRACE);
                }
            }
        } else if kill_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            warn!(
                "Worker pid={} did not exit within {:?}; sending SIGKILL",
                child_pid, WORKER_STOP_GRACE
            );
            unsafe { libc::kill(child_pid, libc::SIGKILL) };
            kill_deadline = None;
        }
    }
}

/// Reap the worker if it has already exited, without blocking.
fn try_reap(child_pid: libc::pid_t) -> Result<Option<libc::c_int>> {
    let mut status: libc::c_int = 0;
    let rc = unsafe { libc::waitpid(child_pid, &mut status as *mut libc::c_int, libc::WNOHANG) };
    if rc == child_pid {
        return Ok(Some(status));
    }
    if rc < 0 {
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(anyhow::anyhow!("waitpid() failed: {}", err));
        }
    }
    Ok(None)
}

/// Milliseconds from `now` until `deadline`, clamped to a poll() timeout.
fn ms_until(deadline: Instant, now: Instant) -> i32 {
    deadline
        .saturating_duration_since(now)
        .as_millis()
        .min(i32::MAX as u128) as i32
}

fn should_restart(status: libc::c_int) -> bool {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status) != 0
    } else {
        libc::WIFSIGNALED(status)
    }
}

fn redirect_stdio_to_devnull() -> Result<()> {
    let devnull = CString::new("/dev/null").expect("static string");
    let fd = unsafe { libc::open(devnull.as_ptr(), libc::O_RDWR) };
    if fd < 0 {
        return Err(anyhow::anyhow!(
            "open(/dev/null) failed: {}",
            io::Error::last_os_error()
        ));
    }

    for target_fd in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        if unsafe { libc::dup2(fd, target_fd) } < 0 {
            let err = io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(anyhow::anyhow!("dup2() failed: {}", err));
        }
    }

    if fd > libc::STDERR_FILENO {
        unsafe {
            libc::close(fd);
        }
    }
    Ok(())
}

fn set_send_buf(socket: &UdpSocket, size: usize) {
    use std::os::unix::io::AsRawFd;
    let fd = socket.as_raw_fd();
    let buf_size = size as libc::c_int;

    // Try SO_SNDBUFFORCE first
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUFFORCE,
            &buf_size as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        debug!("SO_SNDBUFFORCE failed, falling back to SO_SNDBUF");
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &buf_size as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            warn!(
                "Failed to set SO_SNDBUF: {}",
                io::Error::last_os_error()
            );
        }
    }
}

fn apply_conntrack_sysctl_settings() -> Result<()> {
    set_proc_sysctl("/proc/sys/net/netfilter/nf_conntrack_acct", "1")?;
    set_proc_sysctl("/proc/sys/net/netfilter/nf_conntrack_events", "1")?;
    Ok(())
}

fn set_proc_sysctl(path: &str, value: &str) -> Result<()> {
    let desired = format!("{value}\n");
    let current = fs::read_to_string(path)
        .with_context(|| format!("failed to read sysctl {}", path))?
        .trim()
        .to_string();

    if current != value {
        fs::write(path, desired.as_bytes())
            .with_context(|| format!("failed to write sysctl {}={value}", path))?;
    }

    Ok(())
}
