mod event;
mod export;
mod netlink;
mod signals;

use std::io;
use std::ffi::CString;
use std::fs;
use std::net::{SocketAddr, UdpSocket};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Instant;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use log::{debug, error, info, warn};

use export::{CounterWidth, Encoder, Profile, Protocol, Template};
use netlink::constants::{DEFAULT_RECV_BUF_SIZE, DEFAULT_SEND_BUF_SIZE};
use netlink::{parse_conntrack_messages, NetlinkSocket};
use signals::SignalFd;

/// How long the supervisor waits for the worker to exit on its own after
/// SIGTERM before escalating to SIGKILL.
const WORKER_STOP_GRACE: Duration = Duration::from_secs(10);

/// Delay before the first restart, doubled on each successive failure.
const RESTART_BACKOFF_MIN: Duration = Duration::from_secs(1);

/// Ceiling for the restart delay.
const RESTART_BACKOFF_MAX: Duration = Duration::from_secs(60);

/// A worker that stayed up at least this long is treated as a fresh failure
/// rather than part of a crash loop, and resets the backoff.
const HEALTHY_RUNTIME: Duration = Duration::from_secs(60);

const CONNTRACK_ACCT_SYSCTL: &str = "/proc/sys/net/netfilter/nf_conntrack_acct";
const CONNTRACK_EVENTS_SYSCTL: &str = "/proc/sys/net/netfilter/nf_conntrack_events";

#[derive(Parser, Debug)]
#[command(name = "conntrack_exporter", about = "Conntrack NAT event IPFIX / NetFlow v9 exporter")]
struct Args {
    /// Flow collector address (ip:port)
    #[arg(short, long)]
    collector: SocketAddr,

    /// Netlink receive buffer size in bytes
    #[arg(long, default_value_t = DEFAULT_RECV_BUF_SIZE)]
    recv_buf: usize,

    /// UDP send buffer size in bytes
    #[arg(long, default_value_t = DEFAULT_SEND_BUF_SIZE)]
    send_buf: usize,

    /// Observation domain ID
    #[arg(long, default_value_t = 0)]
    domain_id: u32,

    /// Export protocol to speak
    #[arg(long, value_enum, default_value_t = Protocol::Ipfix)]
    protocol: Protocol,

    /// Which field set to export
    #[arg(long, value_enum, default_value_t = Profile::Full)]
    profile: Profile,

    /// Byte and packet counter width, in bytes (4 or 8)
    #[arg(long, default_value_t = 8)]
    counter_width: u8,

    /// Template ID to advertise (must be at least 256)
    #[arg(long, default_value_t = export::elements::DEFAULT_TEMPLATE_ID)]
    template_id: u16,

    /// Seconds between template retransmissions
    #[arg(long, default_value_t = export::elements::DEFAULT_TEMPLATE_INTERVAL_SECS)]
    template_interval: u64,

    /// Enable verbose (debug) logging
    #[arg(short, long)]
    verbose: bool,

    /// Run as a background daemon with self-supervision
    #[arg(long)]
    daemon: bool,

    /// In --daemon mode, append log output to this file instead of discarding it
    #[arg(long, value_name = "PATH")]
    log_file: Option<PathBuf>,

    /// Do not touch the nf_conntrack sysctls; assume they are already set
    #[arg(long)]
    no_sysctl: bool,
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
    // Validate the configuration before touching anything on the system, so a
    // bad flag is reported as a bad flag rather than as whatever fails next.
    if args.template_interval == 0 {
        anyhow::bail!("--template-interval must be at least 1 second");
    }
    let template = Template::resolve(
        args.protocol,
        args.profile,
        CounterWidth::from_bytes(args.counter_width)?,
        args.template_id,
    )
    .context("Invalid export configuration")?;

    info!("Starting conntrack_exporter worker, collector={}", args.collector);
    info!(
        "Exporting {:?}, profile={:?}, counters={}B, record={}B, template id={}, \
         up to {} records per message",
        template.protocol,
        template.profile,
        template.counter_width.bytes(),
        template.record_size,
        template.template_id,
        template.max_records_per_message(),
    );

    apply_conntrack_sysctl_settings(args)?;

    // Consume shutdown signals through a descriptor so they are observed by the
    // same poll() that waits for netlink data, with no EINTR races.
    let signals = SignalFd::new(&[libc::SIGTERM, libc::SIGINT])
        .context("Failed to set up signal handling")?;

    // Create UDP socket for flow export
    let udp_socket = UdpSocket::bind("0.0.0.0:0").context("Failed to bind UDP socket")?;
    udp_socket
        .connect(args.collector)
        .context("Failed to connect UDP socket to collector")?;

    // Set UDP send buffer
    set_send_buf(&udp_socket, args.send_buf);

    // Create netlink socket
    let nl_socket =
        NetlinkSocket::open(args.recv_buf).context("Failed to open netlink socket")?;

    // Create the encoder from the template resolved above
    let mut encoder = Encoder::new(args.domain_id, template);

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
    let mut truncated_msgs: u64 = 0;
    let mut prev_truncated_msgs: u64 = 0;
    let mut foreign_msgs: u64 = 0;
    let mut prev_foreign_msgs: u64 = 0;
    let mut prev_saturated: u64 = 0;

    // Receive buffer (64KB)
    let mut recv_buf = vec![0u8; 65536];

    info!("Listening for conntrack NAT events...");

    let template_interval = Duration::from_secs(args.template_interval);
    let stats_interval = Duration::from_secs(STATS_INTERVAL_SECS);

    let mut running = true;
    while running {
        // Check if template retransmit is due
        let now = Instant::now();
        if now.duration_since(last_template_time) >= template_interval {
            include_template = true;
        }

        // Report drop stats every 10 seconds
        if now.duration_since(last_stats_time) >= stats_interval {
            // The kernel drop counter is a u32 that wraps, and reads as 0 if
            // SO_MEMINFO is unavailable, so it is not monotonic in practice.
            let nl_drops = nl_socket.get_drops();
            let new_nl_drops = nl_drops.saturating_sub(prev_nl_drops);
            let new_send_errors = send_errors.saturating_sub(prev_send_errors);
            let new_truncated = truncated_msgs.saturating_sub(prev_truncated_msgs);
            let new_foreign = foreign_msgs.saturating_sub(prev_foreign_msgs);
            let saturated = encoder.saturated_counters();
            let new_saturated = saturated.saturating_sub(prev_saturated);
            if new_nl_drops > 0
                || new_send_errors > 0
                || new_truncated > 0
                || new_foreign > 0
                || new_saturated > 0
            {
                warn!(
                    "drops: nl_recv={} udp_send={} truncated={} foreign={} clamped_counters={} \
                     (total: nl_recv={} udp_send={} truncated={} foreign={} clamped_counters={})",
                    new_nl_drops,
                    new_send_errors,
                    new_truncated,
                    new_foreign,
                    new_saturated,
                    nl_drops,
                    send_errors,
                    truncated_msgs,
                    foreign_msgs,
                    saturated,
                );
            }
            prev_nl_drops = nl_drops;
            prev_send_errors = send_errors;
            prev_truncated_msgs = truncated_msgs;
            prev_foreign_msgs = foreign_msgs;
            prev_saturated = saturated;
            last_stats_time = now;
        }

        // A retransmit falling due with nothing buffered goes out on its own,
        // so a collector that ages templates out is refreshed even when the
        // link is idle.
        if include_template && !message_active {
            encoder.begin_message(true);
            flush_message(
                &mut encoder,
                &udp_socket,
                &mut send_errors,
                &mut include_template,
                &mut last_template_time,
                "template",
            );
        }

        // Poll: use the flush timeout if a message is buffered, otherwise sleep
        // until the next timer is due. Signals arrive on the signalfd, so there
        // is no reason to wake up otherwise.
        let timeout = if message_active {
            FLUSH_TIMEOUT_MS
        } else {
            let next_deadline =
                (last_template_time + template_interval).min(last_stats_time + stats_interval);
            ms_until(next_deadline, Instant::now())
        };
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
            // Timeout — flush whatever is buffered. Clear the active flag even
            // when there was nothing to send, so a message begun for a batch
            // that turned out to hold no NAT events does not keep the loop on
            // the short flush timeout indefinitely.
            if message_active {
                flush_message(
                    &mut encoder,
                    &udp_socket,
                    &mut send_errors,
                    &mut include_template,
                    &mut last_template_time,
                    "flush",
                );
                message_active = false;
            }
            continue;
        }

        // Receive netlink messages
        let datagram = match nl_socket.recv(&mut recv_buf) {
            Ok(datagram) => datagram,
            Err(e) => {
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                error!("recv() failed: {}", e);
                continue;
            }
        };

        // Conntrack notifications originate in the kernel, which uses port ID 0.
        if datagram.sender_portid != 0 {
            foreign_msgs += 1;
            continue;
        }

        if datagram.datagram_len > datagram.len {
            truncated_msgs += 1;
            warn!(
                "netlink datagram truncated: kept {} of {} bytes",
                datagram.len, datagram.datagram_len
            );
        }

        if datagram.len == 0 {
            continue;
        }

        // Ensure we have an active message
        if !message_active {
            encoder.begin_message(include_template);
            message_active = true;
        }

        // Parse all conntrack messages and encode them
        parse_conntrack_messages(&recv_buf[..datagram.len], |event| {
            debug!("{}", event);

            if !encoder.add_record(&event) {
                // Message full — finalize and send, then start a new one
                flush_message(
                    &mut encoder,
                    &udp_socket,
                    &mut send_errors,
                    &mut include_template,
                    &mut last_template_time,
                    "full",
                );

                encoder.begin_message(include_template);
                if !encoder.add_record(&event) {
                    error!("BUG: failed to add record to fresh message");
                }
            }
        });
    }

    // Flush remaining records on shutdown
    if message_active {
        flush_message(
            &mut encoder,
            &udp_socket,
            &mut send_errors,
            &mut include_template,
            &mut last_template_time,
            "shutdown",
        );
    }

    info!("Worker shutting down.");
    Ok(())
}

/// Send the buffered message, if it holds anything worth sending.
///
/// A message carrying the template settles the retransmit schedule whether or
/// not the send succeeds: retrying immediately would spin, and the next
/// interval will carry the template again anyway.
fn flush_message(
    encoder: &mut Encoder,
    udp_socket: &UdpSocket,
    send_errors: &mut u64,
    include_template: &mut bool,
    last_template_time: &mut Instant,
    reason: &str,
) {
    if !encoder.has_pending_output() {
        return;
    }

    if encoder.template_included() {
        *include_template = false;
        *last_template_time = Instant::now();
    }

    let (data, count) = encoder.finalize();
    match udp_socket.send(data) {
        Ok(_) => debug!("Sent message with {} records ({})", count, reason),
        Err(e) => {
            *send_errors += 1;
            warn!("sendto() failed: {}", e);
        }
    }
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
    redirect_stdio(args.log_file.as_deref())?;

    // SIGCHLD is included so a worker exit wakes the poll() below, letting the
    // supervisor wait on signals and child status through one descriptor.
    let signals = SignalFd::new(&[libc::SIGTERM, libc::SIGINT, libc::SIGCHLD])
        .context("Failed to set up signal handling")?;

    info!("Supervisor started, pid={}", std::process::id());
    let mut backoff = RESTART_BACKOFF_MIN;
    loop {
        let started = Instant::now();
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
                // A worker that stayed up is a fresh failure, not a crash loop.
                if started.elapsed() >= HEALTHY_RUNTIME {
                    backoff = RESTART_BACKOFF_MIN;
                }
                warn!(
                    "Worker terminated (status=0x{:x}); restarting in {:?}",
                    status, backoff
                );
                if wait_before_restart(&signals, backoff)? {
                    break;
                }
                backoff = (backoff * 2).min(RESTART_BACKOFF_MAX);
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

/// Wait out the restart backoff, returning true if a shutdown signal arrives
/// first — the delay must not make the daemon unresponsive to SIGTERM.
fn wait_before_restart(signals: &SignalFd, delay: Duration) -> Result<bool> {
    let deadline = Instant::now() + delay;
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Ok(false);
        }

        let ready = match signals::poll_readable(signals.as_raw_fd(), ms_until(deadline, now)) {
            Ok(ready) => ready,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e).context("poll() on signalfd failed"),
        };

        if ready
            && let Some(sig) = signals
                .read_pending()
                .context("failed to read signalfd")?
                .into_iter()
                .find(|&sig| sig != libc::SIGCHLD)
        {
            info!("Received signal {} while waiting to restart", sig);
            return Ok(true);
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

/// Detach stdio from the terminal. Log output goes to `log_file` when given;
/// otherwise it is discarded, which leaves the daemon unable to explain itself.
fn redirect_stdio(log_file: Option<&Path>) -> Result<()> {
    let devnull = open_fd(Path::new("/dev/null"), libc::O_RDWR, 0)?;

    let out_fd = match log_file {
        Some(path) => open_fd(
            path,
            libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND,
            0o640,
        )?,
        None => devnull,
    };

    let result = (|| {
        dup2_checked(devnull, libc::STDIN_FILENO)?;
        dup2_checked(out_fd, libc::STDOUT_FILENO)?;
        dup2_checked(out_fd, libc::STDERR_FILENO)
    })();

    if out_fd != devnull && out_fd > libc::STDERR_FILENO {
        unsafe { libc::close(out_fd) };
    }
    if devnull > libc::STDERR_FILENO {
        unsafe { libc::close(devnull) };
    }

    result
}

fn open_fd(path: &Path, flags: libc::c_int, mode: libc::c_uint) -> Result<libc::c_int> {
    let c_path = CString::new(path.as_os_str().as_bytes())
        .with_context(|| format!("path {} contains a NUL byte", path.display()))?;
    let fd = unsafe { libc::open(c_path.as_ptr(), flags, mode) };
    if fd < 0 {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("failed to open {}", path.display()));
    }
    Ok(fd)
}

fn dup2_checked(fd: libc::c_int, target_fd: libc::c_int) -> Result<()> {
    if unsafe { libc::dup2(fd, target_fd) } < 0 {
        return Err(io::Error::last_os_error()).context("dup2() failed");
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

fn apply_conntrack_sysctl_settings(args: &Args) -> Result<()> {
    if args.no_sysctl {
        info!("Skipping conntrack sysctl setup (--no-sysctl)");
        return Ok(());
    }

    // Without event delivery there is nothing at all to export, so a failure
    // here is worth refusing to start over.
    set_proc_sysctl(CONNTRACK_EVENTS_SYSCTL, "1").context(
        "failed to enable conntrack event delivery; load the nf_conntrack \
         module, run with CAP_NET_ADMIN, or pass --no-sysctl if the sysctls \
         are already set",
    )?;

    // Without accounting the flows are still exported, just with zero counters.
    // That is degraded, not fatal.
    if let Err(e) = set_proc_sysctl(CONNTRACK_ACCT_SYSCTL, "1") {
        warn!("conntrack accounting unavailable, counters will be zero: {:#}", e);
    }

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
