mod event;
mod ipfix;
mod netlink;

use std::io;
use std::ffi::CString;
use std::fs;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Instant;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use log::{debug, error, info, warn};

use ipfix::IpfixEncoder;
use netlink::constants::{DEFAULT_RECV_BUF_SIZE, DEFAULT_SEND_BUF_SIZE};
use netlink::{parse_conntrack_messages, NetlinkSocket};

static RUNNING: AtomicBool = AtomicBool::new(true);
static SUPERVISOR_RUNNING: AtomicBool = AtomicBool::new(true);

#[derive(Parser, Debug)]
#[command(name = "spank_ipfixd", about = "Conntrack NAT event IPFIX exporter")]
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
    RUNNING.store(true, Ordering::Relaxed);

    info!("Starting spank_ipfixd worker, collector={}", args.collector);
    apply_conntrack_sysctl_settings()?;

    // Install signal handlers for worker shutdown
    unsafe {
        libc::signal(libc::SIGTERM, worker_signal_handler as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, worker_signal_handler as *const () as libc::sighandler_t);
    }

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

    while RUNNING.load(Ordering::Relaxed) {
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
        let ready = match nl_socket.poll(timeout) {
            Ok(ready) => ready,
            Err(e) => {
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                error!("poll() failed: {}", e);
                continue;
            }
        };

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

    SUPERVISOR_RUNNING.store(true, Ordering::Relaxed);
    unsafe {
        libc::signal(
            libc::SIGTERM,
            supervisor_signal_handler as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGINT,
            supervisor_signal_handler as *const () as libc::sighandler_t,
        );
    }

    info!("Supervisor started, pid={}", std::process::id());
    while SUPERVISOR_RUNNING.load(Ordering::Relaxed) {
        let child_pid = unsafe { libc::fork() };
        if child_pid < 0 {
            return Err(anyhow::anyhow!(
                "supervisor fork() failed: {}",
                io::Error::last_os_error()
            ));
        }

        if child_pid == 0 {
            let rc = match run_worker(args) {
                Ok(()) => 0,
                Err(e) => {
                    error!("Worker exited with error: {:#}", e);
                    1
                }
            };
            unsafe { libc::_exit(rc) };
        }

        let status = wait_for_child(child_pid)?;
        if !SUPERVISOR_RUNNING.load(Ordering::Relaxed) {
            break;
        }

        if !should_restart(status) {
            info!("Worker exited cleanly; supervisor stopping");
            break;
        }

        warn!(
            "Worker crashed (status=0x{:x}); restarting in 1s",
            status
        );
        thread::sleep(Duration::from_secs(1));
    }

    info!("Supervisor shutting down.");
    Ok(())
}

fn wait_for_child(child_pid: libc::pid_t) -> Result<libc::c_int> {
    loop {
        let mut status: libc::c_int = 0;
        let rc = unsafe { libc::waitpid(child_pid, &mut status as *mut libc::c_int, 0) };
        if rc == child_pid {
            return Ok(status);
        }
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                if !SUPERVISOR_RUNNING.load(Ordering::Relaxed) {
                    unsafe {
                        libc::kill(child_pid, libc::SIGTERM);
                    }
                }
                continue;
            }
            return Err(anyhow::anyhow!("waitpid() failed: {}", err));
        }
    }
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

extern "C" fn worker_signal_handler(_sig: libc::c_int) {
    RUNNING.store(false, Ordering::Relaxed);
}

extern "C" fn supervisor_signal_handler(_sig: libc::c_int) {
    SUPERVISOR_RUNNING.store(false, Ordering::Relaxed);
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
