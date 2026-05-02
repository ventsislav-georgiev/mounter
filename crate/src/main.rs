//! mounter: Mount remote SSH directories via SMB2-over-SFTP.
//!
//! Single binary — SMB2 server + SFTP client in one process.
//! Works on macOS (`mount_smbfs`) and Linux (`gio mount`).
//! No Docker, no FUSE, no kernel extensions, no sudo.

mod server;
mod sftp;
mod smb2;

use server::SmbSession;
use sftp::{ReconnectingSftp, CONN_STATE_DISCONNECTED};
use std::env;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::process;
use std::sync::Arc;
use std::thread;

fn usage() -> ! {
    eprintln!("mounter — mount remote SSH directories via SMB2-over-SFTP");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  mounter mount [user@]host:[path] <mountpoint> [opts]  Mount and serve");
    eprintln!("  mounter [user@]host:[path] [opts]                     Start SMB server only");
    eprintln!("  mounter unmount <name|path|all>                        Unmount cleanly");
    eprintln!("  mounter list                                           Show active mounts");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -p PORT         SSH port (default: 22)");
    eprintln!("  -i IDENTITY     SSH identity file");
    eprintln!("  -n NAME         Share name (default: host)");
    eprintln!("  --smb-port PORT Local SMB port (default: auto)");
    eprintln!("  -f, --foreground  Run in foreground (default: daemonize after mount)");
    process::exit(1);
}

const DAEMON_MARKER_ENV: &str = "_MOUNTER_DAEMONIZED";

/// Re-exec self as a detached daemon with output redirected to a log file.
/// Polls the log file for the "Mounted at" message, then exits.
fn spawn_daemon(args: &[String]) -> ! {
    use std::io::Read;
    use std::time::{Duration, Instant};

    let log_path = format!("/tmp/mounter-{}.log", std::process::id());
    let log_file = match std::fs::File::create(&log_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to create log file: {e}");
            process::exit(1);
        }
    };
    let log_err = log_file.try_clone().unwrap();

    let exe = env::current_exe().unwrap_or_else(|_| args[0].clone().into());
    let mut cmd = process::Command::new(exe);
    cmd.args(&args[1..]);
    cmd.env(DAEMON_MARKER_ENV, "1");
    cmd.stdin(process::Stdio::null());
    cmd.stdout(log_file);
    cmd.stderr(log_err);

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to start daemon: {e}");
            process::exit(1);
        }
    };

    // Poll log file for mount success or failure
    let start = Instant::now();
    let timeout = Duration::from_secs(30);
    loop {
        // Check if child died prematurely
        if let Ok(Some(status)) = child.try_wait() {
            let mut content = String::new();
            let _ = std::fs::File::open(&log_path).and_then(|mut f| f.read_to_string(&mut content));
            eprint!("{content}");
            eprintln!("mounter daemon exited early: {status}");
            process::exit(1);
        }

        let content = std::fs::read_to_string(&log_path).unwrap_or_default();
        if content.contains("Mounted at") {
            // Relay log output up to this point, then detach
            print!("{content}");
            println!("(mounter running in background — unmount with `mounter unmount`)");
            process::exit(0);
        }
        if content.contains("Mount failed") || content.contains("SSH connection failed") {
            eprint!("{content}");
            let _ = child.kill();
            process::exit(1);
        }
        if start.elapsed() > timeout {
            eprintln!("Timeout waiting for mount. Log: {log_path}");
            let _ = child.kill();
            process::exit(1);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_secs()
        .init();

    let raw_args: Vec<String> = env::args().collect();
    if raw_args.len() < 2 {
        usage();
    }

    // Extract -f/--foreground flag out of args so subsequent parsing is unaffected
    let foreground = raw_args.iter().any(|a| a == "-f" || a == "--foreground");
    let args: Vec<String> = raw_args
        .iter()
        .filter(|a| a.as_str() != "-f" && a.as_str() != "--foreground")
        .cloned()
        .collect();
    let is_daemon_child = env::var(DAEMON_MARKER_ENV).is_ok();

    // Daemonize the "mount" subcommand by default unless -f is given
    if args.len() >= 2 && args[1] == "mount" && !foreground && !is_daemon_child {
        spawn_daemon(&raw_args);
    }

    // Subcommands
    let auto_mount = args[1] == "mount";
    match args[1].as_str() {
        "unmount" | "umount" => {
            let target = args.get(2).map(|s| s.as_str()).unwrap_or_else(|| {
                eprintln!("Usage: mounter unmount <name|path|all>");
                process::exit(1);
            });
            process::exit(cmd_unmount(target));
        }
        "list" | "ls" => {
            cmd_list();
            process::exit(0);
        }
        "-h" | "--help" | "help" => usage(),
        _ => {}
    }

    // For "mount" subcommand: mounter mount user@host:path /mount/point [opts]
    let remote_idx = if auto_mount { 2 } else { 1 };
    let remote = match args.get(remote_idx) {
        Some(r) => r,
        None => {
            if auto_mount {
                eprintln!("Usage: mounter mount [user@]host:[path] <mountpoint> [opts]");
            } else {
                eprintln!("Usage: mounter [user@]host:[path] [opts]");
            }
            process::exit(1);
        }
    };

    // Mount subcommand requires a mount point as the next positional arg
    let mount_point = if auto_mount {
        match args.get(remote_idx + 1) {
            Some(mp) if !mp.starts_with('-') => Some(mp.clone()),
            _ => {
                eprintln!(
                    "Missing mount point. Usage: mounter mount [user@]host:[path] <mountpoint>"
                );
                process::exit(1);
            }
        }
    } else {
        None
    };
    let opt_start = if auto_mount {
        remote_idx + 2
    } else {
        remote_idx + 1
    };
    let mut ssh_port: u16 = 22;
    let mut identity: Option<String> = None;
    let mut share_name: Option<String> = None;
    let mut smb_port: u16 = 0; // 0 = auto-assign

    let mut i = opt_start;
    while i < args.len() {
        match args[i].as_str() {
            "-p" => {
                i += 1;
                ssh_port = match args.get(i) {
                    Some(s) => match s.parse() {
                        Ok(p) => p,
                        Err(_) => {
                            eprintln!("invalid port: {s}");
                            process::exit(1);
                        }
                    },
                    None => {
                        eprintln!("missing port after -p");
                        process::exit(1);
                    }
                };
            }
            "-i" => {
                i += 1;
                identity = args.get(i).cloned();
            }
            "-n" => {
                i += 1;
                share_name = args.get(i).cloned();
            }
            "--smb-port" => {
                i += 1;
                smb_port = match args.get(i) {
                    Some(s) => match s.parse() {
                        Ok(p) => p,
                        Err(_) => {
                            eprintln!("invalid SMB port: {s}");
                            process::exit(1);
                        }
                    },
                    None => {
                        eprintln!("missing port after --smb-port");
                        process::exit(1);
                    }
                };
            }
            "-h" | "--help" => usage(),
            other => {
                eprintln!("unknown option: {other}");
                usage();
            }
        }
        i += 1;
    }

    // Parse remote spec
    let (user, host, remote_path) = parse_remote(remote);
    let name = share_name.unwrap_or_else(|| host.clone());

    // Connect via SFTP
    log::info!("Connecting to {host}:{ssh_port}...");
    let sftp =
        match ReconnectingSftp::connect(&host, ssh_port, user.as_deref(), identity.as_deref()) {
            Ok(s) => Arc::new(s),
            Err(e) => {
                eprintln!("SSH connection failed: {e}");
                process::exit(1);
            }
        };

    // Resolve remote path
    let root = if remote_path.is_empty() || remote_path == "." {
        match sftp.realpath(".") {
            Ok(p) => p,
            Err(e) => {
                eprintln!("realpath failed: {e}");
                process::exit(1);
            }
        }
    } else {
        match sftp.realpath(&remote_path) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("realpath '{remote_path}' failed: {e}");
                process::exit(1);
            }
        }
    };

    log::info!("Remote root: {root}");

    // Start SMB2 server
    let listener = match TcpListener::bind(format!("127.0.0.1:{smb_port}")) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to bind SMB port: {e}");
            process::exit(1);
        }
    };
    let local_port = listener.local_addr().map(|a| a.port()).unwrap_or(0);

    log::info!("SMB server listening on 127.0.0.1:{local_port}");

    if let Some(ref mp) = mount_point {
        spawn_mount(local_port, &name, mp);
        println!("Press Ctrl-C to stop. Clean up with: mounter unmount {name}");
    } else {
        println!("Mount with:");
        println!("  {}", mount_cmd_hint(local_port, &name));
    }

    // Health-check thread: probe SFTP connectivity and auto-unmount on failure
    if mount_point.is_some() {
        let hc_sftp = Arc::clone(&sftp);
        let hc_name = name.clone();
        let hc_port = local_port;
        let hc_mp = mount_point.clone().unwrap();
        thread::spawn(move || {
            use std::sync::atomic::Ordering;
            use std::time::Duration;
            loop {
                thread::sleep(Duration::from_secs(15));
                if hc_sftp.realpath(".").is_err() {
                    log::warn!("Health-check failed — attempting reconnect");
                    hc_sftp.force_reconnect();
                    thread::sleep(Duration::from_secs(2));
                    if hc_sftp.state().load(Ordering::SeqCst) == CONN_STATE_DISCONNECTED {
                        log::error!("SFTP disconnected after reconnect — auto-unmounting {hc_name}");
                        let info = MountInfo {
                            share: hc_name,
                            port: hc_port,
                            path: hc_mp,
                        };
                        unmount_one(&info);
                        process::exit(1);
                    }
                }
            }
        });
    }

    // Accept connections — one thread per client
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let sftp = Arc::clone(&sftp);
                let root = root.clone();
                let name = name.clone();
                thread::spawn(move || handle_client(stream, sftp, root, name));
            }
            Err(e) => log::warn!("Accept error: {e}"),
        }
    }
}

fn handle_client(mut stream: TcpStream, sftp: Arc<ReconnectingSftp>, root: String, name: String) {
    let _ = stream.set_nodelay(true);
    log::info!(
        "Client connected: {}",
        stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_default()
    );
    let mut session = SmbSession::new(sftp, root, name);

    loop {
        let msg = match smb2::read_message(&mut stream) {
            Ok(m) => m,
            Err(e) => {
                log::debug!("Connection closed: {e}");
                break;
            }
        };

        log::debug!("Received {} bytes:{}", msg.len(), smb2::hex_dump(&msg, 128));

        // Check for SMB1 negotiate (macOS sends \xFF SMB first)
        if smb2::is_smb1_negotiate(&msg) {
            log::info!("Received SMB1 negotiate — responding with SMB2 upgrade");
            let response = smb2::build_smb1_to_smb2_negotiate_response();
            if let Err(e) = stream.write_all(&response) {
                log::debug!("Write error: {e}");
                break;
            }
            if let Err(e) = stream.flush() {
                log::debug!("Flush error: {e}");
                break;
            }
            continue;
        }

        // Handle compounded requests — macOS sends multiple
        // SMB2 commands in one TCP message (NextCommand field).
        // Compound responses must be in a SINGLE NetBIOS frame.
        let mut cmd_offsets = Vec::new();
        let mut offset = 0;
        while offset < msg.len() {
            if msg.len() - offset < smb2::SMB2_HEADER_SIZE {
                break;
            }
            let next_cmd = smb2::read_u32_le(&msg[offset..], 20) as usize;
            let cmd_end = if next_cmd > 0 {
                offset + next_cmd
            } else {
                msg.len()
            };
            cmd_offsets.push((offset, cmd_end));
            if next_cmd == 0 {
                break;
            }
            offset += next_cmd;
        }

        if cmd_offsets.len() <= 1 {
            let response = session.handle_message(&msg);
            if !response.is_empty() {
                if let Err(e) = stream.write_all(&response) {
                    log::debug!("Write: {e}");
                    break;
                }
            }
        } else {
            let mut resp_bodies: Vec<Vec<u8>> = Vec::new();
            for (i, (start, end)) in cmd_offsets.iter().enumerate() {
                let single = &msg[*start..*end];
                let cmd_code = smb2::read_u16_le(single, 12);
                log::debug!("  Compound[{i}]: cmd=0x{cmd_code:04x} len={}", single.len());
                let resp = session.handle_message(single);
                if resp.len() > 4 {
                    resp_bodies.push(resp[4..].to_vec());
                }
            }

            let count = resp_bodies.len();
            let mut combined = Vec::new();
            for i in 0..count {
                if i < count - 1 {
                    while resp_bodies[i].len() % 8 != 0 {
                        resp_bodies[i].push(0);
                    }
                    let next = resp_bodies[i].len() as u32;
                    resp_bodies[i][20..24].copy_from_slice(&next.to_le_bytes());
                }
                combined.extend_from_slice(&resp_bodies[i]);
            }

            let frame_len = (combined.len() as u32).to_be_bytes();
            if let Err(e) = stream.write_all(&frame_len) {
                log::debug!("Write: {e}");
                break;
            }
            if let Err(e) = stream.write_all(&combined) {
                log::debug!("Write: {e}");
                break;
            }
        }
        if let Err(e) = stream.flush() {
            log::debug!("Flush: {e}");
            break;
        }
    }
    log::info!("Client disconnected");
}

// ── Platform-aware mount/unmount ────────────────────────────────────

use std::process::Command;

fn is_macos() -> bool {
    cfg!(target_os = "macos")
}

fn mount_cmd_hint(port: u16, name: &str) -> String {
    if is_macos() {
        format!("mount_smbfs //guest@localhost:{port}/{name} <mountpoint>")
    } else {
        format!("gio mount smb://guest@127.0.0.1:{port}/{name}")
    }
}

/// Spawn the mount command in the background (non-blocking).
/// The mount will complete once the SMB server starts accepting connections.
fn spawn_mount(port: u16, name: &str, mount_point: &str) {
    let _ = std::fs::create_dir_all(mount_point);

    let mp = mount_point.to_string();
    let name = name.to_string();
    std::thread::spawn(move || {
        let ok = if is_macos() {
            Command::new("mount_smbfs")
                .args([&format!("//guest@localhost:{port}/{name}"), &mp])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        } else {
            // Linux: gio mount (userspace SMB, no root needed)
            Command::new("gio")
                .args(["mount", &format!("smb://guest@127.0.0.1:{port}/{name}")])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        };

        if ok {
            eprintln!("Mounted at {mp}");
        } else {
            eprintln!(
                "Mount failed. Try manually:\n  {}",
                mount_cmd_hint(port, &name)
            );
        }
    });
}

// ── Subcommands ─────────────────────────────────────────────────────

/// An active mounter mount parsed from `mount` output.
struct MountInfo {
    share: String, // e.g. "myserver"
    port: u16,     // localhost port
    path: String,  // mount point, e.g. /Users/x/mnt/myserver
}

/// Parse `mount` output to find our SMB mounts.
/// Supports both old format (guest@localhost:PORT/SHARE) and
/// new format (guest@SHARE:PORT/SHARE).
fn find_smb_mounts() -> Vec<MountInfo> {
    let output = match Command::new("mount").output() {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(_) => return vec![],
    };
    let mut mounts = Vec::new();
    for line in output.lines() {
        if !line.contains("smbfs") && !line.contains("smb") {
            continue;
        }
        let parts: Vec<&str> = line.splitn(4, ' ').collect();
        if parts.len() < 4 || parts[1] != "on" {
            continue;
        }
        let source = parts[0];
        let path = parts[2];
        // Parse source: //guest:@HOST:PORT/SHARE
        // where HOST is either "localhost" (old) or the share name (new)
        if let Some(rest) = source.strip_prefix("//") {
            // rest = "guest:@HOST:PORT/SHARE"
            if let Some(at) = rest.find('@') {
                let after_at = &rest[at + 1..];
                // after_at = "HOST:PORT/SHARE"
                if let Some(colon) = after_at.find(':') {
                    let host = &after_at[..colon];
                    let after_colon = &after_at[colon + 1..];
                    if let Some(slash) = after_colon.find('/') {
                        let port: u16 = after_colon[..slash].parse().unwrap_or(0);
                        let share = &after_colon[slash + 1..];
                        // Accept: host is "localhost", "SHARE.localhost", or "SHARE"
                        let is_ours = host == "localhost"
                            || host == share
                            || host.strip_suffix(".localhost").is_some_and(|h| h == share);
                        if port > 0 && is_ours {
                            mounts.push(MountInfo {
                                share: share.to_string(),
                                port,
                                path: path.to_string(),
                            });
                        }
                    }
                }
            }
        }
    }
    mounts
}

/// Kill the mounter process listening on the given port.
fn kill_server(port: u16) -> bool {
    let output = match Command::new("lsof")
        .args(["-ti", &format!(":{port}")])
        .output()
    {
        Ok(o) => o,
        Err(_) => return false,
    };
    let pids = String::from_utf8_lossy(&output.stdout);
    let mut killed = false;
    for pid_str in pids.split_whitespace() {
        if let Ok(pid) = pid_str.parse::<u32>() {
            // Verify it's actually mounter before killing
            if let Ok(ps) = Command::new("ps")
                .args(["-p", &pid.to_string(), "-o", "comm="])
                .output()
            {
                let comm = String::from_utf8_lossy(&ps.stdout);
                if comm.trim().contains("mounter") {
                    let _ = Command::new("kill").arg(pid.to_string()).status();
                    eprintln!("  killed server pid {pid}");
                    killed = true;
                }
            }
        }
    }
    killed
}

/// Unmount a single mount with escalating force.
fn unmount_one(info: &MountInfo) -> bool {
    eprintln!("Unmounting {} ({})", info.share, info.path);

    // Strategy 1: normal umount
    if Command::new("umount")
        .arg(&info.path)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        eprintln!("  unmounted");
        kill_server(info.port);
        return true;
    }

    // Strategy 2: platform-specific
    if is_macos() {
        if Command::new("diskutil")
            .args(["unmount", &info.path])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            eprintln!("  unmounted (diskutil)");
            kill_server(info.port);
            return true;
        }
    }

    // Strategy 3: kill the server first, then force unmount.
    // Killing the server drops the TCP connection, which makes the OS
    // release the mount more willingly.
    eprintln!("  mount busy — killing server and force-unmounting");
    kill_server(info.port);
    std::thread::sleep(std::time::Duration::from_millis(500));

    let force_ok = if is_macos() {
        Command::new("diskutil")
            .args(["unmount", "force", &info.path])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    } else {
        // Linux: lazy unmount detaches immediately
        Command::new("umount")
            .args(["-l", &info.path])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    };

    if force_ok {
        eprintln!("  force-unmounted");
        return true;
    }

    eprintln!("  failed to unmount {}", info.path);
    false
}

fn cmd_unmount(target: &str) -> i32 {
    let mounts = find_smb_mounts();
    if mounts.is_empty() {
        eprintln!("No active mounter mounts found.");
        return 1;
    }

    if target == "all" {
        let mut failures = 0;
        for m in &mounts {
            if !unmount_one(m) {
                failures += 1;
            }
        }
        return if failures > 0 { 1 } else { 0 };
    }

    // Match by share name or mount path
    let matched: Vec<&MountInfo> = mounts
        .iter()
        .filter(|m| {
            m.share == target || m.path == target || m.path.ends_with(&format!("/{target}"))
        })
        .collect();

    if matched.is_empty() {
        eprintln!("No mount matching '{target}'. Active mounts:");
        for m in &mounts {
            eprintln!("  {} → {}", m.share, m.path);
        }
        return 1;
    }

    let mut failures = 0;
    for m in matched {
        if !unmount_one(m) {
            failures += 1;
        }
    }
    if failures > 0 { 1 } else { 0 }
}

fn cmd_list() {
    let mounts = find_smb_mounts();
    if mounts.is_empty() {
        println!("No active mounter mounts.");
        return;
    }
    for m in &mounts {
        println!("{:<20} {} (port {})", m.share, m.path, m.port);
    }
}

fn parse_remote(spec: &str) -> (Option<String>, String, String) {
    let mut rest = spec.to_string();
    let mut user = None;
    if let Some(at) = rest.find('@') {
        user = Some(rest[..at].to_string());
        rest = rest[at + 1..].to_string();
    }
    if let Some(colon) = rest.find(':') {
        let host = rest[..colon].to_string();
        let path = rest[colon + 1..].to_string();
        (user, host, path)
    } else {
        (user, rest, String::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_remote_full() {
        let (u, h, p) = parse_remote("alice@host:/data");
        assert_eq!(u, Some("alice".to_string()));
        assert_eq!(h, "host");
        assert_eq!(p, "/data");
    }

    #[test]
    fn parse_remote_no_user() {
        let (u, h, p) = parse_remote("host:/data");
        assert_eq!(u, None);
        assert_eq!(h, "host");
        assert_eq!(p, "/data");
    }

    #[test]
    fn parse_remote_host_only() {
        let (u, h, p) = parse_remote("host");
        assert_eq!(u, None);
        assert_eq!(h, "host");
        assert_eq!(p, "");
    }
}
