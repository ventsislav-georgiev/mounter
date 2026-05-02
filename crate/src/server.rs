//! SMB2 server that translates filesystem operations to SFTP calls.
//!
//! Handles one macOS client connection. Implements the minimal SMB2 command
//! set that mount_smbfs needs: NEGOTIATE, SESSION_SETUP, TREE_CONNECT,
//! CREATE, CLOSE, READ, WRITE, QUERY_DIRECTORY, QUERY_INFO, SET_INFO.

use crate::sftp::{
    DirEntry, FileAttr, ReconnectingSftp, SSH_FXF_CREAT, SSH_FXF_READ, SSH_FXF_TRUNC,
    SSH_FXF_WRITE, SftpError,
};
use crate::smb2::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ── macOS noise filter ──────────────────────────────────────────────
// Files that macOS queries for every directory but never exist on Linux.

/// Match an SMB search pattern against a filename.
/// Supports '*' (any chars), '?' (single char), and literal matches.
pub fn smb_pattern_match(pattern: &str, name: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    // Case-insensitive comparison for exact match (SMB is case-insensitive)
    if !pattern.contains('*') && !pattern.contains('?') {
        return pattern.eq_ignore_ascii_case(name);
    }
    // Simple wildcard matching
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    wildcard_match(&p, &n, 0, 0)
}

fn wildcard_match(p: &[char], n: &[char], pi: usize, ni: usize) -> bool {
    if pi == p.len() {
        return ni == n.len();
    }
    if p[pi] == '*' {
        // '*' matches zero or more characters
        for skip in 0..=n.len().saturating_sub(ni) {
            if wildcard_match(p, n, pi + 1, ni + skip) {
                return true;
            }
        }
        false
    } else if ni < n.len()
        && (p[pi] == '?' || p[pi].to_ascii_lowercase() == n[ni].to_ascii_lowercase())
    {
        wildcard_match(p, n, pi + 1, ni + 1)
    } else {
        false
    }
}

pub fn is_apple_metadata(name: &str) -> bool {
    name == ".DS_Store"
        || name == ".localized"
        || name == ".hidden"
        || name.starts_with("._")
        || name == "Icon\r"
        || name == ".Spotlight-V100"
        || name == ".Trashes"
        || name == ".fseventsd"
        || name == ".TemporaryItems"
        || name == ".com.apple.timemachine.donotpresent"
        || name == ".metadata_never_index"
        || name == ".metadata_never_index_unless_rootfs"
        || name == ".metadata_direct_scope_only"
        || name == "mdssvc"
        || name == "MsFteWds"
}

/// Files we fake as existing empty files in the share root so macOS
/// Spotlight skips indexing the entire volume.
fn is_spotlight_inhibitor(name: &str) -> bool {
    name == ".metadata_never_index"
}

// ── Attr cache ──────────────────────────────────────────────────────

const CACHE_TTL_SECS: u64 = 60;
const NEG_CACHE_TTL_SECS: u64 = 120; // longer for negative since Apple metadata never exists
const READAHEAD_SIZE: u32 = 2 * 1024 * 1024; // 2 MB speculative read-ahead

pub struct CachedAttr {
    attr: FileAttr,
    is_dir: bool,
    expires: Instant,
}

pub struct AttrCache {
    positive: HashMap<String, CachedAttr>,
    negative: HashMap<String, Instant>,
}

impl AttrCache {
    pub fn new() -> Self {
        AttrCache {
            positive: HashMap::new(),
            negative: HashMap::new(),
        }
    }

    pub fn get(&self, path: &str) -> Option<(&FileAttr, bool)> {
        self.positive.get(path).and_then(|c| {
            if c.expires > Instant::now() {
                Some((&c.attr, c.is_dir))
            } else {
                None
            }
        })
    }

    pub fn is_negative(&self, path: &str) -> bool {
        self.negative
            .get(path)
            .map(|exp| *exp > Instant::now())
            .unwrap_or(false)
    }

    pub fn insert(&mut self, path: String, attr: FileAttr, is_dir: bool) {
        self.negative.remove(&path);
        self.positive.insert(
            path,
            CachedAttr {
                attr,
                is_dir,
                expires: Instant::now() + std::time::Duration::from_secs(CACHE_TTL_SECS),
            },
        );
    }

    pub fn insert_negative(&mut self, path: String) {
        let ttl = if is_apple_metadata(path.rsplit('/').next().unwrap_or("")) {
            NEG_CACHE_TTL_SECS
        } else {
            CACHE_TTL_SECS / 2
        };
        self.negative
            .insert(path, Instant::now() + std::time::Duration::from_secs(ttl));
    }

    pub fn invalidate(&mut self, path: &str) {
        self.positive.remove(path);
        self.negative.remove(path);
    }

    /// Remove expired entries periodically to prevent unbounded growth.
    pub fn evict_expired(&mut self) {
        let now = Instant::now();
        self.positive.retain(|_, c| c.expires > now);
        self.negative.retain(|_, exp| *exp > now);
    }

    pub fn insert_dir_entries(&mut self, parent: &str, entries: &[DirEntry]) {
        for e in entries {
            let child = format!("{parent}/{}", e.name);
            let is_dir = e.attrs.perm & 0o40000 != 0;
            self.insert(child, e.attrs.clone(), is_dir);
        }
    }
}

// ── Directory listing cache (session-level) ─────────────────────────
// macOS sends per-file CREATE+QUERY_DIRECTORY+CLOSE compounds for stat
// lookups.  Without this cache, each compound triggers a full SFTP readdir.

const DIR_CACHE_TTL_SECS: u64 = 60;

pub struct CachedDir {
    entries: Arc<Vec<DirEntry>>,
    expires: Instant,
}

pub struct DirCache {
    dirs: HashMap<String, CachedDir>,
}

impl DirCache {
    pub fn new() -> Self {
        DirCache {
            dirs: HashMap::new(),
        }
    }

    pub fn get(&self, path: &str) -> Option<Arc<Vec<DirEntry>>> {
        self.dirs.get(path).and_then(|c| {
            if c.expires > Instant::now() {
                Some(Arc::clone(&c.entries))
            } else {
                None
            }
        })
    }

    pub fn insert(&mut self, path: String, entries: Vec<DirEntry>) {
        self.dirs.insert(
            path,
            CachedDir {
                entries: Arc::new(entries),
                expires: Instant::now() + Duration::from_secs(DIR_CACHE_TTL_SECS),
            },
        );
    }

    pub fn invalidate(&mut self, path: &str) {
        self.dirs.remove(path);
    }

    pub fn evict_expired(&mut self) {
        let now = Instant::now();
        self.dirs.retain(|_, c| c.expires > now);
    }
}

// ── Open file/dir handles ───────────────────────────────────────────

/// Read cache: cache each SFTP read so small follow-up reads (macOS
/// sends 2KB resource-fork probes after each 512KB read) are served
/// without an extra SFTP round-trip.

struct ReadAhead {
    data: Vec<u8>,
    offset: u64, // start offset of buffered data
}

struct OpenHandle {
    sftp_handle: Option<Vec<u8>>, // None for directories
    path: String,
    is_dir: bool,
    is_pipe: bool,
    pipe_response: Option<Vec<u8>>, // buffered DCE/RPC response for named pipes
    dir_entries: Option<Arc<Vec<DirEntry>>>, // shared with dir_cache
    dir_offset: usize,
    readahead: Option<ReadAhead>,
}

// ── SMB2 Server Session ─────────────────────────────────────────────

pub struct SmbSession {
    sftp: Arc<ReconnectingSftp>,
    root_path: String,
    share_name: String,
    session_id: u64,
    tree_id: u32,
    next_tree_id: u32,
    ipc_tree_id: Option<u32>,
    handles: HashMap<u64, OpenHandle>,
    next_handle: u64,
    cache: AttrCache,
    dir_cache: DirCache,
    auth_phase: u8,
    /// Last handle created — used for related compound requests where
    /// QUERY_INFO/CLOSE reference FileId=0xFFFFFFFF meaning "use CREATE's handle."
    last_create_handle: u64,
    msg_count: u64,
}

impl SmbSession {
    pub fn new(sftp: Arc<ReconnectingSftp>, root_path: String, share_name: String) -> Self {
        SmbSession {
            sftp,
            root_path,
            share_name,
            session_id: 0x0000_0001_0000_0001,
            tree_id: 1,
            next_tree_id: 2,
            ipc_tree_id: None,
            handles: HashMap::new(),
            next_handle: 1,
            cache: AttrCache::new(),
            dir_cache: DirCache::new(),
            auth_phase: 0,
            last_create_handle: 0,
            msg_count: 0,
        }
    }

    /// Resolve FileId — handles 0xFFFFFFFFFFFFFFFF sentinel for related compounds.
    fn resolve_fid(&self, fid: u64) -> u64 {
        if fid == 0xFFFF_FFFF_FFFF_FFFF {
            self.last_create_handle
        } else {
            fid
        }
    }

    /// Invalidate all caches for a path (attr + parent dir listing).
    fn invalidate_path(&mut self, path: &str) {
        self.cache.invalidate(path);
        if let Some((parent, _)) = path.rsplit_once('/') {
            self.dir_cache.invalidate(parent);
        }
    }

    /// Called after SFTP reconnect — all SFTP file handles are dead,
    /// and remote state may have changed.
    fn on_reconnect(&mut self) {
        log::info!("Flushing caches and handles after reconnect");
        // Invalidate all SFTP handles — they belong to the dead session
        for (_id, handle) in self.handles.iter_mut() {
            handle.sftp_handle = None;
            handle.readahead = None;
        }
        // Flush all caches — remote state may have changed
        self.cache = AttrCache::new();
        self.dir_cache = DirCache::new();
    }

    fn full_path(&self, rel: &str) -> String {
        if rel.is_empty() || rel == "\\" || rel == "/" {
            self.root_path.clone()
        } else {
            let normalized = rel.replace('\\', "/");
            let trimmed = normalized.trim_start_matches('/');
            format!("{}/{}", self.root_path, trimmed)
        }
    }

    fn alloc_handle(&mut self) -> u64 {
        let h = self.next_handle;
        self.next_handle += 1;
        h
    }

    fn stat_cached(&mut self, path: &str) -> Result<(FileAttr, bool), u32> {
        if let Some((attr, is_dir)) = self.cache.get(path) {
            return Ok((attr.clone(), is_dir));
        }
        if self.cache.is_negative(path) {
            return Err(STATUS_OBJECT_NAME_NOT_FOUND);
        }

        // Check macOS noise — skip SFTP for known-absent files
        let basename = path.rsplit('/').next().unwrap_or("");
        if is_apple_metadata(basename) {
            self.cache.insert_negative(path.to_string());
            return Err(STATUS_OBJECT_NAME_NOT_FOUND);
        }

        match self.sftp.lstat(path) {
            Ok(attr) => {
                let is_dir = attr.perm & 0o40000 != 0;
                self.cache.insert(path.to_string(), attr.clone(), is_dir);
                Ok((attr, is_dir))
            }
            Err(SftpError::Status(2, _)) => {
                self.cache.insert_negative(path.to_string());
                Err(STATUS_OBJECT_NAME_NOT_FOUND)
            }
            Err(_) => Err(STATUS_ACCESS_DENIED),
        }
    }

    // ── Command dispatch ────────────────────────────────────────────

    pub fn handle_message(&mut self, msg: &[u8]) -> Vec<u8> {
        // Periodic cache eviction every 256 messages
        self.msg_count += 1;
        if self.msg_count % 256 == 0 {
            self.cache.evict_expired();
            self.dir_cache.evict_expired();
        }

        let hdr = match Smb2Header::parse(msg) {
            Some(h) => h,
            None => return Vec::new(),
        };
        let body = &msg[SMB2_HEADER_SIZE..];

        let mut response = Vec::new();
        match hdr.command {
            SMB2_NEGOTIATE => self.handle_negotiate(&hdr, body, &mut response),
            SMB2_SESSION_SETUP => self.handle_session_setup(&hdr, body, &mut response),
            SMB2_LOGOFF => self.handle_logoff(&hdr, &mut response),
            SMB2_TREE_CONNECT => self.handle_tree_connect(&hdr, body, &mut response),
            SMB2_TREE_DISCONNECT => self.handle_tree_disconnect(&hdr, &mut response),
            SMB2_CREATE => self.handle_create(&hdr, body, &mut response),
            SMB2_CLOSE => self.handle_close(&hdr, body, &mut response),
            SMB2_READ => self.handle_read(&hdr, body, &mut response),
            SMB2_WRITE => self.handle_write(&hdr, body, &mut response),
            SMB2_LOCK => self.handle_lock(&hdr, &mut response),
            SMB2_QUERY_DIRECTORY => self.handle_query_directory(&hdr, body, &mut response),
            SMB2_QUERY_INFO => self.handle_query_info(&hdr, body, &mut response),
            SMB2_SET_INFO => self.handle_set_info(&hdr, body, &mut response),
            SMB2_FLUSH => self.handle_flush(&hdr, &mut response),
            SMB2_IOCTL => self.handle_ioctl(&hdr, body, &mut response),
            _ => {
                log::warn!("Unsupported SMB2 command: 0x{:04x}", hdr.command);
                self.error_response(&hdr, STATUS_NOT_SUPPORTED, &mut response);
            }
        }
        response
    }

    fn error_response(&self, hdr: &Smb2Header, status: u32, out: &mut Vec<u8>) {
        // 9-byte error response body
        let mut body = Vec::with_capacity(9);
        body.extend_from_slice(&9u16.to_le_bytes()); // StructureSize
        body.push(0); // ErrorContextCount
        body.push(0); // Reserved
        body.extend_from_slice(&0u32.to_le_bytes()); // ByteCount
        body.push(0); // ErrorData (1 byte padding)
        hdr.write_response(status, &body, out);
    }

    // ── NEGOTIATE ───────────────────────────────────────────────────

    fn handle_negotiate(&mut self, hdr: &Smb2Header, body: &[u8], out: &mut Vec<u8>) {
        // Parse client's requested dialects to pick the best one
        let dialect_count = if body.len() >= 4 {
            read_u16_le(body, 2) as usize
        } else {
            0
        };
        // Force SMB 2.0.2 — simplest dialect, no signing needed for guest.
        // SMB 3.x requires signing which breaks unsigned guest sessions.
        let _ = dialect_count;
        let best_dialect = SMB2_DIALECT_202;
        log::info!("Negotiated dialect: 0x{:04x}", best_dialect);

        let spnego = build_spnego_negotiate_token();

        let mut resp = Vec::with_capacity(128 + spnego.len());
        resp.extend_from_slice(&65u16.to_le_bytes()); // StructureSize
        resp.extend_from_slice(&1u16.to_le_bytes()); // SecurityMode: SIGNING_ENABLED
        resp.extend_from_slice(&best_dialect.to_le_bytes()); // DialectRevision
        resp.extend_from_slice(&0u16.to_le_bytes()); // Reserved

        // ServerGuid (16 bytes)
        resp.extend_from_slice(&[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ]);
        resp.extend_from_slice(&7u32.to_le_bytes()); // Capabilities: DFS | LEASING | LARGE_MTU
        resp.extend_from_slice(&(8 * 1024 * 1024u32).to_le_bytes()); // MaxTransactSize: 8 MB
        resp.extend_from_slice(&(8 * 1024 * 1024u32).to_le_bytes()); // MaxReadSize: 8 MB
        resp.extend_from_slice(&(8 * 1024 * 1024u32).to_le_bytes()); // MaxWriteSize: 8 MB

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        resp.extend_from_slice(&unix_to_filetime(now).to_le_bytes()); // SystemTime
        resp.extend_from_slice(&unix_to_filetime(now).to_le_bytes()); // ServerStartTime

        // SecurityBuffer at offset 128 from start of SMB2 header (64 hdr + 64 body fields)
        resp.extend_from_slice(&128u16.to_le_bytes()); // SecurityBufferOffset
        resp.extend_from_slice(&(spnego.len() as u16).to_le_bytes()); // SecurityBufferLength
        resp.extend_from_slice(&0u32.to_le_bytes()); // Reserved2
        resp.extend_from_slice(&spnego);

        hdr.write_response(STATUS_SUCCESS, &resp, out);
    }

    // ── SESSION_SETUP ───────────────────────────────────────────────

    fn handle_session_setup(&mut self, hdr: &Smb2Header, body: &[u8], out: &mut Vec<u8>) {
        self.auth_phase += 1;
        log::info!("SESSION_SETUP phase {}", self.auth_phase);

        // Extract client's security buffer (SPNEGO wrapping NTLMSSP)
        // MS-SMB2 2.2.5: SecurityBufferOffset at body[12], Length at body[14]
        let sec_offset = if body.len() >= 14 {
            read_u16_le(body, 12) as usize
        } else {
            0
        };
        let sec_length = if body.len() >= 16 {
            read_u16_le(body, 14) as usize
        } else {
            0
        };
        let sec_start = sec_offset.saturating_sub(SMB2_HEADER_SIZE);
        let sec_data = if sec_start + sec_length <= body.len() {
            &body[sec_start..sec_start + sec_length]
        } else {
            &[]
        };

        // Detect NTLMSSP message type inside SPNEGO wrapper
        let ntlmssp_type = sec_data
            .windows(12)
            .find(|w| w.starts_with(b"NTLMSSP\0"))
            .map(|w| u32::from_le_bytes([w[8], w[9], w[10], w[11]]));

        log::info!(
            "SESSION_SETUP: sec_offset={sec_offset} sec_length={sec_length} ntlmssp_type={:?}",
            ntlmssp_type
        );

        if ntlmssp_type == Some(1) {
            // Phase 1: extract client's NTLMSSP flags, build matching challenge

            // Find client's negotiate flags
            let client_flags = sec_data
                .windows(12)
                .find(|w| w.starts_with(b"NTLMSSP\0"))
                .and_then(|w| {
                    if w.len() >= 16 {
                        Some(u32::from_le_bytes([w[12], w[13], w[14], w[15]]))
                    } else {
                        None
                    }
                })
                .unwrap_or(0xe2088233);

            // Build NTLMSSP_CHALLENGE with TargetInfo (required by Linux CIFS).
            // Flags: echo client flags, remove VERSION, add TARGET_TYPE_SERVER + TARGET_INFO.
            let server_flags = (client_flags & !0x02000000) | 0x00020000 | 0x00800000;

            // Build TargetInfo AV_PAIRs (required by Linux kernel CIFS driver)
            let target_name_utf16 = to_utf16le("SSHFS");
            let mut target_info = Vec::with_capacity(64);
            // MsvAvNbDomainName (2) = "SSHFS"
            target_info.extend_from_slice(&2u16.to_le_bytes());
            target_info.extend_from_slice(&(target_name_utf16.len() as u16).to_le_bytes());
            target_info.extend_from_slice(&target_name_utf16);
            // MsvAvNbComputerName (1) = "SSHFS"
            target_info.extend_from_slice(&1u16.to_le_bytes());
            target_info.extend_from_slice(&(target_name_utf16.len() as u16).to_le_bytes());
            target_info.extend_from_slice(&target_name_utf16);
            // MsvAvDnsDomainName (4) = ""
            target_info.extend_from_slice(&4u16.to_le_bytes());
            target_info.extend_from_slice(&0u16.to_le_bytes());
            // MsvAvDnsComputerName (3) = "sshfs"
            let dns_name = to_utf16le("sshfs");
            target_info.extend_from_slice(&3u16.to_le_bytes());
            target_info.extend_from_slice(&(dns_name.len() as u16).to_le_bytes());
            target_info.extend_from_slice(&dns_name);
            // MsvAvTimestamp (7) = current FILETIME
            let now_ft = unix_to_filetime(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            );
            target_info.extend_from_slice(&7u16.to_le_bytes());
            target_info.extend_from_slice(&8u16.to_le_bytes());
            target_info.extend_from_slice(&now_ft.to_le_bytes());
            // MsvAvEOL (0) — terminator
            target_info.extend_from_slice(&0u16.to_le_bytes());
            target_info.extend_from_slice(&0u16.to_le_bytes());

            // Fixed header is 48 bytes, TargetName starts at 48, TargetInfo after that
            let target_name_offset = 48u32;
            let target_info_offset = target_name_offset + target_name_utf16.len() as u32;

            let mut challenge =
                Vec::with_capacity(48 + target_name_utf16.len() + target_info.len());
            challenge.extend_from_slice(b"NTLMSSP\0"); // 0: Signature
            challenge.extend_from_slice(&2u32.to_le_bytes()); // 8: Type=CHALLENGE
            // TargetName fields
            challenge.extend_from_slice(&(target_name_utf16.len() as u16).to_le_bytes()); // 12
            challenge.extend_from_slice(&(target_name_utf16.len() as u16).to_le_bytes()); // 14
            challenge.extend_from_slice(&target_name_offset.to_le_bytes()); // 16
            challenge.extend_from_slice(&server_flags.to_le_bytes()); // 20: NegotiateFlags
            // ServerChallenge (8 bytes)
            challenge.extend_from_slice(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]); // 24
            challenge.extend_from_slice(&[0u8; 8]); // 32: Reserved
            // TargetInfo fields
            challenge.extend_from_slice(&(target_info.len() as u16).to_le_bytes()); // 40
            challenge.extend_from_slice(&(target_info.len() as u16).to_le_bytes()); // 42
            challenge.extend_from_slice(&target_info_offset.to_le_bytes()); // 44
            // Payload: TargetName + TargetInfo
            challenge.extend_from_slice(&target_name_utf16);
            challenge.extend_from_slice(&target_info);

            log::info!(
                "NTLMSSP challenge: client_flags=0x{client_flags:08x} server_flags=0x{server_flags:08x}"
            );

            // Wrap in SPNEGO negTokenResp
            let spnego = wrap_ntlmssp_in_spnego(&challenge);

            let mut resp = Vec::with_capacity(16 + spnego.len());
            resp.extend_from_slice(&9u16.to_le_bytes());
            resp.extend_from_slice(&0u16.to_le_bytes()); // SessionFlags: 0
            let sec_off = (SMB2_HEADER_SIZE + 8) as u16;
            resp.extend_from_slice(&sec_off.to_le_bytes());
            resp.extend_from_slice(&(spnego.len() as u16).to_le_bytes());
            resp.extend_from_slice(&spnego);

            let mut full_hdr = hdr.clone();
            full_hdr.session_id = self.session_id;
            full_hdr.write_response(STATUS_MORE_PROCESSING, &resp, out);

            log::info!("Sent NTLMSSP challenge in SPNEGO ({} bytes)", spnego.len());
            // Dump the SPNEGO for debugging
            log::debug!("SPNEGO challenge hex: {}", hex_dump(&spnego, 128));
        } else {
            // Phase 2 (NTLMSSP_AUTH type=3) or any follow-up: accept as guest
            let accept = spnego_accept_complete();

            let mut resp = Vec::with_capacity(16 + accept.len());
            resp.extend_from_slice(&9u16.to_le_bytes());
            resp.extend_from_slice(&1u16.to_le_bytes()); // SessionFlags: IS_GUEST
            let sec_off = (SMB2_HEADER_SIZE + 8) as u16;
            resp.extend_from_slice(&sec_off.to_le_bytes());
            resp.extend_from_slice(&(accept.len() as u16).to_le_bytes());
            resp.extend_from_slice(&accept);

            let mut full_hdr = hdr.clone();
            full_hdr.session_id = self.session_id;
            full_hdr.write_response(STATUS_SUCCESS, &resp, out);
            log::info!("Session accepted as guest (phase {})", self.auth_phase);
            self.auth_phase = 0;
        }
    }

    // ── LOGOFF ──────────────────────────────────────────────────────

    fn handle_logoff(&mut self, hdr: &Smb2Header, out: &mut Vec<u8>) {
        let mut resp = Vec::with_capacity(4);
        resp.extend_from_slice(&4u16.to_le_bytes()); // StructureSize
        resp.extend_from_slice(&0u16.to_le_bytes()); // Reserved
        hdr.write_response(STATUS_SUCCESS, &resp, out);
    }

    // ── TREE_CONNECT ────────────────────────────────────────────────

    fn handle_tree_connect(&mut self, hdr: &Smb2Header, body: &[u8], out: &mut Vec<u8>) {
        // Parse the share path from the request (\\server\share in UTF-16LE)
        let mut is_ipc = false;
        if body.len() >= 8 {
            let path_offset = read_u16_le(body, 4) as usize;
            let path_length = read_u16_le(body, 6) as usize;
            let path_start = path_offset.saturating_sub(SMB2_HEADER_SIZE);
            if path_start + path_length <= body.len() {
                let path = from_utf16le(&body[path_start..path_start + path_length]);
                is_ipc = path.to_ascii_uppercase().ends_with("\\IPC$");
            }
        }

        let (share_type, tid) = if is_ipc {
            let tid = self.next_tree_id;
            self.next_tree_id += 1;
            self.ipc_tree_id = Some(tid);
            log::debug!("Tree connected: IPC$ (tid={tid})");
            (0x02u8, tid) // ShareType: PIPE
        } else {
            log::debug!("Tree connected: share={}", self.share_name);
            (0x01u8, self.tree_id) // ShareType: DISK
        };

        let mut resp = Vec::with_capacity(16);
        resp.extend_from_slice(&16u16.to_le_bytes()); // StructureSize
        resp.push(share_type);
        resp.push(0); // Reserved
        resp.extend_from_slice(&0x0000_0030u32.to_le_bytes()); // ShareFlags
        resp.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
        resp.extend_from_slice(&0x001F01FFu32.to_le_bytes()); // MaximalAccess

        let mut full_hdr = hdr.clone();
        full_hdr.tree_id = tid;
        full_hdr.write_response(STATUS_SUCCESS, &resp, out);
    }

    // ── TREE_DISCONNECT ─────────────────────────────────────────────

    fn handle_tree_disconnect(&mut self, hdr: &Smb2Header, out: &mut Vec<u8>) {
        let mut resp = Vec::with_capacity(4);
        resp.extend_from_slice(&4u16.to_le_bytes());
        resp.extend_from_slice(&0u16.to_le_bytes());
        hdr.write_response(STATUS_SUCCESS, &resp, out);
    }

    // ── CREATE (open file/directory) ────────────────────────────────

    fn handle_create(&mut self, hdr: &Smb2Header, body: &[u8], out: &mut Vec<u8>) {
        if body.len() < 48 {
            self.error_response(hdr, STATUS_INVALID_PARAMETER, out);
            return;
        }

        // MS-SMB2 2.2.13 CREATE Request body layout:
        // 0-1: StructureSize=57, 2: SecurityFlags, 3: OplockLevel
        // 4-7: ImpersonationLevel, 8-15: SmbCreateFlags, 16-23: Reserved
        let _desired_access = read_u32_le(body, 24);
        let _file_attributes = read_u32_le(body, 28);
        let _share_access = read_u32_le(body, 32);
        let create_disposition = read_u32_le(body, 36);
        let create_options = read_u32_le(body, 40);
        let name_offset = read_u16_le(body, 44) as usize;
        let name_length = read_u16_le(body, 46) as usize;

        // Extract filename (UTF-16LE, offset from start of SMB2 header)
        let name_start = name_offset.saturating_sub(SMB2_HEADER_SIZE);
        let rel_name = if name_length > 0 && name_start + name_length <= body.len() {
            from_utf16le(&body[name_start..name_start + name_length])
        } else {
            String::new()
        };

        // IPC$ pipe: handle named pipes for share enumeration
        if self.ipc_tree_id == Some(hdr.tree_id) {
            let pipe_name = rel_name.to_ascii_lowercase();
            if pipe_name == "srvsvc" {
                log::debug!("CREATE: opening pipe srvsvc");
                let handle_id = self.alloc_handle();
                self.last_create_handle = handle_id;
                self.handles.insert(
                    handle_id,
                    OpenHandle {
                        sftp_handle: None,
                        path: "srvsvc".into(),
                        is_dir: false,
                        is_pipe: true,
                        pipe_response: None,
                        dir_entries: None,
                        dir_offset: 0,
                        readahead: None,
                    },
                );
                // Minimal CREATE response for a pipe
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let ft = unix_to_filetime(now);
                let mut resp = Vec::with_capacity(96);
                resp.extend_from_slice(&89u16.to_le_bytes());
                resp.push(0);
                resp.push(0);
                resp.extend_from_slice(&1u32.to_le_bytes()); // FILE_OPENED
                for _ in 0..4 {
                    resp.extend_from_slice(&ft.to_le_bytes());
                }
                resp.extend_from_slice(&0u64.to_le_bytes()); // AllocationSize
                resp.extend_from_slice(&0u64.to_le_bytes()); // EndOfFile
                resp.extend_from_slice(&0x00000080u32.to_le_bytes()); // FILE_ATTRIBUTE_NORMAL
                resp.extend_from_slice(&0u32.to_le_bytes()); // Reserved2
                resp.extend_from_slice(&handle_id.to_le_bytes());
                resp.extend_from_slice(&handle_id.to_le_bytes());
                resp.extend_from_slice(&0u32.to_le_bytes()); // CreateContextsOffset
                resp.extend_from_slice(&0u32.to_le_bytes()); // CreateContextsLength
                hdr.write_response(STATUS_SUCCESS, &resp, out);
            } else {
                self.error_response(hdr, STATUS_OBJECT_NAME_NOT_FOUND, out);
            }
            return;
        }

        let path = self.full_path(&rel_name);
        let want_dir = create_options & FILE_DIRECTORY_FILE != 0;

        log::debug!("CREATE: path={path} disposition={create_disposition} dir={want_dir}");

        // Fake Spotlight-inhibitor files so macOS doesn't recursively index the volume
        let basename = rel_name.rsplit(['/', '\\']).next().unwrap_or("");
        if is_spotlight_inhibitor(basename) && !rel_name.contains('/') && !rel_name.contains('\\') {
            let now_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as u32;
            let fake_attr = FileAttr {
                size: 0,
                uid: 0,
                gid: 0,
                perm: 0o100444,
                atime: now_secs,
                mtime: now_secs,
            };
            self.respond_create_success(hdr, &path, &fake_attr, false, out);
            return;
        }

        // Handle create dispositions
        // FILE_SUPERSEDE (0) is treated as FILE_OPEN for existing files (macOS uses it for share root)
        match create_disposition {
            FILE_SUPERSEDE | FILE_OPEN | FILE_OPEN_IF => {
                match self.stat_cached(&path) {
                    Ok((attr, is_dir)) => {
                        self.respond_create_success(hdr, &path, &attr, is_dir, out);
                    }
                    Err(_) if create_disposition == FILE_OPEN_IF => {
                        // Create it
                        if want_dir {
                            if let Err(e) = self.sftp.mkdir(&path, 0o755) {
                                log::warn!("mkdir failed: {e}");
                                self.error_response(hdr, STATUS_ACCESS_DENIED, out);
                                return;
                            }
                            self.invalidate_path(&path);
                            match self.stat_cached(&path) {
                                Ok((attr, is_dir)) => {
                                    self.respond_create_success(hdr, &path, &attr, is_dir, out);
                                }
                                Err(s) => self.error_response(hdr, s, out),
                            }
                        } else {
                            match self.sftp.open(
                                &path,
                                SSH_FXF_CREAT | SSH_FXF_READ | SSH_FXF_WRITE,
                                0o644,
                            ) {
                                Ok(sftp_handle) => {
                                    let _ = self.sftp.close(&sftp_handle);
                                    self.invalidate_path(&path);
                                    match self.stat_cached(&path) {
                                        Ok((attr, is_dir)) => {
                                            self.respond_create_success(
                                                hdr, &path, &attr, is_dir, out,
                                            );
                                        }
                                        Err(s) => self.error_response(hdr, s, out),
                                    }
                                }
                                Err(_) => self.error_response(hdr, STATUS_ACCESS_DENIED, out),
                            }
                        }
                    }
                    Err(s) => self.error_response(hdr, s, out),
                }
            }
            FILE_CREATE => {
                if self.stat_cached(&path).is_ok() {
                    self.error_response(hdr, STATUS_OBJECT_NAME_COLLISION, out);
                    return;
                }
                if want_dir {
                    if let Err(_) = self.sftp.mkdir(&path, 0o755) {
                        self.error_response(hdr, STATUS_ACCESS_DENIED, out);
                        return;
                    }
                } else {
                    match self.sftp.open(
                        &path,
                        SSH_FXF_CREAT | SSH_FXF_WRITE | SSH_FXF_TRUNC,
                        0o644,
                    ) {
                        Ok(h) => {
                            let _ = self.sftp.close(&h);
                        }
                        Err(_) => {
                            self.error_response(hdr, STATUS_ACCESS_DENIED, out);
                            return;
                        }
                    }
                }
                self.invalidate_path(&path);
                match self.stat_cached(&path) {
                    Ok((attr, is_dir)) => {
                        self.respond_create_success(hdr, &path, &attr, is_dir, out);
                    }
                    Err(s) => self.error_response(hdr, s, out),
                }
            }
            FILE_OVERWRITE | FILE_OVERWRITE_IF => {
                match self
                    .sftp
                    .open(&path, SSH_FXF_CREAT | SSH_FXF_TRUNC | SSH_FXF_WRITE, 0o644)
                {
                    Ok(h) => {
                        let _ = self.sftp.close(&h);
                    }
                    Err(_) => {
                        self.error_response(hdr, STATUS_ACCESS_DENIED, out);
                        return;
                    }
                }
                self.invalidate_path(&path);
                match self.stat_cached(&path) {
                    Ok((attr, is_dir)) => {
                        self.respond_create_success(hdr, &path, &attr, is_dir, out);
                    }
                    Err(s) => self.error_response(hdr, s, out),
                }
            }
            _ => self.error_response(hdr, STATUS_INVALID_PARAMETER, out),
        }
    }

    fn respond_create_success(
        &mut self,
        hdr: &Smb2Header,
        path: &str,
        attr: &FileAttr,
        is_dir: bool,
        out: &mut Vec<u8>,
    ) {
        let handle_id = self.alloc_handle();
        self.last_create_handle = handle_id;
        self.handles.insert(
            handle_id,
            OpenHandle {
                sftp_handle: None, // opened lazily on read/write
                path: path.to_string(),
                is_dir,
                is_pipe: false,
                pipe_response: None,
                dir_entries: None,
                dir_offset: 0,
                readahead: None,
            },
        );

        let ft_create = unix_to_filetime(attr.mtime as u64);
        let ft_access = unix_to_filetime(attr.atime as u64);
        let ft_write = unix_to_filetime(attr.mtime as u64);
        let ft_change = unix_to_filetime(attr.mtime as u64);
        let file_attrs = if is_dir {
            FILE_ATTRIBUTE_DIRECTORY
        } else {
            FILE_ATTRIBUTE_ARCHIVE
        };

        let mut resp = Vec::with_capacity(96);
        resp.extend_from_slice(&89u16.to_le_bytes()); // StructureSize
        resp.push(0); // OplockLevel: none
        resp.push(0); // Flags
        resp.extend_from_slice(&1u32.to_le_bytes()); // CreateAction: FILE_OPENED
        resp.extend_from_slice(&ft_create.to_le_bytes()); // CreationTime
        resp.extend_from_slice(&ft_access.to_le_bytes()); // LastAccessTime
        resp.extend_from_slice(&ft_write.to_le_bytes()); // LastWriteTime
        resp.extend_from_slice(&ft_change.to_le_bytes()); // ChangeTime
        resp.extend_from_slice(&attr.size.to_le_bytes()); // AllocationSize
        resp.extend_from_slice(&attr.size.to_le_bytes()); // EndOfFile
        resp.extend_from_slice(&file_attrs.to_le_bytes()); // FileAttributes
        resp.extend_from_slice(&0u32.to_le_bytes()); // Reserved2
        // FileId: persistent (8) + volatile (8)
        resp.extend_from_slice(&handle_id.to_le_bytes()); // FileId.Persistent
        resp.extend_from_slice(&handle_id.to_le_bytes()); // FileId.Volatile
        // CreateContexts
        resp.extend_from_slice(&0u32.to_le_bytes()); // CreateContextsOffset
        resp.extend_from_slice(&0u32.to_le_bytes()); // CreateContextsLength
        resp.push(0); // 1-byte variable part padding (StructureSize=89 means 88 fixed + 1)

        log::debug!(
            "CREATE OK: path={path} is_dir={is_dir} file_attrs=0x{file_attrs:08x} size={} handle={handle_id}",
            attr.size
        );
        hdr.write_response(STATUS_SUCCESS, &resp, out);
    }

    // ── CLOSE ───────────────────────────────────────────────────────

    fn handle_close(&mut self, hdr: &Smb2Header, body: &[u8], out: &mut Vec<u8>) {
        let fid = if body.len() >= 24 {
            self.resolve_fid(read_u64_le(body, 8)) // FileId.Persistent
        } else {
            0
        };

        if let Some(handle) = self.handles.remove(&fid) {
            if let Some(ref sftp_h) = handle.sftp_handle {
                let _ = self.sftp.close(sftp_h);
            }
        }

        let mut resp = Vec::with_capacity(60);
        resp.extend_from_slice(&60u16.to_le_bytes()); // StructureSize
        resp.extend_from_slice(&0u16.to_le_bytes()); // Flags
        resp.extend_from_slice(&0u32.to_le_bytes()); // Reserved
        resp.extend_from_slice(&[0u8; 48]); // Times + sizes (all zero = don't update)

        hdr.write_response(STATUS_SUCCESS, &resp, out);
    }

    // ── READ ────────────────────────────────────────────────────────

    fn handle_read(&mut self, hdr: &Smb2Header, body: &[u8], out: &mut Vec<u8>) {
        if body.len() < 32 {
            self.error_response(hdr, STATUS_INVALID_PARAMETER, out);
            return;
        }
        let length = read_u32_le(body, 4) as u64;
        let offset = read_u64_le(body, 8);
        let fid = self.resolve_fid(read_u64_le(body, 16));

        let handle = match self.handles.get_mut(&fid) {
            Some(h) => h,
            None => {
                self.error_response(hdr, STATUS_INVALID_PARAMETER, out);
                return;
            }
        };

        // Named pipe read: return buffered DCE/RPC response
        if handle.is_pipe {
            if let Some(data) = handle.pipe_response.take() {
                Self::write_read_response(hdr, &data, out);
            } else {
                self.error_response(hdr, STATUS_END_OF_FILE, out);
            }
            return;
        }

        // Lazy-open SFTP handle
        if handle.sftp_handle.is_none() {
            match self.sftp.open(&handle.path, SSH_FXF_READ, 0) {
                Ok(h) => handle.sftp_handle = Some(h),
                Err(_) => {
                    self.error_response(hdr, STATUS_ACCESS_DENIED, out);
                    return;
                }
            }
        }

        // Try to serve from read-ahead buffer first
        if let Some(ref ra) = handle.readahead {
            if offset >= ra.offset && offset + length <= ra.offset + ra.data.len() as u64 {
                let start = (offset - ra.offset) as usize;
                let end = start + length as usize;
                let data = &ra.data[start..end];
                Self::write_read_response(hdr, data, out);
                return;
            }
        }

        let sftp_h = handle.sftp_handle.as_ref().map(|h| h.clone());
        let path = handle.path.clone();
        let fetch_len = READAHEAD_SIZE.max(length as u32);
        match sftp_h {
            Some(ref h) => match self.sftp.read(h, offset, fetch_len) {
                Ok(data) if data.is_empty() => {
                    self.error_response(hdr, STATUS_END_OF_FILE, out);
                }
                Ok(data) => {
                    let respond_len = (length as usize).min(data.len());
                    Self::write_read_response(hdr, &data[..respond_len], out);
                    if let Some(h) = self.handles.get_mut(&fid) {
                        h.readahead = Some(ReadAhead { data, offset });
                    }
                }
                Err(SftpError::Disconnected) | Err(SftpError::Protocol(_)) => {
                    self.on_reconnect();
                    match self.sftp.open(&path, SSH_FXF_READ, 0) {
                        Ok(new_h) => match self.sftp.read(&new_h, offset, fetch_len) {
                            Ok(data) if data.is_empty() => {
                                self.error_response(hdr, STATUS_END_OF_FILE, out);
                            }
                            Ok(data) => {
                                let respond_len = (length as usize).min(data.len());
                                Self::write_read_response(hdr, &data[..respond_len], out);
                                if let Some(h) = self.handles.get_mut(&fid) {
                                    h.sftp_handle = Some(new_h);
                                    h.readahead = Some(ReadAhead { data, offset });
                                }
                            }
                            Err(_) => self.error_response(hdr, STATUS_ACCESS_DENIED, out),
                        },
                        Err(_) => self.error_response(hdr, STATUS_ACCESS_DENIED, out),
                    }
                }
                Err(_) => self.error_response(hdr, STATUS_ACCESS_DENIED, out),
            },
            None => self.error_response(hdr, STATUS_INVALID_PARAMETER, out),
        }
    }

    fn write_read_response(hdr: &Smb2Header, data: &[u8], out: &mut Vec<u8>) {
        let data_offset = SMB2_HEADER_SIZE as u16 + 16;
        let mut resp = Vec::with_capacity(16 + data.len());
        resp.extend_from_slice(&17u16.to_le_bytes()); // StructureSize
        resp.extend_from_slice(&data_offset.to_le_bytes()); // DataOffset
        resp.extend_from_slice(&(data.len() as u32).to_le_bytes()); // DataLength
        resp.extend_from_slice(&0u32.to_le_bytes()); // DataRemaining
        resp.extend_from_slice(&0u32.to_le_bytes()); // Reserved2
        resp.extend_from_slice(data);
        hdr.write_response(STATUS_SUCCESS, &resp, out);
    }

    // ── WRITE ───────────────────────────────────────────────────────

    fn handle_write(&mut self, hdr: &Smb2Header, body: &[u8], out: &mut Vec<u8>) {
        if body.len() < 32 {
            self.error_response(hdr, STATUS_INVALID_PARAMETER, out);
            return;
        }
        let data_offset = read_u16_le(body, 2) as usize;
        let length = read_u32_le(body, 4) as usize;
        let offset = read_u64_le(body, 8);
        let fid = self.resolve_fid(read_u64_le(body, 16));

        let data_start = data_offset.saturating_sub(SMB2_HEADER_SIZE);
        if data_start + length > body.len() {
            self.error_response(hdr, STATUS_INVALID_PARAMETER, out);
            return;
        }
        let data = &body[data_start..data_start + length];

        let is_pipe = self.handles.get(&fid).map_or(false, |h| h.is_pipe);

        if is_pipe {
            // Named pipe write: process DCE/RPC and buffer response for READ
            let rpc_out = self.handle_dcerpc(data);
            if let Some(h) = self.handles.get_mut(&fid) {
                h.pipe_response = Some(rpc_out);
            }
            // WRITE response
            let mut resp = Vec::with_capacity(16);
            resp.extend_from_slice(&17u16.to_le_bytes()); // StructureSize
            resp.extend_from_slice(&0u16.to_le_bytes()); // Reserved
            resp.extend_from_slice(&(length as u32).to_le_bytes()); // Count
            resp.extend_from_slice(&0u32.to_le_bytes()); // Remaining
            resp.extend_from_slice(&0u16.to_le_bytes()); // WriteChannelInfoOffset
            resp.extend_from_slice(&0u16.to_le_bytes()); // WriteChannelInfoLength
            hdr.write_response(STATUS_SUCCESS, &resp, out);
            return;
        }

        let handle = match self.handles.get_mut(&fid) {
            Some(h) => h,
            None => {
                self.error_response(hdr, STATUS_INVALID_PARAMETER, out);
                return;
            }
        };

        // Lazy-open for write
        if handle.sftp_handle.is_none() {
            match self.sftp.open(&handle.path, SSH_FXF_WRITE, 0) {
                // WRITE
                Ok(h) => handle.sftp_handle = Some(h),
                Err(_) => {
                    self.error_response(hdr, STATUS_ACCESS_DENIED, out);
                    return;
                }
            }
        }

        let sftp_h = handle.sftp_handle.as_ref().map(|h| h.clone());
        let write_path = handle.path.clone();
        handle.readahead = None; // invalidate — data is changing
        let write_result = match sftp_h {
            Some(ref h) => match self.sftp.write(h, offset, data) {
                Err(SftpError::Disconnected) | Err(SftpError::Protocol(_)) => {
                    // Reconnect happened or stream corrupt, reopen handle and retry
                    self.on_reconnect();
                    match self.sftp.open(&write_path, SSH_FXF_WRITE, 0) {
                        Ok(new_h) => {
                            let r = self.sftp.write(&new_h, offset, data);
                            if let Some(h) = self.handles.get_mut(&fid) {
                                h.sftp_handle = Some(new_h);
                            }
                            r
                        }
                        Err(e) => Err(e),
                    }
                }
                other => other,
            },
            None => Err(SftpError::Disconnected),
        };
        match write_result {
            Ok(()) => {
                self.invalidate_path(&write_path);
                let mut resp = Vec::with_capacity(16);
                resp.extend_from_slice(&17u16.to_le_bytes()); // StructureSize
                resp.extend_from_slice(&0u16.to_le_bytes()); // Reserved
                resp.extend_from_slice(&(length as u32).to_le_bytes()); // Count
                resp.extend_from_slice(&0u32.to_le_bytes()); // Remaining
                resp.extend_from_slice(&0u16.to_le_bytes()); // WriteChannelInfoOffset
                resp.extend_from_slice(&0u16.to_le_bytes()); // WriteChannelInfoLength
                resp.push(0); // Padding
                hdr.write_response(STATUS_SUCCESS, &resp, out);
            }
            Err(_) => self.error_response(hdr, STATUS_ACCESS_DENIED, out),
        }
    }

    // ── QUERY_DIRECTORY ─────────────────────────────────────────────

    fn handle_query_directory(&mut self, hdr: &Smb2Header, body: &[u8], out: &mut Vec<u8>) {
        if body.len() < 24 {
            self.error_response(hdr, STATUS_INVALID_PARAMETER, out);
            return;
        }
        let info_level = body[2];
        let flags = body[3];
        let fid = self.resolve_fid(read_u64_le(body, 8));
        let restart = flags & 0x01 != 0; // RESTART_SCANS

        // Parse search pattern (MS-SMB2 2.2.33)
        let name_offset = if body.len() >= 26 {
            read_u16_le(body, 24) as usize
        } else {
            0
        };
        let name_length = if body.len() >= 28 {
            read_u16_le(body, 26) as usize
        } else {
            0
        };
        let pattern = if name_length > 0 {
            let name_start = name_offset.saturating_sub(SMB2_HEADER_SIZE);
            if name_start + name_length <= body.len() {
                from_utf16le(&body[name_start..name_start + name_length])
            } else {
                "*".to_string()
            }
        } else {
            "*".to_string()
        };
        log::debug!(
            "QUERY_DIRECTORY: info_level={info_level} flags=0x{flags:02x} fid={fid} restart={restart} pattern=\"{pattern}\""
        );

        let handle = match self.handles.get_mut(&fid) {
            Some(h) if h.is_dir => h,
            _ => {
                self.error_response(hdr, STATUS_INVALID_PARAMETER, out);
                return;
            }
        };

        // Fetch directory listing — check session-level dir cache first,
        // then per-handle cache, then fall back to SFTP readdir.
        if handle.dir_entries.is_none() || restart {
            let dir_path = handle.path.clone();
            if let Some(cached) = self.dir_cache.get(&dir_path) {
                log::debug!("QUERY_DIRECTORY: dir cache hit for {dir_path}");
                handle.dir_entries = Some(cached);
                if restart {
                    handle.dir_offset = 0;
                }
            } else {
                match self.sftp.readdir(&dir_path) {
                    Ok(entries) => {
                        // Populate both caches
                        self.cache.insert_dir_entries(&dir_path, &entries);
                        self.dir_cache.insert(dir_path.clone(), entries);
                        handle.dir_entries = self.dir_cache.get(&dir_path);
                        handle.dir_offset = 0;
                    }
                    Err(_) => {
                        self.error_response(hdr, STATUS_ACCESS_DENIED, out);
                        return;
                    }
                }
            }
        }

        let entries = match &handle.dir_entries {
            Some(e) => e,
            None => {
                self.error_response(hdr, STATUS_NO_MORE_FILES, out);
                return;
            }
        };

        // Fake Spotlight-inhibitor files so macOS skips volume indexing
        let fake_entry;
        if is_spotlight_inhibitor(&pattern) {
            let now_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as u32;
            fake_entry = Some(DirEntry {
                name: pattern.clone(),
                attrs: FileAttr {
                    size: 0,
                    uid: 0,
                    gid: 0,
                    perm: 0o100444,
                    atime: now_secs,
                    mtime: now_secs,
                },
            });
        } else {
            fake_entry = None;
        }

        // Filter entries by search pattern
        let is_wildcard = pattern == "*";
        let filtered: Vec<&DirEntry> = if let Some(ref fe) = fake_entry {
            vec![fe]
        } else if is_wildcard {
            // Wildcard: return entries starting from dir_offset
            entries.iter().skip(handle.dir_offset).collect()
        } else {
            // Specific filename or pattern: match against entry names
            entries
                .iter()
                .filter(|e| smb_pattern_match(&pattern, &e.name))
                .collect()
        };

        if filtered.is_empty() {
            self.error_response(hdr, STATUS_NO_MORE_FILES, out);
            return;
        }

        // Build directory info response
        // Build directory entries. Track entry start positions for NextEntryOffset patching.
        let single_entry = flags & 0x02 != 0; // RETURN_SINGLE_ENTRY
        let mut dir_data = Vec::with_capacity(if single_entry {
            256
        } else {
            filtered.len() * 128
        });
        let max_entries = if single_entry { 1 } else { usize::MAX };
        let mut count = 0;
        let mut entry_starts: Vec<usize> = Vec::new();

        for entry in &filtered {
            if count >= max_entries {
                break;
            }
            if is_wildcard {
                handle.dir_offset += 1;
            }
            count += 1;

            let name_bytes = to_utf16le(&entry.name);
            let is_dir = entry.attrs.perm & 0o40000 != 0;
            let ft_create = unix_to_filetime(entry.attrs.mtime as u64);
            let ft_access = unix_to_filetime(entry.attrs.atime as u64);
            let ft_write = unix_to_filetime(entry.attrs.mtime as u64);
            let file_attrs = if is_dir {
                FILE_ATTRIBUTE_DIRECTORY
            } else {
                FILE_ATTRIBUTE_ARCHIVE
            };

            // Pad previous entry to 8-byte alignment before starting new one
            if !entry_starts.is_empty() {
                while dir_data.len() % 8 != 0 {
                    dir_data.push(0);
                }
            }

            let entry_start = dir_data.len();
            entry_starts.push(entry_start);

            // FILE_ID_BOTH_DIRECTORY_INFORMATION (level 37) — what macOS requests.
            // Layout per MS-FSCC 2.4.17:
            //   NextEntryOffset(4) + FileIndex(4) + times(4*8=32) +
            //   EndOfFile(8) + AllocationSize(8) + FileAttributes(4) +
            //   FileNameLength(4) + EaSize(4) + ShortNameLength(1) +
            //   Reserved1(1) + ShortName(24) + Reserved2(2) + FileId(8) +
            //   FileName(variable)
            // Fixed part = 104 bytes

            dir_data.extend_from_slice(&0u32.to_le_bytes()); // NextEntryOffset (patched)
            dir_data.extend_from_slice(&0u32.to_le_bytes()); // FileIndex
            dir_data.extend_from_slice(&ft_create.to_le_bytes()); // CreationTime
            dir_data.extend_from_slice(&ft_access.to_le_bytes()); // LastAccessTime
            dir_data.extend_from_slice(&ft_write.to_le_bytes()); // LastWriteTime
            dir_data.extend_from_slice(&ft_write.to_le_bytes()); // ChangeTime
            dir_data.extend_from_slice(&entry.attrs.size.to_le_bytes()); // EndOfFile
            dir_data.extend_from_slice(&entry.attrs.size.to_le_bytes()); // AllocationSize
            dir_data.extend_from_slice(&file_attrs.to_le_bytes()); // FileAttributes
            dir_data.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes()); // FileNameLength
            dir_data.extend_from_slice(&0u32.to_le_bytes()); // EaSize
            dir_data.push(0); // ShortNameLength
            dir_data.push(0); // Reserved1
            dir_data.extend_from_slice(&[0u8; 24]); // ShortName (empty)
            dir_data.extend_from_slice(&0u16.to_le_bytes()); // Reserved2
            dir_data.extend_from_slice(&(count as u64).to_le_bytes()); // FileId
            dir_data.extend_from_slice(&name_bytes); // FileName
        }

        // Patch NextEntryOffset: each entry points to the next, last = 0
        for i in 0..entry_starts.len().saturating_sub(1) {
            let this_start = entry_starts[i];
            let next_start = entry_starts[i + 1];
            let offset = (next_start - this_start) as u32;
            dir_data[this_start..this_start + 4].copy_from_slice(&offset.to_le_bytes());
        }

        if dir_data.is_empty() {
            self.error_response(hdr, STATUS_NO_MORE_FILES, out);
            return;
        }

        // OutputBuffer starts at body byte 8 = header offset 72
        let data_offset = (SMB2_HEADER_SIZE + 8) as u16;
        let mut resp = Vec::with_capacity(8 + dir_data.len());
        resp.extend_from_slice(&9u16.to_le_bytes()); // StructureSize
        resp.extend_from_slice(&data_offset.to_le_bytes()); // OutputBufferOffset
        resp.extend_from_slice(&(dir_data.len() as u32).to_le_bytes()); // OutputBufferLength
        // No padding — OutputBuffer starts immediately at byte 8
        resp.extend_from_slice(&dir_data);

        hdr.write_response(STATUS_SUCCESS, &resp, out);
    }

    // ── QUERY_INFO ──────────────────────────────────────────────────

    fn handle_query_info(&mut self, hdr: &Smb2Header, body: &[u8], out: &mut Vec<u8>) {
        if body.len() < 32 {
            self.error_response(hdr, STATUS_INVALID_PARAMETER, out);
            return;
        }
        let info_type = body[2];
        let file_info_class = body[3];
        let fid = self.resolve_fid(read_u64_le(body, 24));
        log::debug!("QUERY_INFO: type={info_type} class={file_info_class} fid={fid}");

        let handle = match self.handles.get(&fid) {
            Some(h) => h,
            None => {
                self.error_response(hdr, STATUS_INVALID_PARAMETER, out);
                return;
            }
        };

        let path = handle.path.clone();
        let is_dir = handle.is_dir;

        let (attr, _) = match self.stat_cached(&path) {
            Ok(v) => v,
            Err(s) => {
                self.error_response(hdr, s, out);
                return;
            }
        };

        let ft = unix_to_filetime(attr.mtime as u64);
        let ft_access = unix_to_filetime(attr.atime as u64);
        let file_attrs = if is_dir {
            FILE_ATTRIBUTE_DIRECTORY
        } else {
            FILE_ATTRIBUTE_ARCHIVE
        };

        let mut info_data = Vec::with_capacity(128);

        match (info_type, file_info_class) {
            (SMB2_0_INFO_FILE, FILE_BASIC_INFORMATION) => {
                info_data.extend_from_slice(&ft.to_le_bytes()); // CreationTime
                info_data.extend_from_slice(&ft_access.to_le_bytes()); // LastAccessTime
                info_data.extend_from_slice(&ft.to_le_bytes()); // LastWriteTime
                info_data.extend_from_slice(&ft.to_le_bytes()); // ChangeTime
                info_data.extend_from_slice(&file_attrs.to_le_bytes()); // FileAttributes
                info_data.extend_from_slice(&0u32.to_le_bytes()); // Reserved
            }
            (SMB2_0_INFO_FILE, FILE_STANDARD_INFORMATION) => {
                info_data.extend_from_slice(&attr.size.to_le_bytes()); // AllocationSize
                info_data.extend_from_slice(&attr.size.to_le_bytes()); // EndOfFile
                info_data.extend_from_slice(&1u32.to_le_bytes()); // NumberOfLinks
                info_data.push(0); // DeletePending
                info_data.push(if is_dir { 1 } else { 0 }); // Directory
                info_data.extend_from_slice(&0u16.to_le_bytes()); // Reserved
            }
            (SMB2_0_INFO_FILE, FILE_INTERNAL_INFORMATION) => {
                info_data.extend_from_slice(&0u64.to_le_bytes()); // IndexNumber
            }
            (SMB2_0_INFO_FILE, FILE_EA_INFORMATION) => {
                info_data.extend_from_slice(&0u32.to_le_bytes()); // EaSize
            }
            (SMB2_0_INFO_FILE, FILE_NETWORK_OPEN_INFORMATION) => {
                info_data.extend_from_slice(&ft.to_le_bytes()); // CreationTime
                info_data.extend_from_slice(&ft_access.to_le_bytes()); // LastAccessTime
                info_data.extend_from_slice(&ft.to_le_bytes()); // LastWriteTime
                info_data.extend_from_slice(&ft.to_le_bytes()); // ChangeTime
                info_data.extend_from_slice(&attr.size.to_le_bytes()); // AllocationSize
                info_data.extend_from_slice(&attr.size.to_le_bytes()); // EndOfFile
                info_data.extend_from_slice(&file_attrs.to_le_bytes()); // FileAttributes
                info_data.extend_from_slice(&0u32.to_le_bytes()); // Reserved
            }
            (SMB2_0_INFO_FILE, FILE_ATTRIBUTE_TAG_INFORMATION) => {
                info_data.extend_from_slice(&file_attrs.to_le_bytes()); // FileAttributes
                info_data.extend_from_slice(&0u32.to_le_bytes()); // ReparseTag
            }
            (SMB2_0_INFO_FILE, FILE_STREAM_INFORMATION) => {
                // No alternate data streams
                self.error_response(hdr, STATUS_INVALID_PARAMETER, out);
                return;
            }
            (SMB2_0_INFO_FILE, FILE_ALL_INFORMATION) => {
                // BasicInformation
                info_data.extend_from_slice(&ft.to_le_bytes());
                info_data.extend_from_slice(&ft_access.to_le_bytes());
                info_data.extend_from_slice(&ft.to_le_bytes());
                info_data.extend_from_slice(&ft.to_le_bytes());
                info_data.extend_from_slice(&file_attrs.to_le_bytes());
                info_data.extend_from_slice(&0u32.to_le_bytes()); // Reserved
                // StandardInformation
                info_data.extend_from_slice(&attr.size.to_le_bytes());
                info_data.extend_from_slice(&attr.size.to_le_bytes());
                info_data.extend_from_slice(&1u32.to_le_bytes());
                info_data.push(0);
                info_data.push(if is_dir { 1 } else { 0 });
                info_data.extend_from_slice(&0u16.to_le_bytes());
                // InternalInformation
                info_data.extend_from_slice(&0u64.to_le_bytes());
                // EaInformation
                info_data.extend_from_slice(&0u32.to_le_bytes());
                // AccessInformation
                info_data.extend_from_slice(&MAXIMUM_ALLOWED.to_le_bytes());
                // PositionInformation
                info_data.extend_from_slice(&0u64.to_le_bytes());
                // ModeInformation
                info_data.extend_from_slice(&0u32.to_le_bytes());
                // AlignmentInformation
                info_data.extend_from_slice(&0u32.to_le_bytes());
                // NameInformation
                let name_bytes = to_utf16le(path.rsplit('/').next().unwrap_or(""));
                info_data.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
                info_data.extend_from_slice(&name_bytes);
            }
            (SMB2_0_INFO_FILE, FILE_POSITION_INFORMATION) => {
                info_data.extend_from_slice(&0u64.to_le_bytes());
            }
            (SMB2_0_INFO_FILESYSTEM, FS_SIZE_INFORMATION | FS_FULL_SIZE_INFORMATION) => {
                info_data.extend_from_slice(&(1024u64 * 1024 * 1024).to_le_bytes()); // TotalAllocationUnits
                info_data.extend_from_slice(&(512u64 * 1024 * 1024).to_le_bytes()); // AvailableAllocationUnits
                if file_info_class == FS_FULL_SIZE_INFORMATION {
                    info_data.extend_from_slice(&(512u64 * 1024 * 1024).to_le_bytes());
                    // CallerAvailableAllocationUnits
                }
                info_data.extend_from_slice(&1u32.to_le_bytes()); // SectorsPerAllocationUnit
                info_data.extend_from_slice(&4096u32.to_le_bytes()); // BytesPerSector
            }
            (SMB2_0_INFO_FILESYSTEM, FS_ATTRIBUTE_INFORMATION) => {
                info_data.extend_from_slice(&0x0000_0003u32.to_le_bytes()); // Attributes: case sensitive + case preserving
                info_data.extend_from_slice(&255u32.to_le_bytes()); // MaxNameLength
                let label = to_utf16le("SSHFS");
                info_data.extend_from_slice(&(label.len() as u32).to_le_bytes());
                info_data.extend_from_slice(&label);
            }
            (SMB2_0_INFO_FILESYSTEM, FS_VOLUME_INFORMATION) => {
                info_data.extend_from_slice(&ft.to_le_bytes()); // VolumeCreationTime
                info_data.extend_from_slice(&0u32.to_le_bytes()); // VolumeSerialNumber
                let label = to_utf16le("sshfs");
                info_data.extend_from_slice(&(label.len() as u32).to_le_bytes());
                info_data.push(0); // SupportsObjects
                info_data.push(0); // Reserved
                info_data.extend_from_slice(&label);
            }
            (SMB2_0_INFO_FILESYSTEM, FS_SECTOR_SIZE_INFORMATION) => {
                info_data.extend_from_slice(&4096u32.to_le_bytes()); // LogicalBytesPerSector
                info_data.extend_from_slice(&4096u32.to_le_bytes()); // PhysicalBytesPerSector
                info_data.extend_from_slice(&4096u32.to_le_bytes()); // FileSystemEffectiveBytesPerSector
                info_data.extend_from_slice(&0u32.to_le_bytes()); // Flags
                info_data.extend_from_slice(&0u32.to_le_bytes()); // ByteOffsetForSectorAlignment
                info_data.extend_from_slice(&0u32.to_le_bytes()); // ByteOffsetForPartitionAlignment
            }
            (SMB2_0_INFO_SECURITY, _) => {
                // Empty security descriptor
                info_data.extend_from_slice(&[0u8; 20]); // Minimal SD
            }
            _ => {
                log::debug!("QUERY_INFO: unsupported type={info_type} class={file_info_class}");
                self.error_response(hdr, STATUS_NOT_SUPPORTED, out);
                return;
            }
        }

        let data_offset = (SMB2_HEADER_SIZE + 8) as u16;
        let mut resp = Vec::with_capacity(8 + info_data.len());
        resp.extend_from_slice(&9u16.to_le_bytes()); // StructureSize
        resp.extend_from_slice(&data_offset.to_le_bytes()); // OutputBufferOffset
        resp.extend_from_slice(&(info_data.len() as u32).to_le_bytes()); // OutputBufferLength
        resp.extend_from_slice(&info_data);

        hdr.write_response(STATUS_SUCCESS, &resp, out);
    }

    // ── SET_INFO ────────────────────────────────────────────────────

    fn handle_set_info(&mut self, hdr: &Smb2Header, body: &[u8], out: &mut Vec<u8>) {
        if body.len() < 24 {
            self.error_response(hdr, STATUS_INVALID_PARAMETER, out);
            return;
        }
        let info_type = body[2];
        let file_info_class = body[3];
        let buf_length = read_u32_le(body, 4) as usize;
        let buf_offset = read_u16_le(body, 8) as usize;
        let fid = self.resolve_fid(read_u64_le(body, 16));

        let handle = match self.handles.get(&fid) {
            Some(h) => h,
            None => {
                self.error_response(hdr, STATUS_INVALID_PARAMETER, out);
                return;
            }
        };
        let path = handle.path.clone();

        let data_start = buf_offset.saturating_sub(SMB2_HEADER_SIZE);
        let info_data = if data_start + buf_length <= body.len() {
            &body[data_start..data_start + buf_length]
        } else {
            &[]
        };

        match (info_type, file_info_class) {
            (SMB2_0_INFO_FILE, FILE_RENAME_INFORMATION) => {
                if info_data.len() < 24 {
                    self.error_response(hdr, STATUS_INVALID_PARAMETER, out);
                    return;
                }
                let name_len = read_u32_le(info_data, 16) as usize;
                if 20 + name_len > info_data.len() {
                    self.error_response(hdr, STATUS_INVALID_PARAMETER, out);
                    return;
                }
                let new_name = from_utf16le(&info_data[20..20 + name_len]);
                let new_path = self.full_path(&new_name);

                match self.sftp.rename(&path, &new_path) {
                    Ok(()) => {
                        self.invalidate_path(&path);
                        self.invalidate_path(&new_path);
                        // Update handle path
                        if let Some(h) = self.handles.get_mut(&fid) {
                            h.path = new_path;
                        }
                    }
                    Err(_) => {
                        self.error_response(hdr, STATUS_ACCESS_DENIED, out);
                        return;
                    }
                }
            }
            (SMB2_0_INFO_FILE, FILE_DISPOSITION_INFORMATION) => {
                let delete = info_data.first().copied().unwrap_or(0) != 0;
                if delete {
                    let is_dir = handle.is_dir;
                    let result = if is_dir {
                        self.sftp.rmdir(&path)
                    } else {
                        self.sftp.remove(&path)
                    };
                    match result {
                        Ok(()) => self.invalidate_path(&path),
                        Err(_) => {
                            self.error_response(hdr, STATUS_ACCESS_DENIED, out);
                            return;
                        }
                    }
                }
            }
            (SMB2_0_INFO_FILE, FILE_BASIC_INFORMATION) => {
                // Set timestamps/attributes — best effort via SFTP setstat
                if info_data.len() >= 36 {
                    if let Ok((mut attr, _)) = self.stat_cached(&path) {
                        let new_atime = read_u64_le(info_data, 8);
                        let new_mtime = read_u64_le(info_data, 16);
                        if new_atime != 0 {
                            attr.atime = filetime_to_unix(new_atime) as u32;
                        }
                        if new_mtime != 0 {
                            attr.mtime = filetime_to_unix(new_mtime) as u32;
                        }
                        let _ = self.sftp.setstat(&path, &attr);
                        self.invalidate_path(&path);
                    }
                }
            }
            _ => {
                log::debug!("SET_INFO: unsupported type={info_type} class={file_info_class}");
                // Return success anyway — macOS sends many SET_INFO we can ignore
            }
        }

        let mut resp = Vec::with_capacity(2);
        resp.extend_from_slice(&2u16.to_le_bytes()); // StructureSize
        hdr.write_response(STATUS_SUCCESS, &resp, out);
    }

    // ── FLUSH ───────────────────────────────────────────────────────

    fn handle_flush(&mut self, hdr: &Smb2Header, out: &mut Vec<u8>) {
        let mut resp = Vec::with_capacity(4);
        resp.extend_from_slice(&4u16.to_le_bytes());
        resp.extend_from_slice(&0u16.to_le_bytes());
        hdr.write_response(STATUS_SUCCESS, &resp, out);
    }

    // ── LOCK ────────────────────────────────────────────────────────

    fn handle_lock(&mut self, hdr: &Smb2Header, out: &mut Vec<u8>) {
        // MS-SMB2 2.2.26 LOCK Response: StructureSize=4, Reserved=0
        let mut resp = Vec::with_capacity(4);
        resp.extend_from_slice(&4u16.to_le_bytes());
        resp.extend_from_slice(&0u16.to_le_bytes());
        hdr.write_response(STATUS_SUCCESS, &resp, out);
    }

    // ── IOCTL ───────────────────────────────────────────────────────

    fn handle_ioctl(&mut self, hdr: &Smb2Header, body: &[u8], out: &mut Vec<u8>) {
        if body.len() < 56 {
            self.error_response(hdr, STATUS_INVALID_PARAMETER, out);
            return;
        }
        let ctl_code = read_u32_le(body, 4);
        let fid = self.resolve_fid(read_u64_le(body, 8));
        log::debug!("IOCTL: ctl_code=0x{ctl_code:08x} fid={fid}");
        let input_offset = read_u32_le(body, 24) as usize;
        let input_count = read_u32_le(body, 28) as usize;

        const FSCTL_PIPE_TRANSACT: u32 = 0x0011C017;

        if ctl_code == FSCTL_PIPE_TRANSACT {
            let is_pipe = self.handles.get(&fid).map_or(false, |h| h.is_pipe);
            if !is_pipe {
                log::debug!("IOCTL PIPE_TRANSACT: fid={fid} not a pipe handle");
                self.error_response(hdr, STATUS_INVALID_PARAMETER, out);
                return;
            }

            // Extract DCE/RPC input data
            let in_start = input_offset.saturating_sub(SMB2_HEADER_SIZE);
            let rpc_in = if in_start + input_count <= body.len() {
                &body[in_start..in_start + input_count]
            } else {
                &[]
            };

            log::debug!(
                "IOCTL PIPE_TRANSACT: input_len={} pkt_type={}",
                rpc_in.len(),
                rpc_in.get(2).copied().unwrap_or(0xff)
            );
            let rpc_out = self.handle_dcerpc(rpc_in);
            log::debug!("IOCTL PIPE_TRANSACT: response_len={}", rpc_out.len());

            // Build IOCTL response
            let data_offset = (SMB2_HEADER_SIZE + 48) as u32;
            let mut resp = Vec::with_capacity(48 + rpc_out.len());
            resp.extend_from_slice(&49u16.to_le_bytes()); // StructureSize
            resp.extend_from_slice(&0u16.to_le_bytes()); // Reserved
            resp.extend_from_slice(&ctl_code.to_le_bytes());
            resp.extend_from_slice(&fid.to_le_bytes()); // FileId.Persistent
            resp.extend_from_slice(&fid.to_le_bytes()); // FileId.Volatile
            resp.extend_from_slice(&0u32.to_le_bytes()); // InputOffset
            resp.extend_from_slice(&0u32.to_le_bytes()); // InputCount
            resp.extend_from_slice(&data_offset.to_le_bytes()); // OutputOffset
            resp.extend_from_slice(&(rpc_out.len() as u32).to_le_bytes()); // OutputCount
            resp.extend_from_slice(&0u32.to_le_bytes()); // Flags
            resp.extend_from_slice(&0u32.to_le_bytes()); // Reserved2
            resp.extend_from_slice(&rpc_out);
            hdr.write_response(STATUS_SUCCESS, &resp, out);
        } else {
            self.error_response(hdr, STATUS_INVALID_DEVICE_REQUEST, out);
        }
    }

    // ── DCE/RPC ─────────────────────────────────────────────────────

    fn handle_dcerpc(&self, input: &[u8]) -> Vec<u8> {
        if input.len() < 16 {
            return Vec::new();
        }
        let pkt_type = input[2];
        let call_id = read_u32_le(input, 12);

        match pkt_type {
            11 => self.dcerpc_bind_ack(call_id, input),
            0 => self.dcerpc_request(call_id, input),
            _ => Vec::new(),
        }
    }

    fn dcerpc_bind_ack(&self, call_id: u32, _input: &[u8]) -> Vec<u8> {
        // NDR transfer syntax UUID: 8a885d04-1ceb-11c9-9fe8-08002b104860
        let ndr_syntax: [u8; 16] = [
            0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10,
            0x48, 0x60,
        ];

        let secondary_addr = b"\\PIPE\\srvsvc\0";
        let addr_len = secondary_addr.len() as u16;

        let mut pdu = Vec::with_capacity(100);
        // DCE/RPC common header (16 bytes)
        pdu.push(5); // version
        pdu.push(0); // minor
        pdu.push(12); // bind_ack
        pdu.push(0x03); // first+last frag
        pdu.extend_from_slice(&0x00000010u32.to_le_bytes()); // data rep (LE)
        pdu.extend_from_slice(&0u16.to_le_bytes()); // frag_length (patched later)
        pdu.extend_from_slice(&0u16.to_le_bytes()); // auth_length
        pdu.extend_from_slice(&call_id.to_le_bytes());
        // bind_ack body
        pdu.extend_from_slice(&4280u16.to_le_bytes()); // max_xmit_frag
        pdu.extend_from_slice(&4280u16.to_le_bytes()); // max_recv_frag
        pdu.extend_from_slice(&1u32.to_le_bytes()); // assoc_group
        pdu.extend_from_slice(&addr_len.to_le_bytes());
        pdu.extend_from_slice(secondary_addr);
        // Pad to 4-byte boundary (from PDU start) before num_results
        while pdu.len() % 4 != 0 {
            pdu.push(0);
        }
        // results
        pdu.extend_from_slice(&1u32.to_le_bytes()); // num_results + padding
        pdu.extend_from_slice(&0u16.to_le_bytes()); // result: acceptance
        pdu.extend_from_slice(&0u16.to_le_bytes()); // reason
        pdu.extend_from_slice(&ndr_syntax); // transfer syntax UUID
        pdu.extend_from_slice(&2u32.to_le_bytes()); // syntax version

        // Patch frag_length
        let frag_len = pdu.len() as u16;
        pdu[8..10].copy_from_slice(&frag_len.to_le_bytes());
        pdu
    }

    fn dcerpc_request(&self, call_id: u32, input: &[u8]) -> Vec<u8> {
        if input.len() < 24 {
            return Vec::new();
        }
        let opnum = read_u16_le(input, 22);

        let stub = match opnum {
            15 => self.srvsvc_net_share_enum(), // NetShareEnumAll
            _ => {
                log::debug!("DCE/RPC unsupported opnum: {opnum}");
                return Vec::new();
            }
        };

        // DCE/RPC response header
        let frag_len = 24 + stub.len();
        let mut pdu = Vec::with_capacity(frag_len);
        pdu.push(5);
        pdu.push(0);
        pdu.push(2); // response
        pdu.push(0x03); // first+last
        pdu.extend_from_slice(&0x00000010u32.to_le_bytes());
        pdu.extend_from_slice(&(frag_len as u16).to_le_bytes());
        pdu.extend_from_slice(&0u16.to_le_bytes());
        pdu.extend_from_slice(&call_id.to_le_bytes());
        // response body
        pdu.extend_from_slice(&(stub.len() as u32).to_le_bytes()); // alloc_hint
        pdu.extend_from_slice(&0u16.to_le_bytes()); // context_id
        pdu.push(0); // cancel_count
        pdu.push(0); // reserved
        pdu.extend_from_slice(&stub);
        pdu
    }

    /// Build NDR-encoded NetShareEnumAll response (level 1) listing our share.
    fn srvsvc_net_share_enum(&self) -> Vec<u8> {
        let name = &self.share_name;
        let comment = "";

        // Encode UCS-2 strings (with terminating null)
        let name_ucs2: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let comment_ucs2: Vec<u16> = comment.encode_utf16().chain(std::iter::once(0)).collect();

        let mut stub = Vec::with_capacity(128);

        // NetShareInfoCtr struct (level + union)
        stub.extend_from_slice(&1u32.to_le_bytes()); // Level
        stub.extend_from_slice(&1u32.to_le_bytes()); // Switch discriminator
        stub.extend_from_slice(&0x00020000u32.to_le_bytes()); // Ctr1 pointer referent

        // Deferred: NetShareCtr1
        stub.extend_from_slice(&1u32.to_le_bytes()); // Count
        stub.extend_from_slice(&0x00020004u32.to_le_bytes()); // Array pointer referent

        // Deferred: array (conformant)
        stub.extend_from_slice(&1u32.to_le_bytes()); // MaxCount

        // Array elements (SHARE_INFO_1: name_ptr, type, comment_ptr)
        stub.extend_from_slice(&0x00020008u32.to_le_bytes()); // Name pointer referent
        stub.extend_from_slice(&0u32.to_le_bytes()); // Type: STYPE_DISKTREE
        stub.extend_from_slice(&0x0002000Cu32.to_le_bytes()); // Comment pointer referent

        // Deferred strings for element 0: name then comment
        // Name: conformant varying string
        stub.extend_from_slice(&(name_ucs2.len() as u32).to_le_bytes()); // MaxCount
        stub.extend_from_slice(&0u32.to_le_bytes()); // Offset
        stub.extend_from_slice(&(name_ucs2.len() as u32).to_le_bytes()); // ActualCount
        for ch in &name_ucs2 {
            stub.extend_from_slice(&ch.to_le_bytes());
        }
        while stub.len() % 4 != 0 {
            stub.push(0);
        }

        // Comment: conformant varying string
        stub.extend_from_slice(&(comment_ucs2.len() as u32).to_le_bytes());
        stub.extend_from_slice(&0u32.to_le_bytes());
        stub.extend_from_slice(&(comment_ucs2.len() as u32).to_le_bytes());
        for ch in &comment_ucs2 {
            stub.extend_from_slice(&ch.to_le_bytes());
        }
        while stub.len() % 4 != 0 {
            stub.push(0);
        }

        // TotalEntries
        stub.extend_from_slice(&1u32.to_le_bytes());
        // ResumeHandle pointer (null)
        stub.extend_from_slice(&0u32.to_le_bytes());
        // Return value: WERR_OK
        stub.extend_from_slice(&0u32.to_le_bytes());
        stub
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── smb_pattern_match ──────────────────────────────────────────

    #[test]
    fn pattern_wildcard_matches_everything() {
        assert!(smb_pattern_match("*", "anything"));
        assert!(smb_pattern_match("*", ""));
        assert!(smb_pattern_match("*", ".DS_Store"));
    }

    #[test]
    fn pattern_exact_case_insensitive() {
        assert!(smb_pattern_match("hello.txt", "hello.txt"));
        assert!(smb_pattern_match("Hello.TXT", "hello.txt"));
        assert!(smb_pattern_match("hello.txt", "HELLO.TXT"));
        assert!(!smb_pattern_match("hello.txt", "hello.tx"));
        assert!(!smb_pattern_match("hello.txt", "hello.txtt"));
    }

    #[test]
    fn pattern_question_mark() {
        assert!(smb_pattern_match("?.txt", "a.txt"));
        assert!(!smb_pattern_match("?.txt", "ab.txt"));
        assert!(smb_pattern_match("he??o", "hello"));
        assert!(!smb_pattern_match("he??o", "helo"));
    }

    #[test]
    fn pattern_star_prefix_suffix() {
        assert!(smb_pattern_match("*.txt", "readme.txt"));
        assert!(smb_pattern_match("*.txt", ".txt"));
        assert!(!smb_pattern_match("*.txt", "readme.md"));
        assert!(smb_pattern_match("readme.*", "readme.txt"));
        assert!(smb_pattern_match("readme.*", "readme."));
    }

    #[test]
    fn pattern_star_middle() {
        assert!(smb_pattern_match("a*z", "az"));
        assert!(smb_pattern_match("a*z", "abcz"));
        assert!(!smb_pattern_match("a*z", "abcx"));
    }

    #[test]
    fn pattern_empty_inputs() {
        assert!(smb_pattern_match("*", ""));
        assert!(!smb_pattern_match("a", ""));
        assert!(!smb_pattern_match("", "a"));
        assert!(smb_pattern_match("", ""));
    }

    #[test]
    fn pattern_no_panic_on_long_star() {
        // Regression: wildcard_match used n.len() - ni which could underflow
        assert!(smb_pattern_match("*", "x"));
        assert!(!smb_pattern_match("a*b*c", "ac"));
        assert!(smb_pattern_match("a*b*c", "abc"));
        assert!(smb_pattern_match("a*b*c", "aXXbYYc"));
    }

    // ── is_apple_metadata ──────────────────────────────────────────

    #[test]
    fn apple_metadata_detected() {
        assert!(is_apple_metadata(".DS_Store"));
        assert!(is_apple_metadata("._somefile"));
        assert!(is_apple_metadata(".Spotlight-V100"));
        assert!(is_apple_metadata(".Trashes"));
        assert!(is_apple_metadata(".fseventsd"));
        assert!(is_apple_metadata("Icon\r"));
    }

    #[test]
    fn non_apple_metadata() {
        assert!(!is_apple_metadata("readme.md"));
        assert!(!is_apple_metadata(".gitignore"));
        assert!(!is_apple_metadata(".bashrc"));
        assert!(!is_apple_metadata("DS_Store")); // no leading dot
    }

    // ── AttrCache ──────────────────────────────────────────────────

    fn test_attr(size: u64, perm: u32) -> FileAttr {
        FileAttr {
            size,
            uid: 1000,
            gid: 1000,
            perm,
            atime: 1000,
            mtime: 2000,
        }
    }

    #[test]
    fn attr_cache_insert_and_get() {
        let mut c = AttrCache::new();
        c.insert("/a/b".into(), test_attr(100, 0o100644), false);
        let (attr, is_dir) = c.get("/a/b").unwrap();
        assert_eq!(attr.size, 100);
        assert!(!is_dir);
    }

    #[test]
    fn attr_cache_miss() {
        let c = AttrCache::new();
        assert!(c.get("/nonexistent").is_none());
    }

    #[test]
    fn attr_cache_negative() {
        let mut c = AttrCache::new();
        assert!(!c.is_negative("/a"));
        c.insert_negative("/a".into());
        assert!(c.is_negative("/a"));
    }

    #[test]
    fn attr_cache_insert_clears_negative() {
        let mut c = AttrCache::new();
        c.insert_negative("/a".into());
        assert!(c.is_negative("/a"));
        c.insert("/a".into(), test_attr(10, 0o100644), false);
        assert!(!c.is_negative("/a"));
        assert!(c.get("/a").is_some());
    }

    #[test]
    fn attr_cache_invalidate() {
        let mut c = AttrCache::new();
        c.insert("/a".into(), test_attr(10, 0o100644), false);
        c.insert_negative("/b".into());
        c.invalidate("/a");
        c.invalidate("/b");
        assert!(c.get("/a").is_none());
        assert!(!c.is_negative("/b"));
    }

    #[test]
    fn attr_cache_insert_dir_entries() {
        let mut c = AttrCache::new();
        let entries = vec![
            DirEntry {
                name: "file.txt".into(),
                attrs: test_attr(500, 0o100644),
            },
            DirEntry {
                name: "subdir".into(),
                attrs: test_attr(4096, 0o40755),
            },
        ];
        c.insert_dir_entries("/home", &entries);
        let (a, d) = c.get("/home/file.txt").unwrap();
        assert_eq!(a.size, 500);
        assert!(!d);
        let (a, d) = c.get("/home/subdir").unwrap();
        assert_eq!(a.size, 4096);
        assert!(d);
    }

    #[test]
    fn attr_cache_evict_expired() {
        let mut c = AttrCache::new();
        // Insert with a very short TTL by directly manipulating
        c.positive.insert(
            "/stale".into(),
            CachedAttr {
                attr: test_attr(1, 0o100644),
                is_dir: false,
                expires: Instant::now() - Duration::from_secs(1),
            },
        );
        c.negative
            .insert("/gone".into(), Instant::now() - Duration::from_secs(1));
        c.insert("/fresh".into(), test_attr(2, 0o100644), false);

        assert_eq!(c.positive.len(), 2);
        assert_eq!(c.negative.len(), 1);
        c.evict_expired();
        assert_eq!(c.positive.len(), 1); // only /fresh remains
        assert_eq!(c.negative.len(), 0);
        assert!(c.get("/fresh").is_some());
    }

    // ── DirCache ───────────────────────────────────────────────────

    #[test]
    fn dir_cache_insert_and_get() {
        let mut c = DirCache::new();
        let entries = vec![DirEntry {
            name: "a.txt".into(),
            attrs: test_attr(10, 0o100644),
        }];
        c.insert("/dir".into(), entries);
        let got = c.get("/dir").unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, "a.txt");
    }

    #[test]
    fn dir_cache_miss() {
        let c = DirCache::new();
        assert!(c.get("/nope").is_none());
    }

    #[test]
    fn dir_cache_expired_is_miss() {
        let mut c = DirCache::new();
        c.dirs.insert(
            "/old".into(),
            CachedDir {
                entries: Arc::new(vec![]),
                expires: Instant::now() - Duration::from_secs(1),
            },
        );
        assert!(c.get("/old").is_none());
    }

    #[test]
    fn dir_cache_invalidate() {
        let mut c = DirCache::new();
        c.insert("/dir".into(), vec![]);
        assert!(c.get("/dir").is_some());
        c.invalidate("/dir");
        assert!(c.get("/dir").is_none());
    }

    #[test]
    fn dir_cache_arc_sharing() {
        let mut c = DirCache::new();
        let entries = vec![DirEntry {
            name: "x".into(),
            attrs: test_attr(1, 0o100644),
        }];
        c.insert("/d".into(), entries);
        let a1 = c.get("/d").unwrap();
        let a2 = c.get("/d").unwrap();
        // Both point to the same allocation
        assert!(Arc::ptr_eq(&a1, &a2));
    }

    #[test]
    fn dir_cache_evict_expired() {
        let mut c = DirCache::new();
        c.dirs.insert(
            "/stale".into(),
            CachedDir {
                entries: Arc::new(vec![]),
                expires: Instant::now() - Duration::from_secs(1),
            },
        );
        c.insert("/fresh".into(), vec![]);
        assert_eq!(c.dirs.len(), 2);
        c.evict_expired();
        assert_eq!(c.dirs.len(), 1);
        assert!(c.get("/fresh").is_some());
    }

    // ── ReadAhead ──────────────────────────────────────────────────

    #[test]
    fn readahead_hit_within_buffer() {
        let ra = ReadAhead {
            data: vec![0u8; 512 * 1024], // 512KB
            offset: 1000,
        };
        // Read at offset 2000, length 100 — within buffer
        let off = 2000u64;
        let len = 100u64;
        assert!(off >= ra.offset && off + len <= ra.offset + ra.data.len() as u64);
        let start = (off - ra.offset) as usize;
        assert_eq!(start, 1000);
    }

    #[test]
    fn readahead_miss_before_buffer() {
        let ra = ReadAhead {
            data: vec![0u8; 1024],
            offset: 5000,
        };
        let off = 4000u64;
        let len = 100u64;
        assert!(!(off >= ra.offset && off + len <= ra.offset + ra.data.len() as u64));
    }

    #[test]
    fn readahead_miss_past_buffer() {
        let ra = ReadAhead {
            data: vec![0u8; 1024],
            offset: 0,
        };
        let off = 500u64;
        let len = 1000u64;
        // off + len = 1500 > 0 + 1024
        assert!(!(off >= ra.offset && off + len <= ra.offset + ra.data.len() as u64));
    }

    // ── full_path / invalidate_path ────────────────────────────────

    #[test]
    fn full_path_empty_returns_root() {
        let sess = make_test_session();
        assert_eq!(sess.full_path(""), "/home/user");
        assert_eq!(sess.full_path("\\"), "/home/user");
        assert_eq!(sess.full_path("/"), "/home/user");
    }

    #[test]
    fn full_path_relative() {
        let sess = make_test_session();
        assert_eq!(
            sess.full_path("docs/readme.md"),
            "/home/user/docs/readme.md"
        );
    }

    #[test]
    fn full_path_backslash_normalized() {
        let sess = make_test_session();
        assert_eq!(
            sess.full_path("docs\\sub\\file.txt"),
            "/home/user/docs/sub/file.txt"
        );
    }

    #[test]
    fn full_path_leading_slash_stripped() {
        let sess = make_test_session();
        assert_eq!(sess.full_path("/docs"), "/home/user/docs");
    }

    #[test]
    fn invalidate_path_clears_both_caches() {
        let mut sess = make_test_session();
        // Populate attr cache
        sess.cache.insert(
            "/home/user/dir/file.txt".into(),
            test_attr(10, 0o100644),
            false,
        );
        // Populate dir cache for parent
        sess.dir_cache.insert(
            "/home/user/dir".into(),
            vec![DirEntry {
                name: "file.txt".into(),
                attrs: test_attr(10, 0o100644),
            }],
        );
        assert!(sess.cache.get("/home/user/dir/file.txt").is_some());
        assert!(sess.dir_cache.get("/home/user/dir").is_some());

        sess.invalidate_path("/home/user/dir/file.txt");
        assert!(sess.cache.get("/home/user/dir/file.txt").is_none());
        assert!(sess.dir_cache.get("/home/user/dir").is_none());
    }

    // ── Helper: create a minimal SmbSession for testing ────────────

    fn make_test_session() -> SmbSession {
        let sftp = Arc::new(ReconnectingSftp::dummy());
        SmbSession::new(sftp, "/home/user".into(), "test".into())
    }
}

// ── SPNEGO init token ───────────────────────────────────────────────
