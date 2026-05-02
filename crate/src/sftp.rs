//! SFTP protocol implementation over an SSH subprocess.
//!
//! Spawns `ssh -s sftp` and speaks the binary SFTP protocol over pipes.
//! No SSH library needed — uses the system's ssh binary (keys, config, agent all work).
#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU8, AtomicU32, Ordering};

// ── SFTP protocol constants ──────────────────────────────────────────

// Packet types
const SSH_FXP_INIT: u8 = 1;
const SSH_FXP_VERSION: u8 = 2;
const SSH_FXP_OPEN: u8 = 3;
const SSH_FXP_CLOSE: u8 = 4;
const SSH_FXP_READ: u8 = 5;
const SSH_FXP_WRITE: u8 = 6;
const SSH_FXP_LSTAT: u8 = 7;
const SSH_FXP_SETSTAT: u8 = 9;
const SSH_FXP_OPENDIR: u8 = 11;
const SSH_FXP_READDIR: u8 = 12;
const SSH_FXP_REMOVE: u8 = 13;
const SSH_FXP_MKDIR: u8 = 14;
const SSH_FXP_RMDIR: u8 = 15;
const SSH_FXP_REALPATH: u8 = 16;
const SSH_FXP_STAT: u8 = 17;
const SSH_FXP_RENAME: u8 = 18;
const SSH_FXP_SYMLINK: u8 = 20;

// Response types
const SSH_FXP_STATUS: u8 = 101;
const SSH_FXP_HANDLE: u8 = 102;
const SSH_FXP_DATA: u8 = 103;
const SSH_FXP_NAME: u8 = 104;
const SSH_FXP_ATTRS: u8 = 105;

// Status codes
const SSH_FX_OK: u32 = 0;
const SSH_FX_EOF: u32 = 1;

// Attribute flags
const SSH_FILEXFER_ATTR_SIZE: u32 = 0x0000_0001;
const SSH_FILEXFER_ATTR_UIDGID: u32 = 0x0000_0002;
const SSH_FILEXFER_ATTR_PERMISSIONS: u32 = 0x0000_0004;
const SSH_FILEXFER_ATTR_ACMODTIME: u32 = 0x0000_0008;
const SSH_FILEXFER_ATTR_EXTENDED: u32 = 0x8000_0000;

// Open flags
pub const SSH_FXF_READ: u32 = 0x0000_0001;
pub const SSH_FXF_WRITE: u32 = 0x0000_0002;
pub const SSH_FXF_CREAT: u32 = 0x0000_0008;
pub const SSH_FXF_TRUNC: u32 = 0x0000_0010;
pub const SSH_FXF_EXCL: u32 = 0x0000_0020;
pub const SSH_FXF_APPEND: u32 = 0x0000_0004;

const SFTP_PROTO_VERSION: u32 = 3;
const MAX_READ_SIZE: u32 = 262144; // 256KB — most servers support this
const MAX_WRITE_SIZE: u32 = 262144;
const READ_PIPELINE: usize = 32; // concurrent READ requests
const WRITE_PIPELINE: usize = 16; // concurrent WRITE requests

// ── Types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FileAttr {
    pub size: u64,
    pub uid: u32,
    pub gid: u32,
    pub perm: u32,
    pub atime: u32,
    pub mtime: u32,
}

impl Default for FileAttr {
    fn default() -> Self {
        Self {
            size: 0,
            uid: 0,
            gid: 0,
            perm: 0o644,
            atime: 0,
            mtime: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub attrs: FileAttr,
}

pub type SftpResult<T> = Result<T, SftpError>;

#[derive(Debug)]
pub enum SftpError {
    Io(io::Error),
    Protocol(String),
    Status(u32, String),
    Disconnected,
}

impl From<io::Error> for SftpError {
    fn from(e: io::Error) -> Self {
        SftpError::Io(e)
    }
}

impl std::fmt::Display for SftpError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            SftpError::Io(e) => write!(f, "IO: {e}"),
            SftpError::Protocol(s) => write!(f, "Protocol: {s}"),
            SftpError::Status(c, s) => write!(f, "SFTP status {c}: {s}"),
            SftpError::Disconnected => write!(f, "Disconnected"),
        }
    }
}

// ── Buffer helpers (SFTP wire format) ────────────────────────────────

struct Buf(Vec<u8>);

impl Buf {
    fn new() -> Self {
        Buf(Vec::with_capacity(256))
    }
    fn with_capacity(n: usize) -> Self {
        Buf(Vec::with_capacity(n))
    }

    fn put_u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn put_u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn put_u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn put_str(&mut self, s: &str) {
        self.put_u32(s.len() as u32);
        self.0.extend_from_slice(s.as_bytes());
    }
    fn put_bytes(&mut self, b: &[u8]) {
        self.put_u32(b.len() as u32);
        self.0.extend_from_slice(b);
    }
    fn put_attrs(&mut self, attrs: &FileAttr) {
        let mut flags = 0u32;
        flags |= SSH_FILEXFER_ATTR_SIZE;
        flags |= SSH_FILEXFER_ATTR_UIDGID;
        flags |= SSH_FILEXFER_ATTR_PERMISSIONS;
        flags |= SSH_FILEXFER_ATTR_ACMODTIME;
        self.put_u32(flags);
        self.put_u64(attrs.size);
        self.put_u32(attrs.uid);
        self.put_u32(attrs.gid);
        self.put_u32(attrs.perm);
        self.put_u32(attrs.atime);
        self.put_u32(attrs.mtime);
    }
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn get_u8(&mut self) -> SftpResult<u8> {
        if self.pos >= self.data.len() {
            return Err(SftpError::Protocol("buffer underflow".into()));
        }
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn get_u32(&mut self) -> SftpResult<u32> {
        if self.pos + 4 > self.data.len() {
            return Err(SftpError::Protocol("buffer underflow".into()));
        }
        let v = u32::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    fn get_u64(&mut self) -> SftpResult<u64> {
        if self.pos + 8 > self.data.len() {
            return Err(SftpError::Protocol("buffer underflow".into()));
        }
        let v = u64::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
            self.data[self.pos + 4],
            self.data[self.pos + 5],
            self.data[self.pos + 6],
            self.data[self.pos + 7],
        ]);
        self.pos += 8;
        Ok(v)
    }

    fn get_bytes(&mut self) -> SftpResult<Vec<u8>> {
        let len = self.get_u32()? as usize;
        if self.pos + len > self.data.len() {
            return Err(SftpError::Protocol("buffer underflow".into()));
        }
        let v = self.data[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(v)
    }

    fn get_string(&mut self) -> SftpResult<String> {
        let b = self.get_bytes()?;
        String::from_utf8(b).map_err(|e| SftpError::Protocol(format!("invalid UTF-8: {e}")))
    }

    fn get_attrs(&mut self) -> SftpResult<FileAttr> {
        let flags = self.get_u32()?;
        let mut a = FileAttr::default();

        if flags & SSH_FILEXFER_ATTR_SIZE != 0 {
            a.size = self.get_u64()?;
        }
        if flags & SSH_FILEXFER_ATTR_UIDGID != 0 {
            a.uid = self.get_u32()?;
            a.gid = self.get_u32()?;
        }
        if flags & SSH_FILEXFER_ATTR_PERMISSIONS != 0 {
            a.perm = self.get_u32()?;
        }
        if flags & SSH_FILEXFER_ATTR_ACMODTIME != 0 {
            a.atime = self.get_u32()?;
            a.mtime = self.get_u32()?;
        }
        if flags & SSH_FILEXFER_ATTR_EXTENDED != 0 {
            let count = self.get_u32()?;
            for _ in 0..count {
                let _ = self.get_bytes()?; // name
                let _ = self.get_bytes()?; // value
            }
        }
        Ok(a)
    }
}

// ── SFTP Session ─────────────────────────────────────────────────────

pub struct SftpSession {
    reader: Mutex<Box<dyn Read + Send>>,
    writer: Mutex<Box<dyn Write + Send>>,
    next_id: AtomicU32,
    _child: Mutex<Option<Child>>,
}

impl SftpSession {
    /// Create a dummy session for unit tests (no real SSH connection).
    #[cfg(test)]
    pub fn dummy() -> Self {
        use std::io::Cursor;
        SftpSession {
            reader: Mutex::new(Box::new(Cursor::new(Vec::<u8>::new()))),
            writer: Mutex::new(Box::new(Cursor::new(Vec::<u8>::new()))),
            next_id: AtomicU32::new(1),
            _child: Mutex::new(None),
        }
    }

    /// Connect to remote host by spawning `ssh -s sftp`.
    pub fn connect(
        host: &str,
        port: u16,
        user: Option<&str>,
        identity: Option<&str>,
    ) -> SftpResult<Self> {
        let (our_sock, child_sock) = UnixStream::pair()?;
        our_sock.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;

        let mut cmd = Command::new("ssh");
        cmd.arg("-oStrictHostKeyChecking=accept-new")
            .arg("-oConnectTimeout=30")
            .arg("-oServerAliveInterval=15")
            .arg("-oServerAliveCountMax=3")
            .arg("-oBatchMode=yes")
            .arg("-oCiphers=aes128-gcm@openssh.com,chacha20-poly1305@openssh.com");

        if port != 22 {
            cmd.arg("-p").arg(port.to_string());
        }
        if let Some(id) = identity {
            cmd.arg("-i").arg(id);
        }

        let target = match user {
            Some(u) => format!("{u}@{host}"),
            None => host.to_string(),
        };
        cmd.arg(&target).arg("-s").arg("sftp");

        let stdin_fd: OwnedFd = child_sock.try_clone()?.into();
        let stdout_fd: OwnedFd = child_sock.into();
        cmd.stdin(Stdio::from(stdin_fd))
            .stdout(Stdio::from(stdout_fd))
            .stderr(Stdio::inherit());

        let child = cmd.spawn().map_err(|e| {
            SftpError::Io(io::Error::new(
                io::ErrorKind::Other,
                format!("ssh spawn: {e}"),
            ))
        })?;

        let reader = our_sock.try_clone()?;
        let writer = our_sock;

        let session = SftpSession {
            reader: Mutex::new(Box::new(reader)),
            writer: Mutex::new(Box::new(writer)),
            next_id: AtomicU32::new(1),
            _child: Mutex::new(Some(child)),
        };

        session.sftp_init()?;
        Ok(session)
    }

    fn next_id(&self) -> u32 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    // ── Low-level I/O ────────────────────────────────────────────────

    /// Write a packet to an already-locked writer.
    fn write_packet(w: &mut dyn Write, pkt_type: u8, id: u32, payload: &[u8]) -> SftpResult<()> {
        let total_len = 1 + 4 + payload.len();
        let mut msg = Vec::with_capacity(4 + total_len);
        msg.extend_from_slice(&(total_len as u32).to_be_bytes());
        msg.push(pkt_type);
        msg.extend_from_slice(&id.to_be_bytes());
        msg.extend_from_slice(payload);
        w.write_all(&msg).map_err(|_| SftpError::Disconnected)
    }

    /// Read a packet from an already-locked reader.
    fn read_packet(r: &mut dyn Read) -> SftpResult<(u8, Vec<u8>)> {
        let mut lenbuf = [0u8; 4];
        r.read_exact(&mut lenbuf)
            .map_err(|_| SftpError::Disconnected)?;
        let len = u32::from_be_bytes(lenbuf) as usize;
        if len == 0 || len > 512 * 1024 {
            // Bad length means the stream is irrecoverably out of sync.
            // Treat as Disconnected so the reconnect logic kicks in.
            return Err(SftpError::Disconnected);
        }
        let mut data = vec![0u8; len];
        r.read_exact(&mut data)
            .map_err(|_| SftpError::Disconnected)?;
        Ok((data[0], data[1..].to_vec()))
    }

    fn response_id(data: &[u8]) -> SftpResult<u32> {
        if data.len() < 4 {
            return Err(SftpError::Protocol("response missing request id".into()));
        }
        Ok(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
    }

    fn drain_packets(r: &mut dyn Read, count: usize) {
        for _ in 0..count {
            let _ = Self::read_packet(r);
        }
    }

    fn send(&self, pkt_type: u8, id: u32, payload: &[u8]) -> SftpResult<()> {
        let mut w = self.writer.lock().map_err(|_| SftpError::Disconnected)?;
        Self::write_packet(&mut *w, pkt_type, id, payload)?;
        w.flush().map_err(|_| SftpError::Disconnected)
    }

    fn send_no_id(&self, pkt_type: u8, payload: &[u8]) -> SftpResult<()> {
        let total_len = 1 + payload.len();
        let mut msg = Vec::with_capacity(4 + total_len);
        msg.extend_from_slice(&(total_len as u32).to_be_bytes());
        msg.push(pkt_type);
        msg.extend_from_slice(payload);

        let mut w = self.writer.lock().map_err(|_| SftpError::Disconnected)?;
        w.write_all(&msg).map_err(|_| SftpError::Disconnected)?;
        w.flush().map_err(|_| SftpError::Disconnected)
    }

    fn recv(&self) -> SftpResult<(u8, Vec<u8>)> {
        let mut r = self.reader.lock().map_err(|_| SftpError::Disconnected)?;
        Self::read_packet(&mut *r)
    }

    /// Send request and receive matching response.
    fn request(&self, pkt_type: u8, payload: &[u8]) -> SftpResult<(u8, Vec<u8>)> {
        let id = self.next_id();
        self.send(pkt_type, id, payload)?;

        // Read response (simple synchronous model — one request at a time per lock)
        let (resp_type, resp_data) = self.recv()?;

        // Verify ID matches (skip for VERSION which has no id)
        if resp_type != SSH_FXP_VERSION {
            let resp_id = Self::response_id(&resp_data)?;
            if resp_id != id {
                return Err(SftpError::Protocol(format!(
                    "id mismatch: sent {id}, got {resp_id}"
                )));
            }
        }

        Ok((resp_type, resp_data))
    }

    fn check_status(&self, resp_type: u8, data: &[u8]) -> SftpResult<()> {
        if resp_type != SSH_FXP_STATUS {
            return Err(SftpError::Protocol(format!(
                "expected STATUS, got {resp_type}"
            )));
        }
        let mut r = Reader::new(&data[4..]); // skip id
        let code = r.get_u32()?;
        if code == SSH_FX_OK {
            return Ok(());
        }
        let msg = r.get_string().unwrap_or_default();
        Err(SftpError::Status(code, msg))
    }

    // ── SFTP init ────────────────────────────────────────────────────

    fn sftp_init(&self) -> SftpResult<()> {
        let mut buf = Buf::new();
        buf.put_u32(SFTP_PROTO_VERSION);
        self.send_no_id(SSH_FXP_INIT, &buf.0)?;

        let (ptype, data) = self.recv()?;
        if ptype != SSH_FXP_VERSION {
            return Err(SftpError::Protocol(format!(
                "expected VERSION, got {ptype}"
            )));
        }
        let version = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        log::info!("SFTP server version: {version}");
        Ok(())
    }

    // ── Public API ───────────────────────────────────────────────────

    pub fn realpath(&self, path: &str) -> SftpResult<String> {
        let mut buf = Buf::new();
        buf.put_str(path);
        let (t, data) = self.request(SSH_FXP_REALPATH, &buf.0)?;
        if t == SSH_FXP_STATUS {
            self.check_status(t, &data)?;
            return Err(SftpError::Protocol("unexpected OK status".into()));
        }
        if t != SSH_FXP_NAME {
            return Err(SftpError::Protocol(format!("expected NAME, got {t}")));
        }
        let mut r = Reader::new(&data[4..]); // skip id
        let count = r.get_u32()?;
        if count == 0 {
            return Err(SftpError::Protocol("empty realpath response".into()));
        }
        r.get_string()
    }

    pub fn stat(&self, path: &str) -> SftpResult<FileAttr> {
        let mut buf = Buf::new();
        buf.put_str(path);
        let (t, data) = self.request(SSH_FXP_STAT, &buf.0)?;
        if t == SSH_FXP_STATUS {
            self.check_status(t, &data)?;
            return Err(SftpError::Protocol("unexpected OK status".into()));
        }
        if t != SSH_FXP_ATTRS {
            return Err(SftpError::Protocol(format!("expected ATTRS, got {t}")));
        }
        Reader::new(&data[4..]).get_attrs()
    }

    pub fn lstat(&self, path: &str) -> SftpResult<FileAttr> {
        let mut buf = Buf::new();
        buf.put_str(path);
        let (t, data) = self.request(SSH_FXP_LSTAT, &buf.0)?;
        if t == SSH_FXP_STATUS {
            self.check_status(t, &data)?;
            return Err(SftpError::Protocol("unexpected OK status".into()));
        }
        if t != SSH_FXP_ATTRS {
            return Err(SftpError::Protocol(format!("expected ATTRS, got {t}")));
        }
        Reader::new(&data[4..]).get_attrs()
    }

    pub fn setstat(&self, path: &str, attrs: &FileAttr) -> SftpResult<()> {
        let mut buf = Buf::new();
        buf.put_str(path);
        buf.put_attrs(attrs);
        let (t, data) = self.request(SSH_FXP_SETSTAT, &buf.0)?;
        self.check_status(t, &data)
    }

    pub fn readdir(&self, path: &str) -> SftpResult<Vec<DirEntry>> {
        // Open directory (1 round-trip)
        let mut buf = Buf::new();
        buf.put_str(path);
        let (t, data) = self.request(SSH_FXP_OPENDIR, &buf.0)?;
        if t == SSH_FXP_STATUS {
            self.check_status(t, &data)?;
            return Err(SftpError::Protocol("unexpected OK status".into()));
        }
        if t != SSH_FXP_HANDLE {
            return Err(SftpError::Protocol(format!("expected HANDLE, got {t}")));
        }
        let handle = Reader::new(&data[4..]).get_bytes()?;

        // READDIR operates on mutable directory-handle state. Even though SFTP
        // responses carry request IDs, the protocol does not guarantee a server
        // will advance a directory stream in request-ID order, so keep READDIR
        // serialized for correctness.
        let result = (|| {
            let mut entries = Vec::new();
            loop {
                let mut rbuf = Buf::new();
                rbuf.put_bytes(&handle);
                let (t, data) = self.request(SSH_FXP_READDIR, &rbuf.0)?;
                if t == SSH_FXP_STATUS {
                    let mut sr = Reader::new(&data[4..]);
                    let code = sr.get_u32()?;
                    if code == SSH_FX_EOF {
                        break;
                    }
                    let msg = sr.get_string().unwrap_or_default();
                    return Err(SftpError::Status(code, msg));
                }
                if t != SSH_FXP_NAME {
                    return Err(SftpError::Disconnected);
                }

                let mut r = Reader::new(&data[4..]);
                let count = r.get_u32()?;
                for _ in 0..count {
                    let name = r.get_string()?;
                    let _longname = r.get_string()?;
                    let attrs = r.get_attrs()?;
                    if name != "." && name != ".." {
                        entries.push(DirEntry { name, attrs });
                    }
                }
            }
            Ok(entries)
        })();

        let _ = self.close_handle(&handle);
        result
    }

    pub fn open(&self, path: &str, flags: u32, mode: u32) -> SftpResult<Vec<u8>> {
        let mut buf = Buf::new();
        buf.put_str(path);
        buf.put_u32(flags);

        // Attrs with permissions
        let mut attr_flags = 0u32;
        if flags & SSH_FXF_CREAT != 0 {
            attr_flags |= SSH_FILEXFER_ATTR_PERMISSIONS;
        }
        buf.put_u32(attr_flags);
        if attr_flags & SSH_FILEXFER_ATTR_PERMISSIONS != 0 {
            buf.put_u32(mode);
        }

        let (t, data) = self.request(SSH_FXP_OPEN, &buf.0)?;
        if t == SSH_FXP_STATUS {
            self.check_status(t, &data)?;
            return Err(SftpError::Protocol("unexpected OK status".into()));
        }
        if t != SSH_FXP_HANDLE {
            return Err(SftpError::Protocol(format!("expected HANDLE, got {t}")));
        }
        Reader::new(&data[4..]).get_bytes()
    }

    fn close_handle(&self, handle: &[u8]) -> SftpResult<()> {
        let mut buf = Buf::new();
        buf.put_bytes(handle);
        let (t, data) = self.request(SSH_FXP_CLOSE, &buf.0)?;
        self.check_status(t, &data)
    }

    pub fn close(&self, handle: &[u8]) -> SftpResult<()> {
        self.close_handle(handle)
    }

    pub fn read(&self, handle: &[u8], offset: u64, len: u32) -> SftpResult<Vec<u8>> {
        struct PendingRead {
            id: u32,
            requested_len: u32,
        }

        let total = len as u64;
        if total <= MAX_READ_SIZE as u64 {
            return self.read_single(handle, offset, len);
        }

        let mut result = Vec::with_capacity(total as usize);
        let mut next_offset = offset;
        let mut remaining = total;
        let mut chunk_size = MAX_READ_SIZE;

        while remaining > 0 {
            let mut pending = Vec::new();
            {
                let mut w = self.writer.lock().map_err(|_| SftpError::Disconnected)?;
                let mut request_offset = next_offset;
                let mut request_remaining = remaining;
                while pending.len() < READ_PIPELINE && request_remaining > 0 {
                    let requested_len = request_remaining.min(chunk_size as u64) as u32;
                    let id = self.next_id();
                    let mut buf = Buf::new();
                    buf.put_bytes(handle);
                    buf.put_u64(request_offset);
                    buf.put_u32(requested_len);
                    Self::write_packet(&mut *w, SSH_FXP_READ, id, &buf.0)?;
                    pending.push(PendingRead { id, requested_len });
                    request_offset += requested_len as u64;
                    request_remaining -= requested_len as u64;
                }
                w.flush().map_err(|_| SftpError::Disconnected)?;
            }

            let mut index_by_id = HashMap::with_capacity(pending.len());
            for request in &pending {
                index_by_id.insert(request.id, request.requested_len);
            }

            let mut responses = HashMap::with_capacity(pending.len());
            {
                let mut r = self.reader.lock().map_err(|_| SftpError::Disconnected)?;
                for received in 0..pending.len() {
                    let (t, data) = Self::read_packet(&mut *r)?;
                    let unread = pending.len() - received - 1;
                    let resp_id = match Self::response_id(&data) {
                        Ok(id) => id,
                        Err(err) => {
                            Self::drain_packets(&mut *r, unread);
                            return Err(err);
                        }
                    };
                    if !index_by_id.contains_key(&resp_id) {
                        Self::drain_packets(&mut *r, unread);
                        return Err(SftpError::Protocol(format!(
                            "pipelined read: unexpected response id {resp_id}"
                        )));
                    }
                    if responses.insert(resp_id, (t, data)).is_some() {
                        Self::drain_packets(&mut *r, unread);
                        return Err(SftpError::Protocol(format!(
                            "pipelined read: duplicate response id {resp_id}"
                        )));
                    }
                }
            }

            let mut restart = false;
            for request in &pending {
                let Some((t, data)) = responses.remove(&request.id) else {
                    return Err(SftpError::Protocol(
                        "pipelined read: missing response".into(),
                    ));
                };

                if t == SSH_FXP_STATUS {
                    let mut sr = Reader::new(&data[4..]);
                    let code = sr.get_u32()?;
                    if code == SSH_FX_EOF {
                        return Ok(result);
                    }
                    let msg = sr.get_string().unwrap_or_default();
                    return Err(SftpError::Status(code, msg));
                }
                if t != SSH_FXP_DATA {
                    return Err(SftpError::Disconnected);
                }

                let chunk = Reader::new(&data[4..]).get_bytes()?;
                if chunk.is_empty() {
                    return Ok(result);
                }

                next_offset += chunk.len() as u64;
                remaining -= chunk.len() as u64;
                result.extend_from_slice(&chunk);

                if chunk.len() < request.requested_len as usize {
                    // Later in-flight requests were scheduled assuming a full
                    // chunk at this offset, so discard those responses and retry
                    // from the first unread byte with a server-proven chunk size.
                    chunk_size = chunk_size.min(chunk.len() as u32);
                    restart = true;
                    break;
                }
                if remaining == 0 {
                    return Ok(result);
                }
            }

            if !restart {
                break;
            }
        }

        Ok(result)
    }

    fn read_single(&self, handle: &[u8], offset: u64, len: u32) -> SftpResult<Vec<u8>> {
        let len = len.min(MAX_READ_SIZE);
        let mut buf = Buf::new();
        buf.put_bytes(handle);
        buf.put_u64(offset);
        buf.put_u32(len);

        let (t, data) = self.request(SSH_FXP_READ, &buf.0)?;
        if t == SSH_FXP_STATUS {
            let mut sr = Reader::new(&data[4..]);
            let code = sr.get_u32()?;
            if code == SSH_FX_EOF {
                return Ok(Vec::new());
            }
            let msg = sr.get_string().unwrap_or_default();
            return Err(SftpError::Status(code, msg));
        }
        if t != SSH_FXP_DATA {
            return Err(SftpError::Protocol(format!("expected DATA, got {t}")));
        }
        Reader::new(&data[4..]).get_bytes()
    }

    pub fn write(&self, handle: &[u8], offset: u64, data: &[u8]) -> SftpResult<()> {
        let total = data.len() as u64;
        if total <= MAX_WRITE_SIZE as u64 {
            return self.write_single(handle, offset, data);
        }

        let mut written: u64 = 0;
        while written < total {
            let mut pending_ids = Vec::new();
            {
                let mut w = self.writer.lock().map_err(|_| SftpError::Disconnected)?;
                while pending_ids.len() < WRITE_PIPELINE && written < total {
                    let chunk_len = ((total - written) as u32).min(MAX_WRITE_SIZE);
                    let chunk_start = written as usize;
                    let chunk_end = chunk_start + chunk_len as usize;
                    let id = self.next_id();
                    let mut buf = Buf::with_capacity(chunk_len as usize + 32);
                    buf.put_bytes(handle);
                    buf.put_u64(offset + written);
                    buf.put_bytes(&data[chunk_start..chunk_end]);
                    Self::write_packet(&mut *w, SSH_FXP_WRITE, id, &buf.0)?;
                    pending_ids.push(id);
                    written += chunk_len as u64;
                }
                w.flush().map_err(|_| SftpError::Disconnected)?;
            }

            let mut r = self.reader.lock().map_err(|_| SftpError::Disconnected)?;
            for i in 0..pending_ids.len() {
                let (t, resp) = Self::read_packet(&mut *r)?;
                if t == SSH_FXP_STATUS {
                    let mut sr = Reader::new(&resp[4..]);
                    let code = sr.get_u32()?;
                    if code != SSH_FX_OK {
                        let msg = sr.get_string().unwrap_or_default();
                        let unread = pending_ids.len() - i - 1;
                        Self::drain_packets(&mut *r, unread);
                        return Err(SftpError::Status(code, msg));
                    }
                } else {
                    let unread = pending_ids.len() - i - 1;
                    Self::drain_packets(&mut *r, unread);
                    return Err(SftpError::Disconnected);
                }
            }
        }
        Ok(())
    }

    fn write_single(&self, handle: &[u8], offset: u64, data: &[u8]) -> SftpResult<()> {
        let mut buf = Buf::with_capacity(data.len() + 32);
        buf.put_bytes(handle);
        buf.put_u64(offset);
        buf.put_bytes(data);

        let (t, resp) = self.request(SSH_FXP_WRITE, &buf.0)?;
        self.check_status(t, &resp)
    }

    pub fn mkdir(&self, path: &str, mode: u32) -> SftpResult<()> {
        let mut buf = Buf::new();
        buf.put_str(path);
        buf.put_u32(SSH_FILEXFER_ATTR_PERMISSIONS);
        buf.put_u32(mode);
        let (t, data) = self.request(SSH_FXP_MKDIR, &buf.0)?;
        self.check_status(t, &data)
    }

    pub fn rmdir(&self, path: &str) -> SftpResult<()> {
        let mut buf = Buf::new();
        buf.put_str(path);
        let (t, data) = self.request(SSH_FXP_RMDIR, &buf.0)?;
        self.check_status(t, &data)
    }

    pub fn remove(&self, path: &str) -> SftpResult<()> {
        let mut buf = Buf::new();
        buf.put_str(path);
        let (t, data) = self.request(SSH_FXP_REMOVE, &buf.0)?;
        self.check_status(t, &data)
    }

    pub fn rename(&self, from: &str, to: &str) -> SftpResult<()> {
        let mut buf = Buf::new();
        buf.put_str(from);
        buf.put_str(to);
        let (t, data) = self.request(SSH_FXP_RENAME, &buf.0)?;
        self.check_status(t, &data)
    }

    pub fn symlink(&self, target: &str, link: &str) -> SftpResult<()> {
        let mut buf = Buf::new();
        buf.put_str(target);
        buf.put_str(link);
        let (t, data) = self.request(SSH_FXP_SYMLINK, &buf.0)?;
        self.check_status(t, &data)
    }

    // ── Convenience: open flags from POSIX ───────────────────────────

    pub fn open_flags_from_libc(flags: i32) -> u32 {
        let mut sf = 0u32;
        let accmode = flags & libc::O_ACCMODE;
        if accmode == libc::O_RDONLY {
            sf |= SSH_FXF_READ;
        }
        if accmode == libc::O_WRONLY {
            sf |= SSH_FXF_WRITE;
        }
        if accmode == libc::O_RDWR {
            sf |= SSH_FXF_READ | SSH_FXF_WRITE;
        }
        if flags & libc::O_CREAT != 0 {
            sf |= SSH_FXF_CREAT;
        }
        if flags & libc::O_TRUNC != 0 {
            sf |= SSH_FXF_TRUNC;
        }
        if flags & libc::O_EXCL != 0 {
            sf |= SSH_FXF_EXCL;
        }
        if flags & libc::O_APPEND != 0 {
            sf |= SSH_FXF_APPEND;
        }
        sf
    }
}

// ── Reconnecting wrapper ─────────────────────────────────────────────
// Maintains a pool of SSH connections for parallel I/O. Handles are
// prefixed with a session index byte so read/write/close route to the
// correct underlying session.

pub const CONN_STATE_CONNECTED: u8 = 0;
pub const CONN_STATE_RECONNECTING: u8 = 1;
pub const CONN_STATE_DISCONNECTED: u8 = 2;

const MAX_RECONNECT_FAILURES: u8 = 3;
const NUM_CONNECTIONS: usize = 4;

pub struct ReconnectingSftp {
    sessions: Vec<Mutex<Option<SftpSession>>>,
    next_session: AtomicU32,
    host: String,
    port: u16,
    user: Option<String>,
    identity: Option<String>,
    state: Arc<AtomicU8>,
    fail_count: AtomicU8,
}

impl ReconnectingSftp {
    #[cfg(test)]
    pub fn dummy() -> Self {
        let mut sessions = Vec::with_capacity(NUM_CONNECTIONS);
        sessions.push(Mutex::new(Some(SftpSession::dummy())));
        for _ in 1..NUM_CONNECTIONS {
            sessions.push(Mutex::new(None));
        }
        ReconnectingSftp {
            sessions,
            next_session: AtomicU32::new(0),
            host: "test".into(),
            port: 22,
            user: None,
            identity: None,
            state: Arc::new(AtomicU8::new(CONN_STATE_CONNECTED)),
            fail_count: AtomicU8::new(0),
        }
    }

    pub fn connect(
        host: &str,
        port: u16,
        user: Option<&str>,
        identity: Option<&str>,
    ) -> SftpResult<Self> {
        let primary = SftpSession::connect(host, port, user, identity)?;
        let mut sessions = Vec::with_capacity(NUM_CONNECTIONS);
        sessions.push(Mutex::new(Some(primary)));
        for _ in 1..NUM_CONNECTIONS {
            match SftpSession::connect(host, port, user, identity) {
                Ok(s) => sessions.push(Mutex::new(Some(s))),
                Err(_) => sessions.push(Mutex::new(None)),
            }
        }
        Ok(ReconnectingSftp {
            sessions,
            next_session: AtomicU32::new(0),
            host: host.to_string(),
            port,
            user: user.map(|s| s.to_string()),
            identity: identity.map(|s| s.to_string()),
            state: Arc::new(AtomicU8::new(CONN_STATE_CONNECTED)),
            fail_count: AtomicU8::new(0),
        })
    }

    pub fn state(&self) -> &Arc<AtomicU8> {
        &self.state
    }

    fn pick_session(&self) -> usize {
        (self.next_session.fetch_add(1, Ordering::Relaxed) as usize) % NUM_CONNECTIONS
    }

    fn reconnect_session(&self, idx: usize) -> bool {
        self.state.store(CONN_STATE_RECONNECTING, Ordering::SeqCst);
        log::warn!("SFTP session {idx} disconnected — reconnecting to {}...", self.host);
        let mut guard = match self.sessions[idx].lock() {
            Ok(g) => g,
            Err(_) => {
                self.state.store(CONN_STATE_DISCONNECTED, Ordering::SeqCst);
                return false;
            }
        };
        *guard = None;

        match SftpSession::connect(
            &self.host,
            self.port,
            self.user.as_deref(),
            self.identity.as_deref(),
        ) {
            Ok(new_session) => {
                log::info!("SFTP session {idx} reconnected to {}", self.host);
                *guard = Some(new_session);
                self.fail_count.store(0, Ordering::SeqCst);
                self.state.store(CONN_STATE_CONNECTED, Ordering::SeqCst);
                true
            }
            Err(e) => {
                log::error!("SFTP session {idx} reconnect failed: {e}");
                let prev = self.fail_count.fetch_add(1, Ordering::SeqCst);
                if prev + 1 >= MAX_RECONNECT_FAILURES {
                    self.state.store(CONN_STATE_DISCONNECTED, Ordering::SeqCst);
                } else {
                    self.state.store(CONN_STATE_RECONNECTING, Ordering::SeqCst);
                }
                false
            }
        }
    }

    fn reconnect(&self) -> bool {
        self.reconnect_session(0)
    }

    pub fn force_reconnect(&self) -> bool {
        self.fail_count.store(0, Ordering::SeqCst);
        let mut any_ok = false;
        for i in 0..NUM_CONNECTIONS {
            if self.reconnect_session(i) {
                any_ok = true;
            }
        }
        any_ok
    }

    fn with_retry<T, F>(&self, op: F) -> SftpResult<T>
    where
        F: Fn(&SftpSession) -> SftpResult<T>,
    {
        {
            let guard = self.sessions[0].lock().map_err(|_| SftpError::Disconnected)?;
            if let Some(ref session) = *guard {
                match op(session) {
                    Err(SftpError::Disconnected) | Err(SftpError::Protocol(_)) => {}
                    result => return result,
                }
            }
        }

        if !self.reconnect_session(0) {
            return Err(SftpError::Disconnected);
        }
        let guard = self.sessions[0].lock().map_err(|_| SftpError::Disconnected)?;
        match &*guard {
            Some(session) => op(session),
            None => Err(SftpError::Disconnected),
        }
    }

    pub fn is_connected(&self) -> bool {
        self.sessions[0].lock().map(|g| g.is_some()).unwrap_or(false)
    }

    // ── Public API ───────────────────────────────────────────────────────

    pub fn realpath(&self, path: &str) -> SftpResult<String> {
        self.with_retry(|s| s.realpath(path))
    }

    pub fn lstat(&self, path: &str) -> SftpResult<FileAttr> {
        self.with_retry(|s| s.lstat(path))
    }

    pub fn setstat(&self, path: &str, attrs: &FileAttr) -> SftpResult<()> {
        self.with_retry(|s| s.setstat(path, attrs))
    }

    pub fn readdir(&self, path: &str) -> SftpResult<Vec<DirEntry>> {
        self.with_retry(|s| s.readdir(path))
    }

    pub fn open(&self, path: &str, flags: u32, mode: u32) -> SftpResult<Vec<u8>> {
        let idx = self.pick_session();
        let guard = self.sessions[idx].lock().map_err(|_| SftpError::Disconnected)?;
        match &*guard {
            Some(session) => {
                let handle = session.open(path, flags, mode)?;
                let mut prefixed = Vec::with_capacity(1 + handle.len());
                prefixed.push(idx as u8);
                prefixed.extend_from_slice(&handle);
                Ok(prefixed)
            }
            None => {
                drop(guard);
                if !self.reconnect_session(idx) {
                    return Err(SftpError::Disconnected);
                }
                let guard = self.sessions[idx].lock().map_err(|_| SftpError::Disconnected)?;
                match &*guard {
                    Some(session) => {
                        let handle = session.open(path, flags, mode)?;
                        let mut prefixed = Vec::with_capacity(1 + handle.len());
                        prefixed.push(idx as u8);
                        prefixed.extend_from_slice(&handle);
                        Ok(prefixed)
                    }
                    None => Err(SftpError::Disconnected),
                }
            }
        }
    }

    pub fn close(&self, handle: &[u8]) -> SftpResult<()> {
        if handle.is_empty() {
            return Ok(());
        }
        let idx = handle[0] as usize % NUM_CONNECTIONS;
        let raw = &handle[1..];
        let guard = self.sessions[idx].lock().map_err(|_| SftpError::Disconnected)?;
        match &*guard {
            Some(session) => session.close(raw),
            None => Ok(()),
        }
    }

    pub fn read(&self, handle: &[u8], offset: u64, len: u32) -> SftpResult<Vec<u8>> {
        if handle.is_empty() {
            return Err(SftpError::Disconnected);
        }
        let idx = handle[0] as usize % NUM_CONNECTIONS;
        let raw = &handle[1..];
        let guard = self.sessions[idx].lock().map_err(|_| SftpError::Disconnected)?;
        match &*guard {
            Some(session) => session.read(raw, offset, len),
            None => Err(SftpError::Disconnected),
        }
    }

    pub fn write(&self, handle: &[u8], offset: u64, data: &[u8]) -> SftpResult<()> {
        if handle.is_empty() {
            return Err(SftpError::Disconnected);
        }
        let idx = handle[0] as usize % NUM_CONNECTIONS;
        let raw = &handle[1..];
        let guard = self.sessions[idx].lock().map_err(|_| SftpError::Disconnected)?;
        match &*guard {
            Some(session) => session.write(raw, offset, data),
            None => Err(SftpError::Disconnected),
        }
    }

    pub fn mkdir(&self, path: &str, mode: u32) -> SftpResult<()> {
        self.with_retry(|s| s.mkdir(path, mode))
    }

    pub fn rmdir(&self, path: &str) -> SftpResult<()> {
        self.with_retry(|s| s.rmdir(path))
    }

    pub fn remove(&self, path: &str) -> SftpResult<()> {
        self.with_retry(|s| s.remove(path))
    }

    pub fn rename(&self, from: &str, to: &str) -> SftpResult<()> {
        self.with_retry(|s| s.rename(from, to))
    }
}

impl Drop for SftpSession {
    fn drop(&mut self) {
        if let Ok(mut guard) = self._child.lock() {
            if let Some(ref mut child) = *guard {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn session_with_packets(packets: &[(u8, u32, Vec<u8>)]) -> SftpSession {
        let mut bytes = Cursor::new(Vec::new());
        for (pkt_type, id, payload) in packets {
            SftpSession::write_packet(&mut bytes, *pkt_type, *id, payload).unwrap();
        }
        SftpSession {
            reader: Mutex::new(Box::new(Cursor::new(bytes.into_inner()))),
            writer: Mutex::new(Box::new(Cursor::new(Vec::<u8>::new()))),
            next_id: AtomicU32::new(1),
            _child: Mutex::new(None),
        }
    }

    fn data_packet(id: u32, data: &[u8]) -> (u8, u32, Vec<u8>) {
        let mut payload = Buf::new();
        payload.put_bytes(data);
        (SSH_FXP_DATA, id, payload.0)
    }

    fn status_packet(id: u32, code: u32) -> (u8, u32, Vec<u8>) {
        let mut payload = Buf::new();
        payload.put_u32(code);
        payload.put_str("");
        payload.put_str("");
        (SSH_FXP_STATUS, id, payload.0)
    }

    #[test]
    fn buf_put_u32() {
        let mut buf = Buf::new();
        buf.put_u32(0x01020304);
        assert_eq!(buf.0, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn buf_put_str() {
        let mut buf = Buf::new();
        buf.put_str("abc");
        // 4-byte length (3) + 3 bytes "abc"
        assert_eq!(buf.0, vec![0, 0, 0, 3, b'a', b'b', b'c']);
    }

    #[test]
    fn buf_put_bytes() {
        let mut buf = Buf::new();
        buf.put_bytes(&[0xDE, 0xAD]);
        assert_eq!(buf.0, vec![0, 0, 0, 2, 0xDE, 0xAD]);
    }

    #[test]
    fn buf_put_attrs() {
        let attrs = FileAttr {
            size: 1024,
            uid: 1000,
            gid: 1000,
            perm: 0o100644,
            atime: 1000000,
            mtime: 2000000,
        };
        let mut buf = Buf::new();
        buf.put_attrs(&attrs);

        let mut r = Reader::new(&buf.0);
        let flags = r.get_u32().unwrap();
        assert_eq!(
            flags,
            SSH_FILEXFER_ATTR_SIZE
                | SSH_FILEXFER_ATTR_UIDGID
                | SSH_FILEXFER_ATTR_PERMISSIONS
                | SSH_FILEXFER_ATTR_ACMODTIME
        );
        assert_eq!(r.get_u64().unwrap(), 1024);
        assert_eq!(r.get_u32().unwrap(), 1000); // uid
        assert_eq!(r.get_u32().unwrap(), 1000); // gid
        assert_eq!(r.get_u32().unwrap(), 0o100644); // perm
        assert_eq!(r.get_u32().unwrap(), 1000000); // atime
        assert_eq!(r.get_u32().unwrap(), 2000000); // mtime
    }

    #[test]
    fn reader_get_u32() {
        let data = [0x00, 0x00, 0x01, 0x00];
        let mut r = Reader::new(&data);
        assert_eq!(r.get_u32().unwrap(), 256);
    }

    #[test]
    fn reader_get_string() {
        let mut buf = Buf::new();
        buf.put_str("hello");
        let mut r = Reader::new(&buf.0);
        assert_eq!(r.get_string().unwrap(), "hello");
    }

    #[test]
    fn reader_get_attrs_roundtrip() {
        let original = FileAttr {
            size: 999,
            uid: 501,
            gid: 20,
            perm: 0o40755,
            atime: 12345,
            mtime: 67890,
        };
        let mut buf = Buf::new();
        buf.put_attrs(&original);

        let mut r = Reader::new(&buf.0);
        let parsed = r.get_attrs().unwrap();
        assert_eq!(parsed.size, original.size);
        assert_eq!(parsed.uid, original.uid);
        assert_eq!(parsed.gid, original.gid);
        assert_eq!(parsed.perm, original.perm);
        assert_eq!(parsed.atime, original.atime);
        assert_eq!(parsed.mtime, original.mtime);
    }

    #[test]
    fn reader_underflow() {
        let data = [0x00, 0x01];
        let mut r = Reader::new(&data);
        assert!(r.get_u32().is_err());
    }

    #[test]
    fn open_flags_rdonly() {
        let sf = SftpSession::open_flags_from_libc(libc::O_RDONLY);
        assert_eq!(sf, SSH_FXF_READ);
    }

    #[test]
    fn open_flags_wronly() {
        let sf = SftpSession::open_flags_from_libc(libc::O_WRONLY);
        assert_eq!(sf, SSH_FXF_WRITE);
    }

    #[test]
    fn open_flags_rdwr() {
        let sf = SftpSession::open_flags_from_libc(libc::O_RDWR);
        assert_eq!(sf, SSH_FXF_READ | SSH_FXF_WRITE);
    }

    #[test]
    fn open_flags_create_trunc() {
        let sf = SftpSession::open_flags_from_libc(libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC);
        assert!(sf & SSH_FXF_WRITE != 0);
        assert!(sf & SSH_FXF_CREAT != 0);
        assert!(sf & SSH_FXF_TRUNC != 0);
    }

    #[test]
    fn open_flags_append() {
        let sf = SftpSession::open_flags_from_libc(libc::O_WRONLY | libc::O_APPEND);
        assert!(sf & SSH_FXF_WRITE != 0);
        assert!(sf & SSH_FXF_APPEND != 0);
    }

    #[test]
    fn open_flags_excl() {
        let sf = SftpSession::open_flags_from_libc(libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL);
        assert!(sf & SSH_FXF_WRITE != 0);
        assert!(sf & SSH_FXF_CREAT != 0);
        assert!(sf & SSH_FXF_EXCL != 0);
    }

    #[test]
    fn large_read_reorders_out_of_order_responses() {
        let first = vec![b'a'; MAX_READ_SIZE as usize];
        let second = b"second".to_vec();
        let mut expected = first.clone();
        expected.extend_from_slice(&second);
        let session = session_with_packets(&[data_packet(2, &second), data_packet(1, &first)]);

        let data = session
            .read(b"handle", 0, MAX_READ_SIZE + second.len() as u32)
            .unwrap();
        assert_eq!(data, expected);
    }

    #[test]
    fn large_read_handles_short_chunks_without_skipping_bytes() {
        let chunk = 65536usize;
        let tail = b"tail".to_vec();
        let a = vec![b'a'; chunk];
        let b = vec![b'b'; chunk];
        let c = vec![b'c'; chunk];
        let d = vec![b'd'; chunk];
        let mut expected = a.clone();
        expected.extend_from_slice(&b);
        expected.extend_from_slice(&c);
        expected.extend_from_slice(&d);
        expected.extend_from_slice(&tail);
        let session = session_with_packets(&[
            data_packet(2, b"ignored"),
            data_packet(1, &a),
            data_packet(5, &d),
            data_packet(3, &b),
            data_packet(6, &tail),
            data_packet(4, &c),
            status_packet(7, SSH_FX_EOF),
        ]);

        let data = session
            .read(b"handle", 0, MAX_READ_SIZE + tail.len() as u32 + 1)
            .unwrap();
        assert_eq!(data, expected);
    }
}
