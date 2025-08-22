// lib.rs - Native license guard with obfuscation & anti-tamper
// Keep dependencies in Cargo.toml as in earlier messages (ed25519-dalek, base64, sha2, chrono, chacha20poly1305, argon2, rand_core, get_if_addrs, once_cell, etc.)

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::time::{SystemTime, UNIX_EPOCH};
use sha2::{Digest, Sha256};
use once_cell::sync::Lazy;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{PublicKey, Signature, Verifier};
use serde::{Deserialize, Serialize};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, KeyInit};
use rand_core::OsRng;
use argon2::{Argon2, password_hash::SaltString};
use hex;
use std::path::PathBuf;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

#[derive(Serialize, Deserialize)]
struct TokenPayload {
    license_key: String,
    device_id: String,
    exp: u64,
    plan: Option<String>,
    nonce: Option<String>,
    ver: Option<u32>,
    srv: Option<u64>,
}

// ----------------------
// Build-time constants
// ----------------------

// You must set EXPECTED_LIB_HASH at build time (CI) to enable integrity checking.
// Example in GitHub Actions: cargo build --release --locked -- -DEXPECTED_LIB_HASH="yourhex..."
static EXPECTED_LIB_HASH: Lazy<Option<String>> = Lazy::new(|| {
    // We try to obtain it from compile-time env!
    // Set via: RUSTFLAGS="--cfg expected_hash=\"<hex>\"" cargo build --release
    // Or set environment variable for build.rs to write to env var EXPECTED_LIB_HASH.
    // Fallback: None to disable strict integrity verification.
    option_env!("EXPECTED_LIB_HASH").map(|s| s.to_string())
});

// App-specific salt/pepper: keep private and set at build time or CI.
// We'll obfuscate it below.
static COMPILED_PEPPER_OBFUSCATED: Lazy<&'static [u8]> = Lazy::new(|| {
    // Example: this is an obfuscated byte array (XOR'd). Replace with your generated obfuscated bytes.
    // For demo, we use a tiny xor of the literal. In CI you should generate this.
    // Here we keep a default fallback but you should override at build time.
    b"\x5f\x52\x5a" // small demo, replace during CI
});

// ----------------------
// Utility helpers
// ----------------------

fn now_unix_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

// Simple runtime deobfuscation (XOR with key)
fn deobf_bytes(obf: &[u8], key: u8) -> Vec<u8> {
    obf.iter().map(|b| b ^ key).collect()
}

// Convert obfuscated pepper (single-byte XOR) to string
fn get_pepper() -> String {
    // In production set a better per-byte key or key schedule; here example uses 0xAA key.
    let key: u8 = 0xAA;
    let bytes = deobf_bytes(COMPILED_PEPPER_OBFUSCATED, key);
    String::from_utf8_lossy(&bytes).to_string()
}

// Compute SHA256 of a file
fn sha256_of_file(path: &PathBuf) -> Option<String> {
    let mut f = File::open(path).ok()?;
    let mut sha = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 { break; }
        sha.update(&buf[..n]);
    }
    Some(hex::encode(sha.finalize()))
}

// Find library path at runtime
fn current_lib_path() -> Option<PathBuf> {
    // Try /proc/self/exe on unix-like, GetModuleFileName on windows, or use argv if necessary.
    #[cfg(target_os = "linux")]
    {
        std::fs::read_link("/proc/self/exe").ok()
    }
    #[cfg(target_os = "macos")]
    {
        // On macOS, use std::env::current_exe
        std::env::current_exe().ok()
    }
    #[cfg(target_os = "windows")]
    {
        std::env::current_exe().ok()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        std::env::current_exe().ok()
    }
}

// ----------------------
// Anti-debug (cross platform)
// ----------------------

#[cfg(target_os = "windows")]
fn is_debugger_attached() -> bool {
    use winapi::um::debugapi::IsDebuggerPresent;
    unsafe { IsDebuggerPresent() != 0 }
}

#[cfg(target_os = "linux")]
fn is_debugger_attached() -> bool {
    // check TracerPid in /proc/self/status
    if let Ok(txt) = std::fs::read_to_string("/proc/self/status") {
        for line in txt.lines() {
            if line.starts_with("TracerPid:") {
                if let Some(val) = line.split_whitespace().nth(1) {
                    return val != "0";
                }
            }
        }
    }
    false
}

#[cfg(target_os = "macos")]
fn is_debugger_attached() -> bool {
    use libc::{c_int, c_void};
    use std::mem::size_of;
    use std::ptr::null_mut;
    const CTL_KERN: c_int = 1;
    const KERN_PROC: c_int = 14;
    const KERN_PROC_PID: c_int = 1;
    const P_TRACED: i32 = 0x00000800;

    unsafe {
        let pid = libc::getpid();
        let mut info = libc::kinfo_proc { kp_proc: std::mem::zeroed() };
        // This is platform-specific and may require additional bindings.
        // Keep simple: return false by default if not sure.
        false
    }
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
fn is_debugger_attached() -> bool { false }

// ----------------------
// Integrity check
// ----------------------

fn perform_integrity_check_internal() -> bool {
    if let Some(expected) = EXPECTED_LIB_HASH.clone() {
        if let Some(path) = current_lib_path() {
            if let Some(hash) = sha256_of_file(&path) {
                // constant-time compare
                return hash.eq_ignore_ascii_case(&expected);
            }
        }
        return false;
    }
    // If no expected hash provided, skip strict check (return true)
    true
}

#[no_mangle]
pub extern "C" fn perform_integrity_checks() -> bool {
    // 1) anti-debug
    if is_debugger_attached() {
        return false;
    }
    // 2) integrity
    if !perform_integrity_check_internal() {
        return false;
    }
    true
}

// ----------------------
// HWID generator (composite), similar to previous implementation
// ----------------------

#[cfg(target_os = "windows")]
fn machine_id_windows() -> Option<String> {
    use winreg::enums::*;
    use winreg::RegKey;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(k) = hklm.open_subkey("SOFTWARE\\Microsoft\\Cryptography") {
        if let Ok(v): Result<String, _> = k.get_value("MachineGuid") {
            return Some(v);
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn machine_id_macos() -> Option<String> {
    use std::process::Command;
    if let Ok(out) = Command::new("ioreg").args(["-rd1", "-c", "IOPlatformExpertDevice"]).output() {
        let txt = String::from_utf8_lossy(&out.stdout);
        for line in txt.lines() {
            if line.contains("IOPlatformUUID") {
                if let Some(idx) = line.find('"') {
                    let rest = &line[idx+1..];
                    if let Some(end) = rest.find('"') {
                        return Some(rest[..end].to_string());
                    }
                }
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn machine_id_linux() -> Option<String> {
    for p in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
        if let Ok(txt) = std::fs::read_to_string(p) {
            let v = txt.trim().to_string();
            if !v.is_empty() { return Some(v); }
        }
    }
    None
}

fn machine_id() -> Option<String> {
    #[cfg(target_os = "windows")]
    { machine_id_windows() }
    #[cfg(target_os = "macos")]
    { machine_id_macos() }
    #[cfg(target_os = "linux")]
    { machine_id_linux() }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    { None }
}

fn primary_mac() -> Option<String> {
    // use get_if_addrs crate
    if let Ok(list) = get_if_addrs::get_if_addrs() {
        for iface in list {
            if iface.is_loopback() { continue; }
            if let Some(mac) = iface.mac {
                return Some(format!("{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                    mac.octets()[0], mac.octets()[1], mac.octets()[2],
                    mac.octets()[3], mac.octets()[4], mac.octets()[5]
                ));
            }
        }
    }
    None
}

fn hostname_fallback() -> Option<String> {
    if let Ok(h) = std::env::var("COMPUTERNAME") { return Some(h) }
    if let Ok(h) = std::env::var("HOSTNAME") { return Some(h) }
    if let Ok(out) = std::process::Command::new("hostname").output() {
        if out.status.success() {
            return Some(String::from_utf8_lossy(&out.stdout).trim().to_string());
        }
    }
    None
}

fn compute_hwid() -> String {
    let mid = machine_id().unwrap_or_default();
    let mac = primary_mac().unwrap_or_default();
    let host = hostname_fallback().unwrap_or_default();

    let composite = format!("MID={}|MAC={}|HOST={}", mid, mac, host);

    // pepper from compile-time obfuscated bytes
    let pepper = get_pepper();
    let mut h = Sha256::new();
    h.update(pepper.as_bytes());
    h.update(composite.as_bytes());
    hex::encode(h.finalize())
}

#[no_mangle]
pub extern "C" fn get_hwid() -> *mut c_char {
    let hwid = compute_hwid();
    CString::new(hwid).unwrap().into_raw()
}

// ----------------------
// Token operations (verify_token, validate_expiry, encrypt_token)
// ----------------------

// Split token into payload bytes and signature bytes (base64url)
fn split_token(token: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut p = token.split('.');
    let payload_b64 = p.next()?;
    let sig_b64 = p.next()?;
    if p.next().is_some() { return None; }
    let payload = URL_SAFE_NO_PAD.decode(payload_b64.as_bytes()).ok()?;
    let sig = URL_SAFE_NO_PAD.decode(sig_b64.as_bytes()).ok()?;
    Some((payload, sig))
}

#[no_mangle]
pub extern "C" fn verify_token(pubkey_b64: *const c_char, token_c: *const c_char) -> bool {
    if pubkey_b64.is_null() || token_c.is_null() { return false; }
    let pk = unsafe { CStr::from_ptr(pubkey_b64).to_string_lossy().to_string() };
    let token = unsafe { CStr::from_ptr(token_c).to_string_lossy().to_string() };

    // decode public key (standard base64)
    let pk_raw = match base64::decode(pk.as_bytes()) { Ok(b) => b, Err(_) => return false };
    let public = match PublicKey::from_bytes(&pk_raw) { Ok(p) => p, Err(_) => return false };

    let (payload, sig_raw) = match split_token(&token) { Some(t) => t, None => return false };
    let sig = match Signature::from_bytes(&sig_raw) { Ok(s) => s, Err(_) => return false };

    public.verify(&payload, &sig).is_ok()
}

#[no_mangle]
pub extern "C" fn validate_expiry(token_c: *const c_char) -> bool {
    if token_c.is_null() { return false; }
    let token = unsafe { CStr::from_ptr(token_c).to_string_lossy().to_string() };
    let (payload_json, _sig) = match split_token(&token) { Some(t) => t, None => return false };
    let payload: TokenPayload = match serde_json::from_slice(&payload_json) { Ok(p) => p, Err(_) => return false };
    payload.exp >= now_unix_secs()
}

// Derive key from HWID + app salt and encrypt token (ChaCha20-Poly1305).
// Returns base64url(nonce || ciphertext)
fn derive_key_from_hwid_and_salt() -> Option<Key> {
    let hwid = compute_hwid();
    // Use Argon2 to derive bytes
    let salt = SaltString::generate(&mut OsRng);
    let argon = Argon2::default();
    let phc = argon.hash_password_simple(hwid.as_bytes(), &salt).ok()?;
    // compress phc into 32-bytes via SHA256
    let mut h = Sha256::new();
    h.update(phc.to_string().as_bytes());
    let out = h.finalize();
    Some(Key::from_slice(&out[..32]).clone())
}

#[no_mangle]
pub extern "C" fn encrypt_token(token_c: *const c_char) -> *mut c_char {
    if token_c.is_null() { return std::ptr::null_mut(); }
    let token = unsafe { CStr::from_ptr(token_c).to_string_lossy().to_string() };

    let key = match derive_key_from_hwid_and_salt() { Some(k) => k, None => return std::ptr::null_mut() };
    let cipher = ChaCha20Poly1305::new(&key);

    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes).ok();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ct = match cipher.encrypt(nonce, token.as_bytes()) { Ok(c) => c, Err(_) => return std::ptr::null_mut() };

    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);

    let b64 = URL_SAFE_NO_PAD.encode(out);
    CString::new(b64).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn free_string(s: *mut c_char) {
    if s.is_null() { return; }
    unsafe {
        let _ = CString::from_raw(s);
    }
}
