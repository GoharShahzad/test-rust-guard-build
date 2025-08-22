use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use chrono::Utc;
use sysinfo::{System, SystemExt, DiskExt, NetworkExt};
use ed25519_dalek::{PublicKey, Signature, Verifier};
use base64::{engine::general_purpose, Engine as _};
use chacha20poly1305::{XChaCha20Poly1305, Key, XNonce};
use chacha20poly1305::aead::{Aead, NewAead};
use rand_core::OsRng;
use argon2::{self, Config};

#[derive(Serialize, Deserialize)]
struct LicenseData {
    license_key: String,
    device_id: String,
    expires_at: u64,
}

// Generate HWID from CPU + RAM + Disk + MAC
fn get_device_id() -> String {
    let sys = System::new_all();
    let cpu = sys.global_processor_info().brand().to_string();
    let ram = sys.total_memory().to_string();
    let disk = sys.disks().get(0).map(|d| d.name().to_string_lossy().to_string()).unwrap_or_default();
    let mac = sys.networks().iter().next().map(|(_, n)| n.mac_address().to_string()).unwrap_or_default();

    let raw = format!("{}-{}-{}-{}", cpu, ram, disk, mac);
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    hex::encode(hasher.finalize())
}

fn hwid_hash(hwid: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(hwid.as_bytes());
    hex::encode(hasher.finalize())
}

#[no_mangle]
pub extern "C" fn get_hwid() -> *mut c_char {
    let hwid = get_device_id();
    CString::new(hwid).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn free_string(s: *mut c_char) {
    if s.is_null() { return; }
    unsafe { CString::from_raw(s); }
}

// Encrypt token using HWID-derived key
#[no_mangle]
pub extern "C" fn encrypt_token(token: *const c_char) -> *mut c_char {
    if token.is_null() { return std::ptr::null_mut(); }
    let token_str = unsafe { CStr::from_ptr(token).to_str().unwrap_or("") };
    let hwid = get_device_id();
    let salt = b"unique_salt";
    let key = argon2::hash_raw(hwid.as_bytes(), salt, &Config::default()).unwrap();
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key[0..32]));
    let nonce = XNonce::from_slice(&[0u8; 24]);
    let ciphertext = cipher.encrypt(nonce, token_str.as_bytes()).unwrap();
    CString::new(base64::encode(ciphertext)).unwrap().into_raw()
}

// Decrypt token using HWID-derived key
#[no_mangle]
pub extern "C" fn decrypt_token(enc: *const c_char) -> *mut c_char {
    if enc.is_null() { return std::ptr::null_mut(); }
    let enc_str = unsafe { CStr::from_ptr(enc).to_str().unwrap_or("") };
    let data = base64::decode(enc_str).unwrap_or_default();
    let hwid = get_device_id();
    let salt = b"unique_salt";
    let key = argon2::hash_raw(hwid.as_bytes(), salt, &Config::default()).unwrap();
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key[0..32]));
    let nonce = XNonce::from_slice(&[0u8; 24]);
    let plaintext = cipher.decrypt(nonce, data.as_ref()).unwrap_or_default();
    CString::new(String::from_utf8_lossy(&plaintext).to_string()).unwrap().into_raw()
}

// Verify license signature
#[no_mangle]
pub extern "C" fn verify_token(pub_key_b64: *const c_char, token_b64: *const c_char) -> bool {
    if pub_key_b64.is_null() || token_b64.is_null() { return false; }
    let pub_key_str = unsafe { CStr::from_ptr(pub_key_b64).to_str().unwrap_or("") };
    let token_str = unsafe { CStr::from_ptr(token_b64).to_str().unwrap_or("") };
    let pub_key_bytes = match general_purpose::STANDARD.decode(pub_key_str) {
        Ok(b) => b, Err(_) => return false
    };
    let public_key = match PublicKey::from_bytes(&pub_key_bytes) { Ok(k) => k, Err(_) => return false };
    let sig = match general_purpose::STANDARD.decode(token_str) { Ok(s) => s, Err(_) => return false };
    let signature = match Signature::from_bytes(&sig) { Ok(s) => s, Err(_) => return false };
    public_key.verify(b"license_verification", &signature).is_ok()
}

// Validate token expiry
#[no_mangle]
pub extern "C" fn validate_expiry(token: *const c_char) -> bool {
    if token.is_null() { return false; }
    let token_str = unsafe { CStr::from_ptr(token).to_str().unwrap_or("") };
    let license: LicenseData = match serde_json::from_str(token_str) { Ok(l) => l, Err(_) => return false };
    license.expires_at >= Utc::now().timestamp() as u64
}
