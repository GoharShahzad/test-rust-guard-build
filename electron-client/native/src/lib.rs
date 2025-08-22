use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use chrono::Utc;
use sysinfo::{System, SystemExt, ComponentExt, CpuExt};
use ed25519_dalek::{PublicKey, Signature, Verifier};
use base64::{engine::general_purpose, Engine as _};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand_core::OsRng;
use argon2::{Argon2, password_hash::{SaltString, PasswordHasher, PasswordVerifier}};

#[derive(Serialize, Deserialize)]
struct LicenseData {
    license_key: String,
    device_id: String,
    exp: u64,
    sig: String,
}

fn get_hwid_string() -> String {
    // Example: Use CPU + disk + MAC fingerprint combination
    let mut sys = System::new_all();
    sys.refresh_all();

    let cpu = sys.cpus().first().map(|c| c.brand().to_string()).unwrap_or_default();
    let disk = sys.disks().first().map(|d| d.name().to_string_lossy().to_string()).unwrap_or_default();
    let mac = sys.networks().first().map(|(_, n)| n.mac_address().unwrap_or_default()).unwrap_or_default();

    let combined = format!("{}:{}:{}", cpu, disk, mac);
    let mut hasher = Sha256::new();
    hasher.update(combined.as_bytes());
    hex::encode(hasher.finalize())
}

#[no_mangle]
pub extern "C" fn get_hwid() -> *mut c_char {
    let hwid = get_hwid_string();
    CString::new(hwid).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn verify_token(pub_key_b64: *const c_char, token_json: *const c_char) -> bool {
    if pub_key_b64.is_null() || token_json.is_null() { return false; }

    let pub_key = unsafe { CStr::from_ptr(pub_key_b64).to_str().unwrap_or("") };
    let token_str = unsafe { CStr::from_ptr(token_json).to_str().unwrap_or("") };

    let license: LicenseData = match serde_json::from_str(token_str) { Ok(l) => l, Err(_) => return false };
    if license.device_id != get_hwid_string() { return false; }
    if license.exp < Utc::now().timestamp() as u64 { return false; }

    let sig_bytes = match general_purpose::STANDARD.decode(license.sig) { Ok(b) => b, Err(_) => return false };
    let pub_key_bytes = match general_purpose::STANDARD.decode(pub_key) { Ok(b) => b, Err(_) => return false };

    let pk = match PublicKey::from_bytes(&pub_key_bytes) { Ok(k) => k, Err(_) => return false };
    let message = format!("{}:{}:{}", license.license_key, license.device_id, license.exp);

    pk.verify(message.as_bytes(), &Signature::from_bytes(&sig_bytes).unwrap_or(Signature::from_bytes(&[0;64]).unwrap())).is_ok()
}

#[no_mangle]
pub extern "C" fn encrypt_token(token: *const c_char) -> *mut c_char {
    if token.is_null() { return std::ptr::null_mut(); }
    let token_str = unsafe { CStr::from_ptr(token).to_str().unwrap_or("") };

    let hwid_hash = get_hwid_string();
    let salt = SaltString::b64_encode(hwid_hash.as_bytes()).unwrap();
    let argon = Argon2::default();
    let key = argon.hash_password_simple(token_str.as_bytes(), &salt).unwrap().hash.unwrap();
    let key_bytes = &key.as_bytes()[..32.min(key.as_bytes().len())];

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key_bytes));
    let nonce = Nonce::from_slice(&[0u8;12]);
    let ciphertext = cipher.encrypt(nonce, token_str.as_bytes()).unwrap();

    CString::new(base64::encode(ciphertext)).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn decrypt_token(enc: *const c_char) -> *mut c_char {
    if enc.is_null() { return std::ptr::null_mut(); }
    let enc_str = unsafe { CStr::from_ptr(enc).to_str().unwrap_or("") };
    let ciphertext = base64::decode(enc_str).unwrap_or_default();

    let hwid_hash = get_hwid_string();
    let salt = SaltString::b64_encode(hwid_hash.as_bytes()).unwrap();
    let argon = Argon2::default();
    let key = argon.hash_password_simple(b"", &salt).unwrap().hash.unwrap();
    let key_bytes = &key.as_bytes()[..32.min(key.as_bytes().len())];

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key_bytes));
    let nonce = Nonce::from_slice(&[0u8;12]);
    let decrypted = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap_or_default();

    CString::new(decrypted).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn free_string(s: *mut c_char) {
    if s.is_null() { return; }
    unsafe { CString::from_raw(s); }
}
