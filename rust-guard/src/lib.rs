use ed25519_dalek::{PublicKey, Signature, Verifier};
use sha2::{Sha256, Digest};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, NewAead};
use base64::{encode, decode};
use serde::{Serialize, Deserialize};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use rand::Rng;
use chrono::Utc;

#[derive(Serialize, Deserialize)]
struct LicensePayload {
    license_key: String,
    device_id: String,
    plan: String,
    exp: u64,
}

#[no_mangle]
pub extern "C" fn get_hwid(input: *const c_char) -> *mut c_char {
    unsafe {
        if input.is_null() { return std::ptr::null_mut(); }
        let s = CStr::from_ptr(input).to_str().unwrap_or("");
        let mut hasher = Sha256::new();
        hasher.update(s.as_bytes());
        CString::new(encode(hasher.finalize())).unwrap().into_raw()
    }
}

#[no_mangle]
pub extern "C" fn verify_token(pub_key_b64: *const c_char, token_b64: *const c_char) -> *mut c_char {
    unsafe {
        if pub_key_b64.is_null() || token_b64.is_null() { return std::ptr::null_mut(); }

        let pk_str = CStr::from_ptr(pub_key_b64).to_str().unwrap_or("");
        let token_str = CStr::from_ptr(token_b64).to_str().unwrap_or("");

        let parts: Vec<&str> = token_str.split('.').collect();
        if parts.len() != 2 { return std::ptr::null_mut(); }

        let payload_bytes = decode(parts[0]).unwrap_or(vec![]);
        let sig_bytes = decode(parts[1]).unwrap_or(vec![]);

        let pub_key_bytes = decode(pk_str).unwrap_or(vec![]);
        let pub_key = match PublicKey::from_bytes(&pub_key_bytes) {
            Ok(pk) => pk,
            Err(_) => return std::ptr::null_mut()
        };
        let sig = match Signature::from_bytes(&sig_bytes) {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut()
        };

        if pub_key.verify(&payload_bytes, &sig).is_err() { return std::ptr::null_mut(); }
        CString::new(String::from_utf8(payload_bytes).unwrap_or_default()).unwrap().into_raw()
    }
}

#[no_mangle]
pub extern "C" fn validate_expiry(payload_json: *const c_char) -> bool {
    unsafe {
        if payload_json.is_null() { return false; }
        let s = CStr::from_ptr(payload_json).to_str().unwrap_or("");
        match serde_json::from_str::<LicensePayload>(s) {
            Ok(p) => p.exp > Utc::now().timestamp() as u64,
            Err(_) => false
        }
    }
}

#[no_mangle]
pub extern "C" fn encrypt_token(token: *const c_char) -> *mut c_char {
    unsafe {
        if token.is_null() { return std::ptr::null_mut(); }
        let token_str = CStr::from_ptr(token).to_str().unwrap_or("");

        let key_bytes: [u8; 32] = rand::thread_rng().gen();
        let cipher = Aes256Gcm::new(Key::from_slice(&key_bytes));
        let nonce_bytes: [u8; 12] = rand::thread_rng().gen();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, token_str.as_bytes()).unwrap();

        let combined = [nonce_bytes.to_vec(), ciphertext].concat();
        CString::new(encode(combined)).unwrap().into_raw()
    }
}

#[no_mangle]
pub extern "C" fn free_string(s: *mut c_char) {
    if s.is_null() { return; }
    unsafe { CString::from_raw(s); }
}
