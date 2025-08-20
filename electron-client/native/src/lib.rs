use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use chrono::Utc;

#[derive(Serialize, Deserialize)]
struct LicenseData {
    license_key: String,
    device_id: String,
    expires_at: u64,
}

fn hwid_hash(hwid: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(hwid.as_bytes());
    hex::encode(hasher.finalize())
}

#[no_mangle]
pub extern "C" fn verify_license(license_json: *const c_char, hwid: *const c_char) -> bool {
    if license_json.is_null() || hwid.is_null() { return false; }

    let license_cstr = unsafe { CStr::from_ptr(license_json) };
    let hwid_cstr = unsafe { CStr::from_ptr(hwid) };

    let license_str = match license_cstr.to_str() { Ok(s) => s, Err(_) => return false };
    let hwid_str = match hwid_cstr.to_str() { Ok(s) => s, Err(_) => return false };

    let license: LicenseData = match serde_json::from_str(license_str) {
        Ok(l) => l,
        Err(_) => return false,
    };

    let hwid_calc = hwid_hash(&license.device_id);
    if hwid_calc != hwid_hash(hwid_str) { return false; }

    let now_ts = Utc::now().timestamp() as u64;
    if license.expires_at < now_ts { return false; }

    true
}

#[no_mangle]
pub extern "C" fn free_string(s: *mut c_char) {
    if s.is_null() { return; }
    unsafe { CString::from_raw(s); }
}
