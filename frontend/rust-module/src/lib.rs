use jsonwebtoken::{encode, decode, Header, EncodingKey, DecodingKey, Validation, Algorithm};
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::LineEnding, pkcs1::DecodeRsaPrivateKey};
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{Keypair, SignatureEncoding, RandomizedSigner};
use rsa::sha2::Sha256;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sysinfo::{System, SystemExt, DiskExt, NetworkExt};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::time::{SystemTime, UNIX_EPOCH};
use ring::rand::SystemRandom;
use ring::signature::EcdsaKeyPair;
use ring::signature::KeyPair as RingKeyPair;
use winapi::um::debugapi::IsDebuggerPresent;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,     // License key
    hwid: String,    // Hardware ID
    exp: usize,      // Expiration time
    iat: usize,      // Issued at
    jti: String,     // Unique token identifier
}

// Generate a composite hardware ID using multiple system factors
#[no_mangle]
pub extern "C" fn generate_composite_hardware_id() -> *mut c_char {
    let mut sys = System::new_all();
    sys.refresh_all();
    
    let components = vec![
        // Use disk serial numbers
        sys.disks().iter()
            .filter_map(|disk| disk.serial_number().map(|s| s.to_string_lossy().into_owned()))
            .collect::<Vec<String>>()
            .join(":"),
        
        // Use MAC addresses
        sys.networks().iter()
            .map(|(name, data)| format!("{}:{}", name, data.mac_address()))
            .collect::<Vec<String>>()
            .join(":"),
        
        // Use system information
        format!("{}:{}:{}", 
            sys.total_memory(),
            sys.cpus().len(),
            sys.name().unwrap_or_default()
        ),
    ];
    
    let composite_string = components.join("|");
    let hwid = sha256_hash(&composite_string);
    
    CString::new(hwid).unwrap().into_raw()
}

// Generate ECDSA key pair for signing
#[no_mangle]
pub extern "C" fn generate_key_pair() -> *mut c_char {
    let rng = SystemRandom::new();
    let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
        .expect("Failed to generate key pair");
    
    let key_pair_str = hex::encode(pkcs8_bytes.as_ref());
    CString::new(key_pair_str).unwrap().into_raw()
}

// Sign data with private key
#[no_mangle]
pub extern "C" fn sign_data(data: *const c_char, private_key: *const c_char) -> *mut c_char {
    let data_str = unsafe { CStr::from_ptr(data).to_str().unwrap() };
    let private_key_str = unsafe { CStr::from_ptr(private_key).to_str().unwrap() };
    
    let pkcs8_bytes = hex::decode(private_key_str).expect("Invalid private key format");
    let key_pair = EcdsaKeyPair::from_pkcs8(&ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8_bytes)
        .expect("Invalid private key");
    
    let signature = key_pair.sign(data_str.as_bytes())
        .expect("Signing failed");
    
    let signature_hex = hex::encode(signature.as_ref());
    CString::new(signature_hex).unwrap().into_raw()
}

// Verify signature with public key
#[no_mangle]
pub extern "C" fn verify_signature(data: *const c_char, signature: *const c_char, public_key: *const c_char) -> bool {
    let data_str = unsafe { CStr::from_ptr(data).to_str().unwrap() };
    let signature_str = unsafe { CStr::from_ptr(signature).to_str().unwrap() };
    let public_key_str = unsafe { CStr::from_ptr(public_key).to_str().unwrap() };
    
    let signature_bytes = hex::decode(signature_str).expect("Invalid signature format");
    let public_key_bytes = hex::decode(public_key_str).expect("Invalid public key format");
    
    let peer_public_key = ring::signature::UnparsedPublicKey::new(
        &ring::signature::ECDSA_P256_SHA256_ASN1,
        &public_key_bytes,
    );
    
    peer_public_key.verify(data_str.as_bytes(), &signature_bytes).is_ok()
}

// Create license token
#[no_mangle]
pub extern "C" fn create_license_token(
    license_key: *const c_char, 
    hardware_id: *const c_char, 
    secret: *const c_char,
    token_id: *const c_char
) -> *mut c_char {
    let license_key_str = unsafe { CStr::from_ptr(license_key).to_str().unwrap() };
    let hardware_id_str = unsafe { CStr::from_ptr(hardware_id).to_str().unwrap() };
    let secret_str = unsafe { CStr::from_ptr(secret).to_str().unwrap() };
    let token_id_str = unsafe { CStr::from_ptr(token_id).to_str().unwrap() };
    
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as usize;
    
    let expiration = now + (2 * 60 * 60); // 2 hours
    
    let claims = Claims {
        sub: license_key_str.to_owned(),
        hwid: hardware_id_str.to_owned(),
        exp: expiration,
        iat: now,
        jti: token_id_str.to_owned(),
    };
    
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret_str.as_bytes()),
    ).unwrap();
    
    CString::new(token).unwrap().into_raw()
}

// Verify license token
#[no_mangle]
pub extern "C" fn verify_license_token(token: *const c_char, secret: *const c_char) -> bool {
    let token_str = unsafe { CStr::from_ptr(token).to_str().unwrap() };
    let secret_str = unsafe { CStr::from_ptr(secret).to_str().unwrap() };
    
    match decode::<Claims>(
        token_str,
        &DecodingKey::from_secret(secret_str.as_bytes()),
        &Validation::default(),
    ) {
        Ok(_) => true,
        Err(_) => false,
    }
}

// Get token claims
#[no_mangle]
pub extern "C" fn get_token_claims(token: *const c_char, secret: *const c_char) -> *mut c_char {
    let token_str = unsafe { CStr::from_ptr(token).to_str().unwrap() };
    let secret_str = unsafe { CStr::from_ptr(secret).to_str().unwrap() };
    
    match decode::<Claims>(
        token_str,
        &DecodingKey::from_secret(secret_str.as_bytes()),
        &Validation::default(),
    ) {
        Ok(token_data) => {
            let claims_json = serde_json::to_string(&token_data.claims).unwrap();
            CString::new(claims_json).unwrap().into_raw()
        },
        Err(_) => std::ptr::null_mut(),
    }
}

// Generate SHA256 hash
fn sha256_hash(input: &str) -> String {
    use sha2::{Sha256, Digest};
    
    let mut hasher = Sha256::new();
    hasher.update(input);
    let result = hasher.finalize();
    
    hex::encode(result)
}

// Detect debugger presence (anti-debugging)
#[no_mangle]
pub extern "C" fn is_debugger_present() -> bool {
    unsafe { IsDebuggerPresent() != 0 }
}

// Free C string memory
#[no_mangle]
pub extern "C" fn free_c_string(ptr: *mut c_char) {
    unsafe {
        if ptr.is_null() {
            return;
        }
        CString::from_raw(ptr);
    }
}