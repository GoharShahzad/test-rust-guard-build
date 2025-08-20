import ffi from 'ffi-napi';
import path from 'path';

const libPath = path.join(__dirname, '../native/',
    process.platform === 'win32' ? 'hwid_guard.dll'
    : process.platform === 'darwin' ? 'libhwid_guard.dylib'
    : 'libhwid_guard.so');

const guard = ffi.Library(libPath, {
    get_hwid: ['string', ['string']],
    verify_token: ['string', ['string','string']],
    encrypt_token: ['string', ['string']],
    validate_expiry: ['bool', ['string']],
    free_string: ['void', ['pointer']]
});

export const getNativeHWID = guard.get_hwid;
export const verifyToken = guard.verify_token;
export const encryptToken = guard.encrypt_token;
export const validateExpiry = guard.validate_expiry;
export const freeString = guard.free_string;
