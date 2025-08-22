import path from "path";
import { fileURLToPath } from "url";
import koffi from "koffi";
// --- Fix __dirname for ESM ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const libPath = path.join(__dirname, "../native/", process.platform === "win32"
    ? "hwid_guard.dll"
    : process.platform === "darwin"
        ? "libhwid_guard.dylib"
        : "libhwid_guard.so");
// Define C signatures with koffi
const guard = koffi.load(libPath);
// Bind functions
const get_hwid = guard.func("char* get_hwid(void)");
const verify_token = guard.func("char* verify_token(const char*, const char*)");
const encrypt_token = guard.func("char* encrypt_token(const char*)");
const validate_expiry = guard.func("bool validate_expiry(const char*)");
const free_string = guard.func("void free_string(void*)");
// --- Wrappers to convert char* → JS string safely ---
function wrapCString(fn, free = free_string) {
    return (...args) => {
        const cstr = fn(...args);
        if (!cstr)
            return null;
        const result = cstr.toString("utf8").replace(/\0.*$/, ""); // strip trailing null
        free(cstr);
        return result;
    };
}
// Exported API (same names as before)
export const getNativeHWID = wrapCString(get_hwid);
export const verifyToken = wrapCString(verify_token);
export const encryptToken = wrapCString(encrypt_token);
export const validateExpiry = validate_expiry; // already returns bool
export const freeString = free_string;
// --- JWT-like decode helper (no verify) for exp/device checks if needed ---
export function decodePayload(token) {
    try {
        const [payloadB64] = token.split(".");
        return JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8"));
    }
    catch {
        return null;
    }
}
