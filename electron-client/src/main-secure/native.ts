import path from "path";
import { fileURLToPath } from "url";
import koffi from "koffi";

// --- Fix __dirname for ESM ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const libPath = path.join(
  __dirname,
  "../native/",
  process.platform === "win32"
    ? "hwid_guard.dll"
    : process.platform === "darwin"
    ? "libhwid_guard.dylib"
    : "libhwid_guard.so"
);

const lib = koffi.load(libPath);

// C exports
const _get_hwid = lib.func("char* get_hwid(void)");
const _verify_token = lib.func("bool verify_token(const char*, const char*)");
const _validate_expiry = lib.func("bool validate_expiry(const char*)");
const _encrypt_token = lib.func("char* encrypt_token(const char*)");
const _free_string = lib.func("void free_string(void*)");

// Helpers for char* → string
function wrapCString(fn: (...args: any[]) => Buffer | null) {
  return (...args: any[]) => {
    const ptr = fn(...args) as unknown as Buffer | null;
    if (!ptr) return null;
    const str = ptr.toString("utf8").replace(/\0.*$/, "");
    _free_string(ptr);
    return str;
  };
}

// Public API
export const getNativeHWID: () => string = wrapCString(_get_hwid) as any;
export const verifyToken = (pubKeyB64: string, token: string): boolean =>
  _verify_token(pubKeyB64, token);
export const validateExpiry = (token: string): boolean => _validate_expiry(token);
export const encryptToken: (token: string) => string | null = wrapCString(_encrypt_token);

// Optional: helper used by your TS code
export function decodePayload<T = any>(token: string): T | null {
  try {
    const [payloadB64] = token.split(".");
    return JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8"));
  } catch {
    return null;
  }
}
