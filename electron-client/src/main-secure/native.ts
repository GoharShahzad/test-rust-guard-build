import path from "path";
import { fileURLToPath } from "url";
import koffi from "koffi";

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

const guard = koffi.load(libPath);

const get_hwid = guard.func("char* get_hwid(void)");
const verify_token = guard.func("bool verify_token(const char*, const char*)");
const encrypt_token = guard.func("char* encrypt_token(const char*)");
const decrypt_token = guard.func("char* decrypt_token(const char*)");
const free_string = guard.func("void free_string(void*)");

function wrapCString(fn: Function) {
  return (...args: any[]) => {
    const cstr: Buffer | null = fn(...args);
    if (!cstr) return null;
    const result = cstr.toString("utf8").replace(/\0.*$/, "");
    free_string(cstr);
    return result;
  };
}

export const getNativeHWID = wrapCString(get_hwid);
export const verifyToken = verify_token;
export const encryptToken = wrapCString(encrypt_token);
export const decryptToken = wrapCString(decrypt_token);
export const freeString = free_string;

export function decodePayload<T = any>(token: string): T | null {
  try {
    const [payloadB64] = token.split(".");
    return JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8"));
  } catch { return null; }
}
