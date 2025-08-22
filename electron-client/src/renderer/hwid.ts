import path from "path";
import { fileURLToPath } from "url";
import koffi from "koffi";
import fetch from "node-fetch";

// --- Fix __dirname for ESM ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// --- DLL path handling ---
const dllPath =
  process.env.NODE_ENV === "production"
    ? path.join(process.resourcesPath, "hwid_guard.dll") // Production
    : path.join(__dirname, "..", "hwid_guard.dll"); // Development

// --- Load native library ---
const hwidLib = koffi.load(dllPath);

// --- Define functions ---
const get_hwid = hwidLib.func("char* get_hwid(void)");
const free_string = hwidLib.func("void free_string(void*)");

// --- Safe wrapper (auto free char* to avoid leaks) ---
function getHWID(): string {
  const cstr: Buffer | null = get_hwid();
  if (!cstr) return "UNKNOWN_HWID";
  const hwid = cstr.toString("utf8").replace(/\0.*$/, ""); // strip null terminator
  free_string(cstr);
  return hwid;
}

// --- Laravel verification ---
export async function verifyWithLaravel(license: string): Promise<boolean> {
  const hwid = getHWID();

  const response = await fetch("http://localhost:8000/api/v1/activate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ license, hwid }),
  });

  if (!response.ok) throw new Error("Server rejected license");

  type ValidationResponse = { valid?: boolean; error?: string };
  const data = (await response.json()) as ValidationResponse;

  return data.valid === true;
}

export { getHWID };
