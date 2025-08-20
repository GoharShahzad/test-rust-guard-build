import ffi from 'ffi-napi';
import { join } from 'path';

const libPath = join(__dirname, '../native/hwid_guard.dll'); // change per OS
const hwidLib = ffi.Library(libPath, {
  'verify_license': ['bool', ['string','string']],
  'free_string': ['void', ['pointer']],
});

const licenseJson = JSON.stringify({
  license_key: "TEST-001",
  device_id: "HWID-1234",
  expires_at: Math.floor(Date.now()/1000)+3600
});

const hwid = "HWID-1234";

console.log('License valid:', hwidLib.verify_license(licenseJson, hwid));
