import Store from 'electron-store';
import fetch from 'node-fetch';
import { getNativeHWID, verifyToken, decodePayload } from './native.js';
import { encryptAndPack, unpackAndDecrypt } from './secret-store.js';

const store = new Store();
const LICENSE_SERVER = 'http://127.0.0.1:8000/api/v1';
const PUB_KEY_B64 = 'u82DR/AlqEfPyrXnnCQelNqQRTC490PjxE6W9Faahwc=';
const OFFLINE_HOURS = 72;

type Saved = { token_enc: string; key: string; last_sync: number };

export async function activate(licenseKey: string) {
  const deviceId = getNativeHWID(); // now guaranteed string
  const res = await fetch(`${LICENSE_SERVER}/activate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ license_key: licenseKey, device_id: deviceId })
  });
  
    type ActivationResponse = { token?: string; error?: string };
    const data = (await res.json()) as ActivationResponse;
//   const data = await res.json().catch(() => ({}));
  if (!res.ok || !data.token) throw new Error(data.error || 'Activation failed');

  if (!verifyToken(PUB_KEY_B64, data.token)) throw new Error('Signature invalid');
  const payload = decodePayload<any>(data.token);
  if (!payload || payload.device_id !== deviceId) throw new Error('Device mismatch');
  if (!payload.exp || Date.now()/1000 > payload.exp) throw new Error('Token expired');

  const token_enc = await encryptAndPack(data.token);
  const save: Saved = { token_enc, key: licenseKey, last_sync: Date.now() };
  store.set('license', save);
  return true;
}

export async function heartbeat(): Promise<boolean> {
  const saved = store.get('license') as Saved | undefined;
  if (!saved) return false;

  const deviceId = getNativeHWID();
  try {
    const res = await fetch(`${LICENSE_SERVER}/heartbeat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ license_key: saved.key, device_id: deviceId })
    });
    type ActivationResponse = { token?: string; error?: string };
    const data = (await res.json()) as ActivationResponse;
    if (!res.ok || !data.token) throw new Error('no token');

    if (!verifyToken(PUB_KEY_B64, data.token)) throw new Error('bad sig');
    const payload = decodePayload<any>(data.token);
    if (!payload || payload.device_id !== deviceId) throw new Error('device mismatch');
    if (!payload.exp || Date.now()/1000 > payload.exp) throw new Error('expired');

    const token_enc = await encryptAndPack(data.token);
    store.set('license', { ...saved, token_enc, last_sync: Date.now() });
    return true;
  } catch {
    const hours = (Date.now() - saved.last_sync) / 36e5;
    if (hours > OFFLINE_HOURS) { store.delete('license'); return false; }
    return true; // still within offline window
  }
}

export async function deactivate() {
  store.delete('license');
  return true;
}

export async function isValid(): Promise<boolean> {
  const saved = store.get('license') as Saved | undefined;
  if (!saved) return false;
  try {
    const token = await unpackAndDecrypt(saved.token_enc);
    if (!verifyToken(PUB_KEY_B64, token)) return false;
    const payload = decodePayload<any>(token);
    return !!(payload && payload.exp && Date.now()/1000 <= payload.exp);
  } catch { return false; }
}
