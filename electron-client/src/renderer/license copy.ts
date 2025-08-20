import Store from 'electron-store';
import fetch from 'node-fetch';
import { getNativeHWID, verifyToken, encryptToken, validateExpiry } from './native';

const store = new Store();
const LICENSE_SERVER = 'https://license.yourdomain.com/api/v1';
const PUB_KEY_B64 = '<YOUR_PUBLIC_ED25519_B64>';
const OFFLINE_HOURS = 72;

async function getDeviceId(): Promise<string> {
    const base = `${require('os').hostname()}-${require('os').platform()}`;
    return getNativeHWID(base);
}

export async function activate(licenseKey: string) {
    const deviceId = await getDeviceId();
    const res = await fetch(`${LICENSE_SERVER}/activate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ license_key: licenseKey, device_id: deviceId })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Activation failed');

    const payload = verifyToken(PUB_KEY_B64, data.token);
    if (!payload || !validateExpiry(payload)) throw new Error('Token invalid or expired');

    store.set('license', { token: encryptToken(data.token), key: licenseKey, last_sync: Date.now() });
}

export async function heartbeat(): Promise<boolean> {
    const licenseData = store.get('license') as any;
    if (!licenseData) return false;

    const deviceId = await getDeviceId();
    try {
        const res = await fetch(`${LICENSE_SERVER}/heartbeat`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ license_key: licenseData.key, device_id: deviceId })
        });
        const data = await res.json();
        if (!res.ok || !data.token) throw new Error();

        const payload = verifyToken(PUB_KEY_B64, data.token);
        if (!payload || !validateExpiry(payload)) throw new Error();

        store.set('license', { ...licenseData, token: encryptToken(data.token), last_sync: Date.now() });
        return true;
    } catch {
        const offlineHours = (Date.now() - licenseData.last_sync) / (1000*60*60);
        if (offlineHours > OFFLINE_HOURS) store.delete('license');
        return offlineHours <= OFFLINE_HOURS;
    }
}

export async function deactivate() {
    const licenseData = store.get('license') as any;
    if (!licenseData) return;
    store.delete('license');
}

export function isLicenseValid(): boolean {
    const licenseData = store.get('license') as any;
    if (!licenseData) return false;
    const payload = verifyToken(PUB_KEY_B64, licenseData.token);
    return payload && validateExpiry(payload);
}
