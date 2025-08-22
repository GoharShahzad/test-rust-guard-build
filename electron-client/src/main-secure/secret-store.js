import keytar from 'keytar';
import crypto from 'crypto';
const SERVICE = 'com.example.license';
const ACCOUNT = 'token-key';
async function getOrCreateKey() {
    const existing = await keytar.getPassword(SERVICE, ACCOUNT);
    if (existing)
        return Buffer.from(existing, 'base64');
    const key = crypto.randomBytes(32); // AES-256
    await keytar.setPassword(SERVICE, ACCOUNT, key.toString('base64'));
    return key;
}
export async function encryptAndPack(plaintext) {
    const key = await getOrCreateKey();
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([iv, tag, ct]).toString('base64'); // [12|16|N]
}
export async function unpackAndDecrypt(packedB64) {
    const buf = Buffer.from(packedB64, 'base64');
    const iv = buf.subarray(0, 12);
    const tag = buf.subarray(12, 28);
    const ct = buf.subarray(28);
    const key = await getOrCreateKey();
    const dec = crypto.createDecipheriv('aes-256-gcm', key, iv);
    dec.setAuthTag(tag);
    return Buffer.concat([dec.update(ct), dec.final()]).toString('utf8');
}
