import { getNativeHWID } from './native.js';
import { randomBytes } from 'crypto';
import { ChaCha20Poly1305 } from 'chacha20poly1305';
import argon2 from 'argon2';

async function deriveKey(): Promise<Uint8Array> {
  const hwid = getNativeHWID();
  return argon2.hash(hwid, {
    type: argon2.argon2id,
    memoryCost: 65536,
    hashLength: 32,
    raw: true,
  }) as Promise<Uint8Array>;
}

export async function encryptAndPack(token: string): Promise<string> {
  const key = await deriveKey();
  const cipher = new ChaCha20Poly1305(key);
  const nonce = randomBytes(12);
  const ciphertext = cipher.encrypt(nonce, Buffer.from(token, 'utf8'), null);
  return Buffer.concat([nonce, ciphertext]).toString('base64');
}

export async function unpackAndDecrypt(packed: string): Promise<string> {
  const data = Buffer.from(packed, 'base64');
  const nonce = data.subarray(0, 12);
  const ciphertext = data.subarray(12);

  const key = await deriveKey();
  const cipher = new ChaCha20Poly1305(key);

  const decrypted = cipher.decrypt(nonce, ciphertext, null);
  if (!decrypted) throw new Error('Decryption failed');

  return decrypted.toString('utf8');
}
