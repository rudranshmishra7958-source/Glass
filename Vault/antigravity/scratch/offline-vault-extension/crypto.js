/**
 * Cryptographic operations using the browser's native Web Crypto API.
 * PBKDF2 (100,000 iterations, SHA-256) + AES-GCM 256-bit.
 * Zero external dependencies.
 */

export const CANARY_SECRET = '__OFFLINE_VAULT_CANARY_OK__';
export const PBKDF2_ITERATIONS = 100000;

export function bufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function base64ToBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function generateSalt(length = 16) {
  const salt = new Uint8Array(length);
  crypto.getRandomValues(salt);
  return bufferToBase64(salt);
}

export async function deriveMasterKey(masterPassword, saltBase64) {
  const encoder = new TextEncoder();
  const passwordKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(masterPassword),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  const salt = base64ToBuffer(saltBase64);

  return await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256'
    },
    passwordKey,
    {
      name: 'AES-GCM',
      length: 256
    },
    true, // exportable so it can be held in chrome.storage.session during browser session
    ['encrypt', 'decrypt']
  );
}

/**
 * Export CryptoKey to Base64 string for in-memory chrome.storage.session persistence.
 */
export async function exportRawKey(key) {
  const raw = await crypto.subtle.exportKey('raw', key);
  return bufferToBase64(raw);
}

/**
 * Re-import CryptoKey from Base64 string stored in chrome.storage.session.
 */
export async function importRawKey(keyBase64) {
  const raw = base64ToBuffer(keyBase64);
  return await crypto.subtle.importKey(
    'raw',
    raw,
    { name: 'AES-GCM' },
    true,
    ['encrypt', 'decrypt']
  );
}

export async function encryptPayload(data, key) {
  const encoder = new TextEncoder();
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);

  const encryptedBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoder.encode(JSON.stringify(data))
  );

  return {
    ciphertext: bufferToBase64(encryptedBuffer),
    iv: bufferToBase64(iv)
  };
}

export async function decryptPayload(encryptedObj, key) {
  const ivBuffer = base64ToBuffer(encryptedObj.iv);
  const dataBuffer = base64ToBuffer(encryptedObj.ciphertext);

  const decryptedBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: ivBuffer },
    key,
    dataBuffer
  );

  const decoder = new TextDecoder();
  return JSON.parse(decoder.decode(decryptedBuffer));
}

export function generateSecurePassword({
  length = 20,
  useLower = true,
  useUpper = true,
  useNumbers = true,
  useSymbols = true,
  avoidAmbiguous = false
} = {}) {
  let lower = 'abcdefghijklmnopqrstuvwxyz';
  let upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  let nums = '0123456789';
  let syms = '!@#$%^&*()_+-=[]{}|;:,.<>?';

  if (avoidAmbiguous) {
    lower = lower.replace(/[il1]/g, '');
    upper = upper.replace(/[IO]/g, '');
    nums = nums.replace(/[01]/g, '');
    syms = syms.replace(/[{}[\]()/\\'"`~,;:.<>]/g, '');
  }

  let pool = '';
  const guaranteed = [];
  const getRand = (max) => {
    const arr = new Uint32Array(1);
    crypto.getRandomValues(arr);
    return arr[0] % max;
  };

  if (useLower) { pool += lower; guaranteed.push(lower[getRand(lower.length)]); }
  if (useUpper) { pool += upper; guaranteed.push(upper[getRand(upper.length)]); }
  if (useNumbers) { pool += nums; guaranteed.push(nums[getRand(nums.length)]); }
  if (useSymbols) { pool += syms; guaranteed.push(syms[getRand(syms.length)]); }
  if (!pool) { pool = lower; guaranteed.push(lower[getRand(lower.length)]); }

  const res = [...guaranteed];
  while (res.length < length) res.push(pool[getRand(pool.length)]);

  for (let i = res.length - 1; i > 0; i--) {
    const j = getRand(i + 1);
    [res[i], res[j]] = [res[j], res[i]];
  }

  return res.join('');
}

export function evaluateStrength(pwd) {
  if (!pwd) return { score: 0, label: 'Empty', color: '#64748b', bits: 0 };
  let pool = 0;
  if (/[a-z]/.test(pwd)) pool += 26;
  if (/[A-Z]/.test(pwd)) pool += 26;
  if (/[0-9]/.test(pwd)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pwd)) pool += 32;

  const bits = Math.floor(pwd.length * Math.log2(pool || 1));
  if (pwd.length < 8 || bits < 40) return { score: 1, label: 'Weak', color: '#ef4444', bits };
  if (pwd.length < 12 || bits < 60) return { score: 2, label: 'Fair', color: '#f59e0b', bits };
  if (pwd.length < 16 || bits < 80) return { score: 3, label: 'Strong', color: '#10b981', bits };
  return { score: 4, label: 'Very Strong', color: '#34d399', bits };
}
