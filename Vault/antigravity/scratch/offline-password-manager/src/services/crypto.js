/**
 * Cryptographic operations using the browser's native Web Crypto API.
 * PBKDF2 for key derivation (100,000 iterations, SHA-256)
 * AES-GCM 256-bit for authenticated encryption with unique 12-byte IVs.
 * ZERO external dependencies, 100% offline.
 */

const CANARY_SECRET = '__OFFLINE_VAULT_CANARY_OK__';
const PBKDF2_ITERATIONS = 100000;

// Convert Uint8Array to base64 string
export function bufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

// Convert base64 string to Uint8Array
export function base64ToBuffer(base64) {
  const binary = window.atob(base64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// Generate cryptographically secure random salt (default 16 bytes)
export function generateSalt(length = 16) {
  const salt = new Uint8Array(length);
  window.crypto.getRandomValues(salt);
  return bufferToBase64(salt);
}

// Generate random IV (12 bytes recommended for AES-GCM)
export function generateIV() {
  const iv = new Uint8Array(12);
  window.crypto.getRandomValues(iv);
  return iv;
}

/**
 * Derive an AES-GCM 256-bit CryptoKey from a master password and salt using PBKDF2.
 */
export async function deriveMasterKey(masterPassword, saltBase64) {
  const encoder = new TextEncoder();
  const passwordKey = await window.crypto.subtle.importKey(
    'raw',
    encoder.encode(masterPassword),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  const salt = base64ToBuffer(saltBase64);

  const aesKey = await window.crypto.subtle.deriveKey(
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
    false,
    ['encrypt', 'decrypt']
  );

  return aesKey;
}

/**
 * Encrypt any serializable data using AES-GCM and a derived CryptoKey.
 * Returns an object with base64 encoded ciphertext and iv.
 */
export async function encryptPayload(data, key) {
  const encoder = new TextEncoder();
  const encodedData = encoder.encode(JSON.stringify(data));
  const iv = generateIV();

  const encryptedBuffer = await window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv
    },
    key,
    encodedData
  );

  return {
    ciphertext: bufferToBase64(encryptedBuffer),
    iv: bufferToBase64(iv)
  };
}

/**
 * Decrypt ciphertext using AES-GCM and a derived CryptoKey.
 * Throws an error if decryption fails (e.g. incorrect key / tampered data).
 */
export async function decryptPayload(encryptedObj, key) {
  const { ciphertext, iv } = encryptedObj;
  const ivBuffer = base64ToBuffer(iv);
  const dataBuffer = base64ToBuffer(ciphertext);

  const decryptedBuffer = await window.crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: ivBuffer
    },
    key,
    dataBuffer
  );

  const decoder = new TextDecoder();
  const jsonString = decoder.decode(decryptedBuffer);
  return JSON.parse(jsonString);
}

/**
 * Creates the auth verification token (canary) to safely test passwords without storing them.
 */
export async function createAuthVerification(key) {
  return await encryptPayload({ canary: CANARY_SECRET }, key);
}

/**
 * Verifies if a derived key is valid by attempting to decrypt the canary.
 */
export async function verifyAuth(encryptedCanary, key) {
  try {
    const result = await decryptPayload(encryptedCanary, key);
    return result && result.canary === CANARY_SECRET;
  } catch (err) {
    return false;
  }
}
