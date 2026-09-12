/**
 * Cryptographically secure password generation and strength estimation.
 */

const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const NUMBERS = '0123456789';
const SYMBOLS = '!@#$%^&*()_+-=[]{}|;:,.<>?';
const AMBIGUOUS = /[il1Lo0O]/g;

// Secure random integer in range [0, max - 1]
function getSecureRandomInt(max) {
  const array = new Uint32Array(1);
  const maxRange = Math.floor(0xffffffff / max) * max;
  let rand;
  do {
    window.crypto.getRandomValues(array);
    rand = array[0];
  } while (rand >= maxRange);
  return rand % max;
}

export function generateSecurePassword({
  length = 18,
  useLower = true,
  useUpper = true,
  useNumbers = true,
  useSymbols = true,
  avoidAmbiguous = false
} = {}) {
  let charPool = '';
  let guaranteedChars = [];

  let lower = LOWERCASE;
  let upper = UPPERCASE;
  let nums = NUMBERS;
  let syms = SYMBOLS;

  if (avoidAmbiguous) {
    lower = lower.replace(AMBIGUOUS, '');
    upper = upper.replace(AMBIGUOUS, '');
    nums = nums.replace(AMBIGUOUS, '');
    syms = syms.replace(/[{}[\]()/\\'"`~,;:.<>]/g, '');
  }

  if (useLower) {
    charPool += lower;
    guaranteedChars.push(lower[getSecureRandomInt(lower.length)]);
  }
  if (useUpper) {
    charPool += upper;
    guaranteedChars.push(upper[getSecureRandomInt(upper.length)]);
  }
  if (useNumbers) {
    charPool += nums;
    guaranteedChars.push(nums[getSecureRandomInt(nums.length)]);
  }
  if (useSymbols) {
    charPool += syms;
    guaranteedChars.push(syms[getSecureRandomInt(syms.length)]);
  }

  if (charPool.length === 0) {
    charPool = lower;
    guaranteedChars.push(lower[getSecureRandomInt(lower.length)]);
  }

  const resultChars = [...guaranteedChars];
  while (resultChars.length < length) {
    resultChars.push(charPool[getSecureRandomInt(charPool.length)]);
  }

  // Fisher-Yates shuffle with cryptographic random values
  for (let i = resultChars.length - 1; i > 0; i--) {
    const j = getSecureRandomInt(i + 1);
    [resultChars[i], resultChars[j]] = [resultChars[j], resultChars[i]];
  }

  return resultChars.join('');
}

export function evaluatePasswordStrength(password) {
  if (!password) {
    return { score: 0, label: 'Empty', color: 'var(--text-muted)', bits: 0 };
  }

  let poolSize = 0;
  if (/[a-z]/.test(password)) poolSize += 26;
  if (/[A-Z]/.test(password)) poolSize += 26;
  if (/[0-9]/.test(password)) poolSize += 10;
  if (/[^a-zA-Z0-9]/.test(password)) poolSize += 32;

  const bits = Math.floor(password.length * (Math.log2(poolSize || 1)));

  if (password.length < 8 || bits < 40) {
    return { score: 1, label: 'Weak', color: 'var(--danger)', bits };
  } else if (password.length < 12 || bits < 60) {
    return { score: 2, label: 'Fair', color: 'var(--warning)', bits };
  } else if (password.length < 16 || bits < 80) {
    return { score: 3, label: 'Strong', color: 'var(--primary)', bits };
  } else {
    return { score: 4, label: 'Very Strong', color: '#34d399', bits };
  }
}
