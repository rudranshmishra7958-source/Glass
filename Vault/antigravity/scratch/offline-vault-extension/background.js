/**
 * Offline Vault - Background Service Worker
 * Coordinates session unlock, intelligent domain matching (subdomains/neocollab/examly), and in-page auto-fill.
 */

import { getStoredMeta, getStoredItems, getSessionKey, setSessionKey, clearSessionKey } from './storage.js';
import { decryptPayload, importRawKey } from './crypto.js';

// Generate dynamic toolbar action icon
function generateBadgeIcon() {
  try {
    const canvas = new OffscreenCanvas(32, 32);
    const ctx = canvas.getContext('2d');

    ctx.fillStyle = '#090d16';
    ctx.beginPath();
    ctx.arc(16, 16, 15, 0, Math.PI * 2);
    ctx.fill();

    ctx.strokeStyle = '#10b981';
    ctx.lineWidth = 2.5;
    ctx.beginPath();
    ctx.moveTo(16, 6);
    ctx.lineTo(24, 9);
    ctx.lineTo(24, 16);
    ctx.quadraticCurveTo(24, 25, 16, 27);
    ctx.quadraticCurveTo(8, 25, 8, 16);
    ctx.lineTo(8, 9);
    ctx.closePath();
    ctx.stroke();

    ctx.strokeStyle = '#34d399';
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.moveTo(12, 16);
    ctx.lineTo(15, 19);
    ctx.lineTo(20, 13);
    ctx.stroke();

    const imageData = ctx.getImageData(0, 0, 32, 32);
    chrome.action.setIcon({ imageData });
  } catch (err) {
    // fallback
  }
}

chrome.runtime.onInstalled.addListener(() => generateBadgeIcon());
chrome.runtime.onStartup.addListener(() => generateBadgeIcon());

/**
 * Flexible domain & brand matching:
 * Matches "vitvellore312.examly.io" with "examly.io" or "examly"
 * Matches "neocollab.com" or "app.neocollab.com" with "neocollab"
 */
function isDomainMatch(savedUrlOrTitle, pageUrl) {
  if (!savedUrlOrTitle || !pageUrl) return false;

  const cleanSaved = savedUrlOrTitle
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '')
    .replace(/^www\./, '')
    .trim();

  const cleanPage = pageUrl
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '')
    .replace(/^www\./, '')
    .trim();

  // 1. Direct contains check
  if (cleanPage.includes(cleanSaved) || cleanSaved.includes(cleanPage)) {
    return true;
  }

  // 2. Subdomain check (e.g., vitvellore312.examly.io -> examly.io)
  const pageParts = cleanPage.split('.');
  const savedParts = cleanSaved.split('.');

  // Check root domains
  if (pageParts.length >= 2 && savedParts.length >= 2) {
    const pageRoot = pageParts.slice(-2).join('.');
    const savedRoot = savedParts.slice(-2).join('.');
    if (pageRoot === savedRoot) return true;
  }

  // 3. Keyword / brand name matching (e.g. "neocollab" or "examly")
  const brandKeywords = cleanSaved.replace(/[^a-z0-9]/g, ' ').split(/\s+/).filter(w => w.length > 3);
  for (const kw of brandKeywords) {
    if (cleanPage.includes(kw)) {
      return true;
    }
  }

  return false;
}

// Handle messages from content scripts and popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'GET_VAULT_STATUS') {
    (async () => {
      const meta = await getStoredMeta();
      const sessionKeyBase64 = await getSessionKey();
      sendResponse({
        isInitialized: !!(meta && meta.salt && meta.canary),
        isUnlocked: !!sessionKeyBase64
      });
    })();
    return true;
  }

  if (message.type === 'SET_SESSION_KEY') {
    (async () => {
      await setSessionKey(message.keyBase64);
      sendResponse({ success: true });
    })();
    return true;
  }

  if (message.type === 'GET_SESSION_KEY') {
    (async () => {
      const keyBase64 = await getSessionKey();
      sendResponse({ keyBase64 });
    })();
    return true;
  }

  if (message.type === 'LOCK_VAULT') {
    (async () => {
      await clearSessionKey();
      sendResponse({ success: true });
    })();
    return true;
  }

  // Content script asks for matching credentials on active website
  if (message.type === 'GET_MATCHING_CREDENTIALS') {
    (async () => {
      const keyBase64 = await getSessionKey();
      if (!keyBase64) {
        sendResponse({ isUnlocked: false, credentials: [] });
        return;
      }

      try {
        const masterKey = await importRawKey(keyBase64);
        const encryptedItems = await getStoredItems();
        const matches = [];

        for (const item of encryptedItems) {
          if (item.category && item.category !== 'logins') continue;

          try {
            const secret = await decryptPayload(
              { ciphertext: item.ciphertext, iv: item.iv },
              masterKey
            );

            // Match against URL or Title
            if (isDomainMatch(secret.url, message.url) || isDomainMatch(secret.title, message.url)) {
              matches.push({
                id: item.id,
                title: secret.title,
                username: secret.username,
                password: secret.password
              });
            }
          } catch (err) {
            console.error('Decryption error for item', item.id, err);
          }
        }

        sendResponse({ isUnlocked: true, credentials: matches });
      } catch (err) {
        console.error('Session key import error', err);
        sendResponse({ isUnlocked: false, credentials: [] });
      }
    })();

    return true; // asynchronous response
  }
});
