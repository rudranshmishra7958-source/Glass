/**
 * Storage wrapper for both persistent storage (chrome.storage.local)
 * and in-memory session persistence (chrome.storage.session).
 * Zero external calls.
 */

// Persistent encrypted metadata
export async function getStoredMeta() {
  const result = await chrome.storage.local.get(['vault_meta']);
  return result.vault_meta || null;
}

export async function setStoredMeta(meta) {
  await chrome.storage.local.set({ vault_meta: meta });
}

// Persistent encrypted items
export async function getStoredItems() {
  const result = await chrome.storage.local.get(['vault_items']);
  return result.vault_items || [];
}

export async function saveStoredItem(item) {
  const result = await chrome.storage.local.get(['vault_items']);
  const items = result.vault_items || [];
  const index = items.findIndex(i => i.id === item.id);
  if (index >= 0) {
    items[index] = item;
  } else {
    items.unshift(item);
  }
  await chrome.storage.local.set({ vault_items: items });
  return items;
}

export async function deleteStoredItem(id) {
  const result = await chrome.storage.local.get(['vault_items']);
  const items = result.vault_items || [];
  const filtered = items.filter(i => i.id !== id);
  await chrome.storage.local.set({ vault_items: filtered });
  return filtered;
}

export async function clearAllStoredData() {
  await chrome.storage.local.clear();
  await clearSessionKey();
}

// In-Memory Browser Session Key (Lives until browser closes or user locks)
export async function getSessionKey() {
  try {
    if (chrome.storage.session) {
      const result = await chrome.storage.session.get(['vault_session_key']);
      return result.vault_session_key || null;
    }
  } catch (err) {
    console.warn('Session storage not available:', err);
  }
  return null;
}

export async function setSessionKey(keyBase64) {
  try {
    if (chrome.storage.session) {
      await chrome.storage.session.set({ vault_session_key: keyBase64 });
    }
  } catch (err) {
    console.warn('Session storage error:', err);
  }
}

export async function clearSessionKey() {
  try {
    if (chrome.storage.session) {
      await chrome.storage.session.remove(['vault_session_key']);
    }
  } catch (err) {
    console.warn('Session storage clear error:', err);
  }
}
