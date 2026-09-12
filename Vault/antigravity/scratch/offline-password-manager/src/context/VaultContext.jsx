import React, { createContext, useContext, useState, useEffect, useRef, useCallback } from 'react';
import {
  generateSalt,
  deriveMasterKey,
  createAuthVerification,
  verifyAuth,
  encryptPayload,
  decryptPayload
} from '../services/crypto';
import {
  getMeta,
  saveMeta,
  getAllEncryptedItems,
  saveEncryptedItem,
  deleteEncryptedItem,
  clearAllData
} from '../services/db';

const VaultContext = createContext(null);

export function VaultProvider({ children }) {
  const [vaultState, setVaultState] = useState('loading'); // 'loading' | 'uninitialized' | 'locked' | 'unlocked'
  const [items, setItems] = useState([]);
  const [autoLockMinutes, setAutoLockMinutes] = useState(15);
  const [metaInfo, setMetaInfo] = useState(null);

  // In-memory master key (never stored to disk or localStorage)
  const masterKeyRef = useRef(null);
  const lastActiveRef = useRef(Date.now());

  // Check vault initialization on load
  const checkVaultStatus = useCallback(async () => {
    try {
      const meta = await getMeta();
      if (!meta || !meta.salt || !meta.canary) {
        setVaultState('uninitialized');
      } else {
        setMetaInfo(meta);
        if (meta.autoLockMinutes) {
          setAutoLockMinutes(meta.autoLockMinutes);
        }
        setVaultState('locked');
      }
    } catch (err) {
      console.error('Error initializing vault:', err);
      setVaultState('uninitialized');
    }
  }, []);

  useEffect(() => {
    checkVaultStatus();
  }, [checkVaultStatus]);

  // Lock Vault: Immediately clear sensitive keys and decrypted items from memory
  const lockVault = useCallback(() => {
    masterKeyRef.current = null;
    setItems([]);
    setVaultState('locked');
  }, []);

  // Setup Vault (first-time initialization)
  const setupVault = async (masterPassword) => {
    const salt = generateSalt(16);
    const key = await deriveMasterKey(masterPassword, salt);
    const canary = await createAuthVerification(key);

    const meta = {
      salt,
      canary,
      autoLockMinutes: 15,
      createdAt: new Date().toISOString()
    };

    await saveMeta(meta);
    setMetaInfo(meta);
    masterKeyRef.current = key;
    setItems([]);
    setVaultState('unlocked');
    lastActiveRef.current = Date.now();
  };

  // Unlock Vault
  const unlockVault = async (masterPassword) => {
    const meta = await getMeta();
    if (!meta || !meta.salt || !meta.canary) {
      throw new Error('Vault is not initialized.');
    }

    const key = await deriveMasterKey(masterPassword, meta.salt);
    const isValid = await verifyAuth(meta.canary, key);
    if (!isValid) {
      throw new Error('Incorrect master password.');
    }

    // Load and decrypt items
    const encryptedItems = await getAllEncryptedItems();
    const decryptedItems = [];

    for (const item of encryptedItems) {
      try {
        const payload = await decryptPayload(
          { ciphertext: item.ciphertext, iv: item.iv },
          key
        );
        decryptedItems.push({
          id: item.id,
          category: item.category || 'logins',
          favorite: !!item.favorite,
          updatedAt: item.updatedAt,
          createdAt: item.createdAt,
          ...payload
        });
      } catch (err) {
        console.error(`Failed to decrypt item ${item.id}`, err);
      }
    }

    masterKeyRef.current = key;
    setItems(decryptedItems);
    setMetaInfo(meta);
    if (meta.autoLockMinutes) {
      setAutoLockMinutes(meta.autoLockMinutes);
    }
    setVaultState('unlocked');
    lastActiveRef.current = Date.now();
  };

  // Add Item
  const addItem = async (itemData) => {
    if (!masterKeyRef.current) throw new Error('Vault is locked');

    const id = Date.now().toString(36) + Math.random().toString(36).substr(2, 6);
    const now = new Date().toISOString();

    const { category = 'logins', favorite = false, ...secretData } = itemData;

    const encrypted = await encryptPayload(secretData, masterKeyRef.current);

    const record = {
      id,
      category,
      favorite,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      createdAt: now,
      updatedAt: now
    };

    await saveEncryptedItem(record);

    const newItem = {
      id,
      category,
      favorite,
      createdAt: now,
      updatedAt: now,
      ...secretData
    };

    setItems((prev) => [newItem, ...prev]);
    lastActiveRef.current = Date.now();
    return newItem;
  };

  // Update Item
  const updateItem = async (id, itemData) => {
    if (!masterKeyRef.current) throw new Error('Vault is locked');

    const existing = items.find((i) => i.id === id);
    if (!existing) throw new Error('Item not found');

    const { category = existing.category, favorite = existing.favorite, ...secretData } = itemData;

    const encrypted = await encryptPayload(secretData, masterKeyRef.current);
    const now = new Date().toISOString();

    const record = {
      id,
      category,
      favorite,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      createdAt: existing.createdAt || now,
      updatedAt: now
    };

    await saveEncryptedItem(record);

    const updated = {
      ...existing,
      category,
      favorite,
      updatedAt: now,
      ...secretData
    };

    setItems((prev) => prev.map((item) => (item.id === id ? updated : item)));
    lastActiveRef.current = Date.now();
    return updated;
  };

  // Delete Item
  const deleteItem = async (id) => {
    await deleteEncryptedItem(id);
    setItems((prev) => prev.filter((i) => i.id !== id));
    lastActiveRef.current = Date.now();
  };

  // Toggle Favorite
  const toggleFavorite = async (id) => {
    const item = items.find((i) => i.id === id);
    if (!item) return;
    await updateItem(id, { ...item, favorite: !item.favorite });
  };

  // Change Master Password (re-encrypts everything)
  const changeMasterPassword = async (currentPassword, newPassword) => {
    if (!metaInfo) throw new Error('Vault metadata not found');

    // 1. Verify current password
    const oldKey = await deriveMasterKey(currentPassword, metaInfo.salt);
    const isValid = await verifyAuth(metaInfo.canary, oldKey);
    if (!isValid) {
      throw new Error('Current master password does not match.');
    }

    // 2. Generate new salt and derive new key
    const newSalt = generateSalt(16);
    const newKey = await deriveMasterKey(newPassword, newSalt);
    const newCanary = await createAuthVerification(newKey);

    // 3. Re-encrypt all items
    for (const item of items) {
      const { id, category, favorite, createdAt, updatedAt, ...secretData } = item;
      const encrypted = await encryptPayload(secretData, newKey);
      await saveEncryptedItem({
        id,
        category,
        favorite,
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv,
        createdAt,
        updatedAt: new Date().toISOString()
      });
    }

    // 4. Save new meta
    const updatedMeta = {
      ...metaInfo,
      salt: newSalt,
      canary: newCanary,
      updatedAt: new Date().toISOString()
    };
    await saveMeta(updatedMeta);

    masterKeyRef.current = newKey;
    setMetaInfo(updatedMeta);
    lastActiveRef.current = Date.now();
  };

  // Update Settings (Auto-lock timer)
  const updateSettings = async (settings) => {
    if (settings.autoLockMinutes !== undefined) {
      setAutoLockMinutes(settings.autoLockMinutes);
      if (metaInfo) {
        const updatedMeta = { ...metaInfo, autoLockMinutes: settings.autoLockMinutes };
        await saveMeta(updatedMeta);
        setMetaInfo(updatedMeta);
      }
    }
  };

  // Export Encrypted Vault Backup
  const exportEncryptedVault = async () => {
    const meta = await getMeta();
    const encryptedRecords = await getAllEncryptedItems();

    const backupPayload = {
      appName: 'OfflinePasswordManager',
      version: 1,
      exportedAt: new Date().toISOString(),
      salt: meta.salt,
      canary: meta.canary,
      items: encryptedRecords
    };

    const blob = new Blob([JSON.stringify(backupPayload, null, 2)], {
      type: 'application/json'
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `offline-vault-backup-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Import Backup
  const importBackup = async (backupJsonString, backupMasterPassword) => {
    let backup;
    try {
      backup = JSON.parse(backupJsonString);
    } catch (e) {
      throw new Error('Invalid JSON backup file.');
    }

    if (!backup.salt || !backup.canary || !Array.isArray(backup.items)) {
      throw new Error('Unrecognized backup format.');
    }

    // Verify password for the backup
    const backupKey = await deriveMasterKey(backupMasterPassword, backup.salt);
    const isValid = await verifyAuth(backup.canary, backupKey);
    if (!isValid) {
      throw new Error('Incorrect master password for the backup file.');
    }

    let importCount = 0;
    // Decrypt items from backup and re-encrypt into current vault
    for (const bItem of backup.items) {
      try {
        const secretData = await decryptPayload(
          { ciphertext: bItem.ciphertext, iv: bItem.iv },
          backupKey
        );
        await addItem({
          category: bItem.category || 'logins',
          favorite: !!bItem.favorite,
          ...secretData
        });
        importCount++;
      } catch (err) {
        console.error('Failed to import item', err);
      }
    }

    return importCount;
  };

  // Reset / Clear Vault
  const resetVault = async () => {
    await clearAllData();
    masterKeyRef.current = null;
    setItems([]);
    setMetaInfo(null);
    setVaultState('uninitialized');
  };

  // Auto-lock inactivity detection
  useEffect(() => {
    if (vaultState !== 'unlocked' || autoLockMinutes <= 0) return;

    const resetActivity = () => {
      lastActiveRef.current = Date.now();
    };

    const events = ['mousemove', 'mousedown', 'keydown', 'touchstart', 'scroll'];
    events.forEach((evt) => window.addEventListener(evt, resetActivity));

    const checkInterval = setInterval(() => {
      const idleTime = Date.now() - lastActiveRef.current;
      if (idleTime >= autoLockMinutes * 60 * 1000) {
        lockVault();
      }
    }, 10000);

    return () => {
      events.forEach((evt) => window.removeEventListener(evt, resetActivity));
      clearInterval(checkInterval);
    };
  }, [vaultState, autoLockMinutes, lockVault]);

  return (
    <VaultContext.Provider
      value={{
        vaultState,
        items,
        autoLockMinutes,
        setupVault,
        unlockVault,
        lockVault,
        addItem,
        updateItem,
        deleteItem,
        toggleFavorite,
        changeMasterPassword,
        updateSettings,
        exportEncryptedVault,
        importBackup,
        resetVault
      }}
    >
      {children}
    </VaultContext.Provider>
  );
}

export function useVault() {
  const context = useContext(VaultContext);
  if (!context) {
    throw new Error('useVault must be used within a VaultProvider');
  }
  return context;
}
