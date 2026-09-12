import React, { useState, useRef } from 'react';
import { useVault } from '../context/VaultContext';
import { useToast } from './Toast';
import { X, Settings, Key, Download, Upload, Trash2, AlertTriangle, Shield } from './Icons';
import { evaluatePasswordStrength } from '../services/generator';

export function SettingsModal({ isOpen, onClose }) {
  const {
    autoLockMinutes,
    updateSettings,
    changeMasterPassword,
    exportEncryptedVault,
    importBackup,
    resetVault
  } = useVault();
  const { showToast } = useToast();

  const [activeTab, setActiveTab] = useState('general'); // 'general' | 'password' | 'backup' | 'danger'

  // Change password states
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [isChangingPass, setIsChangingPass] = useState(false);

  // Import states
  const [importPassword, setImportPassword] = useState('');
  const [selectedFileContent, setSelectedFileContent] = useState(null);
  const [isImporting, setIsImporting] = useState(false);
  const fileInputRef = useRef(null);

  if (!isOpen) return null;

  const handleChangePassword = async (e) => {
    e.preventDefault();
    if (!currentPassword || !newPassword) {
      showToast('Please fill in all password fields.', 'danger');
      return;
    }
    if (newPassword.length < 8) {
      showToast('New master password must be at least 8 characters.', 'danger');
      return;
    }
    if (newPassword !== confirmPassword) {
      showToast('New passwords do not match.', 'danger');
      return;
    }

    setIsChangingPass(true);
    try {
      await changeMasterPassword(currentPassword, newPassword);
      showToast('Master password changed and vault re-encrypted successfully!');
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (err) {
      showToast('Failed to change password: ' + err.message, 'danger');
    } finally {
      setIsChangingPass(false);
    }
  };

  const handleExport = async () => {
    try {
      await exportEncryptedVault();
      showToast('Encrypted vault backup downloaded!');
    } catch (err) {
      showToast('Export failed: ' + err.message, 'danger');
    }
  };

  const handleFileChange = (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      setSelectedFileContent(event.target.result);
    };
    reader.readAsText(file);
  };

  const handleImport = async (e) => {
    e.preventDefault();
    if (!selectedFileContent) {
      showToast('Please select a backup file first.', 'danger');
      return;
    }
    if (!importPassword) {
      showToast('Please enter the master password for this backup.', 'danger');
      return;
    }

    setIsImporting(true);
    try {
      const count = await importBackup(selectedFileContent, importPassword);
      showToast(`Successfully imported ${count} items!`);
      setSelectedFileContent(null);
      setImportPassword('');
      if (fileInputRef.current) fileInputRef.current.value = '';
    } catch (err) {
      showToast('Import failed: ' + err.message, 'danger');
    } finally {
      setIsImporting(false);
    }
  };

  const handleResetVault = async () => {
    const confirmed = window.confirm(
      'DANGER: Are you sure you want to permanently wipe all vault items and reset your master password? This cannot be undone!'
    );
    if (confirmed) {
      await resetVault();
      showToast('Vault has been completely reset.');
      onClose();
    }
  };

  const newPassStrength = evaluatePasswordStrength(newPassword);

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-card" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '560px' }}>
        <div className="modal-header">
          <div className="modal-title">
            <Settings size={20} />
            <span>Vault Settings</span>
          </div>
          <button className="btn-icon" onClick={onClose}>
            <X size={18} />
          </button>
        </div>

        {/* Tab Navigation */}
        <div style={{ display: 'flex', borderBottom: '1px solid var(--border-color)', padding: '0 1rem', background: 'rgba(17, 24, 39, 0.4)' }}>
          {[
            { id: 'general', label: 'General' },
            { id: 'password', label: 'Master Password' },
            { id: 'backup', label: 'Backup & Restore' },
            { id: 'danger', label: 'Danger Zone' }
          ].map((tab) => (
            <button
              key={tab.id}
              className={`sidebar-item ${activeTab === tab.id ? 'active' : ''}`}
              style={{ borderRadius: '0', borderBottom: activeTab === tab.id ? '2px solid var(--primary)' : 'none', padding: '0.75rem 1rem' }}
              onClick={() => setActiveTab(tab.id)}
            >
              {tab.label}
            </button>
          ))}
        </div>

        <div className="modal-body">
          {/* General Tab */}
          {activeTab === 'general' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
              <div className="form-group">
                <label className="form-label">Auto-Lock Inactivity Timer</label>
                <select
                  className="form-select"
                  value={autoLockMinutes}
                  onChange={(e) => updateSettings({ autoLockMinutes: parseInt(e.target.value, 10) })}
                >
                  <option value={1}>1 minute (strict)</option>
                  <option value={5}>5 minutes</option>
                  <option value={10}>10 minutes</option>
                  <option value={15}>15 minutes (default)</option>
                  <option value={30}>30 minutes</option>
                  <option value={60}>1 hour</option>
                  <option value={0}>Never (not recommended)</option>
                </select>
                <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                  The vault will automatically lock itself and flush decrypted keys from memory after inactivity.
                </span>
              </div>

              <div
                style={{
                  background: 'var(--bg-input)',
                  border: '1px solid var(--border-color)',
                  borderRadius: 'var(--radius-md)',
                  padding: '1rem',
                  fontSize: '0.85rem'
                }}
              >
                <div style={{ fontWeight: 600, color: 'var(--primary)', display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.35rem' }}>
                  <Shield size={16} /> Privacy & Security Guarantee
                </div>
                <p style={{ color: 'var(--text-secondary)' }}>
                  All cryptography is handled directly in your browser using the W3C Web Crypto API standard (PBKDF2 SHA-256 and AES-GCM 256-bit). Data is stored locally in IndexedDB. No external servers or analytics are ever pinged.
                </p>
              </div>
            </div>
          )}

          {/* Master Password Tab */}
          {activeTab === 'password' && (
            <form onSubmit={handleChangePassword} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div className="form-group">
                <label className="form-label">Current Master Password</label>
                <input
                  type="password"
                  className="form-input"
                  placeholder="Enter current password"
                  value={currentPassword}
                  onChange={(e) => setCurrentPassword(e.target.value)}
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">New Master Password</label>
                <input
                  type="password"
                  className="form-input"
                  placeholder="Enter new master password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  required
                />
                {newPassword && (
                  <div style={{ marginTop: '0.25rem' }}>
                    <div className="strength-meter">
                      <div className={`strength-bar ${newPassStrength.score >= 1 ? (newPassStrength.score === 1 ? 'weak' : newPassStrength.score === 2 ? 'medium' : 'strong') : ''}`} />
                      <div className={`strength-bar ${newPassStrength.score >= 2 ? (newPassStrength.score === 2 ? 'medium' : 'strong') : ''}`} />
                      <div className={`strength-bar ${newPassStrength.score >= 3 ? 'strong' : ''}`} />
                      <div className={`strength-bar ${newPassStrength.score >= 4 ? 'strong' : ''}`} />
                    </div>
                    <div className="strength-text" style={{ color: newPassStrength.color }}>
                      {newPassStrength.label} ({newPassStrength.bits} bits)
                    </div>
                  </div>
                )}
              </div>

              <div className="form-group">
                <label className="form-label">Confirm New Password</label>
                <input
                  type="password"
                  className="form-input"
                  placeholder="Confirm new password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  required
                />
              </div>

              <button
                type="submit"
                className="btn btn-primary"
                disabled={isChangingPass}
                style={{ alignSelf: 'flex-start', marginTop: '0.5rem' }}
              >
                {isChangingPass ? 'Re-encrypting Vault...' : 'Update & Re-encrypt Vault'}
              </button>
            </form>
          )}

          {/* Backup & Restore Tab */}
          {activeTab === 'backup' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
              <div>
                <h4 style={{ fontSize: '0.95rem', fontWeight: 600, marginBottom: '0.4rem' }}>
                  Export Encrypted Vault
                </h4>
                <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: '0.75rem' }}>
                  Download an encrypted `.json` file of your vault. Because it remains AES-GCM encrypted with your master password, it is safe to store in USB drives or cloud backups.
                </p>
                <button className="btn btn-secondary" onClick={handleExport}>
                  <Download size={16} /> Export Backup (.json)
                </button>
              </div>

              <hr style={{ borderColor: 'var(--border-color)' }} />

              <div>
                <h4 style={{ fontSize: '0.95rem', fontWeight: 600, marginBottom: '0.4rem' }}>
                  Import Encrypted Vault
                </h4>
                <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: '0.75rem' }}>
                  Restore credentials from an encrypted backup file. Items will be decrypted using the backup's master password and merged into your current vault.
                </p>

                <form onSubmit={handleImport} style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                  <input
                    type="file"
                    accept=".json"
                    ref={fileInputRef}
                    onChange={handleFileChange}
                    style={{ fontSize: '0.85rem' }}
                  />

                  {selectedFileContent && (
                    <div className="form-group">
                      <label className="form-label">Master Password of the Backup File</label>
                      <input
                        type="password"
                        className="form-input"
                        placeholder="Enter password for this backup"
                        value={importPassword}
                        onChange={(e) => setImportPassword(e.target.value)}
                        required
                      />
                    </div>
                  )}

                  <button
                    type="submit"
                    className="btn btn-primary"
                    disabled={!selectedFileContent || isImporting}
                    style={{ alignSelf: 'flex-start' }}
                  >
                    <Upload size={16} /> {isImporting ? 'Decrypting & Importing...' : 'Import Backup'}
                  </button>
                </form>
              </div>
            </div>
          )}

          {/* Danger Zone Tab */}
          {activeTab === 'danger' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div
                style={{
                  border: '1px solid var(--danger)',
                  borderRadius: 'var(--radius-md)',
                  padding: '1.25rem',
                  background: 'var(--danger-light)'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--danger)', fontWeight: 700, marginBottom: '0.5rem' }}>
                  <AlertTriangle size={20} /> Danger Zone: Factory Reset
                </div>
                <p style={{ fontSize: '0.85rem', color: 'var(--text-primary)', marginBottom: '1rem' }}>
                  Permanently delete all stored credentials, clear the master password salt, and reset IndexedDB to an empty state. There is NO way to recover your data after this step!
                </p>
                <button className="btn btn-danger" onClick={handleResetVault}>
                  <Trash2 size={16} /> Wipe Everything & Reset Vault
                </button>
              </div>
            </div>
          )}
        </div>

        <div className="modal-footer">
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
