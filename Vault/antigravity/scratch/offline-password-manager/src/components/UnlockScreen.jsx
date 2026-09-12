import React, { useState } from 'react';
import { useVault } from '../context/VaultContext';
import { useToast } from './Toast';
import { Shield, Lock, Unlock, Eye, EyeOff, Key, AlertTriangle } from './Icons';
import { evaluatePasswordStrength } from '../services/generator';

export function UnlockScreen() {
  const { vaultState, setupVault, unlockVault } = useVault();
  const { showToast } = useToast();

  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [shake, setShake] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');

  const isSetup = vaultState === 'uninitialized';
  const strength = isSetup ? evaluatePasswordStrength(password) : null;

  const triggerShake = (msg) => {
    setErrorMsg(msg);
    setShake(true);
    setTimeout(() => setShake(false), 500);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setErrorMsg('');

    if (!password) {
      triggerShake('Please enter your master password.');
      return;
    }

    if (isSetup) {
      if (password.length < 8) {
        triggerShake('Master password should be at least 8 characters long.');
        return;
      }
      if (password !== confirmPassword) {
        triggerShake('Passwords do not match.');
        return;
      }

      setIsLoading(true);
      try {
        await setupVault(password);
        showToast('Vault created successfully!');
      } catch (err) {
        triggerShake('Failed to create vault: ' + err.message);
      } finally {
        setIsLoading(false);
      }
    } else {
      setIsLoading(true);
      try {
        await unlockVault(password);
        showToast('Vault unlocked.');
      } catch (err) {
        triggerShake('Incorrect master password. Please try again.');
      } finally {
        setIsLoading(false);
      }
    }
  };

  return (
    <div className="lock-screen-wrapper">
      <div className={`lock-card ${shake ? 'shake' : ''}`}>
        <div className="lock-logo-badge">
          {isSetup ? <Key size={32} /> : <Lock size={32} />}
        </div>

        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700, marginBottom: '0.35rem' }}>
            {isSetup ? 'Create Your Vault' : 'Vault Locked'}
          </h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>
            {isSetup
              ? 'Set a master password to encrypt your credentials locally.'
              : 'Enter your master password to unlock your offline vault.'}
          </p>
        </div>

        {errorMsg && (
          <div
            style={{
              padding: '0.65rem 0.85rem',
              borderRadius: 'var(--radius-md)',
              background: 'var(--danger-light)',
              color: 'var(--danger)',
              fontSize: '0.85rem',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
              textAlign: 'left'
            }}
          >
            <AlertTriangle size={18} style={{ flexShrink: 0 }} />
            <span>{errorMsg}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem', textAlign: 'left' }}>
          <div className="form-group">
            <label className="form-label">Master Password</label>
            <div className="input-with-action">
              <input
                type={showPassword ? 'text' : 'password'}
                className="form-input"
                placeholder="Enter master password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoFocus
                disabled={isLoading}
              />
              <div className="input-action-buttons">
                <button
                  type="button"
                  className="btn-icon"
                  onClick={() => setShowPassword(!showPassword)}
                  title={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </div>
            </div>

            {isSetup && password && (
              <div style={{ marginTop: '0.35rem' }}>
                <div className="strength-meter">
                  <div className={`strength-bar ${strength.score >= 1 ? (strength.score === 1 ? 'weak' : strength.score === 2 ? 'medium' : 'strong') : ''}`} />
                  <div className={`strength-bar ${strength.score >= 2 ? (strength.score === 2 ? 'medium' : 'strong') : ''}`} />
                  <div className={`strength-bar ${strength.score >= 3 ? 'strong' : ''}`} />
                  <div className={`strength-bar ${strength.score >= 4 ? 'strong' : ''}`} />
                </div>
                <div className="strength-text" style={{ color: strength.color }}>
                  Strength: {strength.label} ({strength.bits} bits entropy)
                </div>
              </div>
            )}
          </div>

          {isSetup && (
            <div className="form-group">
              <label className="form-label">Confirm Master Password</label>
              <input
                type={showPassword ? 'text' : 'password'}
                className="form-input"
                placeholder="Repeat master password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                disabled={isLoading}
              />
            </div>
          )}

          <button
            type="submit"
            className="btn btn-primary"
            style={{ width: '100%', padding: '0.75rem', marginTop: '0.5rem' }}
            disabled={isLoading}
          >
            {isLoading ? (
              <span>Decrypting...</span>
            ) : isSetup ? (
              <>
                <Shield size={18} /> Create Secure Vault
              </>
            ) : (
              <>
                <Unlock size={18} /> Unlock Vault
              </>
            )}
          </button>
        </form>

        <div
          style={{
            background: 'rgba(16, 185, 129, 0.08)',
            border: '1px solid rgba(16, 185, 129, 0.2)',
            borderRadius: 'var(--radius-md)',
            padding: '0.85rem',
            fontSize: '0.8rem',
            color: 'var(--text-secondary)',
            textAlign: 'left'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--primary)', fontWeight: 600, marginBottom: '0.25rem' }}>
            <Shield size={16} /> 100% Offline & Zero-Knowledge
          </div>
          <p>
            Your data is encrypted with AES-GCM 256-bit and saved exclusively in your browser's IndexedDB. No backend servers, no cloud sync, zero telemetry.
          </p>
        </div>
      </div>
    </div>
  );
}
