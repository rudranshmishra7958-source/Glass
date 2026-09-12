import React, { useState, useEffect, useCallback } from 'react';
import { useToast } from './Toast';
import { X, Copy, RefreshCw, Sparkles } from './Icons';
import { generateSecurePassword, evaluatePasswordStrength } from '../services/generator';

export function PasswordGeneratorModal({ isOpen, onClose }) {
  const { showToast } = useToast();

  const [length, setLength] = useState(20);
  const [useLower, setUseLower] = useState(true);
  const [useUpper, setUseUpper] = useState(true);
  const [useNumbers, setUseNumbers] = useState(true);
  const [useSymbols, setUseSymbols] = useState(true);
  const [avoidAmbiguous, setAvoidAmbiguous] = useState(false);
  const [generatedPassword, setGeneratedPassword] = useState('');

  const regenerate = useCallback(() => {
    const pwd = generateSecurePassword({
      length,
      useLower,
      useUpper,
      useNumbers,
      useSymbols,
      avoidAmbiguous
    });
    setGeneratedPassword(pwd);
  }, [length, useLower, useUpper, useNumbers, useSymbols, avoidAmbiguous]);

  useEffect(() => {
    if (isOpen) {
      regenerate();
    }
  }, [isOpen, regenerate]);

  if (!isOpen) return null;

  const copyPassword = () => {
    if (!generatedPassword) return;
    navigator.clipboard.writeText(generatedPassword);
    showToast('Password copied to clipboard!');
  };

  const strength = evaluatePasswordStrength(generatedPassword);

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-card" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '480px' }}>
        <div className="modal-header">
          <div className="modal-title">
            <Sparkles size={20} style={{ color: 'var(--primary)' }} />
            <span>Password Generator</span>
          </div>
          <button className="btn-icon" onClick={onClose}>
            <X size={18} />
          </button>
        </div>

        <div className="modal-body">
          {/* Password Display Box */}
          <div
            style={{
              background: 'var(--bg-input)',
              border: '1px solid var(--border-color)',
              borderRadius: 'var(--radius-md)',
              padding: '1rem',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: '0.75rem'
            }}
          >
            <span
              style={{
                fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
                fontSize: '1.2rem',
                wordBreak: 'break-all',
                color: 'var(--text-primary)',
                letterSpacing: '1px'
              }}
            >
              {generatedPassword}
            </span>

            <div style={{ display: 'flex', gap: '0.25rem', flexShrink: 0 }}>
              <button
                type="button"
                className="btn-icon"
                onClick={regenerate}
                title="Generate new password"
              >
                <RefreshCw size={18} />
              </button>
              <button
                type="button"
                className="btn-icon"
                onClick={copyPassword}
                title="Copy to clipboard"
                style={{ color: 'var(--primary)' }}
              >
                <Copy size={18} />
              </button>
            </div>
          </div>

          {/* Strength Meter */}
          <div>
            <div className="strength-meter">
              <div className={`strength-bar ${strength.score >= 1 ? (strength.score === 1 ? 'weak' : strength.score === 2 ? 'medium' : 'strong') : ''}`} />
              <div className={`strength-bar ${strength.score >= 2 ? (strength.score === 2 ? 'medium' : 'strong') : ''}`} />
              <div className={`strength-bar ${strength.score >= 3 ? 'strong' : ''}`} />
              <div className={`strength-bar ${strength.score >= 4 ? 'strong' : ''}`} />
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '0.25rem' }}>
              <span className="strength-text" style={{ color: strength.color }}>
                {strength.label}
              </span>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                ~{strength.bits} bits of entropy
              </span>
            </div>
          </div>

          {/* Length Slider */}
          <div className="form-group">
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <label className="form-label">Password Length</label>
              <span style={{ fontWeight: 600, color: 'var(--primary)' }}>{length}</span>
            </div>
            <input
              type="range"
              min="8"
              max="64"
              value={length}
              onChange={(e) => setLength(parseInt(e.target.value, 10))}
              style={{ width: '100%', accentColor: 'var(--primary)', cursor: 'pointer' }}
            />
          </div>

          {/* Character Options */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', fontSize: '0.9rem', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={useUpper}
                onChange={(e) => setUseUpper(e.target.checked)}
                style={{ accentColor: 'var(--primary)' }}
              />
              <span>Uppercase Letters (A-Z)</span>
            </label>

            <label style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', fontSize: '0.9rem', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={useLower}
                onChange={(e) => setUseLower(e.target.checked)}
                style={{ accentColor: 'var(--primary)' }}
              />
              <span>Lowercase Letters (a-z)</span>
            </label>

            <label style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', fontSize: '0.9rem', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={useNumbers}
                onChange={(e) => setUseNumbers(e.target.checked)}
                style={{ accentColor: 'var(--primary)' }}
              />
              <span>Numbers (0-9)</span>
            </label>

            <label style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', fontSize: '0.9rem', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={useSymbols}
                onChange={(e) => setUseSymbols(e.target.checked)}
                style={{ accentColor: 'var(--primary)' }}
              />
              <span>Special Symbols (!@#$%^&*)</span>
            </label>

            <label style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', fontSize: '0.9rem', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={avoidAmbiguous}
                onChange={(e) => setAvoidAmbiguous(e.target.checked)}
                style={{ accentColor: 'var(--primary)' }}
              />
              <span>Avoid Ambiguous Characters (e.g. 1, l, I, 0, O)</span>
            </label>
          </div>
        </div>

        <div className="modal-footer">
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Done
          </button>
          <button type="button" className="btn btn-primary" onClick={copyPassword}>
            <Copy size={16} /> Copy Password
          </button>
        </div>
      </div>
    </div>
  );
}
