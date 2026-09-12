import React from 'react';
import { useVault } from '../context/VaultContext';
import { useToast } from './Toast';
import { Shield, Search, Plus, Lock, Key, Settings, ShieldAlert, Sparkles } from './Icons';

export function Navbar({
  searchQuery,
  setSearchQuery,
  onOpenAddModal,
  onOpenGenerator,
  onOpenSettings,
  onOpenAudit,
  auditCount
}) {
  const { lockVault } = useVault();
  const { showToast } = useToast();

  const handleLock = () => {
    lockVault();
    showToast('Vault locked.');
  };

  return (
    <header className="navbar">
      <div className="nav-brand">
        <div className="brand-icon">
          <Shield size={26} />
        </div>
        <span>Offline Vault</span>
      </div>

      <div className="nav-search">
        <div className="search-icon-pos">
          <Search size={16} />
        </div>
        <input
          type="text"
          placeholder="Search logins, cards, notes..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
        />
      </div>

      <div className="nav-actions">
        <button
          className="btn btn-secondary"
          onClick={onOpenGenerator}
          title="Password Generator"
        >
          <Sparkles size={16} />
          <span style={{ display: 'inline-block' }}>Generator</span>
        </button>

        <button
          className="btn btn-secondary"
          onClick={onOpenAudit}
          title="Security Health Check"
          style={{ position: 'relative' }}
        >
          <ShieldAlert size={16} />
          <span>Health</span>
          {auditCount > 0 && (
            <span
              style={{
                background: 'var(--danger)',
                color: 'white',
                fontSize: '0.7rem',
                fontWeight: 700,
                padding: '1px 6px',
                borderRadius: '9999px',
                marginLeft: '4px'
              }}
            >
              {auditCount}
            </span>
          )}
        </button>

        <button
          className="btn btn-primary"
          onClick={onOpenAddModal}
        >
          <Plus size={16} />
          <span>New Item</span>
        </button>

        <button
          className="btn-icon"
          onClick={onOpenSettings}
          title="Settings & Backups"
        >
          <Settings size={20} />
        </button>

        <button
          className="btn btn-danger"
          onClick={handleLock}
          title="Lock Vault Now"
          style={{ padding: '0.55rem 0.85rem' }}
        >
          <Lock size={16} />
          <span>Lock</span>
        </button>
      </div>
    </header>
  );
}
