import React from 'react';
import { Key, Globe, CreditCard, FileText, Star, Shield, ShieldAlert } from './Icons';

export function Sidebar({
  activeCategory,
  setActiveCategory,
  categoryCounts,
  onOpenAudit,
  auditCount
}) {
  const navItems = [
    { id: 'all', label: 'All Items', icon: Key, count: categoryCounts.all },
    { id: 'favorites', label: 'Favorites', icon: Star, count: categoryCounts.favorites },
    { id: 'logins', label: 'Logins', icon: Globe, count: categoryCounts.logins },
    { id: 'cards', label: 'Cards', icon: CreditCard, count: categoryCounts.cards },
    { id: 'notes', label: 'Secure Notes', icon: FileText, count: categoryCounts.notes }
  ];

  return (
    <aside className="sidebar">
      <div>
        <div className="sidebar-heading">Categories</div>
        <nav className="sidebar-nav">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeCategory === item.id;
            return (
              <button
                key={item.id}
                className={`sidebar-item ${isActive ? 'active' : ''}`}
                onClick={() => setActiveCategory(item.id)}
              >
                <div className="sidebar-item-left">
                  <Icon size={18} />
                  <span>{item.label}</span>
                </div>
                <span className="badge">{item.count || 0}</span>
              </button>
            );
          })}
        </nav>
      </div>

      <div>
        <div className="sidebar-heading">Security Health</div>
        <button
          className="sidebar-item"
          onClick={onOpenAudit}
          style={{ width: '100%' }}
        >
          <div className="sidebar-item-left">
            <ShieldAlert size={18} style={{ color: auditCount > 0 ? 'var(--warning)' : 'var(--primary)' }} />
            <span>Vault Health</span>
          </div>
          {auditCount > 0 ? (
            <span className="badge" style={{ background: 'var(--danger-light)', color: 'var(--danger)' }}>
              {auditCount} alerts
            </span>
          ) : (
            <span className="badge" style={{ background: 'var(--primary-light)', color: 'var(--primary)' }}>
              Good
            </span>
          )}
        </button>
      </div>

      <div className="sidebar-footer">
        <div
          style={{
            background: 'var(--bg-input)',
            borderRadius: 'var(--radius-md)',
            padding: '0.75rem',
            fontSize: '0.78rem',
            color: 'var(--text-secondary)',
            display: 'flex',
            flexDirection: 'column',
            gap: '0.35rem'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', color: 'var(--primary)', fontWeight: 600 }}>
            <span
              style={{
                width: '8px',
                height: '8px',
                borderRadius: '50%',
                background: 'var(--primary)',
                display: 'inline-block',
                boxShadow: '0 0 6px var(--primary)'
              }}
            />
            Strictly Local Storage
          </div>
          <p style={{ color: 'var(--text-muted)' }}>
            IndexedDB encrypted. Zero network socket or server connection.
          </p>
        </div>
      </div>
    </aside>
  );
}
