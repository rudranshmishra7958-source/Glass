import React, { useMemo } from 'react';
import { X, ShieldAlert, AlertTriangle, Check, Edit, Key } from './Icons';

export function SecurityAuditModal({ isOpen, onClose, items, onEditItem }) {
  const auditResults = useMemo(() => {
    const weakItems = [];
    const passwordGroups = {}; // password -> [items]
    let totalPasswords = 0;

    items.forEach((item) => {
      if (item.category === 'logins' && item.password) {
        totalPasswords++;
        // Weak check
        if (item.password.length < 12) {
          weakItems.push({ item, reason: `Too short (${item.password.length} chars, recommended 14+)` });
        }

        // Reused check
        if (!passwordGroups[item.password]) {
          passwordGroups[item.password] = [];
        }
        passwordGroups[item.password].push(item);
      }
    });

    const reusedGroups = Object.values(passwordGroups).filter((group) => group.length > 1);

    return {
      totalPasswords,
      weakItems,
      reusedGroups,
      isHealthy: weakItems.length === 0 && reusedGroups.length === 0
    };
  }, [items]);

  if (!isOpen) return null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-card" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '600px' }}>
        <div className="modal-header">
          <div className="modal-title">
            <ShieldAlert size={20} style={{ color: auditResults.isHealthy ? 'var(--primary)' : 'var(--warning)' }} />
            <span>Vault Security Health Audit</span>
          </div>
          <button className="btn-icon" onClick={onClose}>
            <X size={18} />
          </button>
        </div>

        <div className="modal-body">
          {/* Stats Bar */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '0.75rem' }}>
            <div style={{ background: 'var(--bg-input)', padding: '0.85rem', borderRadius: 'var(--radius-md)', textAlign: 'center' }}>
              <div style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                {auditResults.totalPasswords}
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Total Logins</div>
            </div>

            <div style={{ background: 'var(--bg-input)', padding: '0.85rem', borderRadius: 'var(--radius-md)', textAlign: 'center' }}>
              <div style={{ fontSize: '1.4rem', fontWeight: 700, color: auditResults.weakItems.length > 0 ? 'var(--danger)' : 'var(--primary)' }}>
                {auditResults.weakItems.length}
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Weak Passwords</div>
            </div>

            <div style={{ background: 'var(--bg-input)', padding: '0.85rem', borderRadius: 'var(--radius-md)', textAlign: 'center' }}>
              <div style={{ fontSize: '1.4rem', fontWeight: 700, color: auditResults.reusedGroups.length > 0 ? 'var(--warning)' : 'var(--primary)' }}>
                {auditResults.reusedGroups.length}
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Reused Groups</div>
            </div>
          </div>

          {auditResults.isHealthy ? (
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.75rem',
                background: 'rgba(16, 185, 129, 0.1)',
                border: '1px solid var(--primary)',
                padding: '1rem',
                borderRadius: 'var(--radius-md)',
                color: 'var(--primary)'
              }}
            >
              <Check size={24} />
              <div>
                <div style={{ fontWeight: 600 }}>All Passwords Look Strong!</div>
                <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                  No weak or duplicate passwords detected across your login credentials.
                </div>
              </div>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
              {/* Weak Passwords List */}
              {auditResults.weakItems.length > 0 && (
                <div>
                  <h4 style={{ fontSize: '0.9rem', color: 'var(--danger)', marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                    <AlertTriangle size={16} /> Weak Passwords ({auditResults.weakItems.length})
                  </h4>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                    {auditResults.weakItems.map(({ item, reason }) => (
                      <div
                        key={item.id}
                        style={{
                          background: 'var(--bg-input)',
                          border: '1px solid var(--border-color)',
                          borderRadius: 'var(--radius-md)',
                          padding: '0.65rem 0.85rem',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between'
                        }}
                      >
                        <div>
                          <div style={{ fontWeight: 600, fontSize: '0.9rem' }}>{item.title}</div>
                          <div style={{ fontSize: '0.78rem', color: 'var(--danger)' }}>{reason}</div>
                        </div>
                        <button
                          className="btn btn-secondary"
                          style={{ padding: '0.35rem 0.65rem', fontSize: '0.8rem' }}
                          onClick={() => {
                            onClose();
                            onEditItem(item);
                          }}
                        >
                          <Edit size={14} /> Update
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Reused Passwords List */}
              {auditResults.reusedGroups.length > 0 && (
                <div>
                  <h4 style={{ fontSize: '0.9rem', color: 'var(--warning)', marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                    <AlertTriangle size={16} /> Reused Passwords Across Accounts
                  </h4>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                    {auditResults.reusedGroups.map((group, idx) => (
                      <div
                        key={idx}
                        style={{
                          background: 'var(--bg-input)',
                          border: '1px solid rgba(245, 158, 11, 0.3)',
                          borderRadius: 'var(--radius-md)',
                          padding: '0.75rem'
                        }}
                      >
                        <div style={{ fontSize: '0.8rem', color: 'var(--warning)', marginBottom: '0.4rem', fontWeight: 600 }}>
                          Shared across {group.length} accounts:
                        </div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                          {group.map((item) => (
                            <div
                              key={item.id}
                              style={{
                                display: 'flex',
                                alignItems: 'center',
                                justifyContent: 'space-between',
                                fontSize: '0.85rem'
                              }}
                            >
                              <span>
                                <strong>{item.title}</strong>{' '}
                                <span style={{ color: 'var(--text-muted)' }}>({item.username || 'no username'})</span>
                              </span>
                              <button
                                className="btn btn-secondary"
                                style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}
                                onClick={() => {
                                  onClose();
                                  onEditItem(item);
                                }}
                              >
                                Change
                              </button>
                            </div>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
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
