import React, { useState } from 'react';
import { useVault } from '../context/VaultContext';
import { useToast } from './Toast';
import {
  Globe,
  CreditCard,
  FileText,
  Star,
  Copy,
  Eye,
  EyeOff,
  Edit,
  Trash2,
  ExternalLink
} from './Icons';

export function ItemCard({ item, onEdit }) {
  const { deleteItem, toggleFavorite } = useVault();
  const { showToast } = useToast();
  const [showPassword, setShowPassword] = useState(false);

  const copyToClipboard = (text, label) => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    showToast(`${label} copied to clipboard!`);
  };

  const getCategoryIcon = () => {
    switch (item.category) {
      case 'cards':
        return <CreditCard size={18} />;
      case 'notes':
        return <FileText size={18} />;
      default:
        return <Globe size={18} />;
    }
  };

  const handleDelete = () => {
    if (window.confirm(`Are you sure you want to delete "${item.title || 'Untitled'}"?`)) {
      deleteItem(item.id);
      showToast('Item deleted.');
    }
  };

  return (
    <div className="item-card">
      <div className="item-card-header">
        <div className="item-title-wrap">
          <div className="item-category-icon">{getCategoryIcon()}</div>
          <div style={{ overflow: 'hidden' }}>
            <h3 className="item-title" title={item.title}>
              {item.title || 'Untitled'}
            </h3>
            {item.url && (
              <a
                href={item.url.startsWith('http') ? item.url : `https://${item.url}`}
                target="_blank"
                rel="noreferrer noopener"
                style={{
                  color: 'var(--text-muted)',
                  fontSize: '0.78rem',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '3px',
                  textDecoration: 'none'
                }}
              >
                <span>{item.url.replace(/^https?:\/\//, '').replace(/\/.*$/, '')}</span>
                <ExternalLink size={12} />
              </a>
            )}
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
          <button
            className="btn-icon"
            onClick={() => toggleFavorite(item.id)}
            title={item.favorite ? 'Remove favorite' : 'Mark favorite'}
            style={{ color: item.favorite ? 'var(--warning)' : 'var(--text-muted)' }}
          >
            <Star size={18} filled={item.favorite} />
          </button>
          <button
            className="btn-icon"
            onClick={() => onEdit(item)}
            title="Edit item"
          >
            <Edit size={16} />
          </button>
          <button
            className="btn-icon"
            onClick={handleDelete}
            title="Delete item"
            style={{ color: 'var(--danger)' }}
          >
            <Trash2 size={16} />
          </button>
        </div>
      </div>

      <div className="item-fields">
        {/* Logins Category */}
        {item.category === 'logins' && (
          <>
            {item.username && (
              <div className="field-row">
                <span className="field-label">Username</span>
                <span className="field-value" title={item.username}>
                  {item.username}
                </span>
                <div className="field-actions">
                  <button
                    className="btn-icon"
                    style={{ padding: '3px' }}
                    onClick={() => copyToClipboard(item.username, 'Username')}
                    title="Copy username"
                  >
                    <Copy size={14} />
                  </button>
                </div>
              </div>
            )}

            {item.password && (
              <div className="field-row">
                <span className="field-label">Password</span>
                <span className="field-value" style={{ letterSpacing: showPassword ? 'normal' : '2px' }}>
                  {showPassword ? item.password : '••••••••••••'}
                </span>
                <div className="field-actions">
                  <button
                    className="btn-icon"
                    style={{ padding: '3px' }}
                    onClick={() => setShowPassword(!showPassword)}
                    title={showPassword ? 'Hide' : 'Reveal'}
                  >
                    {showPassword ? <EyeOff size={14} /> : <Eye size={14} />}
                  </button>
                  <button
                    className="btn-icon"
                    style={{ padding: '3px' }}
                    onClick={() => copyToClipboard(item.password, 'Password')}
                    title="Copy password"
                  >
                    <Copy size={14} />
                  </button>
                </div>
              </div>
            )}
          </>
        )}

        {/* Cards Category */}
        {item.category === 'cards' && (
          <>
            {item.cardholder && (
              <div className="field-row">
                <span className="field-label">Name</span>
                <span className="field-value">{item.cardholder}</span>
              </div>
            )}
            {item.cardNumber && (
              <div className="field-row">
                <span className="field-label">Number</span>
                <span className="field-value">
                  {showPassword
                    ? item.cardNumber
                    : `•••• •••• •••• ${item.cardNumber.slice(-4)}`}
                </span>
                <div className="field-actions">
                  <button
                    className="btn-icon"
                    style={{ padding: '3px' }}
                    onClick={() => setShowPassword(!showPassword)}
                    title={showPassword ? 'Hide' : 'Reveal'}
                  >
                    {showPassword ? <EyeOff size={14} /> : <Eye size={14} />}
                  </button>
                  <button
                    className="btn-icon"
                    style={{ padding: '3px' }}
                    onClick={() => copyToClipboard(item.cardNumber, 'Card number')}
                    title="Copy card number"
                  >
                    <Copy size={14} />
                  </button>
                </div>
              </div>
            )}
            {(item.expiry || item.cvv) && (
              <div className="field-row">
                <span className="field-label">Exp / CVV</span>
                <span className="field-value">
                  {item.expiry || '--/--'} | {showPassword ? item.cvv || '---' : '•••'}
                </span>
                {item.cvv && (
                  <button
                    className="btn-icon"
                    style={{ padding: '3px' }}
                    onClick={() => copyToClipboard(item.cvv, 'CVV')}
                    title="Copy CVV"
                  >
                    <Copy size={14} />
                  </button>
                )}
              </div>
            )}
          </>
        )}

        {/* Notes Category */}
        {item.category === 'notes' && (
          <div style={{ fontSize: '0.85rem', color: 'var(--text-primary)', whiteSpace: 'pre-wrap', maxHeight: '120px', overflowY: 'auto' }}>
            {item.notes || <span style={{ color: 'var(--text-muted)' }}>No content in this note.</span>}
          </div>
        )}

        {/* Generic Notes for logins/cards */}
        {item.category !== 'notes' && item.notes && (
          <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', borderTop: '1px dashed var(--border-color)', paddingTop: '0.35rem', marginTop: '0.2rem' }}>
            <span style={{ color: 'var(--text-muted)' }}>Note: </span>
            {item.notes}
          </div>
        )}
      </div>

      <div className="item-card-footer">
        <span>Updated: {item.updatedAt ? new Date(item.updatedAt).toLocaleDateString() : 'Just now'}</span>
        {item.category !== 'notes' && (
          <span style={{ textTransform: 'capitalize', color: 'var(--text-secondary)' }}>
            {item.category}
          </span>
        )}
      </div>
    </div>
  );
}
