import React, { useState, useEffect } from 'react';
import { useVault } from '../context/VaultContext';
import { useToast } from './Toast';
import { X, Globe, CreditCard, FileText, Sparkles, Eye, EyeOff, Star } from './Icons';
import { generateSecurePassword, evaluatePasswordStrength } from '../services/generator';

export function ItemModal({ isOpen, onClose, editingItem }) {
  const { addItem, updateItem } = useVault();
  const { showToast } = useToast();

  const [category, setCategory] = useState('logins');
  const [title, setTitle] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [url, setUrl] = useState('');
  const [cardholder, setCardholder] = useState('');
  const [cardNumber, setCardNumber] = useState('');
  const [expiry, setExpiry] = useState('');
  const [cvv, setCvv] = useState('');
  const [notes, setNotes] = useState('');
  const [favorite, setFavorite] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (editingItem) {
      setCategory(editingItem.category || 'logins');
      setTitle(editingItem.title || '');
      setUsername(editingItem.username || '');
      setPassword(editingItem.password || '');
      setUrl(editingItem.url || '');
      setCardholder(editingItem.cardholder || '');
      setCardNumber(editingItem.cardNumber || '');
      setExpiry(editingItem.expiry || '');
      setCvv(editingItem.cvv || '');
      setNotes(editingItem.notes || '');
      setFavorite(!!editingItem.favorite);
    } else {
      setCategory('logins');
      setTitle('');
      setUsername('');
      setPassword('');
      setUrl('');
      setCardholder('');
      setCardNumber('');
      setExpiry('');
      setCvv('');
      setNotes('');
      setFavorite(false);
    }
  }, [editingItem, isOpen]);

  if (!isOpen) return null;

  const handleQuickGenerate = () => {
    const generated = generateSecurePassword({ length: 20 });
    setPassword(generated);
    setShowPassword(true);
    showToast('Generated strong 20-character password');
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!title.trim()) {
      showToast('Please enter a title', 'danger');
      return;
    }

    setIsSubmitting(true);
    try {
      const itemData = {
        category,
        title: title.trim(),
        favorite,
        notes: notes.trim()
      };

      if (category === 'logins') {
        itemData.username = username.trim();
        itemData.password = password;
        itemData.url = url.trim();
      } else if (category === 'cards') {
        itemData.cardholder = cardholder.trim();
        itemData.cardNumber = cardNumber.trim();
        itemData.expiry = expiry.trim();
        itemData.cvv = cvv.trim();
      }

      if (editingItem) {
        await updateItem(editingItem.id, itemData);
        showToast('Item updated successfully');
      } else {
        await addItem(itemData);
        showToast('Item created and encrypted');
      }
      onClose();
    } catch (err) {
      showToast('Failed to save: ' + err.message, 'danger');
    } finally {
      setIsSubmitting(false);
    }
  };

  const strength = evaluatePasswordStrength(password);

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-card" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div className="modal-title">
            {editingItem ? 'Edit Item' : 'New Vault Item'}
          </div>
          <button className="btn-icon" onClick={onClose}>
            <X size={18} />
          </button>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="modal-body">
            {/* Category tabs */}
            {!editingItem && (
              <div style={{ display: 'flex', gap: '0.5rem', background: 'var(--bg-input)', padding: '0.25rem', borderRadius: 'var(--radius-md)' }}>
                {[
                  { id: 'logins', label: 'Login', icon: Globe },
                  { id: 'cards', label: 'Card', icon: CreditCard },
                  { id: 'notes', label: 'Note', icon: FileText }
                ].map((tab) => {
                  const Icon = tab.icon;
                  return (
                    <button
                      key={tab.id}
                      type="button"
                      className={`btn ${category === tab.id ? 'btn-primary' : 'btn-secondary'}`}
                      style={{ flex: 1, padding: '0.45rem', fontSize: '0.85rem' }}
                      onClick={() => setCategory(tab.id)}
                    >
                      <Icon size={16} /> {tab.label}
                    </button>
                  );
                })}
              </div>
            )}

            {/* Title */}
            <div className="form-group">
              <label className="form-label">Title / Service Name *</label>
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                <input
                  type="text"
                  className="form-input"
                  placeholder="e.g. GitHub, Google, Wi-Fi router"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  required
                  autoFocus
                />
                <button
                  type="button"
                  className="btn-icon"
                  style={{
                    color: favorite ? 'var(--warning)' : 'var(--text-muted)',
                    background: 'var(--bg-input)',
                    border: '1px solid var(--border-color)'
                  }}
                  onClick={() => setFavorite(!favorite)}
                  title={favorite ? 'Favorited' : 'Add to Favorites'}
                >
                  <Star size={18} filled={favorite} />
                </button>
              </div>
            </div>

            {/* Logins Fields */}
            {category === 'logins' && (
              <>
                <div className="form-group">
                  <label className="form-label">Username / Email</label>
                  <input
                    type="text"
                    className="form-input"
                    placeholder="user@example.com"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                  />
                </div>

                <div className="form-group">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <label className="form-label">Password</label>
                    <button
                      type="button"
                      onClick={handleQuickGenerate}
                      style={{
                        background: 'transparent',
                        border: 'none',
                        color: 'var(--primary)',
                        fontSize: '0.8rem',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '4px',
                        cursor: 'pointer',
                        padding: '2px 6px'
                      }}
                    >
                      <Sparkles size={14} /> Generate Strong
                    </button>
                  </div>
                  <div className="input-with-action">
                    <input
                      type={showPassword ? 'text' : 'password'}
                      className="form-input"
                      placeholder="Enter or generate password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                    />
                    <div className="input-action-buttons">
                      <button
                        type="button"
                        className="btn-icon"
                        onClick={() => setShowPassword(!showPassword)}
                      >
                        {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                      </button>
                    </div>
                  </div>

                  {password && (
                    <div style={{ marginTop: '0.25rem' }}>
                      <div className="strength-meter">
                        <div className={`strength-bar ${strength.score >= 1 ? (strength.score === 1 ? 'weak' : strength.score === 2 ? 'medium' : 'strong') : ''}`} />
                        <div className={`strength-bar ${strength.score >= 2 ? (strength.score === 2 ? 'medium' : 'strong') : ''}`} />
                        <div className={`strength-bar ${strength.score >= 3 ? 'strong' : ''}`} />
                        <div className={`strength-bar ${strength.score >= 4 ? 'strong' : ''}`} />
                      </div>
                      <div className="strength-text" style={{ color: strength.color }}>
                        {strength.label} ({strength.bits} bits)
                      </div>
                    </div>
                  )}
                </div>

                <div className="form-group">
                  <label className="form-label">Website URL</label>
                  <input
                    type="text"
                    className="form-input"
                    placeholder="https://example.com"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                  />
                </div>
              </>
            )}

            {/* Cards Fields */}
            {category === 'cards' && (
              <>
                <div className="form-group">
                  <label className="form-label">Cardholder Name</label>
                  <input
                    type="text"
                    className="form-input"
                    placeholder="John Doe"
                    value={cardholder}
                    onChange={(e) => setCardholder(e.target.value)}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Card Number</label>
                  <input
                    type="text"
                    className="form-input"
                    placeholder="4000 1234 5678 9010"
                    value={cardNumber}
                    onChange={(e) => setCardNumber(e.target.value)}
                  />
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                  <div className="form-group">
                    <label className="form-label">Expires (MM/YY)</label>
                    <input
                      type="text"
                      className="form-input"
                      placeholder="12/28"
                      value={expiry}
                      onChange={(e) => setExpiry(e.target.value)}
                    />
                  </div>
                  <div className="form-group">
                    <label className="form-label">Security Code (CVV)</label>
                    <input
                      type="password"
                      className="form-input"
                      placeholder="123"
                      maxLength={4}
                      value={cvv}
                      onChange={(e) => setCvv(e.target.value)}
                    />
                  </div>
                </div>
              </>
            )}

            {/* Notes / Secret content */}
            <div className="form-group">
              <label className="form-label">
                {category === 'notes' ? 'Secret Notes Content *' : 'Additional Notes (Encrypted)'}
              </label>
              <textarea
                className="form-textarea"
                rows={category === 'notes' ? 6 : 3}
                placeholder={category === 'notes' ? 'Type sensitive notes, recovery keys, recovery phrases...' : 'Optional private notes...'}
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
              />
            </div>
          </div>

          <div className="modal-footer">
            <button type="button" className="btn btn-secondary" onClick={onClose} disabled={isSubmitting}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary" disabled={isSubmitting}>
              {isSubmitting ? 'Encrypting...' : editingItem ? 'Save Changes' : 'Encrypt & Save'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
