import React, { useMemo } from 'react';
import { ItemCard } from './ItemCard';
import { Key, Plus, Search } from './Icons';

export function ItemList({
  items,
  activeCategory,
  searchQuery,
  onOpenAddModal,
  onEditItem
}) {
  const filteredItems = useMemo(() => {
    return items.filter((item) => {
      // Category filter
      if (activeCategory === 'favorites') {
        if (!item.favorite) return false;
      } else if (activeCategory !== 'all') {
        if (item.category !== activeCategory) return false;
      }

      // Search filter
      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase();
        const titleMatch = item.title?.toLowerCase().includes(query);
        const userMatch = item.username?.toLowerCase().includes(query);
        const urlMatch = item.url?.toLowerCase().includes(query);
        const notesMatch = item.notes?.toLowerCase().includes(query);
        const cardMatch = item.cardholder?.toLowerCase().includes(query);
        return titleMatch || userMatch || urlMatch || notesMatch || cardMatch;
      }

      return true;
    });
  }, [items, activeCategory, searchQuery]);

  const getCategoryTitle = () => {
    switch (activeCategory) {
      case 'favorites':
        return 'Favorite Credentials';
      case 'logins':
        return 'Logins & Passwords';
      case 'cards':
        return 'Payment Cards';
      case 'notes':
        return 'Secure Notes';
      default:
        return 'All Vault Items';
    }
  };

  return (
    <div className="content-area">
      <div className="content-header">
        <div>
          <h2 className="content-title">{getCategoryTitle()}</h2>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>
            {filteredItems.length} {filteredItems.length === 1 ? 'item' : 'items'} found
            {searchQuery && ` matching "${searchQuery}"`}
          </p>
        </div>

        <button className="btn btn-primary" onClick={onOpenAddModal}>
          <Plus size={16} />
          <span>Add New</span>
        </button>
      </div>

      {filteredItems.length === 0 ? (
        <div className="empty-state">
          <div className="empty-icon">
            {searchQuery ? <Search size={28} /> : <Key size={28} />}
          </div>
          <div>
            <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.25rem' }}>
              {searchQuery ? 'No matching items found' : 'No items in this category'}
            </h3>
            <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
              {searchQuery
                ? 'Try refining your search term or clear the search field.'
                : 'Start organizing your sensitive data securely in this offline vault.'}
            </p>
          </div>
          {!searchQuery && (
            <button className="btn btn-primary" onClick={onOpenAddModal} style={{ marginTop: '0.5rem' }}>
              <Plus size={16} /> Add Your First Item
            </button>
          )}
        </div>
      ) : (
        <div className="items-grid">
          {filteredItems.map((item) => (
            <ItemCard key={item.id} item={item} onEdit={onEditItem} />
          ))}
        </div>
      )}
    </div>
  );
}
