import React, { useState, useMemo } from 'react';
import { VaultProvider, useVault } from './context/VaultContext';
import { ToastProvider } from './components/Toast';
import { UnlockScreen } from './components/UnlockScreen';
import { Navbar } from './components/Navbar';
import { Sidebar } from './components/Sidebar';
import { ItemList } from './components/ItemList';
import { ItemModal } from './components/ItemModal';
import { PasswordGeneratorModal } from './components/PasswordGeneratorModal';
import { SettingsModal } from './components/SettingsModal';
import { SecurityAuditModal } from './components/SecurityAuditModal';
import { Shield } from './components/Icons';

function VaultDashboard() {
  const { vaultState, items } = useVault();

  const [activeCategory, setActiveCategory] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');

  // Modal controls
  const [isItemModalOpen, setIsItemModalOpen] = useState(false);
  const [editingItem, setEditingItem] = useState(null);
  const [isGeneratorOpen, setIsGeneratorOpen] = useState(false);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [isAuditOpen, setIsAuditOpen] = useState(false);

  // Calculate counts
  const categoryCounts = useMemo(() => {
    const counts = { all: items.length, favorites: 0, logins: 0, cards: 0, notes: 0 };
    items.forEach((item) => {
      if (item.favorite) counts.favorites++;
      const cat = item.category || 'logins';
      if (counts[cat] !== undefined) counts[cat]++;
    });
    return counts;
  }, [items]);

  // Security audit count
  const auditCount = useMemo(() => {
    let weakCount = 0;
    const pwdMap = {};
    items.forEach((item) => {
      if (item.category === 'logins' && item.password) {
        if (item.password.length < 12) weakCount++;
        pwdMap[item.password] = (pwdMap[item.password] || 0) + 1;
      }
    });
    const reusedCount = Object.values(pwdMap).filter((c) => c > 1).length;
    return weakCount + reusedCount;
  }, [items]);

  if (vaultState === 'loading') {
    return (
      <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--bg-main)' }}>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '1rem', color: 'var(--primary)' }}>
          <Shield size={40} className="shake" />
          <span style={{ fontSize: '1rem', color: 'var(--text-secondary)' }}>Loading offline vault...</span>
        </div>
      </div>
    );
  }

  if (vaultState === 'uninitialized' || vaultState === 'locked') {
    return <UnlockScreen />;
  }

  const handleOpenAddModal = () => {
    setEditingItem(null);
    setIsItemModalOpen(true);
  };

  const handleEditItem = (item) => {
    setEditingItem(item);
    setIsItemModalOpen(true);
  };

  return (
    <div className="app-container">
      <Navbar
        searchQuery={searchQuery}
        setSearchQuery={setSearchQuery}
        onOpenAddModal={handleOpenAddModal}
        onOpenGenerator={() => setIsGeneratorOpen(true)}
        onOpenSettings={() => setIsSettingsOpen(true)}
        onOpenAudit={() => setIsAuditOpen(true)}
        auditCount={auditCount}
      />

      <div className="main-layout">
        <Sidebar
          activeCategory={activeCategory}
          setActiveCategory={setActiveCategory}
          categoryCounts={categoryCounts}
          onOpenAudit={() => setIsAuditOpen(true)}
          auditCount={auditCount}
        />

        <ItemList
          items={items}
          activeCategory={activeCategory}
          searchQuery={searchQuery}
          onOpenAddModal={handleOpenAddModal}
          onEditItem={handleEditItem}
        />
      </div>

      {/* Modals */}
      <ItemModal
        isOpen={isItemModalOpen}
        onClose={() => setIsItemModalOpen(false)}
        editingItem={editingItem}
      />

      <PasswordGeneratorModal
        isOpen={isGeneratorOpen}
        onClose={() => setIsGeneratorOpen(false)}
      />

      <SettingsModal
        isOpen={isSettingsOpen}
        onClose={() => setIsSettingsOpen(false)}
      />

      <SecurityAuditModal
        isOpen={isAuditOpen}
        onClose={() => setIsAuditOpen(false)}
        items={items}
        onEditItem={handleEditItem}
      />
    </div>
  );
}

export default function App() {
  return (
    <ToastProvider>
      <VaultProvider>
        <VaultDashboard />
      </VaultProvider>
    </ToastProvider>
  );
}
