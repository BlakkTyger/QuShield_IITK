import { Outlet, useLocation } from 'react-router-dom';
import Sidebar from './Sidebar';
import { useAuth } from '../hooks/useAuth';
import { useEffect } from 'react';
import { User } from 'lucide-react';

const pageTitles: Record<string, string> = {
  '/dashboard': 'Dashboard',
  '/inventory': 'Asset Inventory',
  '/discovery': 'Asset Discovery',
  '/cbom': 'Cryptographic BOM',
  '/posture': 'PQC Posture',
  '/rating': 'Cyber Rating',
  '/reports': 'Reports',
  '/scans': 'Scan Management',
};

export default function Layout() {
  const { user, fetchUser } = useAuth();
  const location = useLocation();
  const pageTitle = pageTitles[location.pathname] || 'QuShield';

  useEffect(() => {
    if (!user) fetchUser();
  }, [user, fetchUser]);

  return (
    <div className="app-layout">
      <Sidebar />
      <main className="app-main">
        <header className="app-header">
          <h1>{pageTitle}</h1>
          <div className="header-actions">
            <div className="header-user">
              <User size={16} />
              <span>{user?.full_name || user?.email || 'User'}</span>
            </div>
          </div>
        </header>
        <div className="app-content animate-fadeIn">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
