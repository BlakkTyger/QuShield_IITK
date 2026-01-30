import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard, Server, Globe, FileCode2, Shield,
  Star, FileText, Scan, LogOut, Atom
} from 'lucide-react';
import { useAuth } from '../hooks/useAuth';

const navItems = [
  { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/inventory', label: 'Asset Inventory', icon: Server },
  { to: '/discovery', label: 'Discovery', icon: Globe },
  { to: '/cbom', label: 'CBOM', icon: FileCode2 },
  { to: '/posture', label: 'PQC Posture', icon: Shield },
  { to: '/rating', label: 'Cyber Rating', icon: Star },
  { to: '/reports', label: 'Reports', icon: FileText },
  { to: '/scans', label: 'Scan Management', icon: Scan },
];

export default function Sidebar() {
  const { logout } = useAuth();

  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <div className="logo-icon">
          <Atom size={22} color="#FBBC09" />
        </div>
        <div className="logo-text">
          <span className="brand">QuShield</span>
          <span className="subtitle">PNB Quantum Security</span>
        </div>
      </div>

      <nav className="sidebar-nav">
        <span className="sidebar-section-label">Main</span>
        {navItems.slice(0, 3).map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) => `sidebar-link ${isActive ? 'active' : ''}`}
          >
            <item.icon size={18} />
            {item.label}
          </NavLink>
        ))}

        <span className="sidebar-section-label">Analysis</span>
        {navItems.slice(3, 6).map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) => `sidebar-link ${isActive ? 'active' : ''}`}
          >
            <item.icon size={18} />
            {item.label}
          </NavLink>
        ))}

        <span className="sidebar-section-label">Operations</span>
        {navItems.slice(6).map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) => `sidebar-link ${isActive ? 'active' : ''}`}
          >
            <item.icon size={18} />
            {item.label}
          </NavLink>
        ))}
      </nav>

      <div className="sidebar-footer">
        <button className="sidebar-link w-full" onClick={logout} style={{ border: 'none', background: 'none', width: '100%', textAlign: 'left' }}>
          <LogOut size={18} />
          Sign Out
        </button>
      </div>
    </aside>
  );
}
