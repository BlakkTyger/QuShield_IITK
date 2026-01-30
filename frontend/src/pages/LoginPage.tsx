import { useState } from 'react';
import type { FormEvent } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import { Atom, Mail, Lock, Loader2 } from 'lucide-react';

export default function LoginPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const { login, loading, error } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    const success = await login(email, password);
    if (success) navigate('/dashboard');
  };

  return (
    <div className="auth-layout">
      <div className="auth-card animate-slideUp">
        <div className="auth-logo">
          <div className="logo-icon">
            <Atom size={28} color="#FBBC09" />
          </div>
          <h2>QuShield</h2>
          <p>PNB Quantum-Safe Security Platform</p>
        </div>

        <form className="auth-form" onSubmit={handleSubmit}>
          {error && (
            <div style={{ 
              padding: '10px 14px', 
              background: 'rgba(239,68,68,0.1)', 
              border: '1px solid rgba(239,68,68,0.3)',
              borderRadius: 'var(--radius-md)',
              color: '#EF4444',
              fontSize: '0.85rem',
              marginBottom: '16px'
            }}>
              {error}
            </div>
          )}

          <div className="form-group">
            <label className="form-label">
              <Mail size={14} style={{ display: 'inline', marginRight: 6, verticalAlign: 'middle' }} />
              Email Address
            </label>
            <input
              id="login-email"
              type="email"
              className="form-input"
              placeholder="admin@pnb.bank.in"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              autoComplete="email"
            />
          </div>

          <div className="form-group">
            <label className="form-label">
              <Lock size={14} style={{ display: 'inline', marginRight: 6, verticalAlign: 'middle' }} />
              Password
            </label>
            <input
              id="login-password"
              type="password"
              className="form-input"
              placeholder="Enter your password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              autoComplete="current-password"
            />
          </div>

          <button 
            id="login-submit"
            type="submit" 
            className="btn btn-primary btn-lg" 
            disabled={loading}
          >
            {loading ? <Loader2 size={18} className="spinner" /> : null}
            {loading ? 'Signing In...' : 'Sign In'}
          </button>
        </form>

        <div className="auth-footer">
          Don't have an account? <Link to="/register">Create one</Link>
        </div>
      </div>
    </div>
  );
}
