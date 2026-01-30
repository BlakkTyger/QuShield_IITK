import { useState } from 'react';
import type { FormEvent } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import { Atom, Mail, Lock, UserPlus, Loader2 } from 'lucide-react';

export default function RegisterPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const { register, loading, error } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    const success = await register({ email, password, full_name: fullName });
    if (success) navigate('/login');
  };

  return (
    <div className="auth-layout">
      <div className="auth-card animate-slideUp">
        <div className="auth-logo">
          <div className="logo-icon">
            <Atom size={28} color="#FBBC09" />
          </div>
          <h2>Create Account</h2>
          <p>Join QuShield Security Platform</p>
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
              <UserPlus size={14} style={{ display: 'inline', marginRight: 6, verticalAlign: 'middle' }} />
              Full Name
            </label>
            <input
              id="register-name"
              type="text"
              className="form-input"
              placeholder="Your full name"
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              required
            />
          </div>

          <div className="form-group">
            <label className="form-label">
              <Mail size={14} style={{ display: 'inline', marginRight: 6, verticalAlign: 'middle' }} />
              Email Address
            </label>
            <input
              id="register-email"
              type="email"
              className="form-input"
              placeholder="admin@pnb.bank.in"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </div>

          <div className="form-group">
            <label className="form-label">
              <Lock size={14} style={{ display: 'inline', marginRight: 6, verticalAlign: 'middle' }} />
              Password
            </label>
            <input
              id="register-password"
              type="password"
              className="form-input"
              placeholder="Minimum 8 characters"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              minLength={6}
            />
          </div>

          <button
            id="register-submit"
            type="submit"
            className="btn btn-primary btn-lg"
            disabled={loading}
          >
            {loading ? <Loader2 size={18} /> : null}
            {loading ? 'Creating Account...' : 'Create Account'}
          </button>
        </form>

        <div className="auth-footer">
          Already have an account? <Link to="/login">Sign in</Link>
        </div>
      </div>
    </div>
  );
}
