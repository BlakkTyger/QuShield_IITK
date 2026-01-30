import { useState, useCallback } from 'react';
import api from '../lib/api';
import type { Token, UserResponse, UserCreate } from '../types/api';

export function useAuth() {
  const [user, setUser] = useState<UserResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const login = useCallback(async (email: string, password: string) => {
    setLoading(true);
    setError(null);
    try {
      const formData = new URLSearchParams();
      formData.append('username', email);
      formData.append('password', password);

      const { data } = await api.post<Token>('/auth/login', formData, {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      });
      localStorage.setItem('access_token', data.access_token);
      localStorage.setItem('refresh_token', data.refresh_token);
      
      // Fetch user info
      const userRes = await api.get<UserResponse>('/auth/me');
      setUser(userRes.data);
      return true;
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail || 'Login failed';
      setError(msg);
      return false;
    } finally {
      setLoading(false);
    }
  }, []);

  const register = useCallback(async (userData: UserCreate) => {
    setLoading(true);
    setError(null);
    try {
      await api.post('/auth/register', userData);
      return true;
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail || 'Registration failed';
      setError(msg);
      return false;
    } finally {
      setLoading(false);
    }
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    setUser(null);
    window.location.href = '/login';
  }, []);

  const fetchUser = useCallback(async () => {
    try {
      const { data } = await api.get<UserResponse>('/auth/me');
      setUser(data);
      return data;
    } catch {
      return null;
    }
  }, []);

  const isAuthenticated = !!localStorage.getItem('access_token');

  return { user, loading, error, login, register, logout, fetchUser, isAuthenticated };
}
