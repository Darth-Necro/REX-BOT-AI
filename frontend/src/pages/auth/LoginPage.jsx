/**
 * LoginPage -- full-screen auth with REX identity.
 *
 * Checks auth state on mount:
 * - "setup_required" -> show Create Admin Password form
 * - "active" -> show normal Login form
 * - loading -> show spinner
 *
 * Dark, futuristic aesthetic. ASCII REX dog, version badge.
 */

import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { login } from '../../api/auth';
import api from '../../api/client';
import useAuthStore from '../../stores/useAuthStore';

const _apiBase = import.meta.env.VITE_API_URL || window.location.origin;

function Spinner() {
  return (
    <div className="flex flex-col items-center gap-3">
      <svg className="w-8 h-8 animate-spin text-red-400" fill="none" viewBox="0 0 24 24">
        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
      </svg>
      <span className="text-rex-muted text-sm">Connecting to REX...</span>
    </div>
  );
}

function SetupForm() {
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const setAuthToken = useAuthStore((s) => s.setToken);

  const handleSubmit = useCallback(async (e) => {
    e.preventDefault();
    setError('');

    if (newPassword.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }
    if (newPassword !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    setLoading(true);
    try {
      const res = await api.post('/auth/setup', { new_password: newPassword });
      const token = res.data?.access_token || '';
      if (!token) {
        setError('Server returned an empty token');
        return;
      }
      setAuthToken(token);
      localStorage.setItem('rex_setup_complete', Date.now().toString());
      navigate('/overview');
    } catch (err) {
      const msg =
        err.response?.data?.detail ||
        err.message ||
        'Setup failed. Is REX running?';
      setError(msg);
    } finally {
      setLoading(false);
    }
  }, [newPassword, confirmPassword, setAuthToken]);

  return (
    <form onSubmit={handleSubmit} className="space-y-4 w-full">
      <div className="text-center mb-2">
        <h2 className="text-sm font-semibold text-rex-text tracking-wide">Create Admin Password</h2>
        <p className="text-xs text-rex-muted mt-1">First-time setup. Choose a strong password.</p>
      </div>

      {/* New Password */}
      <div className="relative group">
        <div className="absolute inset-0 rounded-lg bg-gradient-to-r from-green-500/20 to-blue-500/20 opacity-0 group-focus-within:opacity-100 transition-opacity blur-sm" />
        <input
          type="password"
          value={newPassword}
          onChange={(e) => setNewPassword(e.target.value)}
          placeholder="New password (min 8 characters)"
          autoComplete="new-password"
          autoFocus
          className="relative w-full px-4 py-3 bg-rex-bg/80 border border-rex-card rounded-lg text-rex-text placeholder-rex-muted/60 focus:border-green-500 focus:ring-1 focus:ring-green-500/30 focus:outline-none transition-all text-sm tracking-wide"
        />
      </div>

      {/* Confirm Password */}
      <div className="relative group">
        <div className="absolute inset-0 rounded-lg bg-gradient-to-r from-green-500/20 to-blue-500/20 opacity-0 group-focus-within:opacity-100 transition-opacity blur-sm" />
        <input
          type="password"
          value={confirmPassword}
          onChange={(e) => setConfirmPassword(e.target.value)}
          placeholder="Confirm password"
          autoComplete="new-password"
          className="relative w-full px-4 py-3 bg-rex-bg/80 border border-rex-card rounded-lg text-rex-text placeholder-rex-muted/60 focus:border-green-500 focus:ring-1 focus:ring-green-500/30 focus:outline-none transition-all text-sm tracking-wide"
        />
      </div>

      {/* Error message */}
      {error && (
        <div className="flex items-center gap-2 text-sm text-rex-threat bg-rex-threat/10 border border-rex-threat/20 rounded-lg px-3 py-2">
          <svg className="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
          </svg>
          <span>{error}</span>
        </div>
      )}

      {/* Submit button */}
      <button
        type="submit"
        disabled={loading || !newPassword.trim() || !confirmPassword.trim()}
        className="relative w-full py-3 rounded-lg font-medium text-sm tracking-wide transition-all disabled:opacity-40 disabled:cursor-not-allowed overflow-hidden group"
      >
        <span className="absolute inset-0 bg-gradient-to-r from-green-600 to-blue-600 group-hover:from-green-500 group-hover:to-blue-500 transition-all" />
        <span className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity bg-gradient-to-r from-green-400/20 to-blue-400/20 blur-xl" />
        <span className="relative flex items-center justify-center gap-2 text-white">
          {loading ? (
            <>
              <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              Creating account...
            </>
          ) : (
            'Create Password & Login'
          )}
        </span>
      </button>
    </form>
  );
}

function LoginFormInline() {
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const setAuthToken = useAuthStore((s) => s.setToken);
  const beginLogin = useAuthStore((s) => s.beginLogin);
  const setAuthError = useAuthStore((s) => s.setError);

  const handleSubmit = useCallback(async (e) => {
    e.preventDefault();
    if (!password.trim()) return;

    setError('');
    setLoading(true);
    beginLogin();

    try {
      const { token } = await login(password);
      setAuthToken(token);
      navigate('/overview');
    } catch (err) {
      const msg =
        err.response?.data?.detail ||
        err.message ||
        'Authentication failed. Is REX running?';
      setError(msg);
      setAuthError(msg);
    } finally {
      setLoading(false);
      setPassword('');
    }
  }, [password, setAuthToken, beginLogin, setAuthError]);

  // Detect lockout messages for special styling
  const isLockout = error && /locked|lock.*try again/i.test(error);

  return (
    <form onSubmit={handleSubmit} className="space-y-5 w-full">
      <div className="relative group">
        <div className="absolute inset-0 rounded-lg bg-gradient-to-r from-red-500/20 to-blue-500/20 opacity-0 group-focus-within:opacity-100 transition-opacity blur-sm" />
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Enter your admin password"
          autoComplete="current-password"
          autoFocus
          className="relative w-full px-4 py-3 bg-rex-bg/80 border border-rex-card rounded-lg text-rex-text placeholder-rex-muted/60 focus:border-red-500 focus:ring-1 focus:ring-red-500/30 focus:outline-none transition-all text-sm tracking-wide"
        />
      </div>

      {/* Error message */}
      {error && (
        <div className={`flex items-center gap-2 text-sm rounded-lg px-3 py-2 ${
          isLockout
            ? 'text-amber-400 bg-amber-500/10 border border-amber-500/20'
            : 'text-rex-threat bg-rex-threat/10 border border-rex-threat/20'
        }`}>
          <svg className="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            {isLockout ? (
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z" />
            ) : (
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
            )}
          </svg>
          <span>{error}</span>
        </div>
      )}

      {/* Submit button */}
      <button
        type="submit"
        disabled={loading || !password.trim()}
        className="relative w-full py-3 rounded-lg font-medium text-sm tracking-wide transition-all disabled:opacity-40 disabled:cursor-not-allowed overflow-hidden group"
      >
        <span className="absolute inset-0 bg-gradient-to-r from-red-600 to-blue-600 group-hover:from-red-500 group-hover:to-blue-500 transition-all" />
        <span className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity bg-gradient-to-r from-red-400/20 to-blue-400/20 blur-xl" />
        <span className="relative flex items-center justify-center gap-2 text-white">
          {loading ? (
            <>
              <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              Authenticating...
            </>
          ) : (
            'Authenticate'
          )}
        </span>
      </button>
    </form>
  );
}

export default function LoginPage() {
  const [version, setVersion] = useState(null);
  const [authState, setAuthState] = useState(null); // null = loading, 'setup_required', 'active'

  useEffect(() => {
    // Fetch version and auth state in parallel
    api.get('/status').then(res => {
      if (res.data?.version) setVersion(res.data.version);
    }).catch(() => { /* backend unreachable */ });

    api.get('/auth/auth-state').then(res => {
      setAuthState(res.data?.state || 'active');
    }).catch(() => {
      // If we can't reach the endpoint, assume active (fallback to login)
      setAuthState('active');
    });
  }, []);

  return (
    <div className="min-h-screen bg-rex-bg flex items-center justify-center px-4">
      {/* Subtle background grid */}
      <div className="absolute inset-0 opacity-[0.03] pointer-events-none"
           style={{
             backgroundImage:
               'linear-gradient(rgba(0,255,255,.3) 1px, transparent 1px), linear-gradient(90deg, rgba(0,255,255,.3) 1px, transparent 1px)',
             backgroundSize: '40px 40px',
           }}
      />

      <div className="relative w-full max-w-sm">
        {/* Card */}
        <div className="bg-rex-surface/90 backdrop-blur-sm border border-rex-card rounded-2xl p-8 shadow-2xl shadow-red-500/5">
          {/* REX ASCII identity */}
          <div className="flex justify-center mb-2">
            <pre
              className="text-red-400 text-xs leading-tight select-none font-mono"
              aria-hidden="true"
            >
{`    ^
   / \\__
  (    @\\___
  /         O
 /   (_____/
/_____/   U`}</pre>
          </div>

          <h1 className="text-xl font-bold text-center text-rex-text tracking-wide mb-1">
            REX-BOT-AI
          </h1>
          <p className="text-xs text-rex-muted text-center mb-6">
            Network Security Console
          </p>

          {/* Auth state-driven content */}
          {authState === null ? (
            <Spinner />
          ) : authState === 'setup_required' ? (
            <SetupForm />
          ) : (
            <LoginFormInline />
          )}

          {/* Footer */}
          <div className="mt-6 pt-4 border-t border-rex-card/50 space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-[10px] text-rex-muted/50 font-mono">{version || 'loading...'}</span>
              <span className="text-[10px] text-rex-muted/50">Local auth only</span>
            </div>
            <div className="text-[10px] text-rex-muted/40 font-mono truncate" title={_apiBase}>
              {_apiBase}
            </div>
          </div>
        </div>

        {/* Subtle glow beneath the card */}
        <div className="absolute -bottom-4 left-1/2 -translate-x-1/2 w-3/4 h-8 bg-red-500/10 rounded-full blur-2xl pointer-events-none" />
      </div>
    </div>
  );
}
