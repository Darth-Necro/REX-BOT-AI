/**
 * LoginForm -- secure password-only login form.
 *
 * Futuristic dark styling consistent with the REX theme.
 * Shows loading spinner and error states. No stored credentials.
 */

import React, { useState, useCallback } from 'react';
import { login } from '../../api/auth';
import useAuthStore from '../../stores/useAuthStore';

export default function LoginForm() {
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const setAuthToken = useAuthStore((s) => s.setToken);
  const beginLogin = useAuthStore((s) => s.beginLogin);
  const setAuthError = useAuthStore((s) => s.setError);

  const handleSubmit = useCallback(
    async (e) => {
      e.preventDefault();
      if (!password.trim()) return;

      setError('');
      setLoading(true);
      beginLogin();

      try {
        const { token } = await login(password);
        setAuthToken(token);
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
    },
    [password, setAuthToken, beginLogin, setAuthError],
  );

  return (
    <form onSubmit={handleSubmit} className="space-y-5 w-full">
      {/* Password field */}
      <div className="relative group">
        <div className="absolute inset-0 rounded-lg bg-gradient-to-r from-cyan-500/20 to-blue-500/20 opacity-0 group-focus-within:opacity-100 transition-opacity blur-sm" />
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Enter admin password"
          autoComplete="current-password"
          autoFocus
          className="relative w-full px-4 py-3 bg-rex-bg/80 border border-rex-card rounded-lg text-rex-text placeholder-rex-muted/60 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/30 focus:outline-none transition-all text-sm tracking-wide"
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
        disabled={loading || !password.trim()}
        className="relative w-full py-3 rounded-lg font-medium text-sm tracking-wide transition-all disabled:opacity-40 disabled:cursor-not-allowed overflow-hidden group"
      >
        {/* Gradient background */}
        <span className="absolute inset-0 bg-gradient-to-r from-cyan-600 to-blue-600 group-hover:from-cyan-500 group-hover:to-blue-500 transition-all" />
        {/* Glow overlay */}
        <span className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity bg-gradient-to-r from-cyan-400/20 to-blue-400/20 blur-xl" />
        {/* Label */}
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
