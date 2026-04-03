/**
 * ResetPasswordPage -- reset admin password without knowing the old one.
 *
 * Requires an active authenticated session. Calls POST /api/auth/reset-password
 * with only the new password.  After success the JWT secret is rotated
 * server-side, so the user is logged out and must log in with the new password.
 */

import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../../api/client';
import useAuthStore from '../../stores/useAuthStore';

export default function ResetPasswordPage() {
  const navigate = useNavigate();
  const logout = useAuthStore((s) => s.logout);
  const [newPw, setNewPw] = useState('');
  const [confirmPw, setConfirmPw] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (newPw !== confirmPw) {
      setError('Passwords do not match');
      return;
    }
    if (newPw.length < 12) {
      setError('Password must be at least 12 characters');
      return;
    }
    setLoading(true);
    setError('');
    try {
      await api.post('/auth/reset-password', { new_password: newPw });
      setSuccess(true);
      // JWT secret was rotated, so the current token is invalid.
      // Log out after a short delay so the user sees the success message.
      setTimeout(() => {
        logout();
      }, 3000);
    } catch (err) {
      setError(err?.response?.data?.detail || 'Failed to reset password');
    }
    setLoading(false);
  };

  return (
    <div className="max-w-md mx-auto mt-12 p-6">
      <h1 className="text-xl font-bold text-white mb-2">Reset Password</h1>
      <p className="text-sm text-rex-muted mb-6">
        Set a new password without entering the old one. You will be logged out
        after the reset and must sign in with the new password.
      </p>

      {success ? (
        <div className="bg-green-900/50 border border-green-500 rounded p-4 text-green-300">
          Password reset successfully! Redirecting to login...
        </div>
      ) : (
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="new-password" className="block text-xs text-rex-muted mb-1">
              New password (min 12 characters)
            </label>
            <input
              id="new-password"
              type="password"
              placeholder="New password"
              value={newPw}
              onChange={(e) => setNewPw(e.target.value)}
              className="w-full bg-gray-700 text-white rounded px-4 py-2 text-sm
                         focus:outline-none focus:ring-2 focus:ring-cyan-500"
            />
          </div>

          <div>
            <label htmlFor="confirm-password" className="block text-xs text-rex-muted mb-1">
              Confirm new password
            </label>
            <input
              id="confirm-password"
              type="password"
              placeholder="Confirm new password"
              value={confirmPw}
              onChange={(e) => setConfirmPw(e.target.value)}
              className="w-full bg-gray-700 text-white rounded px-4 py-2 text-sm
                         focus:outline-none focus:ring-2 focus:ring-cyan-500"
            />
          </div>

          {error && <p className="text-red-400 text-xs">{error}</p>}

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-cyan-600 hover:bg-cyan-700 text-white py-2 rounded-lg
                       disabled:opacity-50 transition-colors"
          >
            {loading ? 'Resetting...' : 'Reset Password'}
          </button>

          <button
            type="button"
            onClick={() => navigate('/settings')}
            className="w-full text-rex-muted hover:text-white text-sm py-1 transition-colors"
          >
            Cancel
          </button>
        </form>
      )}
    </div>
  );
}
