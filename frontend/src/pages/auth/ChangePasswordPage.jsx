import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import api from '../../api/client';

export default function ChangePasswordPage() {
  const navigate = useNavigate();
  const [oldPw, setOldPw] = useState('');
  const [newPw, setNewPw] = useState('');
  const [confirmPw, setConfirmPw] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    if (!oldPw) { setError('Current password is required'); return; }
    if (newPw.length < 4) { setError('New password must be at least 4 characters'); return; }
    if (newPw !== confirmPw) { setError('New passwords do not match'); return; }
    if (oldPw === newPw) { setError('New password must be different from current password'); return; }
    setLoading(true);
    try {
      await api.post('/auth/change-password', { old_password: oldPw, new_password: newPw });
      setSuccess(true);
      setTimeout(() => navigate('/settings'), 2000);
    } catch (e) {
      setError(e?.response?.data?.detail || 'Failed to change password. Check your current password.');
    }
    setLoading(false);
  };

  return (
    <div className="p-6 lg:p-8 max-w-lg mx-auto space-y-6">
      {/* Breadcrumb */}
      <nav className="text-xs text-rex-muted">
        <Link to="/settings" className="hover:text-red-400 transition-colors">Settings</Link>
        <span className="mx-2">/</span>
        <span className="text-slate-300">Change Password</span>
      </nav>

      <div>
        <h1 className="text-xl font-bold text-slate-100 tracking-tight">Change Password</h1>
        <p className="text-sm text-slate-500 mt-1">
          Update your dashboard admin password. You'll be redirected to Settings after.
        </p>
      </div>

      {success ? (
        <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-4 text-sm text-emerald-300">
          Password changed successfully! Redirecting to Settings...
        </div>
      ) : (
        <form onSubmit={handleSubmit}>
          <div className="rounded-[26px] border border-white/[0.06] bg-gradient-to-br from-[#0a0a0a] to-[#141414] p-6 space-y-5">
            {/* Current password */}
            <div className="space-y-1.5">
              <label className="text-xs text-slate-400 font-medium" htmlFor="current-pw">
                Current Password
              </label>
              <input
                id="current-pw"
                type="password"
                value={oldPw}
                onChange={(e) => setOldPw(e.target.value)}
                placeholder="Enter your current password"
                className="w-full bg-rex-bg border border-rex-card rounded-xl px-4 py-2.5 text-sm text-rex-text placeholder-rex-muted focus:outline-none focus:border-red-500/50 transition-colors"
                autoComplete="current-password"
              />
            </div>

            {/* New password */}
            <div className="space-y-1.5">
              <label className="text-xs text-slate-400 font-medium" htmlFor="new-pw">
                New Password
              </label>
              <input
                id="new-pw"
                type="password"
                value={newPw}
                onChange={(e) => setNewPw(e.target.value)}
                placeholder="Enter a new password (min 4 characters)"
                className="w-full bg-rex-bg border border-rex-card rounded-xl px-4 py-2.5 text-sm text-rex-text placeholder-rex-muted focus:outline-none focus:border-red-500/50 transition-colors"
                autoComplete="new-password"
              />
              {newPw && newPw.length < 4 && (
                <p className="text-[10px] text-amber-400">Must be at least 4 characters</p>
              )}
              {newPw && newPw.length >= 12 && (
                <p className="text-[10px] text-emerald-400">Strong password</p>
              )}
            </div>

            {/* Confirm new password */}
            <div className="space-y-1.5">
              <label className="text-xs text-slate-400 font-medium" htmlFor="confirm-pw">
                Confirm New Password
              </label>
              <input
                id="confirm-pw"
                type="password"
                value={confirmPw}
                onChange={(e) => setConfirmPw(e.target.value)}
                placeholder="Type the new password again"
                className="w-full bg-rex-bg border border-rex-card rounded-xl px-4 py-2.5 text-sm text-rex-text placeholder-rex-muted focus:outline-none focus:border-red-500/50 transition-colors"
                autoComplete="new-password"
              />
              {confirmPw && newPw !== confirmPw && (
                <p className="text-[10px] text-red-400">Passwords do not match</p>
              )}
              {confirmPw && newPw === confirmPw && confirmPw.length >= 4 && (
                <p className="text-[10px] text-emerald-400">Passwords match</p>
              )}
            </div>

            {/* Error */}
            {error && (
              <div className="rounded-xl border border-red-500/30 bg-red-500/5 p-3 text-sm text-red-300">
                {error}
              </div>
            )}

            {/* Submit */}
            <button
              type="submit"
              disabled={loading || !oldPw || newPw.length < 4 || newPw !== confirmPw}
              className="w-full px-6 py-2.5 rounded-xl bg-red-500/20 text-red-300 text-sm font-medium border border-red-500/30 hover:bg-red-500/30 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            >
              {loading ? 'Changing Password...' : 'Change Password'}
            </button>
          </div>
        </form>
      )}
    </div>
  );
}
