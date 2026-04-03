import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
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
    if (newPw !== confirmPw) { setError('Passwords do not match'); return; }
    if (newPw.length < 4) { setError('Password must be at least 4 characters'); return; }
    setLoading(true);
    setError('');
    try {
      await api.post('/auth/change-password', { old_password: oldPw, new_password: newPw });
      setSuccess(true);
      setTimeout(() => navigate('/overview'), 2000);
    } catch (e) {
      setError(e?.response?.data?.detail || 'Failed to change password');
    }
    setLoading(false);
  };

  return (
    <div className="max-w-md mx-auto mt-12 p-6">
      <h1 className="text-xl font-bold text-white mb-4">Change Password</h1>
      {success ? (
        <div className="bg-green-900/50 border border-green-500 rounded p-4 text-green-300">
          Password changed successfully! Redirecting...
        </div>
      ) : (
        <form onSubmit={handleSubmit} className="space-y-4">
          <input type="password" placeholder="Current password" value={oldPw} onChange={e => setOldPw(e.target.value)}
            className="w-full bg-gray-700 text-white rounded px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500" />
          <input type="password" placeholder="New password" value={newPw} onChange={e => setNewPw(e.target.value)}
            className="w-full bg-gray-700 text-white rounded px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500" />
          <input type="password" placeholder="Confirm new password" value={confirmPw} onChange={e => setConfirmPw(e.target.value)}
            className="w-full bg-gray-700 text-white rounded px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500" />
          {error && <p className="text-red-400 text-xs">{error}</p>}
          <button type="submit" disabled={loading}
            className="w-full bg-blue-600 hover:bg-blue-700 text-white py-2 rounded-lg disabled:opacity-50">
            {loading ? 'Changing...' : 'Change Password'}
          </button>
        </form>
      )}
    </div>
  );
}
