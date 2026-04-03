import React, { useState } from 'react';
import api from '../api/client';

function ActionButton({ label, onClick, confirm, variant = 'default', requireAuth, token }) {
  const [state, setState] = useState('idle');
  const [error, setError] = useState('');

  const disabled = requireAuth && !token;

  const handleClick = async () => {
    if (disabled) return;
    if (confirm && !window.confirm(confirm)) return;
    setState('loading');
    setError('');
    try {
      await onClick();
      setState('success');
      setTimeout(() => setState('idle'), 3000);
    } catch (e) {
      setState('error');
      setError(e?.response?.data?.detail || e.message || 'Failed');
      setTimeout(() => setState('idle'), 5000);
    }
  };

  const baseClass = 'px-4 py-3 rounded-lg text-sm font-medium transition-all duration-200 flex items-center justify-center gap-2 min-h-[48px]';
  const variants = {
    default: 'bg-blue-600 hover:bg-blue-700 text-white',
    danger: 'bg-red-600 hover:bg-red-700 text-white',
    secondary: 'bg-gray-600 hover:bg-gray-700 text-white',
  };

  const stateClass = {
    idle: '',
    loading: 'opacity-70 cursor-wait',
    success: '!bg-green-600',
    error: '!bg-red-800',
  };

  return (
    <div className="flex flex-col">
      <button
        className={`${baseClass} ${variants[variant]} ${stateClass[state]} ${disabled ? 'opacity-40 cursor-not-allowed' : ''}`}
        onClick={handleClick}
        disabled={state === 'loading' || disabled}
      >
        {state === 'loading' && (
          <svg className="w-4 h-4 animate-spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="12" cy="12" r="10" className="opacity-25" />
            <path d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" className="opacity-75" fill="currentColor" />
          </svg>
        )}
        {state === 'success' ? 'Done!' : state === 'error' ? 'Failed' : label}
      </button>
      {disabled && <span className="text-xs text-gray-400 mt-1">Login required</span>}
      {error && <span className="text-xs text-red-400 mt-1">{error}</span>}
    </div>
  );
}

export default function ActionPanel({ token }) {
  return (
    <div className="bg-gray-800 rounded-lg p-4">
      <h3 className="text-sm font-semibold text-gray-300 mb-3 uppercase tracking-wide">Quick Actions</h3>
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
        <ActionButton
          label="Scan Now"
          requireAuth
          token={token}
          onClick={() => api.post('/devices/scan', { scan_type: 'quick' })}
        />
        <ActionButton
          label="Sleep"
          requireAuth
          token={token}
          onClick={() => api.post('/schedule/sleep')}
        />
        <ActionButton
          label="Wake"
          requireAuth
          token={token}
          onClick={() => api.post('/schedule/wake')}
        />
        <ActionButton
          label="Patrol Now"
          requireAuth
          token={token}
          onClick={() => api.post('/devices/scan', { scan_type: 'deep' })}
        />
        <ActionButton
          label="Privacy Audit"
          variant="secondary"
          requireAuth
          token={token}
          onClick={() => api.get('/privacy/audit')}
        />
        <ActionButton
          label="JUNKYARD MODE"
          variant="danger"
          requireAuth
          token={token}
          confirm="ACTIVATE JUNKYARD DOG MODE?\n\nREX will aggressively block and remove ALL threats.\nThis escalates ALL detections to maximum response.\n\nAre you sure?"
          onClick={() => api.post('/config/protection-mode', { mode: 'junkyard_dog' })}
        />
      </div>
    </div>
  );
}
