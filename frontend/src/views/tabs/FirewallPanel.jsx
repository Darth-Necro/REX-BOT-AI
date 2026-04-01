import React, { useState, useCallback, useEffect } from 'react';
import api from '../../api/client';

function PanicModal({ onConfirm, onCancel }) {
  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
      <div className="bg-rex-surface border border-rex-threat rounded-2xl p-6 max-w-md w-full shadow-2xl">
        <div className="flex flex-col items-center text-center">
          <div className="w-16 h-16 rounded-full bg-rex-threat/20 flex items-center justify-center mb-4">
            <svg className="w-8 h-8 text-rex-threat" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
            </svg>
          </div>
          <h3 className="text-xl font-bold text-rex-threat mb-2">PANIC MODE</h3>
          <p className="text-sm text-rex-text mb-2">
            This will immediately block ALL inbound and outbound network traffic except essential system services.
          </p>
          <p className="text-xs text-rex-muted mb-6">
            Only use this if you believe your network is actively under attack. You will need to manually restore normal operation afterward.
          </p>
          <div className="flex items-center gap-3 w-full">
            <button
              onClick={onCancel}
              className="flex-1 px-4 py-2.5 bg-rex-card text-rex-text rounded-lg hover:bg-rex-card/80 transition-colors text-sm font-medium"
            >
              Cancel
            </button>
            <button
              onClick={onConfirm}
              className="flex-1 px-4 py-2.5 bg-rex-threat text-white rounded-lg hover:bg-rex-threat/80 transition-colors text-sm font-bold"
            >
              ACTIVATE PANIC
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function AddRuleForm({ onAdd }) {
  const [ip, setIp] = useState('');
  const [direction, setDirection] = useState('inbound');
  const [reason, setReason] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = useCallback(async (e) => {
    e.preventDefault();
    if (!ip.trim()) return;
    setSubmitting(true);
    try {
      await onAdd({ ip: ip.trim(), direction, reason: reason.trim() || 'Manual rule' });
      setIp('');
      setReason('');
    } finally {
      setSubmitting(false);
    }
  }, [ip, direction, reason, onAdd]);

  return (
    <form onSubmit={handleSubmit} className="bg-rex-surface border border-rex-card rounded-xl p-4">
      <h3 className="text-xs text-rex-muted uppercase tracking-wide mb-3">Add Firewall Rule</h3>
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
        <div>
          <label className="text-xs text-rex-muted block mb-1">IP Address / CIDR</label>
          <input
            type="text"
            value={ip}
            onChange={(e) => setIp(e.target.value)}
            placeholder="192.168.1.100"
            className="w-full bg-rex-bg border border-rex-card rounded-lg px-3 py-2 text-sm text-rex-text placeholder-rex-muted focus:outline-none focus:border-rex-accent transition-colors"
            required
          />
        </div>
        <div>
          <label className="text-xs text-rex-muted block mb-1">Direction</label>
          <div className="relative">
            <select
              value={direction}
              onChange={(e) => setDirection(e.target.value)}
              className="appearance-none w-full bg-rex-bg border border-rex-card rounded-lg px-3 py-2 pr-8 text-sm text-rex-text focus:outline-none focus:border-rex-accent transition-colors cursor-pointer"
            >
              <option value="inbound">Inbound</option>
              <option value="outbound">Outbound</option>
              <option value="both">Both</option>
            </select>
            <svg className="absolute right-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-rex-muted pointer-events-none" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </div>
        </div>
        <div>
          <label className="text-xs text-rex-muted block mb-1">Reason</label>
          <input
            type="text"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Suspicious activity"
            className="w-full bg-rex-bg border border-rex-card rounded-lg px-3 py-2 text-sm text-rex-text placeholder-rex-muted focus:outline-none focus:border-rex-accent transition-colors"
          />
        </div>
        <div className="flex items-end">
          <button
            type="submit"
            disabled={!ip.trim() || submitting}
            className="w-full px-4 py-2 bg-rex-accent text-white rounded-lg hover:bg-rex-accent/80 disabled:opacity-50 disabled:cursor-not-allowed transition-colors text-sm font-medium"
          >
            {submitting ? 'Adding...' : 'Add Rule'}
          </button>
        </div>
      </div>
    </form>
  );
}

export default function FirewallPanel() {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showPanic, setShowPanic] = useState(false);
  const [deletingId, setDeletingId] = useState(null);

  // Fetch rules
  useEffect(() => {
    api.get('/firewall/rules')
      .then((res) => {
        const list = res.data?.rules || res.data || [];
        setRules(Array.isArray(list) ? list : []);
      })
      .catch((err) => console.error('Failed to fetch firewall rules:', err))
      .finally(() => setLoading(false));
  }, []);

  const handleAddRule = useCallback(async (rule) => {
    try {
      const res = await api.post('/firewall/rules', rule);
      const newRule = res.data?.rule || res.data || { ...rule, id: Date.now().toString(), action: 'block', created_at: new Date().toISOString() };
      setRules((prev) => [...prev, newRule]);
    } catch (err) {
      console.error('Failed to add rule:', err);
    }
  }, []);

  const handleDeleteRule = useCallback(async (id) => {
    setDeletingId(id);
    try {
      await api.delete(`/firewall/rules/${id}`);
      setRules((prev) => prev.filter((r) => r.id !== id));
    } catch (err) {
      console.error('Failed to delete rule:', err);
    } finally {
      setDeletingId(null);
    }
  }, []);

  const handlePanic = useCallback(async () => {
    setShowPanic(false);
    try {
      await api.post('/firewall/panic');
      // Refetch rules to show the panic-added rules
      const res = await api.get('/firewall/rules');
      const list = res.data?.rules || res.data || [];
      setRules(Array.isArray(list) ? list : []);
    } catch (err) {
      console.error('Panic mode failed:', err);
    }
  }, []);

  const formatDate = (ts) => {
    if (!ts) return '-';
    return new Date(ts).toLocaleString([], {
      month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  };

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-rex-text">Firewall Rules</h2>
          <p className="text-xs text-rex-muted mt-0.5">{rules.length} active rule{rules.length !== 1 ? 's' : ''}</p>
        </div>
        <button
          onClick={() => setShowPanic(true)}
          className="flex items-center gap-2 px-5 py-3 bg-rex-threat text-white rounded-xl hover:bg-rex-threat/80 transition-colors text-sm font-bold shadow-lg shadow-rex-threat/20 border-2 border-rex-threat"
        >
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
          </svg>
          PANIC BUTTON
        </button>
      </div>

      {/* Add rule form */}
      <AddRuleForm onAdd={handleAddRule} />

      {/* Rules table */}
      <div className="overflow-x-auto rounded-lg border border-rex-card">
        <table className="w-full text-sm text-left">
          <thead>
            <tr className="bg-rex-surface border-b border-rex-card">
              <th className="px-4 py-3 text-xs font-medium text-rex-muted uppercase tracking-wide">IP</th>
              <th className="px-4 py-3 text-xs font-medium text-rex-muted uppercase tracking-wide">Direction</th>
              <th className="px-4 py-3 text-xs font-medium text-rex-muted uppercase tracking-wide">Action</th>
              <th className="px-4 py-3 text-xs font-medium text-rex-muted uppercase tracking-wide">Reason</th>
              <th className="px-4 py-3 text-xs font-medium text-rex-muted uppercase tracking-wide">Created</th>
              <th className="px-4 py-3 text-xs font-medium text-rex-muted uppercase tracking-wide w-20" />
            </tr>
          </thead>
          <tbody className="divide-y divide-rex-card">
            {loading ? (
              <tr>
                <td colSpan={6} className="px-4 py-12 text-center text-rex-muted">
                  Loading rules...
                </td>
              </tr>
            ) : rules.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-4 py-12 text-center text-rex-muted">
                  No firewall rules configured. Add one above or let REX manage them automatically.
                </td>
              </tr>
            ) : (
              rules.map((rule) => (
                <tr key={rule.id} className="hover:bg-rex-surface/40 transition-colors">
                  <td className="px-4 py-3 font-mono text-xs text-rex-text">{rule.ip || rule.ip_address || '-'}</td>
                  <td className="px-4 py-3 text-rex-muted capitalize">{rule.direction || '-'}</td>
                  <td className="px-4 py-3">
                    <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${
                      (rule.action || 'block') === 'block'
                        ? 'bg-rex-threat/20 text-rex-threat'
                        : 'bg-rex-safe/20 text-rex-safe'
                    }`}>
                      {rule.action || 'block'}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-rex-muted text-xs">{rule.reason || '-'}</td>
                  <td className="px-4 py-3 text-rex-muted text-xs">{formatDate(rule.created_at)}</td>
                  <td className="px-4 py-3">
                    <button
                      onClick={() => handleDeleteRule(rule.id)}
                      disabled={deletingId === rule.id}
                      className="text-rex-threat hover:text-rex-threat/80 disabled:opacity-50 transition-colors"
                      title="Delete rule"
                    >
                      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 01-2.244 2.077H8.084a2.25 2.25 0 01-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 00-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 013.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 00-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 00-7.5 0" />
                      </svg>
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Panic modal */}
      {showPanic && (
        <PanicModal onConfirm={handlePanic} onCancel={() => setShowPanic(false)} />
      )}
    </div>
  );
}
