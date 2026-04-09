/**
 * FirewallRulesTable — tabular display of firewall rules.
 * Columns: action, source, destination, port, protocol, reason, delete.
 * Handles loading / empty states honestly.
 */
import React from 'react';

function ActionBadge({ action }) {
  const styles = {
    block: 'bg-red-500/15 text-red-300 border-red-500/30',
    drop: 'bg-red-500/15 text-red-300 border-red-500/30',
    allow: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
    accept: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
    reject: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
  };
  const cls = styles[(action || '').toLowerCase()] || 'bg-slate-700/40 text-slate-400 border-slate-600';
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full font-medium border ${cls}`}>
      {action || 'unknown'}
    </span>
  );
}

export default function FirewallRulesTable({
  rules = [],
  loading = false,
  canDelete = false,
  onDelete,
  deletingId = null,
}) {
  const formatDate = (ts) => {
    if (!ts) return '--';
    try {
      return new Date(ts).toLocaleString([], {
        month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
      });
    } catch {
      return '--';
    }
  };

  return (
    <div className="overflow-x-auto rounded-2xl border border-white/[0.06]">
      <table className="w-full text-sm text-left">
        <thead>
          <tr className="bg-[#0B1020] border-b border-white/[0.06]">
            <th className="px-4 py-3 text-xs font-medium text-slate-500 uppercase tracking-wide">Action</th>
            <th className="px-4 py-3 text-xs font-medium text-slate-500 uppercase tracking-wide">Source</th>
            <th className="px-4 py-3 text-xs font-medium text-slate-500 uppercase tracking-wide">Destination</th>
            <th className="px-4 py-3 text-xs font-medium text-slate-500 uppercase tracking-wide">Port</th>
            <th className="px-4 py-3 text-xs font-medium text-slate-500 uppercase tracking-wide">Protocol</th>
            <th className="px-4 py-3 text-xs font-medium text-slate-500 uppercase tracking-wide">Reason</th>
            <th className="px-4 py-3 text-xs font-medium text-slate-500 uppercase tracking-wide">Created</th>
            {canDelete && <th className="px-4 py-3 w-16" />}
          </tr>
        </thead>
        <tbody className="divide-y divide-white/[0.04]">
          {loading ? (
            <tr>
              <td colSpan={canDelete ? 8 : 7} className="px-4 py-16 text-center text-slate-500">
                <div className="flex items-center justify-center gap-2">
                  <svg className="w-4 h-4 animate-spin" viewBox="0 0 24 24" fill="none">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                  Loading firewall rules...
                </div>
              </td>
            </tr>
          ) : rules.length === 0 ? (
            <tr>
              <td colSpan={canDelete ? 8 : 7} className="px-4 py-16 text-center text-slate-500">
                No firewall rules. Rules will appear here when configured by REX or added manually.
              </td>
            </tr>
          ) : (
            rules.map((rule) => (
              <tr key={rule.id} className="hover:bg-white/[0.02] transition-colors">
                <td className="px-4 py-3"><ActionBadge action={rule.action} /></td>
                <td className="px-4 py-3 font-mono text-xs text-slate-300">{rule.source || rule.ip || '--'}</td>
                <td className="px-4 py-3 font-mono text-xs text-slate-300">{rule.destination || rule.dest || '--'}</td>
                <td className="px-4 py-3 font-mono text-xs text-slate-300">{rule.port ?? '--'}</td>
                <td className="px-4 py-3 text-xs text-slate-400 uppercase">{rule.protocol || '--'}</td>
                <td className="px-4 py-3 text-xs text-slate-400 max-w-[200px] truncate">{rule.reason || '--'}</td>
                <td className="px-4 py-3 text-xs text-slate-500">{formatDate(rule.created_at)}</td>
                {canDelete && (
                  <td className="px-4 py-3">
                    <button
                      onClick={() => onDelete?.(rule.id)}
                      disabled={deletingId === rule.id}
                      className="text-red-400 hover:text-red-300 disabled:opacity-40 transition-colors p-1"
                      title="Delete rule"
                    >
                      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 01-2.244 2.077H8.084a2.25 2.25 0 01-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 00-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 013.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 00-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 00-7.5 0" />
                      </svg>
                    </button>
                  </td>
                )}
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}
