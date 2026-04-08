/**
 * KBHistoryTable — version history for the knowledge base.
 * Columns: version, timestamp, source (who/what changed it), actions (revert).
 */
import React from 'react';

export default function KBHistoryTable({
  history = [],
  loading = false,
  canRevert = false,
  currentVersion = 0,
  onRevert,
}) {
  const formatDate = (ts) => {
    if (!ts) return '--';
    try {
      return new Date(ts).toLocaleString([], {
        month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit',
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
            <th className="px-4 py-3 text-xs font-medium text-slate-500 uppercase tracking-wide">Version</th>
            <th className="px-4 py-3 text-xs font-medium text-slate-500 uppercase tracking-wide">Timestamp</th>
            <th className="px-4 py-3 text-xs font-medium text-slate-500 uppercase tracking-wide">Source</th>
            <th className="px-4 py-3 text-xs font-medium text-slate-500 uppercase tracking-wide">Summary</th>
            {canRevert && <th className="px-4 py-3 w-24" />}
          </tr>
        </thead>
        <tbody className="divide-y divide-white/[0.04]">
          {loading ? (
            <tr>
              <td colSpan={canRevert ? 5 : 4} className="px-4 py-12 text-center text-slate-500">
                <div className="flex items-center justify-center gap-2">
                  <svg className="w-4 h-4 animate-spin" viewBox="0 0 24 24" fill="none">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                  Loading history...
                </div>
              </td>
            </tr>
          ) : history.length === 0 ? (
            <tr>
              <td colSpan={canRevert ? 5 : 4} className="px-4 py-12 text-center text-slate-500">
                No version history available.
              </td>
            </tr>
          ) : (
            history.map((entry) => {
              const isCurrent = entry.version === currentVersion;
              return (
                <tr key={entry.version ?? entry.id} className="hover:bg-white/[0.02] transition-colors">
                  <td className="px-4 py-3">
                    <span className="font-mono text-xs text-slate-300">
                      v{entry.version ?? '--'}
                    </span>
                    {isCurrent && (
                      <span className="ml-2 text-xs px-1.5 py-0.5 rounded bg-red-500/15 text-red-300 border border-red-500/30">
                        current
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-xs text-slate-400">{formatDate(entry.timestamp ?? entry.created_at)}</td>
                  <td className="px-4 py-3 text-xs text-slate-400">{entry.source ?? entry.author ?? '--'}</td>
                  <td className="px-4 py-3 text-xs text-slate-400 max-w-[200px] truncate">{entry.summary ?? entry.message ?? '--'}</td>
                  {canRevert && (
                    <td className="px-4 py-3">
                      {!isCurrent && (
                        <button
                          onClick={() => onRevert?.(entry.version)}
                          className="text-xs px-3 py-1 rounded-lg bg-amber-500/10 text-amber-300
                                     border border-amber-500/30 hover:bg-amber-500/20 transition-colors"
                        >
                          Revert
                        </button>
                      )}
                    </td>
                  )}
                </tr>
              );
            })
          )}
        </tbody>
      </table>
    </div>
  );
}
