/**
 * JobHistoryTable — scheduled jobs with frequency, last run, next run, status.
 */
import React from 'react';

function StatusBadge({ status }) {
  const styles = {
    active: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
    running: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30',
    paused: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
    disabled: 'bg-slate-700/40 text-slate-400 border-slate-600',
    failed: 'bg-red-500/15 text-red-300 border-red-500/30',
    error: 'bg-red-500/15 text-red-300 border-red-500/30',
  };
  const cls = styles[(status || '').toLowerCase()] || 'bg-slate-700/40 text-slate-400 border-slate-600';
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full font-medium border ${cls}`}>
      {status || 'unknown'}
    </span>
  );
}

export default function JobHistoryTable({ jobs = [], loading = false }) {
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
            <th className="px-4 py-3 text-xs font-medium text-slate-500 uppercase tracking-wide">Job</th>
            <th className="px-4 py-3 text-xs font-medium text-slate-500 uppercase tracking-wide">Frequency</th>
            <th className="px-4 py-3 text-xs font-medium text-slate-500 uppercase tracking-wide">Last Run</th>
            <th className="px-4 py-3 text-xs font-medium text-slate-500 uppercase tracking-wide">Next Run</th>
            <th className="px-4 py-3 text-xs font-medium text-slate-500 uppercase tracking-wide">Status</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-white/[0.04]">
          {loading ? (
            <tr>
              <td colSpan={5} className="px-4 py-16 text-center text-slate-500">
                <div className="flex items-center justify-center gap-2">
                  <svg className="w-4 h-4 animate-spin" viewBox="0 0 24 24" fill="none">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                  Loading jobs...
                </div>
              </td>
            </tr>
          ) : jobs.length === 0 ? (
            <tr>
              <td colSpan={5} className="px-4 py-16 text-center text-slate-500">
                No scheduled jobs. Configure a schedule to see jobs here.
              </td>
            </tr>
          ) : (
            jobs.map((job) => (
              <tr key={job.id ?? job.name} className="hover:bg-white/[0.02] transition-colors">
                <td className="px-4 py-3">
                  <span className="text-sm text-slate-200 font-medium">{job.name ?? job.job ?? '--'}</span>
                  {job.description && (
                    <p className="text-xs text-slate-500 mt-0.5">{job.description}</p>
                  )}
                </td>
                <td className="px-4 py-3 text-xs text-slate-400 font-mono">{job.frequency ?? job.cron ?? '--'}</td>
                <td className="px-4 py-3 text-xs text-slate-400">{formatDate(job.last_run ?? job.lastRun)}</td>
                <td className="px-4 py-3 text-xs text-slate-400">{formatDate(job.next_run ?? job.nextRun)}</td>
                <td className="px-4 py-3"><StatusBadge status={job.status} /></td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}
