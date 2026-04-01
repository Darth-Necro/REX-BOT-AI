/**
 * DiagnosticsPage — service health grid and runtime truth snapshot.
 * No fake data. Everything comes from /health + /status via the diagnostics store.
 */
import React, { useEffect } from 'react';
import useDiagnosticsStore from '../../stores/useDiagnosticsStore';
import ServiceCard from '../../components/cards/ServiceCard';

function formatUptime(seconds) {
  if (!seconds || seconds <= 0) return '--';
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const parts = [];
  if (d > 0) parts.push(`${d}d`);
  if (h > 0) parts.push(`${h}h`);
  parts.push(`${m}m`);
  return parts.join(' ');
}

export default function DiagnosticsPage() {
  const { snapshot, serviceHealth, loading, error, fetchedAt, fetchDiagnostics } =
    useDiagnosticsStore();

  useEffect(() => {
    fetchDiagnostics();
  }, [fetchDiagnostics]);

  const status = snapshot?.status ?? {};

  return (
    <div className="p-4 sm:p-6 lg:p-8 space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100">Diagnostics</h1>
          <p className="text-sm text-slate-500 mt-0.5">
            {loading
              ? 'Fetching runtime state...'
              : fetchedAt
                ? `Last updated ${new Date(fetchedAt).toLocaleTimeString()}`
                : 'No data yet'}
          </p>
        </div>
        <button
          onClick={fetchDiagnostics}
          disabled={loading}
          className="px-4 py-2 text-sm font-medium rounded-xl bg-[#0B1020] text-slate-300
                     border border-white/[0.06] hover:border-cyan-500/30 hover:text-cyan-300
                     disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
        >
          {loading ? 'Refreshing...' : 'Refresh'}
        </button>
      </div>

      {/* Error banner */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-2xl px-4 py-3">
          <p className="text-sm text-red-300">{error}</p>
        </div>
      )}

      {/* Service health grid */}
      <div>
        <h2 className="text-sm font-semibold text-slate-300 mb-3">Service Health</h2>
        {loading && serviceHealth.length === 0 ? (
          <div className="flex items-center justify-center py-12 text-slate-500 text-sm">
            <svg className="w-4 h-4 animate-spin mr-2" viewBox="0 0 24 24" fill="none">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
            </svg>
            Loading service health...
          </div>
        ) : serviceHealth.length === 0 ? (
          <div className="py-12 text-center text-slate-500 text-sm">
            No service health data available. The backend may not be reachable.
          </div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {serviceHealth.map((svc) => (
              <ServiceCard key={svc.name} name={svc.name} status={svc.status} />
            ))}
          </div>
        )}
      </div>

      {/* Runtime truth */}
      {snapshot && (
        <div>
          <h2 className="text-sm font-semibold text-slate-300 mb-3">Runtime State</h2>
          <div className="bg-gradient-to-br from-[#0B1020] to-[#11192C] border border-white/[0.06] rounded-2xl overflow-hidden">
            <table className="w-full text-sm">
              <tbody className="divide-y divide-white/[0.04]">
                <RuntimeRow label="System Status" value={status.status} />
                <RuntimeRow label="Power State" value={status.powerState} />
                <RuntimeRow label="LLM Engine" value={status.llmStatus} />
                <RuntimeRow label="Devices" value={status.deviceCount} />
                <RuntimeRow label="Active Threats" value={status.activeThreats} warn={status.activeThreats > 0} />
                <RuntimeRow label="Threats Blocked (24h)" value={status.threatsBlocked24h} />
                <RuntimeRow label="Uptime" value={formatUptime(status.uptimeSeconds)} />
                <RuntimeRow label="Version" value={status.version ?? '--'} />
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

function RuntimeRow({ label, value, warn = false }) {
  const display = value === 0 ? '0' : value || '--';
  return (
    <tr className="hover:bg-white/[0.02]">
      <td className="px-5 py-3 text-xs text-slate-500 font-medium uppercase tracking-wide w-1/3">
        {label}
      </td>
      <td className={`px-5 py-3 text-sm font-medium ${
        warn ? 'text-red-300' :
        display === 'unknown' || display === '--' ? 'text-slate-500' :
        'text-slate-200'
      }`}>
        {display}
      </td>
    </tr>
  );
}
