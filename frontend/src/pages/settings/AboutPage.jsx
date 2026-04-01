/**
 * AboutPage — version, build info, and uptime from real system state.
 *
 * Reads entirely from useSystemStore. Never fakes version numbers or
 * uptime. Shows '--' for any value the backend has not reported.
 */
import React from 'react';
import useSystemStore from '../../stores/useSystemStore';

/* ---------- helpers ---------- */

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

function InfoRow({ label, value, mono = false }) {
  return (
    <div className="flex items-center justify-between py-2.5 border-b border-white/[0.04] last:border-0">
      <span className="text-sm text-slate-500">{label}</span>
      <span className={`text-sm text-slate-200 ${mono ? 'font-mono' : ''}`}>
        {value ?? '--'}
      </span>
    </div>
  );
}

/* ---------- main page ---------- */

export default function AboutPage() {
  const {
    bootstrapState,
    version,
    uptimeSeconds,
    status,
    powerState,
    llmStatus,
    apiConnection,
    wsConnection,
  } = useSystemStore();

  const isLoading = bootstrapState === 'idle' || bootstrapState === 'loading';

  return (
    <div className="p-6 lg:p-8 max-w-2xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-slate-100 tracking-tight">
          About REX
        </h1>
        <p className="text-sm text-slate-500 mt-1">
          System information from the running backend.
        </p>
      </div>

      {/* Loading state */}
      {isLoading && (
        <div className="flex items-center gap-3 text-sm text-slate-500 py-4">
          <svg className="w-5 h-5 animate-spin text-cyan-400" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
          </svg>
          Waiting for system data...
        </div>
      )}

      {/* Version and build */}
      <section className="rounded-[26px] border border-white/[0.06] bg-gradient-to-br from-[#0B1020] to-[#11192C] p-5">
        <h2 className="text-xs font-bold tracking-widest uppercase text-slate-400 mb-3">
          System Info
        </h2>
        <InfoRow label="Version" value={version} mono />
        <InfoRow label="Uptime" value={isLoading ? '--' : formatUptime(uptimeSeconds)} />
        <InfoRow label="System Status" value={isLoading ? '--' : status} />
        <InfoRow label="Power State" value={isLoading ? '--' : powerState} />
        <InfoRow label="LLM Status" value={isLoading ? '--' : llmStatus} />
      </section>

      {/* Connection state */}
      <section className="rounded-[26px] border border-white/[0.06] bg-gradient-to-br from-[#0B1020] to-[#11192C] p-5">
        <h2 className="text-xs font-bold tracking-widest uppercase text-slate-400 mb-3">
          Connections
        </h2>
        <InfoRow label="API" value={apiConnection} />
        <InfoRow label="WebSocket" value={wsConnection} />
      </section>

      {/* Bootstrap error */}
      {bootstrapState === 'error' && (
        <div className="rounded-xl border border-red-500/30 bg-red-500/5 p-4 text-sm text-red-300">
          Could not reach the REX backend. Values above may be stale or unavailable.
        </div>
      )}

      {/* Footer */}
      <div className="text-center text-[10px] text-slate-700 pt-4">
        REX-BOT-AI -- All values shown are from the running backend. No values are fabricated.
      </div>
    </div>
  );
}
