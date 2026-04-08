import React from 'react';
import useSystemStore from '../../stores/useSystemStore';
import useAuthStore from '../../stores/useAuthStore';
import useThreatStore from '../../stores/useThreatStore';
import StatCard from '../../components/cards/StatCard';
import RoboDogCorePanel from '../../components/chrome/RoboDogCorePanel';
import DegradedBanner from '../../components/DegradedBanner';
import ActionPanel from '../../components/ActionPanel';
import ServiceStatus from '../../components/ServiceStatus';
import RecentActions, { useActionHistory } from '../../components/RecentActions';
import ThreatTrendChart from '../../components/charts/ThreatTrendChart';
import SeverityBreakdownChart from '../../components/charts/SeverityBreakdownChart';
import { SkeletonCard } from '../../components/primitives/Skeleton';
import { colors, radius } from '../../theme/tokens';

/* ------------------------------------------------------------------ */
/*  Helpers                                                           */
/* ------------------------------------------------------------------ */

function formatUptime(seconds) {
  if (!seconds || seconds <= 0) return '--';
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

function timeAgo(timestamp) {
  if (!timestamp) return '';
  const diff = Date.now() - new Date(timestamp).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

const SEVERITY_COLORS = {
  critical: 'border-l-red-500 bg-red-500/5',
  high: 'border-l-orange-500 bg-orange-500/5',
  medium: 'border-l-amber-400 bg-amber-400/5',
  low: 'border-l-emerald-400 bg-emerald-400/5',
  info: 'border-l-slate-500 bg-slate-500/5',
};

const STATUS_SUMMARY = {
  operational: { label: 'Operational', color: 'text-emerald-400' },
  degraded: { label: 'Degraded', color: 'text-amber-300' },
  critical: { label: 'Critical', color: 'text-red-400' },
  maintenance: { label: 'Maintenance', color: 'text-sky-400' },
  unknown: { label: 'Unknown', color: 'text-slate-400' },
};

/* ------------------------------------------------------------------ */
/*  Sub-components                                                    */
/* ------------------------------------------------------------------ */

function SectionHeader({ title, subtitle }) {
  return (
    <div className="mb-3">
      <h2 className="text-sm font-bold tracking-widest uppercase text-slate-400">
        {title}
      </h2>
      {subtitle && (
        <p className="text-xs text-slate-600 mt-0.5">{subtitle}</p>
      )}
    </div>
  );
}

function AlertRow({ alert, index }) {
  const sev = alert.severity || 'info';
  return (
    <div
      className={`border-l-4 rounded-r-lg p-3 ${SEVERITY_COLORS[sev] || SEVERITY_COLORS.info}`}
    >
      <div className="flex justify-between items-start gap-2">
        <div className="flex-1 min-w-0">
          <p className="text-sm text-slate-200 truncate">
            {alert.description || alert.message || 'Security event detected'}
          </p>
          <span className="text-[10px] font-medium uppercase tracking-wide text-slate-500">
            {sev}
          </span>
        </div>
        <span className="text-xs text-slate-500 whitespace-nowrap shrink-0">
          {timeAgo(alert.timestamp)}
        </span>
      </div>
    </div>
  );
}

function EmptyState({ message }) {
  return (
    <div className="flex items-center justify-center py-10 text-sm text-slate-600">
      {message}
    </div>
  );
}

function HealthSummaryBadge({ status }) {
  const info = STATUS_SUMMARY[status] || STATUS_SUMMARY.unknown;
  return (
    <div className={`
      inline-flex items-center gap-2 px-4 py-2
      rounded-full border border-white/[0.06]
      bg-slate-900/60
    `}>
      <span className={`w-2 h-2 rounded-full ${
        status === 'operational' ? 'bg-emerald-400' :
        status === 'degraded' ? 'bg-amber-400' :
        status === 'critical' ? 'bg-red-500' :
        'bg-slate-500'
      }`} />
      <span className={`text-xs font-bold tracking-widest uppercase ${info.color}`}>
        {info.label}
      </span>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Main Page                                                         */
/* ------------------------------------------------------------------ */

export default function AdvancedOverviewPage() {
  const {
    bootstrapState,
    status,
    powerState,
    llmStatus,
    threatPosture,
    connected,
    deviceCount,
    activeThreats,
    threatsBlocked24h,
    uptimeSeconds,
    recentAlerts,
    health,
  } = useSystemStore();
  const token = useAuthStore((s) => s.token);
  const threats = useThreatStore((s) => s.threats);
  const { actions } = useActionHistory();

  const isLoading = bootstrapState === 'idle' || bootstrapState === 'loading';

  // Derive degraded-service flags from health data
  const degradedServices = health ? {
    redis: health.redis !== 'unhealthy',
    ollama: health.ollama !== 'unhealthy',
  } : null;

  return (
    <div className="p-6 lg:p-8 space-y-8 max-w-7xl mx-auto">
      {/* Degraded banner */}
      {degradedServices && <DegradedBanner services={degradedServices} />}
      {/* ------ Top Row: Health + REX Dog ------ */}
      <div className="flex flex-col lg:flex-row gap-6">
        {/* Left column: health summary + stat cards */}
        <div className="flex-1 space-y-6">
          <div className="flex items-center justify-between">
            <h1 className="text-xl font-bold text-slate-100 tracking-tight">
              System Overview
            </h1>
            <HealthSummaryBadge status={status} />
          </div>

          {/* Stat card grid */}
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4">
            <StatCard
              label="Devices"
              value={isLoading ? '--' : deviceCount}
              icon={
                <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
                  <rect x="4" y="4" width="10" height="10" rx="1.5" stroke="currentColor" strokeWidth="1.5" />
                  <path d="M7 1V4M11 1V4M7 14V17M11 14V17M1 7H4M1 11H4M14 7H17M14 11H17" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
                </svg>
              }
            />
            <StatCard
              label="Active Threats"
              value={isLoading ? '--' : activeThreats}
              icon={
                <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
                  <path d="M9 1L1.5 16H16.5L9 1Z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" />
                  <path d="M9 7V10.5M9 13V13.01" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
                </svg>
              }
            />
            <StatCard
              label="Blocked (24h)"
              value={isLoading ? '--' : threatsBlocked24h}
              icon={
                <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
                  <path d="M9 1L2 4.5V9C2 13.1 5 16.4 9 17.5C13 16.4 16 13.1 16 9V4.5L9 1Z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" />
                </svg>
              }
            />
            <StatCard
              label="Uptime"
              value={isLoading ? '--' : formatUptime(uptimeSeconds)}
              icon={
                <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
                  <circle cx="9" cy="9" r="7.5" stroke="currentColor" strokeWidth="1.5" />
                  <path d="M9 5V9.5L12 11" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              }
            />
          </div>
        </div>

        {/* Right column: REX guard dog */}
        <div className="w-full lg:w-80 shrink-0">
          <RoboDogCorePanel
            threatPosture={threatPosture}
            powerState={powerState}
            llmStatus={llmStatus}
            connected={connected}
          />
        </div>
      </div>

      {/* ------ Threat Trends ------ */}
      <section>
        <SectionHeader
          title="Threat Trends"
          subtitle="Last 24 hours"
        />
        {isLoading ? (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="md:col-span-2"><SkeletonCard /></div>
            <SkeletonCard />
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="md:col-span-2 rounded-[26px] border border-white/[0.06] bg-gradient-to-br from-[#0a0a0a] to-[#141414] p-5">
              <ThreatTrendChart threats={threats} />
            </div>
            <div className="rounded-[26px] border border-white/[0.06] bg-gradient-to-br from-[#0a0a0a] to-[#141414] p-5">
              <p className="text-xs font-bold tracking-widest uppercase text-slate-400 mb-3">By Severity</p>
              <SeverityBreakdownChart threats={threats} />
            </div>
          </div>
        )}
      </section>

      {/* ------ Recent Alerts ------ */}
      <section>
        <SectionHeader
          title="Recent Alerts"
          subtitle={isLoading ? 'Waiting for data...' : `${recentAlerts.length} events cached`}
        />

        {isLoading ? (
          <EmptyState message="Loading alert data..." />
        ) : recentAlerts.length === 0 ? (
          <EmptyState message={connected ? 'No recent alerts -- all clear.' : 'Waiting for backend connection...'} />
        ) : (
          <div className="space-y-2">
            {recentAlerts.slice(0, 8).map((alert, i) => (
              <AlertRow key={alert.id || i} alert={alert} index={i} />
            ))}
          </div>
        )}
      </section>

      {/* ------ Service Status ------ */}
      <ServiceStatus />

      {/* ------ Quick Actions ------ */}
      <ActionPanel token={token} />

      {/* ------ Recent Actions ------ */}
      <RecentActions actions={actions} />

      {/* ------ Bootstrap Error Banner ------ */}
      {bootstrapState === 'error' && (
        <div className="rounded-xl border border-red-500/30 bg-red-500/5 p-4 text-sm text-red-300">
          Failed to reach REX backend. Stats above may be stale or unavailable.
          The system will retry when the WebSocket reconnects.
        </div>
      )}
    </div>
  );
}
