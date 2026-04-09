import React, { useState, useCallback } from 'react';
import useSystemStore from '../../stores/useSystemStore';
import useThreatStore from '../../stores/useThreatStore';
import useDeviceStore from '../../stores/useDeviceStore';
import api from '../../api/client';

function StatCard({ label, value, color = 'text-rex-text', icon }) {
  return (
    <div className="bg-rex-surface border border-rex-card rounded-xl p-4 flex items-center gap-4">
      <div className={`w-10 h-10 rounded-lg ${color.replace('text-', 'bg-')}/15 flex items-center justify-center shrink-0`}>
        {icon}
      </div>
      <div>
        <p className={`text-2xl font-bold ${color}`}>{value}</p>
        <p className="text-xs text-rex-muted mt-0.5">{label}</p>
      </div>
    </div>
  );
}

function HealthIndicator({ activeThreats }) {
  let label, color, barWidth;
  if (activeThreats === 0) {
    label = 'Healthy';
    color = 'bg-rex-safe';
    barWidth = '100%';
  } else if (activeThreats < 3) {
    label = 'Minor Alerts';
    color = 'bg-rex-warn';
    barWidth = '70%';
  } else if (activeThreats < 10) {
    label = 'Elevated';
    color = 'bg-orange-500';
    barWidth = '40%';
  } else {
    label = 'Critical';
    color = 'bg-rex-threat';
    barWidth = '15%';
  }

  return (
    <div className="bg-rex-surface border border-rex-card rounded-xl p-4">
      <h3 className="text-xs text-rex-muted uppercase tracking-wide mb-3">Network Health</h3>
      <div className="flex items-center justify-between mb-2">
        <span className="text-sm font-semibold text-rex-text">{label}</span>
        <span className={`w-3 h-3 rounded-full ${color}`} />
      </div>
      <div className="w-full bg-rex-card rounded-full h-2">
        <div className={`${color} h-2 rounded-full transition-all duration-500`} style={{ width: barWidth }} />
      </div>
    </div>
  );
}

function LLMStatusCard({ llmStatus }) {
  const statusMap = {
    ready: { label: 'Available', color: 'text-rex-safe', dot: 'bg-rex-safe' },
    busy: { label: 'Processing', color: 'text-rex-warn', dot: 'bg-rex-warn' },
    degraded: { label: 'Degraded', color: 'text-orange-400', dot: 'bg-orange-400' },
    offline: { label: 'Offline', color: 'text-rex-threat', dot: 'bg-rex-threat' },
    unknown: { label: 'Unknown', color: 'text-rex-muted', dot: 'bg-rex-muted' },
  };
  const info = statusMap[llmStatus] || statusMap.unknown;

  return (
    <div className="bg-rex-surface border border-rex-card rounded-xl p-4">
      <h3 className="text-xs text-rex-muted uppercase tracking-wide mb-3">LLM Brain Status</h3>
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <span className="text-sm text-rex-muted">Status</span>
          <span className="flex items-center gap-1.5">
            <span className={`w-2 h-2 rounded-full ${info.dot}`} />
            <span className={`text-sm font-medium ${info.color}`}>{info.label}</span>
          </span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-sm text-rex-muted">Model</span>
          <span className="text-sm text-rex-text">Local LLM</span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-sm text-rex-muted">Avg Response</span>
          <span className="text-sm text-rex-text">~2.5s</span>
        </div>
      </div>
    </div>
  );
}

function formatTimeAgo(timestamp) {
  if (!timestamp) return '';
  const diff = Date.now() - new Date(timestamp).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

function ActivityTimeline({ threats }) {
  const recent = threats.slice(0, 10);

  const severityDotColor = {
    critical: 'bg-rex-threat',
    high: 'bg-orange-500',
    medium: 'bg-rex-warn',
    low: 'bg-rex-accent',
    info: 'bg-rex-muted',
  };

  return (
    <div className="bg-rex-surface border border-rex-card rounded-xl p-4">
      <h3 className="text-xs text-rex-muted uppercase tracking-wide mb-3">Recent Activity</h3>
      {recent.length === 0 ? (
        <p className="text-sm text-rex-muted py-4 text-center">No recent activity.</p>
      ) : (
        <div className="space-y-0">
          {recent.map((event, i) => (
            <div key={event.id || i} className="flex items-start gap-3 py-2 border-b border-rex-card/50 last:border-0">
              <div className="flex flex-col items-center mt-1">
                <span className={`w-2 h-2 rounded-full ${severityDotColor[event.severity] || 'bg-rex-muted'}`} />
                {i < recent.length - 1 && (
                  <span className="w-px h-full bg-rex-card mt-1" />
                )}
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm text-rex-text truncate">
                  {event.description || 'Event detected'}
                </p>
                <p className="text-xs text-rex-muted mt-0.5">
                  {formatTimeAgo(event.timestamp)}
                </p>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function OverviewPanel() {
  const { deviceCount, activeThreats, threatsBlocked24h, llmStatus } = useSystemStore();
  const { threats } = useThreatStore();
  const { devices } = useDeviceStore();
  const [scanning, setScanning] = useState(false);

  const scansRun = threats.filter(
    (t) => t.action_taken && t.action_taken.toLowerCase().includes('scan')
  ).length || 0;

  const handleScan = useCallback(async () => {
    setScanning(true);
    try {
      await api.post('/devices/scan');
    } catch (err) {
      console.error('Scan failed:', err);
    } finally {
      setTimeout(() => setScanning(false), 2000);
    }
  }, []);

  return (
    <div className="space-y-6">
      {/* Stats grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          label="Devices"
          value={deviceCount || devices.length}
          color="text-rex-accent"
          icon={
            <svg className="w-5 h-5 text-rex-accent" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 17.25v1.007a3 3 0 01-.879 2.122L7.5 21h9l-.621-.621A3 3 0 0115 18.257V17.25m6-12V15a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 15V5.25A2.25 2.25 0 015.25 3h13.5A2.25 2.25 0 0121 5.25z" />
            </svg>
          }
        />
        <StatCard
          label="Threats Today"
          value={activeThreats}
          color={activeThreats > 0 ? 'text-rex-threat' : 'text-rex-safe'}
          icon={
            <svg className={`w-5 h-5 ${activeThreats > 0 ? 'text-rex-threat' : 'text-rex-safe'}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
            </svg>
          }
        />
        <StatCard
          label="Threats Blocked"
          value={threatsBlocked24h}
          color="text-rex-safe"
          icon={
            <svg className="w-5 h-5 text-rex-safe" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
            </svg>
          }
        />
        <StatCard
          label="Scans Run"
          value={scansRun}
          color="text-rex-accent"
          icon={
            <svg className="w-5 h-5 text-rex-accent" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M7.5 3.75H6A2.25 2.25 0 003.75 6v1.5M16.5 3.75H18A2.25 2.25 0 0120.25 6v1.5m0 9V18A2.25 2.25 0 0118 20.25h-1.5m-9 0H6A2.25 2.25 0 013.75 18v-1.5M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
            </svg>
          }
        />
      </div>

      {/* Health + LLM */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <HealthIndicator activeThreats={activeThreats} />
        <LLMStatusCard llmStatus={llmStatus} />
      </div>

      {/* Activity Timeline */}
      <ActivityTimeline threats={threats} />

      {/* Quick Actions */}
      <div className="flex flex-wrap gap-3">
        <button
          onClick={handleScan}
          disabled={scanning}
          className="flex items-center gap-2 px-4 py-2.5 bg-rex-accent text-white rounded-lg hover:bg-rex-accent/80 disabled:opacity-50 disabled:cursor-not-allowed transition-colors text-sm font-medium"
        >
          <svg className={`w-4 h-4 ${scanning ? 'animate-spin' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
          </svg>
          {scanning ? 'Scanning...' : 'Scan Now'}
        </button>
      </div>
    </div>
  );
}
