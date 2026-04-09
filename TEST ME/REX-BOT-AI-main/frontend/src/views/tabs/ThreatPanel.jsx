import React, { useState, useCallback, useEffect, useMemo } from 'react';
import useThreatStore from '../../stores/useThreatStore';
import api from '../../api/client';
import ThreatFeed from '../../components/ThreatFeed';

const SEVERITY_BAR_COLORS = {
  critical: 'bg-rex-threat',
  high: 'bg-orange-500',
  medium: 'bg-rex-warn',
  low: 'bg-rex-accent',
};

function SeverityStatBar({ threats }) {
  const counts = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0 };
    threats.forEach((t) => {
      if (c[t.severity] !== undefined) c[t.severity]++;
    });
    return c;
  }, [threats]);

  const total = threats.length || 1;

  return (
    <div className="bg-rex-surface border border-rex-card rounded-xl p-4">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-xs text-rex-muted uppercase tracking-wide">Threat Distribution</h3>
        <span className="text-xs text-rex-muted">{threats.length} total</span>
      </div>
      {/* Bar chart */}
      <div className="flex rounded-full overflow-hidden h-3 bg-rex-card">
        {Object.entries(counts).map(([severity, count]) => {
          if (count === 0) return null;
          return (
            <div
              key={severity}
              className={`${SEVERITY_BAR_COLORS[severity]} transition-all duration-300`}
              style={{ width: `${(count / total) * 100}%` }}
              title={`${severity}: ${count}`}
            />
          );
        })}
      </div>
      {/* Legend */}
      <div className="flex flex-wrap gap-4 mt-3">
        {Object.entries(counts).map(([severity, count]) => (
          <div key={severity} className="flex items-center gap-1.5">
            <span className={`w-2.5 h-2.5 rounded-sm ${SEVERITY_BAR_COLORS[severity]}`} />
            <span className="text-xs text-rex-muted capitalize">{severity}</span>
            <span className="text-xs font-semibold text-rex-text">{count}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function ThreatPanel() {
  const { threats, setThreats, total } = useThreatStore();
  const [loaded, setLoaded] = useState(false);
  const [dateRange, setDateRange] = useState('all');

  // Fetch threats on mount
  useEffect(() => {
    if (!loaded) {
      const params = {};
      if (dateRange !== 'all') {
        const now = new Date();
        const since = new Date();
        if (dateRange === '1h') since.setHours(now.getHours() - 1);
        else if (dateRange === '24h') since.setDate(now.getDate() - 1);
        else if (dateRange === '7d') since.setDate(now.getDate() - 7);
        else if (dateRange === '30d') since.setDate(now.getDate() - 30);
        params.since = since.toISOString();
      }
      api.get('/threats/', { params })
        .then((res) => {
          const list = res.data?.threats || res.data || [];
          setThreats(Array.isArray(list) ? list : [], res.data?.total || list.length);
        })
        .catch((err) => console.error('Failed to fetch threats:', err))
        .finally(() => setLoaded(true));
    }
  }, [loaded, dateRange, setThreats]);

  // Re-fetch when date range changes
  useEffect(() => {
    setLoaded(false);
  }, [dateRange]);

  const handleExport = useCallback(() => {
    if (threats.length === 0) return;
    const headers = ['Timestamp', 'Severity', 'Source Device', 'Description', 'Action Taken', 'Resolved'];
    const rows = threats.map((t) => [
      t.timestamp || '',
      t.severity || '',
      t.source_device || '',
      t.description || '',
      t.action_taken || '',
      t.resolved ? 'Yes' : 'No',
    ]);
    const csv = [headers, ...rows]
      .map((r) => r.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(','))
      .join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `rex-threats-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }, [threats]);

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <h2 className="text-lg font-semibold text-rex-text">Threats</h2>
        <div className="flex items-center gap-2">
          <div className="relative">
            <select
              value={dateRange}
              onChange={(e) => setDateRange(e.target.value)}
              className="appearance-none bg-rex-surface border border-rex-card rounded-lg px-3 py-2 pr-8 text-sm text-rex-text focus:outline-none focus:border-rex-accent transition-colors cursor-pointer"
            >
              <option value="all">All Time</option>
              <option value="1h">Last Hour</option>
              <option value="24h">Last 24 Hours</option>
              <option value="7d">Last 7 Days</option>
              <option value="30d">Last 30 Days</option>
            </select>
            <svg
              className="absolute right-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-rex-muted pointer-events-none"
              fill="none" viewBox="0 0 24 24" stroke="currentColor"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </div>
          <button
            onClick={handleExport}
            disabled={threats.length === 0}
            className="flex items-center gap-2 px-3 py-2 bg-rex-surface border border-rex-card text-rex-text rounded-lg hover:border-rex-accent transition-colors text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" />
            </svg>
            Export
          </button>
        </div>
      </div>

      {/* Stats bar */}
      <SeverityStatBar threats={threats} />

      {/* Threat feed */}
      <ThreatFeed />
    </div>
  );
}
