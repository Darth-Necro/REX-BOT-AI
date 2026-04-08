/**
 * ThreatsPage -- full threats view with API hydration, severity filters,
 * table, and detail panel.
 *
 * Hydrates from API on mount. WS deltas applied via store.
 * No fake data -- table stays empty until API responds.
 */

import React, { useEffect, useState, useCallback, useMemo } from 'react';
import useThreatStore from '../../stores/useThreatStore';
import ThreatTable from '../../components/tables/ThreatTable';

/* ---------- severity filter chips ---------- */

const SEVERITIES = ['all', 'critical', 'high', 'medium', 'low', 'info'];

const SEVERITY_CHIP_COLORS = {
  all:      'border-rex-card text-rex-muted',
  critical: 'border-rex-threat/40 text-rex-threat',
  high:     'border-orange-500/40 text-orange-400',
  medium:   'border-rex-warn/40 text-rex-warn',
  low:      'border-cyan-500/40 text-cyan-400',
  info:     'border-gray-500/40 text-gray-400',
};

const SEVERITY_CHIP_ACTIVE = {
  all:      'bg-rex-card/50 border-rex-muted/40 text-rex-text',
  critical: 'bg-rex-threat/15 border-rex-threat/50 text-rex-threat',
  high:     'bg-orange-500/15 border-orange-500/50 text-orange-400',
  medium:   'bg-rex-warn/15 border-rex-warn/50 text-rex-warn',
  low:      'bg-cyan-500/15 border-cyan-500/50 text-cyan-400',
  info:     'bg-gray-500/15 border-gray-500/50 text-gray-400',
};

/* ---------- detail panel ---------- */

function ThreatDetailPanel({ threat, onClose }) {
  if (!threat) return null;

  const isResolved = threat.resolved || threat.status === 'resolved';

  return (
    <div className="w-80 shrink-0 bg-rex-surface border-l border-rex-card overflow-y-auto">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-rex-card">
        <h3 className="text-sm font-semibold text-rex-text truncate">
          Threat Detail
        </h3>
        <button
          onClick={onClose}
          className="text-rex-muted hover:text-rex-text transition-colors"
          aria-label="Close detail panel"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>

      {/* Body */}
      <div className="p-4 space-y-4 text-sm">
        <Section label="Overview">
          <Field label="Severity" value={threat.severity} capitalize />
          <Field label="Status" value={isResolved ? 'Resolved' : (threat.status || 'Active')} capitalize />
          <Field label="Category" value={threat.category} capitalize />
        </Section>

        <Section label="Source">
          <Field label="Device" value={threat.source_device} />
          <Field label="IP" value={threat.source_ip} mono />
          <Field label="MAC" value={threat.source_mac} mono />
        </Section>

        {threat.description && (
          <Section label="Description">
            <p className="text-xs text-rex-text leading-relaxed">{threat.description}</p>
          </Section>
        )}

        {threat.action_taken && (
          <Section label="Action Taken">
            <p className="text-xs text-cyan-400">{threat.action_taken}</p>
          </Section>
        )}

        {threat.timestamp && (
          <Section label="Timestamp">
            <span className="text-xs text-rex-muted font-mono">
              {new Date(threat.timestamp).toLocaleString()}
            </span>
          </Section>
        )}

        {threat.id && (
          <Section label="ID">
            <span className="text-xs text-rex-muted font-mono break-all">{threat.id}</span>
          </Section>
        )}

        {/* Resolve / False Positive buttons */}
        {!isResolved && threat.id && (
          <DetailPanelActions threatId={threat.id} />
        )}
      </div>
    </div>
  );
}

function DetailPanelActions({ threatId }) {
  const { resolveThreat, markFalsePositive } = useThreatStore();
  const [acting, setActing] = useState(null);

  const handle = async (action) => {
    setActing(action);
    try {
      if (action === 'resolve') await resolveThreat(threatId);
      else await markFalsePositive(threatId);
    } finally {
      setActing(null);
    }
  };

  return (
    <Section label="Actions">
      <div className="flex flex-col gap-2">
        <button
          onClick={() => handle('resolve')}
          disabled={!!acting}
          className="w-full px-3 py-1.5 rounded-lg bg-emerald-500/20 text-emerald-300 text-xs font-medium border border-emerald-500/30 hover:bg-emerald-500/30 disabled:opacity-40 transition-colors"
        >
          {acting === 'resolve' ? 'Resolving...' : 'Resolve'}
        </button>
        <button
          onClick={() => handle('fp')}
          disabled={!!acting}
          className="w-full px-3 py-1.5 rounded-lg bg-amber-500/20 text-amber-300 text-xs font-medium border border-amber-500/30 hover:bg-amber-500/30 disabled:opacity-40 transition-colors"
        >
          {acting === 'fp' ? 'Marking...' : 'False Positive'}
        </button>
      </div>
    </Section>
  );
}

function Section({ label, children }) {
  return (
    <div>
      <h4 className="text-xs text-rex-muted uppercase tracking-wide mb-2">{label}</h4>
      <div className="space-y-1">{children}</div>
    </div>
  );
}

function Field({ label, value, mono, capitalize: cap }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-rex-muted text-xs">{label}</span>
      <span
        className={`text-xs text-rex-text ${mono ? 'font-mono' : ''} ${cap ? 'capitalize' : ''}`}
      >
        {value || '-'}
      </span>
    </div>
  );
}

/* ---------- main page ---------- */

export default function ThreatsPage() {
  const threats = useThreatStore((s) => s.threats);
  const loading = useThreatStore((s) => s.loading);
  const error = useThreatStore((s) => s.error);
  const fetchThreats = useThreatStore((s) => s.fetchThreats);
  const selectedThreat = useThreatStore((s) => s.selectedThreat);
  const selectThreat = useThreatStore((s) => s.selectThreat);
  const clearSelection = useThreatStore((s) => s.clearSelection);

  const [severityFilter, setSeverityFilter] = useState('all');

  // Hydrate from API on mount
  useEffect(() => {
    fetchThreats();
  }, [fetchThreats]);

  const handleSelect = useCallback(
    (threat) => {
      if (selectedThreat?.id === threat.id) {
        clearSelection();
      } else {
        selectThreat(threat);
      }
    },
    [selectedThreat, selectThreat, clearSelection],
  );

  // Severity counts for filter chips
  const counts = useMemo(() => {
    const c = { all: threats.length, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    threats.forEach((t) => {
      if (c[t.severity] !== undefined) c[t.severity]++;
    });
    return c;
  }, [threats]);

  return (
    <div className="flex h-full">
      {/* Main content */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <h2 className="text-lg font-semibold text-rex-text">Threats</h2>
          <span className="text-xs text-rex-muted">
            {threats.length} total
          </span>
        </div>

        {/* Severity filter chips */}
        <div className="flex flex-wrap gap-2">
          {SEVERITIES.map((sev) => {
            const isActive = severityFilter === sev;
            const baseCls = isActive
              ? SEVERITY_CHIP_ACTIVE[sev]
              : SEVERITY_CHIP_COLORS[sev];

            return (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`text-xs px-3 py-1.5 rounded-full border transition-colors capitalize ${baseCls} ${
                  isActive ? '' : 'hover:bg-rex-card/30'
                }`}
              >
                {sev === 'all' ? 'All' : sev}
                <span className="ml-1.5 opacity-60">{counts[sev]}</span>
              </button>
            );
          })}
        </div>

        {/* Table */}
        <ThreatTable
          threats={threats}
          loading={loading}
          error={error}
          severityFilter={severityFilter}
          onSelect={handleSelect}
          selectedId={selectedThreat?.id}
        />
      </div>

      {/* Detail panel -- sidebar on desktop */}
      {selectedThreat && (
        <div className="hidden md:block">
          <ThreatDetailPanel threat={selectedThreat} onClose={clearSelection} />
        </div>
      )}

      {/* Detail panel -- bottom sheet on mobile */}
      {selectedThreat && (
        <div className="md:hidden fixed inset-x-0 bottom-0 z-40 max-h-[70vh] overflow-y-auto bg-rex-surface border-t border-rex-card rounded-t-2xl shadow-2xl">
          <div className="flex justify-center pt-2 pb-1">
            <span className="w-10 h-1 rounded-full bg-slate-600" />
          </div>
          <ThreatDetailPanel threat={selectedThreat} onClose={clearSelection} />
        </div>
      )}
    </div>
  );
}
