import React, { useState, useEffect, useRef, useCallback } from 'react';
import useThreatStore from '../stores/useThreatStore';

const SEVERITY_COLORS = {
  critical: { bar: 'bg-rex-threat', badge: 'bg-rex-threat/20 text-rex-threat border-rex-threat/40', border: 'border-l-rex-threat' },
  high: { bar: 'bg-orange-500', badge: 'bg-orange-500/20 text-orange-400 border-orange-500/40', border: 'border-l-orange-500' },
  medium: { bar: 'bg-rex-warn', badge: 'bg-rex-warn/20 text-rex-warn border-rex-warn/40', border: 'border-l-rex-warn' },
  low: { bar: 'bg-rex-accent', badge: 'bg-rex-accent/20 text-rex-accent border-rex-accent/40', border: 'border-l-rex-accent' },
  info: { bar: 'bg-gray-500', badge: 'bg-gray-500/20 text-gray-400 border-gray-500/40', border: 'border-l-gray-500' },
};

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

function formatTimestamp(ts) {
  if (!ts) return '';
  const d = new Date(ts);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function formatDate(ts) {
  if (!ts) return '';
  const d = new Date(ts);
  return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
}

function SeverityBadge({ severity }) {
  const colors = SEVERITY_COLORS[severity] || SEVERITY_COLORS.info;
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full border font-medium uppercase ${colors.badge}`}>
      {severity}
    </span>
  );
}

function ThreatEntry({ threat, onResolve, onFalsePositive }) {
  const colors = SEVERITY_COLORS[threat.severity] || SEVERITY_COLORS.info;
  const isResolved = threat.resolved || threat.status === 'resolved';

  return (
    <div
      className={`border-l-4 ${colors.border} bg-rex-surface rounded-r-lg p-3 transition-all ${
        isResolved ? 'opacity-50' : ''
      }`}
    >
      <div className="flex flex-col sm:flex-row sm:items-start gap-2">
        <div className="flex items-center gap-2 shrink-0">
          <span className="text-xs text-rex-muted font-mono whitespace-nowrap">
            {formatDate(threat.timestamp)} {formatTimestamp(threat.timestamp)}
          </span>
          <SeverityBadge severity={threat.severity} />
        </div>
        <div className="flex-1 min-w-0">
          {threat.source_device && (
            <span className="text-xs text-rex-muted">
              from <span className="text-rex-text font-medium">{threat.source_device}</span>
            </span>
          )}
          <p className="text-sm text-rex-text mt-0.5">
            {threat.description || 'Security event detected'}
          </p>
          {threat.action_taken && (
            <p className="text-xs text-rex-muted mt-1">
              Action: <span className="text-rex-accent">{threat.action_taken}</span>
            </p>
          )}
        </div>
        {!isResolved && (
          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={() => onResolve(threat.id)}
              className="text-xs px-2.5 py-1 rounded bg-rex-safe/20 text-rex-safe hover:bg-rex-safe/30 transition-colors"
            >
              Resolve
            </button>
            <button
              onClick={() => onFalsePositive(threat.id)}
              className="text-xs px-2.5 py-1 rounded bg-rex-muted/20 text-rex-muted hover:bg-rex-muted/30 transition-colors"
            >
              False Positive
            </button>
          </div>
        )}
        {isResolved && (
          <span className="text-xs text-rex-safe shrink-0">Resolved</span>
        )}
      </div>
    </div>
  );
}

export default function ThreatFeed() {
  const { threats, resolveThreat } = useThreatStore();
  const [severityFilter, setSeverityFilter] = useState('all');
  const [isPaused, setIsPaused] = useState(false);
  const feedRef = useRef(null);
  const isHovering = useRef(false);
  const prevCountRef = useRef(threats.length);

  const filtered = React.useMemo(() => {
    if (severityFilter === 'all') return threats;
    return threats.filter((t) => t.severity === severityFilter);
  }, [threats, severityFilter]);

  const handleResolve = useCallback((id) => {
    resolveThreat(id);
  }, [resolveThreat]);

  const handleFalsePositive = useCallback((id) => {
    resolveThreat(id);
  }, [resolveThreat]);

  // Auto-scroll when new threats arrive, unless paused or hovering
  useEffect(() => {
    if (threats.length > prevCountRef.current && !isPaused && !isHovering.current && feedRef.current) {
      feedRef.current.scrollTop = 0;
    }
    prevCountRef.current = threats.length;
  }, [threats.length, isPaused]);

  return (
    <div className="flex flex-col gap-4">
      {/* Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center gap-3">
        <div className="relative">
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="appearance-none bg-rex-surface border border-rex-card rounded-lg px-3 py-2 pr-8 text-sm text-rex-text focus:outline-none focus:border-rex-accent transition-colors cursor-pointer"
          >
            <option value="all">All Severities</option>
            {SEVERITY_ORDER.map((s) => (
              <option key={s} value={s}>
                {s.charAt(0).toUpperCase() + s.slice(1)}
              </option>
            ))}
          </select>
          <svg
            className="absolute right-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-rex-muted pointer-events-none"
            fill="none" viewBox="0 0 24 24" stroke="currentColor"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </div>

        <button
          onClick={() => setIsPaused((p) => !p)}
          className={`text-xs px-3 py-2 rounded-lg border transition-colors ${
            isPaused
              ? 'border-rex-warn text-rex-warn bg-rex-warn/10'
              : 'border-rex-card text-rex-muted hover:text-rex-text'
          }`}
        >
          {isPaused ? 'Paused - Click to resume' : 'Auto-scrolling'}
        </button>

        <span className="text-xs text-rex-muted ml-auto">
          {filtered.length} threat{filtered.length !== 1 ? 's' : ''}
        </span>
      </div>

      {/* Feed */}
      <div
        ref={feedRef}
        className="space-y-2 max-h-[calc(100vh-20rem)] overflow-y-auto pr-1 scrollbar-thin"
        onMouseEnter={() => { isHovering.current = true; }}
        onMouseLeave={() => { isHovering.current = false; }}
      >
        {filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-rex-muted">
            <svg className="w-12 h-12 mb-3 opacity-40" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
                d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
            <p>No threats to display.</p>
          </div>
        ) : (
          filtered.map((threat, i) => (
            <ThreatEntry
              key={threat.id || i}
              threat={threat}
              onResolve={handleResolve}
              onFalsePositive={handleFalsePositive}
            />
          ))
        )}
      </div>
    </div>
  );
}
