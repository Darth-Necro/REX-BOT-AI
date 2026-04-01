import React, { useState, useEffect, useRef, useCallback } from 'react';
import { on, off } from '../../ws/socket';
import api from '../../api/client';

const LEVEL_COLORS = {
  debug: 'text-gray-500',
  info: 'text-rex-accent',
  warning: 'text-rex-warn',
  warn: 'text-rex-warn',
  error: 'text-rex-threat',
  critical: 'text-rex-threat font-bold',
};

const LEVEL_BG = {
  debug: '',
  info: '',
  warning: 'bg-rex-warn/5',
  warn: 'bg-rex-warn/5',
  error: 'bg-rex-threat/5',
  critical: 'bg-rex-threat/10',
};

const SERVICE_LABELS = [
  { value: 'all', label: 'All Services' },
  { value: 'eyes', label: 'EYES (Scanner)' },
  { value: 'brain', label: 'BRAIN (LLM)' },
  { value: 'teeth', label: 'TEETH (Firewall)' },
  { value: 'bark', label: 'BARK (Notifier)' },
  { value: 'spine', label: 'SPINE (Orchestrator)' },
  { value: 'tail', label: 'TAIL (Logger)' },
  { value: 'api', label: 'API Server' },
  { value: 'websocket', label: 'WebSocket' },
];

const LEVEL_OPTIONS = [
  { value: 'all', label: 'All Levels' },
  { value: 'debug', label: 'Debug' },
  { value: 'info', label: 'Info' },
  { value: 'warning', label: 'Warning' },
  { value: 'error', label: 'Error' },
  { value: 'critical', label: 'Critical' },
];

function formatTimestamp(ts) {
  if (!ts) return '';
  const d = new Date(ts);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3 });
}

function LogLine({ entry }) {
  const level = (entry.level || 'info').toLowerCase();
  const levelColor = LEVEL_COLORS[level] || 'text-rex-muted';
  const bg = LEVEL_BG[level] || '';

  return (
    <div className={`flex items-start gap-2 px-3 py-1 text-xs font-mono hover:bg-rex-surface/40 ${bg}`}>
      <span className="text-rex-muted shrink-0 w-20 text-right">
        {formatTimestamp(entry.timestamp)}
      </span>
      <span className={`shrink-0 w-16 uppercase text-right ${levelColor}`}>
        {level}
      </span>
      <span className="shrink-0 w-14 text-rex-accent truncate" title={entry.service}>
        {(entry.service || '').toUpperCase().slice(0, 6)}
      </span>
      <span className="text-rex-text break-all flex-1">
        {entry.message || entry.msg || JSON.stringify(entry)}
      </span>
    </div>
  );
}

export default function LogViewer() {
  const [logs, setLogs] = useState([]);
  const [serviceFilter, setServiceFilter] = useState('all');
  const [levelFilter, setLevelFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [isPaused, setIsPaused] = useState(false);
  const containerRef = useRef(null);
  const shouldAutoScroll = useRef(true);
  const maxLogs = 1000;

  // Fetch initial logs
  useEffect(() => {
    api.get('/logs/', { params: { limit: 200 } })
      .then((res) => {
        const list = res.data?.logs || res.data || [];
        setLogs(Array.isArray(list) ? list : []);
      })
      .catch(() => {/* No logs available yet */});
  }, []);

  // Subscribe to real-time log events
  useEffect(() => {
    const handler = (data) => {
      if (isPaused) return;
      const entry = data.payload || data;
      setLogs((prev) => {
        const next = [...prev, entry];
        if (next.length > maxLogs) return next.slice(-maxLogs);
        return next;
      });
    };
    on('log.entry', handler);
    return () => off('log.entry');
  }, [isPaused]);

  // Auto-scroll to bottom
  useEffect(() => {
    if (shouldAutoScroll.current && containerRef.current && !isPaused) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [logs, isPaused]);

  const handleScroll = useCallback(() => {
    if (!containerRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = containerRef.current;
    shouldAutoScroll.current = scrollHeight - scrollTop - clientHeight < 50;
  }, []);

  const levelPriority = { debug: 0, info: 1, warning: 2, warn: 2, error: 3, critical: 4 };

  const filtered = React.useMemo(() => {
    let list = logs;
    if (serviceFilter !== 'all') {
      list = list.filter((l) => (l.service || '').toLowerCase() === serviceFilter);
    }
    if (levelFilter !== 'all') {
      const minLevel = levelPriority[levelFilter] ?? 0;
      list = list.filter((l) => (levelPriority[(l.level || 'info').toLowerCase()] ?? 0) >= minLevel);
    }
    if (search.trim()) {
      const q = search.toLowerCase();
      list = list.filter(
        (l) =>
          (l.message || l.msg || '').toLowerCase().includes(q) ||
          (l.service || '').toLowerCase().includes(q)
      );
    }
    return list;
  }, [logs, serviceFilter, levelFilter, search]);

  return (
    <div className="flex flex-col gap-3 h-[calc(100vh-14rem)]">
      {/* Controls bar */}
      <div className="flex flex-col sm:flex-row sm:items-center gap-2 shrink-0">
        {/* Service filter */}
        <div className="relative">
          <select
            value={serviceFilter}
            onChange={(e) => setServiceFilter(e.target.value)}
            className="appearance-none bg-rex-surface border border-rex-card rounded-lg px-3 py-2 pr-8 text-xs text-rex-text focus:outline-none focus:border-rex-accent transition-colors cursor-pointer"
          >
            {SERVICE_LABELS.map((s) => (
              <option key={s.value} value={s.value}>{s.label}</option>
            ))}
          </select>
          <svg className="absolute right-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-rex-muted pointer-events-none" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </div>

        {/* Level filter */}
        <div className="relative">
          <select
            value={levelFilter}
            onChange={(e) => setLevelFilter(e.target.value)}
            className="appearance-none bg-rex-surface border border-rex-card rounded-lg px-3 py-2 pr-8 text-xs text-rex-text focus:outline-none focus:border-rex-accent transition-colors cursor-pointer"
          >
            {LEVEL_OPTIONS.map((l) => (
              <option key={l.value} value={l.value}>{l.label}</option>
            ))}
          </select>
          <svg className="absolute right-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-rex-muted pointer-events-none" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </div>

        {/* Search */}
        <div className="relative flex-1">
          <svg className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-rex-muted" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search logs..."
            className="w-full pl-8 pr-3 py-2 bg-rex-surface border border-rex-card rounded-lg text-xs text-rex-text placeholder-rex-muted focus:outline-none focus:border-rex-accent transition-colors"
          />
        </div>

        {/* Pause / resume */}
        <button
          onClick={() => setIsPaused((p) => !p)}
          className={`shrink-0 flex items-center gap-1.5 px-3 py-2 rounded-lg border text-xs transition-colors ${
            isPaused
              ? 'border-rex-warn text-rex-warn bg-rex-warn/10'
              : 'border-rex-card text-rex-muted hover:text-rex-text hover:border-rex-accent'
          }`}
        >
          {isPaused ? (
            <>
              <svg className="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 24 24">
                <path d="M8 5v14l11-7z" />
              </svg>
              Resume
            </>
          ) : (
            <>
              <svg className="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 24 24">
                <path d="M6 4h4v16H6zM14 4h4v16h-4z" />
              </svg>
              Pause
            </>
          )}
        </button>

        {/* Count */}
        <span className="text-xs text-rex-muted shrink-0">
          {filtered.length} entries
        </span>
      </div>

      {/* Log output */}
      <div
        ref={containerRef}
        onScroll={handleScroll}
        className="flex-1 bg-rex-bg border border-rex-card rounded-lg overflow-y-auto overflow-x-hidden scrollbar-thin"
      >
        {filtered.length === 0 ? (
          <div className="flex items-center justify-center h-full text-rex-muted text-sm">
            {logs.length === 0 ? 'Waiting for log entries...' : 'No logs match current filters.'}
          </div>
        ) : (
          <div className="py-1">
            {filtered.map((entry, i) => (
              <LogLine key={entry.id || i} entry={entry} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
