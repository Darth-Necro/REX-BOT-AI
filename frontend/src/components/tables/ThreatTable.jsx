/**
 * ThreatTable -- sortable data table for security threats.
 *
 * Columns: Severity, Device, Category, Status, Time.
 * States: loading skeleton, empty, populated.
 * Clicking a row calls onSelect(threat).
 */

import React, { useState, useMemo, useCallback } from 'react';

/* ---------- constants ---------- */

const COLUMNS = [
  { key: 'severity',      label: 'Severity' },
  { key: 'source_device', label: 'Device' },
  { key: 'category',      label: 'Category' },
  { key: 'status',        label: 'Status' },
  { key: 'timestamp',     label: 'Time' },
];

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const SEVERITY_BADGE = {
  critical: 'bg-rex-threat/15 text-rex-threat border-rex-threat/30',
  high:     'bg-orange-500/15 text-orange-400 border-orange-500/30',
  medium:   'bg-rex-warn/15 text-rex-warn border-rex-warn/30',
  low:      'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
  info:     'bg-gray-500/15 text-gray-400 border-gray-500/30',
};

const STATUS_BADGE = {
  active:        'text-rex-threat',
  investigating: 'text-rex-warn',
  resolved:      'text-rex-safe',
  false_positive:'text-rex-muted',
};

/* ---------- helpers ---------- */

function formatTime(ts) {
  if (!ts) return '-';
  const d = new Date(ts);
  const now = new Date();
  const diffMs = now - d;
  const diffMins = Math.floor(diffMs / 60000);

  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins}m ago`;

  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) return `${diffHours}h ago`;

  return d.toLocaleDateString([], { month: 'short', day: 'numeric' }) +
    ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

/* ---------- sub-components ---------- */

function SortArrow({ field, sortField, sortDir }) {
  if (field !== sortField) {
    return (
      <svg className="w-3 h-3 text-rex-muted/30" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16V4m0 0L3 8m4-4l4 4m6 0v12m0 0l4-4m-4 4l-4-4" />
      </svg>
    );
  }
  return (
    <svg className="w-3 h-3 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      {sortDir === 'asc' ? (
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 15l7-7 7 7" />
      ) : (
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
      )}
    </svg>
  );
}

function SkeletonRows({ count = 5 }) {
  return Array.from({ length: count }).map((_, i) => (
    <tr key={i} className="animate-pulse">
      {COLUMNS.map((col) => (
        <td key={col.key} className="px-4 py-3">
          <div className="h-3 bg-rex-card/60 rounded w-3/4" />
        </td>
      ))}
    </tr>
  ));
}

/* ---------- main component ---------- */

/**
 * @param {Object}    props
 * @param {Array}     props.threats       Threat array from store.
 * @param {boolean}   props.loading       Show skeleton.
 * @param {string}    [props.error]       Error message.
 * @param {string}    [props.severityFilter]  Filter by severity level or 'all'.
 * @param {Function}  props.onSelect      Called with threat when row clicked.
 * @param {string}    [props.selectedId]  ID of currently selected threat.
 */
export default function ThreatTable({
  threats = [],
  loading = false,
  error = null,
  severityFilter = 'all',
  onSelect,
  selectedId,
}) {
  const [sortField, setSortField] = useState('timestamp');
  const [sortDir, setSortDir] = useState('desc');

  const handleSort = useCallback(
    (field) => {
      if (sortField === field) {
        setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
      } else {
        setSortField(field);
        setSortDir(field === 'timestamp' ? 'desc' : 'asc');
      }
    },
    [sortField],
  );

  /* filter + sort */
  const rows = useMemo(() => {
    let list = threats;
    if (severityFilter && severityFilter !== 'all') {
      list = threats.filter((t) => t.severity === severityFilter);
    }

    return [...list].sort((a, b) => {
      if (sortField === 'severity') {
        const aOrd = SEVERITY_ORDER[a.severity] ?? 5;
        const bOrd = SEVERITY_ORDER[b.severity] ?? 5;
        return sortDir === 'asc' ? aOrd - bOrd : bOrd - aOrd;
      }
      let aVal = a[sortField] || '';
      let bVal = b[sortField] || '';
      if (typeof aVal === 'string') aVal = aVal.toLowerCase();
      if (typeof bVal === 'string') bVal = bVal.toLowerCase();
      if (aVal < bVal) return sortDir === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortDir === 'asc' ? 1 : -1;
      return 0;
    });
  }, [threats, severityFilter, sortField, sortDir]);

  return (
    <div className="overflow-x-auto rounded-lg border border-rex-card">
      <table className="w-full text-sm text-left">
        {/* Header */}
        <thead>
          <tr className="bg-rex-surface border-b border-rex-card">
            {COLUMNS.map((col) => (
              <th
                key={col.key}
                className="px-4 py-3 text-xs font-medium text-rex-muted uppercase tracking-wide cursor-pointer hover:text-rex-text transition-colors select-none"
                onClick={() => handleSort(col.key)}
              >
                <span className="flex items-center gap-1">
                  {col.label}
                  <SortArrow field={col.key} sortField={sortField} sortDir={sortDir} />
                </span>
              </th>
            ))}
          </tr>
        </thead>

        <tbody className="divide-y divide-rex-card">
          {/* Loading */}
          {loading && <SkeletonRows />}

          {/* Error */}
          {!loading && error && (
            <tr>
              <td colSpan={COLUMNS.length} className="px-4 py-12 text-center text-rex-threat">
                {error}
              </td>
            </tr>
          )}

          {/* Empty */}
          {!loading && !error && rows.length === 0 && (
            <tr>
              <td colSpan={COLUMNS.length} className="px-4 py-12 text-center">
                <div className="flex flex-col items-center gap-2 text-rex-muted">
                  <svg className="w-10 h-10 opacity-30" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  </svg>
                  <span className="text-sm">No threats detected.</span>
                </div>
              </td>
            </tr>
          )}

          {/* Data rows */}
          {!loading &&
            rows.map((threat, i) => {
              const id = threat.id || i;
              const isSelected = selectedId === id;
              const sevCls = SEVERITY_BADGE[threat.severity] || SEVERITY_BADGE.info;
              const isResolved = threat.resolved || threat.status === 'resolved';
              const statusLabel = isResolved ? 'resolved' : threat.status || 'active';
              const statusCls = STATUS_BADGE[statusLabel] || 'text-rex-muted';

              return (
                <tr
                  key={id}
                  onClick={() => onSelect?.(threat)}
                  className={`cursor-pointer transition-colors ${
                    isSelected
                      ? 'bg-red-500/5 border-l-2 border-l-red-500'
                      : isResolved
                        ? 'opacity-50 hover:opacity-70'
                        : 'hover:bg-rex-surface/40'
                  }`}
                >
                  <td className="px-4 py-3">
                    <span className={`text-xs px-2 py-0.5 rounded-full border font-medium uppercase ${sevCls}`}>
                      {threat.severity || 'info'}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-rex-text text-xs">
                    {threat.source_device || '-'}
                  </td>
                  <td className="px-4 py-3 text-rex-muted text-xs capitalize">
                    {threat.category || threat.description?.slice(0, 40) || '-'}
                  </td>
                  <td className="px-4 py-3">
                    <span className={`text-xs capitalize font-medium ${statusCls}`}>
                      {statusLabel}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-rex-muted text-xs whitespace-nowrap">
                    {formatTime(threat.timestamp)}
                  </td>
                </tr>
              );
            })}
        </tbody>
      </table>
    </div>
  );
}
