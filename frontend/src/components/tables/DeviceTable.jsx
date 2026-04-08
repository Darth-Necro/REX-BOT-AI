/**
 * DeviceTable -- sortable data table for network devices.
 *
 * Columns: Name, IP, MAC, Type, Vendor, Trust, Status, Last Seen.
 * States: loading skeleton, empty, error, populated.
 * Clicking a row calls onSelect(device).
 */

import React, { useState, useMemo, useCallback } from 'react';

/* ---------- constants ---------- */

const COLUMNS = [
  { key: 'hostname',    label: 'Name' },
  { key: 'ip_address',  label: 'IP' },
  { key: 'mac_address', label: 'MAC' },
  { key: 'device_type', label: 'Type' },
  { key: 'vendor',      label: 'Vendor' },
  { key: 'trust_level', label: 'Trust' },
  { key: 'status',      label: 'Status' },
  { key: 'last_seen',   label: 'Last Seen' },
];

const STATUS_DOT = {
  online:       'bg-rex-safe',
  offline:      'bg-gray-500',
  quarantined:  'bg-rex-threat',
  trusted:      'bg-red-400',
};

const TRUST_BADGE = {
  trusted:  'bg-red-500/15 text-red-400 border-red-500/30',
  known:    'bg-rex-safe/15 text-rex-safe border-rex-safe/30',
  unknown:  'bg-rex-warn/15 text-rex-warn border-rex-warn/30',
  blocked:  'bg-rex-threat/15 text-rex-threat border-rex-threat/30',
};

/* ---------- helpers ---------- */

function timeAgo(ts) {
  if (!ts) return 'Never';
  const diff = Date.now() - new Date(ts).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'Just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
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
 * @param {Object}   props
 * @param {Array}    props.devices   Device array from store.
 * @param {boolean}  props.loading   Show skeleton.
 * @param {string}   props.error     Error message to display.
 * @param {string}   props.search    Search filter string.
 * @param {Function} props.onSelect  Called with device when row clicked.
 * @param {string}   [props.selectedMac]  MAC of the currently selected device.
 */
export default function DeviceTable({
  devices = [],
  loading = false,
  error = null,
  search = '',
  onSelect,
  selectedMac,
}) {
  const [sortField, setSortField] = useState('hostname');
  const [sortDir, setSortDir] = useState('asc');

  const handleSort = useCallback(
    (field) => {
      if (sortField === field) {
        setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
      } else {
        setSortField(field);
        setSortDir('asc');
      }
    },
    [sortField],
  );

  /* filter + sort */
  const rows = useMemo(() => {
    const q = (search || '').toLowerCase().trim();
    let list = devices;
    if (q) {
      list = devices.filter(
        (d) =>
          (d.hostname || '').toLowerCase().includes(q) ||
          (d.ip_address || '').toLowerCase().includes(q) ||
          (d.mac_address || '').toLowerCase().includes(q) ||
          (d.device_type || '').toLowerCase().includes(q) ||
          (d.vendor || '').toLowerCase().includes(q) ||
          (d.status || '').toLowerCase().includes(q),
      );
    }
    return [...list].sort((a, b) => {
      let aVal = a[sortField] || '';
      let bVal = b[sortField] || '';
      if (typeof aVal === 'string') aVal = aVal.toLowerCase();
      if (typeof bVal === 'string') bVal = bVal.toLowerCase();
      if (aVal < bVal) return sortDir === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortDir === 'asc' ? 1 : -1;
      return 0;
    });
  }, [devices, search, sortField, sortDir]);

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
              <td colSpan={COLUMNS.length} className="px-4 py-12 text-center text-rex-muted">
                {search ? 'No devices match your search.' : 'No devices discovered yet.'}
              </td>
            </tr>
          )}

          {/* Data rows */}
          {!loading &&
            rows.map((device) => {
              const mac = device.mac_address;
              const isSelected = selectedMac === mac;
              const dotColor = STATUS_DOT[device.status] || 'bg-gray-500';
              const trustCls = TRUST_BADGE[device.trust_level] || TRUST_BADGE.unknown;

              return (
                <tr
                  key={mac || device.ip_address}
                  onClick={() => onSelect?.(device)}
                  className={`cursor-pointer transition-colors ${
                    isSelected
                      ? 'bg-red-500/5 border-l-2 border-l-red-500'
                      : 'hover:bg-rex-surface/40'
                  }`}
                >
                  <td className="px-4 py-3 text-rex-text font-medium">
                    {device.hostname || 'Unknown'}
                  </td>
                  <td className="px-4 py-3 text-rex-muted font-mono text-xs">
                    {device.ip_address || '-'}
                  </td>
                  <td className="px-4 py-3 text-rex-muted font-mono text-xs">
                    {mac || '-'}
                  </td>
                  <td className="px-4 py-3 text-rex-muted capitalize text-xs">
                    {device.device_type || 'unknown'}
                  </td>
                  <td className="px-4 py-3 text-rex-muted text-xs">
                    {device.vendor || '-'}
                  </td>
                  <td className="px-4 py-3">
                    <span className={`text-xs px-2 py-0.5 rounded-full border ${trustCls}`}>
                      {device.trust_level || 'unknown'}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="flex items-center gap-1.5">
                      <span className={`w-2 h-2 rounded-full ${dotColor}`} />
                      <span className="text-xs capitalize text-rex-muted">{device.status || 'unknown'}</span>
                    </span>
                  </td>
                  <td className="px-4 py-3 text-rex-muted text-xs">
                    {timeAgo(device.last_seen)}
                  </td>
                </tr>
              );
            })}
        </tbody>
      </table>
    </div>
  );
}
