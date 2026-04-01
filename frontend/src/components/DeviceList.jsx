import React, { useState, useMemo, useCallback } from 'react';
import useDeviceStore from '../stores/useDeviceStore';
import api from '../api/client';

const STATUS_COLORS = {
  online: 'bg-rex-safe',
  offline: 'bg-gray-500',
  quarantined: 'bg-rex-threat',
  trusted: 'bg-rex-accent',
};

const STATUS_TEXT_COLORS = {
  online: 'text-rex-safe',
  offline: 'text-gray-400',
  quarantined: 'text-rex-threat',
  trusted: 'text-rex-accent',
};

const SORT_FIELDS = [
  { key: 'hostname', label: 'Name' },
  { key: 'ip_address', label: 'IP' },
  { key: 'mac_address', label: 'MAC' },
  { key: 'device_type', label: 'Type' },
  { key: 'status', label: 'Status' },
  { key: 'trust_level', label: 'Trust' },
  { key: 'last_seen', label: 'Last Seen' },
];

function SortIcon({ field, sortField, sortDir }) {
  if (field !== sortField) {
    return (
      <svg className="w-3 h-3 text-rex-muted opacity-40" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16V4m0 0L3 8m4-4l4 4m6 0v12m0 0l4-4m-4 4l-4-4" />
      </svg>
    );
  }
  return (
    <svg className="w-3 h-3 text-rex-accent" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      {sortDir === 'asc' ? (
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 15l7-7 7 7" />
      ) : (
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
      )}
    </svg>
  );
}

function StatusBadge({ status }) {
  const dot = STATUS_COLORS[status] || 'bg-gray-500';
  const text = STATUS_TEXT_COLORS[status] || 'text-gray-400';
  return (
    <span className="flex items-center gap-1.5">
      <span className={`w-2 h-2 rounded-full ${dot}`} />
      <span className={`text-xs capitalize ${text}`}>{status || 'unknown'}</span>
    </span>
  );
}

function TrustBadge({ level }) {
  const colors = {
    trusted: 'bg-rex-accent/20 text-rex-accent border-rex-accent/30',
    known: 'bg-rex-safe/20 text-rex-safe border-rex-safe/30',
    unknown: 'bg-rex-warn/20 text-rex-warn border-rex-warn/30',
    blocked: 'bg-rex-threat/20 text-rex-threat border-rex-threat/30',
  };
  const cls = colors[level] || colors.unknown;
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full border ${cls}`}>
      {level || 'unknown'}
    </span>
  );
}

function DeviceDetail({ device }) {
  const ports = device.open_ports || device.ports || [];
  const services = device.services || [];

  return (
    <tr>
      <td colSpan={7} className="px-4 py-4 bg-rex-surface/50">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-sm">
          <div>
            <h4 className="text-rex-muted text-xs uppercase tracking-wide mb-1">Vendor / OS</h4>
            <p className="text-rex-text">{device.vendor || 'Unknown vendor'}</p>
            <p className="text-rex-muted">{device.os || device.operating_system || 'OS undetected'}</p>
          </div>
          <div>
            <h4 className="text-rex-muted text-xs uppercase tracking-wide mb-1">Open Ports</h4>
            {ports.length > 0 ? (
              <div className="flex flex-wrap gap-1">
                {ports.map((p, i) => (
                  <span key={i} className="text-xs bg-rex-card px-2 py-0.5 rounded text-rex-text">
                    {typeof p === 'object' ? `${p.port}/${p.protocol || 'tcp'}` : p}
                  </span>
                ))}
              </div>
            ) : (
              <p className="text-rex-muted">None detected</p>
            )}
          </div>
          <div>
            <h4 className="text-rex-muted text-xs uppercase tracking-wide mb-1">Services</h4>
            {services.length > 0 ? (
              <div className="flex flex-wrap gap-1">
                {services.map((s, i) => (
                  <span key={i} className="text-xs bg-rex-card px-2 py-0.5 rounded text-rex-text">
                    {typeof s === 'object' ? s.name : s}
                  </span>
                ))}
              </div>
            ) : (
              <p className="text-rex-muted">None detected</p>
            )}
          </div>
          <div>
            <h4 className="text-rex-muted text-xs uppercase tracking-wide mb-1">Traffic</h4>
            <p className="text-rex-text">
              {device.bytes_sent != null
                ? `Sent: ${(device.bytes_sent / 1024).toFixed(1)} KB`
                : 'No traffic data'}
            </p>
            <p className="text-rex-text">
              {device.bytes_recv != null
                ? `Recv: ${(device.bytes_recv / 1024).toFixed(1)} KB`
                : ''}
            </p>
          </div>
        </div>
      </td>
    </tr>
  );
}

function timeAgo(timestamp) {
  if (!timestamp) return 'Never';
  const diff = Date.now() - new Date(timestamp).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'Just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

export default function DeviceList() {
  const { devices, updateDevice } = useDeviceStore();
  const [search, setSearch] = useState('');
  const [sortField, setSortField] = useState('hostname');
  const [sortDir, setSortDir] = useState('asc');
  const [expandedMac, setExpandedMac] = useState(null);
  const [actionLoading, setActionLoading] = useState(null);

  const handleSort = useCallback((field) => {
    if (sortField === field) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortDir('asc');
    }
  }, [sortField]);

  const filtered = useMemo(() => {
    const q = search.toLowerCase().trim();
    let list = devices;
    if (q) {
      list = devices.filter(
        (d) =>
          (d.hostname || '').toLowerCase().includes(q) ||
          (d.ip_address || '').toLowerCase().includes(q) ||
          (d.mac_address || '').toLowerCase().includes(q) ||
          (d.device_type || '').toLowerCase().includes(q) ||
          (d.status || '').toLowerCase().includes(q) ||
          (d.vendor || '').toLowerCase().includes(q)
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

  const handleAction = useCallback(async (mac, action) => {
    setActionLoading(`${mac}-${action}`);
    try {
      await api.post(`/devices/${encodeURIComponent(mac)}/${action}`);
      const newStatus = action === 'trust' ? 'trusted' : 'quarantined';
      const newTrust = action === 'trust' ? 'trusted' : 'blocked';
      updateDevice(mac, { status: newStatus, trust_level: newTrust });
    } catch (err) {
      console.error(`Failed to ${action} device:`, err);
    } finally {
      setActionLoading(null);
    }
  }, [updateDevice]);

  return (
    <div className="flex flex-col gap-4">
      {/* Search bar */}
      <div className="relative">
        <svg
          className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-rex-muted"
          fill="none" viewBox="0 0 24 24" stroke="currentColor"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
            d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
        </svg>
        <input
          type="text"
          placeholder="Search devices by name, IP, MAC, type, vendor..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full pl-10 pr-4 py-2.5 bg-rex-surface border border-rex-card rounded-lg text-sm text-rex-text placeholder-rex-muted focus:outline-none focus:border-rex-accent transition-colors"
        />
        {search && (
          <button
            onClick={() => setSearch('')}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-rex-muted hover:text-rex-text"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        )}
      </div>

      {/* Results count */}
      <p className="text-xs text-rex-muted">
        Showing {filtered.length} of {devices.length} device{devices.length !== 1 ? 's' : ''}
      </p>

      {/* Table */}
      <div className="overflow-x-auto rounded-lg border border-rex-card">
        <table className="w-full text-sm text-left">
          <thead>
            <tr className="bg-rex-surface border-b border-rex-card">
              {SORT_FIELDS.map((col) => (
                <th
                  key={col.key}
                  className="px-4 py-3 text-xs font-medium text-rex-muted uppercase tracking-wide cursor-pointer hover:text-rex-text transition-colors select-none"
                  onClick={() => handleSort(col.key)}
                >
                  <span className="flex items-center gap-1">
                    {col.label}
                    <SortIcon field={col.key} sortField={sortField} sortDir={sortDir} />
                  </span>
                </th>
              ))}
              <th className="px-4 py-3 text-xs font-medium text-rex-muted uppercase tracking-wide">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-rex-card">
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={8} className="px-4 py-12 text-center text-rex-muted">
                  {search ? 'No devices match your search.' : 'No devices discovered yet.'}
                </td>
              </tr>
            ) : (
              filtered.map((device) => {
                const mac = device.mac_address;
                const isExpanded = expandedMac === mac;
                return (
                  <React.Fragment key={mac || device.ip_address}>
                    <tr
                      className={`cursor-pointer transition-colors ${
                        isExpanded ? 'bg-rex-surface/70' : 'hover:bg-rex-surface/40'
                      }`}
                      onClick={() => setExpandedMac(isExpanded ? null : mac)}
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
                      <td className="px-4 py-3 text-rex-muted capitalize">
                        {device.device_type || 'unknown'}
                      </td>
                      <td className="px-4 py-3">
                        <StatusBadge status={device.status} />
                      </td>
                      <td className="px-4 py-3">
                        <TrustBadge level={device.trust_level} />
                      </td>
                      <td className="px-4 py-3 text-rex-muted text-xs">
                        {timeAgo(device.last_seen)}
                      </td>
                      <td className="px-4 py-3" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => handleAction(mac, 'trust')}
                            disabled={actionLoading === `${mac}-trust` || device.trust_level === 'trusted'}
                            className="text-xs px-2.5 py-1 rounded bg-rex-accent/20 text-rex-accent hover:bg-rex-accent/30 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                          >
                            {actionLoading === `${mac}-trust` ? '...' : 'Trust'}
                          </button>
                          <button
                            onClick={() => handleAction(mac, 'block')}
                            disabled={actionLoading === `${mac}-block` || device.trust_level === 'blocked'}
                            className="text-xs px-2.5 py-1 rounded bg-rex-threat/20 text-rex-threat hover:bg-rex-threat/30 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                          >
                            {actionLoading === `${mac}-block` ? '...' : 'Block'}
                          </button>
                        </div>
                      </td>
                    </tr>
                    {isExpanded && <DeviceDetail device={device} />}
                  </React.Fragment>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
