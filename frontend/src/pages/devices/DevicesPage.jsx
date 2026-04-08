/**
 * DevicesPage -- full devices view with API hydration, search, table,
 * and detail panel selection.
 *
 * Hydrates from API on mount. WS deltas applied via store.
 * No fake data -- table stays empty until API responds.
 */

import React, { useEffect, useState, useCallback } from 'react';
import useDeviceStore from '../../stores/useDeviceStore';
import DeviceTable from '../../components/tables/DeviceTable';

/* ---------- detail panel ---------- */

function DeviceDetailPanel({ device, onClose }) {
  if (!device) return null;

  const ports = device.open_ports || device.ports || [];
  const services = device.services || [];

  return (
    <div className="w-80 shrink-0 bg-rex-surface border-l border-rex-card overflow-y-auto">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-rex-card">
        <h3 className="text-sm font-semibold text-rex-text truncate">
          {device.hostname || 'Unknown Device'}
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
        <Section label="Network">
          <Field label="IP" value={device.ip_address} mono />
          <Field label="MAC" value={device.mac_address} mono />
          <Field label="Vendor" value={device.vendor} />
        </Section>

        <Section label="Classification">
          <Field label="Type" value={device.device_type} capitalize />
          <Field label="OS" value={device.os || device.operating_system} />
          <Field label="Trust" value={device.trust_level} capitalize />
          <Field label="Status" value={device.status} capitalize />
        </Section>

        {ports.length > 0 && (
          <Section label="Open Ports">
            <div className="flex flex-wrap gap-1">
              {ports.map((p, i) => (
                <span key={i} className="text-xs bg-rex-card px-2 py-0.5 rounded font-mono text-rex-text">
                  {typeof p === 'object' ? `${p.port}/${p.protocol || 'tcp'}` : p}
                </span>
              ))}
            </div>
          </Section>
        )}

        {services.length > 0 && (
          <Section label="Services">
            <div className="flex flex-wrap gap-1">
              {services.map((s, i) => (
                <span key={i} className="text-xs bg-rex-card px-2 py-0.5 rounded text-rex-text">
                  {typeof s === 'object' ? s.name : s}
                </span>
              ))}
            </div>
          </Section>
        )}

        <Section label="Traffic">
          <Field
            label="Sent"
            value={device.bytes_sent != null ? `${(device.bytes_sent / 1024).toFixed(1)} KB` : null}
          />
          <Field
            label="Received"
            value={device.bytes_recv != null ? `${(device.bytes_recv / 1024).toFixed(1)} KB` : null}
          />
        </Section>

        {device.last_seen && (
          <Section label="Last Seen">
            <span className="text-rex-muted text-xs">{new Date(device.last_seen).toLocaleString()}</span>
          </Section>
        )}
      </div>
    </div>
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

export default function DevicesPage() {
  const devices = useDeviceStore((s) => s.devices);
  const loading = useDeviceStore((s) => s.loading);
  const error = useDeviceStore((s) => s.error);
  const fetchDevices = useDeviceStore((s) => s.fetchDevices);
  const selectedDevice = useDeviceStore((s) => s.selectedDevice);
  const selectDevice = useDeviceStore((s) => s.selectDevice);
  const clearSelection = useDeviceStore((s) => s.clearSelection);

  const [search, setSearch] = useState('');

  // Hydrate from API on mount
  useEffect(() => {
    fetchDevices();
  }, [fetchDevices]);

  const handleSelect = useCallback(
    (device) => {
      if (selectedDevice?.mac_address === device.mac_address) {
        clearSelection();
      } else {
        selectDevice(device);
      }
    },
    [selectedDevice, selectDevice, clearSelection],
  );

  const onlineCount = devices.filter(
    (d) => d.status === 'online' || d.status === 'trusted',
  ).length;

  return (
    <div className="flex h-full">
      {/* Main content */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {/* Toolbar */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <div className="flex items-center gap-3">
            <h2 className="text-lg font-semibold text-rex-text">Devices</h2>
            <span className="text-xs text-rex-muted">
              {onlineCount} online / {devices.length} total
            </span>
          </div>

          {/* Search */}
          <div className="relative w-full sm:w-72">
            <svg
              className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-rex-muted"
              fill="none" viewBox="0 0 24 24" stroke="currentColor"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <input
              type="text"
              placeholder="Search devices..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-rex-surface border border-rex-card rounded-lg text-sm text-rex-text placeholder-rex-muted/60 focus:outline-none focus:border-red-500 transition-colors"
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
        </div>

        {/* Table */}
        <DeviceTable
          devices={devices}
          loading={loading}
          error={error}
          search={search}
          onSelect={handleSelect}
          selectedMac={selectedDevice?.mac_address}
        />
      </div>

      {/* Detail panel */}
      {selectedDevice && (
        <DeviceDetailPanel device={selectedDevice} onClose={clearSelection} />
      )}
    </div>
  );
}
