import React, { useState, useCallback, useEffect } from 'react';
import useDeviceStore from '../../stores/useDeviceStore';
import api from '../../api/client';
import DeviceList from '../../components/DeviceList';

export default function DevicePanel() {
  const { devices, setDevices, total } = useDeviceStore();
  const [scanning, setScanning] = useState(false);
  const [loaded, setLoaded] = useState(false);

  // Fetch devices on mount
  useEffect(() => {
    if (!loaded) {
      api.get('/devices/')
        .then((res) => {
          const list = res.data?.devices || res.data || [];
          setDevices(Array.isArray(list) ? list : []);
        })
        .catch((err) => console.error('Failed to fetch devices:', err))
        .finally(() => setLoaded(true));
    }
  }, [loaded, setDevices]);

  const handleScan = useCallback(async () => {
    setScanning(true);
    try {
      await api.post('/devices/scan');
      // Refetch after scan
      const res = await api.get('/devices/');
      const list = res.data?.devices || res.data || [];
      setDevices(Array.isArray(list) ? list : []);
    } catch (err) {
      console.error('Scan failed:', err);
    } finally {
      setScanning(false);
    }
  }, [setDevices]);

  const handleExportCSV = useCallback(() => {
    if (devices.length === 0) return;
    const headers = ['Hostname', 'IP Address', 'MAC Address', 'Type', 'Status', 'Trust Level', 'Vendor', 'Last Seen'];
    const rows = devices.map((d) => [
      d.hostname || '',
      d.ip_address || '',
      d.mac_address || '',
      d.device_type || '',
      d.status || '',
      d.trust_level || '',
      d.vendor || '',
      d.last_seen || '',
    ]);
    const csv = [headers, ...rows].map((r) => r.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `rex-devices-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }, [devices]);

  const onlineCount = devices.filter((d) => d.status === 'online' || d.status === 'trusted').length;
  const offlineCount = devices.filter((d) => d.status === 'offline').length;
  const quarantinedCount = devices.filter((d) => d.status === 'quarantined').length;

  return (
    <div className="space-y-4">
      {/* Header bar */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div className="flex items-center gap-4">
          <h2 className="text-lg font-semibold text-rex-text">Devices</h2>
          <div className="flex items-center gap-3 text-xs">
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-rex-safe" />
              <span className="text-rex-muted">{onlineCount} online</span>
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-gray-500" />
              <span className="text-rex-muted">{offlineCount} offline</span>
            </span>
            {quarantinedCount > 0 && (
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-rex-threat" />
                <span className="text-rex-muted">{quarantinedCount} quarantined</span>
              </span>
            )}
            <span className="text-rex-muted">|</span>
            <span className="text-rex-muted">{total || devices.length} total</span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleScan}
            disabled={scanning}
            className="flex items-center gap-2 px-3 py-2 bg-rex-accent text-white rounded-lg hover:bg-rex-accent/80 disabled:opacity-50 disabled:cursor-not-allowed transition-colors text-sm font-medium"
          >
            <svg className={`w-4 h-4 ${scanning ? 'animate-spin' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
            </svg>
            {scanning ? 'Scanning...' : 'Scan Network'}
          </button>
          <button
            onClick={handleExportCSV}
            disabled={devices.length === 0}
            className="flex items-center gap-2 px-3 py-2 bg-rex-surface border border-rex-card text-rex-text rounded-lg hover:border-rex-accent transition-colors text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" />
            </svg>
            Export CSV
          </button>
        </div>
      </div>

      {/* Device list */}
      <DeviceList />
    </div>
  );
}
