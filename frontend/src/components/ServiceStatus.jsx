import React, { useState, useEffect } from 'react';
import api from '../api/client';

function StatusDot({ status }) {
  const colors = {
    running: 'bg-green-500',
    healthy: 'bg-green-500',
    stopped: 'bg-red-500',
    failed: 'bg-red-500',
    stop_failed: 'bg-red-500',
    degraded: 'bg-yellow-500',
    disabled: 'bg-gray-500',
    unknown: 'bg-gray-400',
  };
  return <span className={`inline-block w-2.5 h-2.5 rounded-full ${colors[status] || colors.unknown}`} />;
}

export default function ServiceStatus() {
  const [data, setData] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => {
    const fetch = async () => {
      try {
        const res = await api.get('/status');
        setData(res.data);
        setError('');
      } catch (e) {
        setError('Cannot reach dashboard');
      }
    };
    fetch();
    const interval = setInterval(fetch, 15000);
    return () => clearInterval(interval);
  }, []);

  if (error) {
    return (
      <div className="bg-gray-800 rounded-lg p-4">
        <p className="text-red-400 text-sm">{error}</p>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="bg-gray-800 rounded-lg p-4">
        <p className="text-gray-400 text-sm">Loading status...</p>
      </div>
    );
  }

  const services = data.services || {};

  return (
    <div className="bg-gray-800 rounded-lg p-4">
      <h3 className="text-sm font-semibold text-gray-300 mb-3 uppercase tracking-wide">Services</h3>
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-2">
        {Object.entries(services).map(([name, info]) => (
          <div key={name} className="flex items-center gap-2 px-2 py-1.5 bg-gray-700/50 rounded text-xs">
            <StatusDot status={info.status || 'unknown'} />
            <span className="text-gray-300 truncate">{name}</span>
          </div>
        ))}
      </div>
      {data.power_state && (
        <div className="mt-3 flex gap-4 text-xs text-gray-400">
          <span>Power: <strong className="text-gray-200">{data.power_state}</strong></span>
          {data.device_count != null && <span>Devices: <strong className="text-gray-200">{data.device_count}</strong></span>}
          {data.active_threats != null && <span>Threats: <strong className="text-gray-200">{data.active_threats}</strong></span>}
        </div>
      )}
    </div>
  );
}
