import React, { useState, useEffect, useRef } from 'react';
import api from '../api/client';

const LEVEL_COLORS = {
  ERROR: 'text-red-400',
  WARNING: 'text-amber-400',
  INFO: 'text-gray-300',
  DEBUG: 'text-gray-500',
};

export default function LogViewer() {
  const [logs, setLogs] = useState([]);
  const [lines, setLines] = useState(100);
  const [level, setLevel] = useState('info');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const bottomRef = useRef(null);

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const res = await api.get(`/health/logs?lines=${lines}&level=${level}`);
      setLogs(res.data.logs || []);
      setError(res.data.message || '');
    } catch (e) {
      setError('Cannot fetch logs. Logs may only be available in the terminal.');
      setLogs([]);
    }
    setLoading(false);
  };

  useEffect(() => { fetchLogs(); }, [lines, level]);
  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [logs]);

  return (
    <div className="bg-gray-900 rounded-lg p-4">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wide">Logs</h3>
        <div className="flex gap-2">
          <select
            className="bg-gray-700 text-gray-300 text-xs rounded px-2 py-1"
            value={level}
            onChange={(e) => setLevel(e.target.value)}
          >
            <option value="debug">Debug</option>
            <option value="info">Info</option>
            <option value="warning">Warning</option>
            <option value="error">Error</option>
          </select>
          <select
            className="bg-gray-700 text-gray-300 text-xs rounded px-2 py-1"
            value={lines}
            onChange={(e) => setLines(Number(e.target.value))}
          >
            <option value={50}>50 lines</option>
            <option value={100}>100 lines</option>
            <option value={500}>500 lines</option>
          </select>
          <button
            className="bg-gray-700 hover:bg-gray-600 text-gray-300 text-xs rounded px-3 py-1"
            onClick={fetchLogs}
            disabled={loading}
          >
            {loading ? '...' : 'Refresh'}
          </button>
        </div>
      </div>
      {error && <p className="text-amber-400 text-xs mb-2">{error}</p>}
      <div className="bg-black rounded p-3 font-mono text-xs max-h-96 overflow-y-auto">
        {logs.length === 0 ? (
          <p className="text-gray-600">No logs available</p>
        ) : (
          logs.map((line, i) => {
            const lvl = Object.keys(LEVEL_COLORS).find(l => line.includes(`[${l}]`)) || 'INFO';
            return (
              <div key={i} className={`${LEVEL_COLORS[lvl]} whitespace-pre-wrap break-all`}>
                {line}
              </div>
            );
          })
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}
