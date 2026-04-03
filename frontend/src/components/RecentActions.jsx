import React, { useState, useCallback } from 'react';

const MAX_ACTIONS = 20;

export function useActionHistory() {
  const [actions, setActions] = useState([]);

  const addAction = useCallback((action) => {
    setActions((prev) => [
      { ...action, timestamp: new Date().toISOString(), id: Date.now() },
      ...prev,
    ].slice(0, MAX_ACTIONS));
  }, []);

  return { actions, addAction };
}

export default function RecentActions({ actions = [] }) {
  if (actions.length === 0) {
    return (
      <div className="bg-gray-800 rounded-lg p-4">
        <h3 className="text-sm font-semibold text-gray-300 mb-2 uppercase tracking-wide">Recent Actions</h3>
        <p className="text-gray-500 text-xs">No actions yet. Use the Quick Actions panel above.</p>
      </div>
    );
  }

  return (
    <div className="bg-gray-800 rounded-lg p-4">
      <h3 className="text-sm font-semibold text-gray-300 mb-2 uppercase tracking-wide">Recent Actions</h3>
      <div className="space-y-1 max-h-48 overflow-y-auto">
        {actions.map((a) => (
          <div key={a.id} className="flex items-center justify-between text-xs py-1 border-b border-gray-700/50">
            <div className="flex items-center gap-2">
              <span className={`w-1.5 h-1.5 rounded-full ${a.status === 'success' ? 'bg-green-500' : a.status === 'error' ? 'bg-red-500' : 'bg-yellow-500'}`} />
              <span className="text-gray-300">{a.label}</span>
            </div>
            <span className="text-gray-500">{new Date(a.timestamp).toLocaleTimeString()}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
