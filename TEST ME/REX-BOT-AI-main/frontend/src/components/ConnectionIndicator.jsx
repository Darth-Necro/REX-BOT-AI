import React from 'react';
import useSystemStore from '../stores/useSystemStore';

export default function ConnectionIndicator() {
  const { connected } = useSystemStore();

  return (
    <div className="flex items-center gap-1.5" role="status" aria-live="polite">
      <span
        className={`w-2 h-2 rounded-full ${
          connected ? 'bg-rex-safe animate-pulse' : 'bg-rex-threat animate-ping'
        }`}
      />
      <span className={`text-xs ${connected ? 'text-rex-safe' : 'text-rex-threat'}`}>
        {connected ? 'Connected' : 'Reconnecting...'}
      </span>
    </div>
  );
}
