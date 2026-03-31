import React from 'react';
import useSystemStore from '../stores/useSystemStore';

const stateColors = {
  awake: 'text-rex-safe',
  alert_sleep: 'text-rex-warn',
  deep_sleep: 'text-rex-muted',
  off: 'text-rex-muted',
};

const stateMessages = {
  awake: 'REX is awake and protecting your network',
  alert_sleep: 'REX is sleeping with one ear open',
  deep_sleep: 'REX is in deep sleep',
  off: 'REX is off',
};

const stateAnimations = {
  awake: 'animate-breathe',
  alert_sleep: 'animate-pulse-slow',
  deep_sleep: '',
  off: 'opacity-50',
};

export default function RexGuardDog() {
  const { powerState, activeThreats } = useSystemStore();
  const hasThreat = activeThreats > 0;
  const color = hasThreat ? 'text-rex-threat' : stateColors[powerState] || 'text-rex-safe';
  const animation = hasThreat ? 'animate-pulse' : stateAnimations[powerState] || '';
  const message = hasThreat
    ? `ALERT: ${activeThreats} active threat${activeThreats > 1 ? 's' : ''} detected`
    : stateMessages[powerState] || 'REX is ready';

  return (
    <div className={`flex flex-col items-center ${animation}`} role="status" aria-live="polite">
      <pre className={`text-4xl sm:text-5xl md:text-6xl font-mono leading-tight select-none ${color}`}>
{`  /\\_/\\
 ( o.o )
  > ^ <
 /|   |\\
(_|   |_)`}
      </pre>
      <p className={`mt-4 text-lg font-medium ${color}`} aria-label={message}>
        {message}
      </p>
    </div>
  );
}
