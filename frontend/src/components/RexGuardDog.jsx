import React from 'react';
import useSystemStore from '../stores/useSystemStore';

const stateColors = {
  awake: 'text-rex-safe',
  alert_sleep: 'text-rex-warn',
  deep_sleep: 'text-rex-muted',
  off: 'text-rex-muted',
  unknown: 'text-rex-warn',
};

const stateMessages = {
  awake: '*WOOF WOOF!* REX is awake and protecting your network',
  alert_sleep: '*woof* ... zzz ... REX is sleeping with one ear open',
  deep_sleep: '*zzz* ... REX is in deep sleep',
  off: '*whimper* REX is off',
  unknown: '*ruff?* Connecting to REX backend...',
};

const stateAnimations = {
  awake: 'animate-breathe',
  alert_sleep: 'animate-pulse-slow',
  deep_sleep: '',
  off: 'opacity-50',
  unknown: 'animate-pulse',
};

/* Great Dane ASCII art from different angles based on state */
const stateArt = {
  /* Front-facing: standing tall, ears up */
  awake: `    /^\\_
   (   @\\___
   /         O
  /   (_____/
 /_____/   U`,

  /* Lying down side view: one ear up */
  alert_sleep: `       _/^\\
  ___/@  - )
 O         \\
  \\_____) _ \\
     U  \\____\\`,

  /* Curled up sleeping */
  deep_sleep: `      _/^\\
 ___/@  - )  zzz
O    ___  \\
 \\__/   \\__\\
    U    U`,

  /* Powered off: lying flat */
  off: `      _/^\\
 ___/@  x )
O    ___  \\
 \\__/   \\__\\
    U    U`,

  /* Looking around confused */
  unknown: `    /^\\_
   ( ? @\\___
   /         O
  /_____/   U`,
};

/* Threat-active Great Dane: alert posture, hackles up */
const threatArt = `    /^\\_
   (!O @\\___     GRRRRR!
   /         O
  /   (\\____/
 /_____/ | U
          |~~`;

export default function RexGuardDog() {
  const { powerState, activeThreats } = useSystemStore();
  const hasThreat = activeThreats > 0;
  const color = hasThreat ? 'text-rex-threat' : stateColors[powerState] || 'text-rex-safe';
  const animation = hasThreat ? 'animate-pulse' : stateAnimations[powerState] || '';
  const message = hasThreat
    ? `*GRRRRR WOOF WOOF!* ${activeThreats} active threat${activeThreats > 1 ? 's' : ''} detected!`
    : stateMessages[powerState] || '*ruff* REX is ready';

  const art = hasThreat ? threatArt : (stateArt[powerState] || stateArt.awake);

  return (
    <div className={`flex flex-col items-center ${animation}`} role="status" aria-live="polite">
      <pre className={`text-2xl sm:text-3xl md:text-4xl font-mono leading-tight select-none ${color}`}>
        {art}
      </pre>
      <p className={`mt-4 text-lg font-medium ${color}`} aria-label={message}>
        {message}
      </p>
    </div>
  );
}
