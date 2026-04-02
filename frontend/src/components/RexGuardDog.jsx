import React, { useState, useEffect } from 'react';
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

/* ------------------------------------------------------------------ */
/* Great Dane ASCII art - side profile (original design)              */
/* ------------------------------------------------------------------ */
const sideArt = {
  awake: `    / \\__
   (    @\\___
   /         O
  /   (_____/
 /_____/   U`,

  alert_sleep: `      __/ \\
 ___/@  - )
O         \\
 \\_____) _ \\
    U  \\____\\`,

  deep_sleep: `      __/ \\
 ___/@  - )  zzz
O    ___  \\
 \\__/   \\__\\
    U    U`,

  off: `      __/ \\
 ___/@  x )
O    ___  \\
 \\__/   \\__\\
    U    U`,

  unknown: `    / \\__
   (  ? @\\___
   /         O
  /_____/   U`,
};

/* ------------------------------------------------------------------ */
/* Great Dane ASCII art - front facing (Tamagotchi frames)            */
/* ------------------------------------------------------------------ */
const frontFrames = {
  idle: [
    /* Frame 1: looking straight */
    `  /^-----^\\
 V  o o  V
  |  Y  |
   \\ Q /
   / - \\
   |    \\
   |     \\_
   || (___\\`,

    /* Frame 2: head tilt right */
    `   /^-----^\\
  V  o o  V
   |  Y  |
    \\ Q /
    / - \\
    |    \\
    |     \\_
    || (___\\`,

    /* Frame 3: tongue out */
    `  /^-----^\\
 V  o o  V
  |  Y  |
   \\ Q /
   / p \\
   |    \\
   |     \\_
   || (___\\`,

    /* Frame 4: wink */
    `  /^-----^\\
 V  - o  V
  |  Y  |
   \\ Q /
   / - \\
   |    \\
   |     \\_
   || (___\\`,
  ],

  alert: [
    /* Frame 1: ears up, growling */
    `  /^-----^\\
 V  O O  V
  |  Y  |
   \\ W /  GRRR!
   / - \\
   |    \\
   |     \\_
   || (___\\`,

    /* Frame 2: barking */
    `  /^-----^\\
 V !O O! V
  |  Y  |
   \\ W /  WOOF!
   / = \\~
   |    \\
   |     \\_
   || (___\\`,
  ],

  sleep: [
    /* Frame 1: eyes closed */
    `  /^-----^\\
 V  - -  V
  |  Y  |  zzz
   \\ q /
   / - \\
   |    \\
   |     \\_
   || (___\\
  U     U`,

    /* Frame 2: snoring */
    `  /^-----^\\
 V  - -  V
  |  Y  | zzZZ
   \\ q /
   / - \\
   |    \\
   |     \\_
   || (___\\`,
  ],
};

/* Threat-active Great Dane: alert posture, hackles up */
const threatArt = `    / \\__
   (!O @\\___     *GRRRRR!*
   /         O
  /   (\\____/
 /_____/ | U
          |~~`;

/* Junkyard Dog mode art */
const junkyardArt = `    / \\__
   (!O @\\___     *WOOF WOOF GRRRRR!*
   /    _____O   JUNKYARD DOG MODE!
  / ___/ ||||
 /___/  |||||U
   CHAIN~~~~`;

export default function RexGuardDog() {
  const { powerState, activeThreats } = useSystemStore();
  const hasThreat = activeThreats > 0;
  const color = hasThreat ? 'text-rex-threat' : stateColors[powerState] || 'text-rex-safe';
  const animation = hasThreat ? 'animate-pulse' : stateAnimations[powerState] || '';
  const message = hasThreat
    ? `*GRRRRR WOOF WOOF!* ${activeThreats} active threat${activeThreats > 1 ? 's' : ''} detected!`
    : stateMessages[powerState] || '*ruff* REX is ready';

  /* Tamagotchi animation: cycle through front-facing frames */
  const [frameIndex, setFrameIndex] = useState(0);
  const [showFront, setShowFront] = useState(false);

  useEffect(() => {
    /* Toggle between side and front view every 8 seconds */
    const viewToggle = setInterval(() => {
      setShowFront((prev) => !prev);
    }, 8000);
    return () => clearInterval(viewToggle);
  }, []);

  useEffect(() => {
    /* Animate front-facing frames like a Tamagotchi */
    const frameSet = hasThreat
      ? frontFrames.alert
      : (powerState === 'deep_sleep' || powerState === 'alert_sleep')
        ? frontFrames.sleep
        : frontFrames.idle;

    const interval = setInterval(() => {
      setFrameIndex((prev) => (prev + 1) % frameSet.length);
    }, hasThreat ? 600 : 2500);
    return () => clearInterval(interval);
  }, [hasThreat, powerState]);

  /* Pick the right art */
  let art;
  if (showFront) {
    const frameSet = hasThreat
      ? frontFrames.alert
      : (powerState === 'deep_sleep' || powerState === 'alert_sleep')
        ? frontFrames.sleep
        : frontFrames.idle;
    art = frameSet[frameIndex % frameSet.length];
  } else {
    art = hasThreat ? threatArt : (sideArt[powerState] || sideArt.awake);
  }

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
