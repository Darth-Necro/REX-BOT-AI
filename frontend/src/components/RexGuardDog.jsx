import React, { useState, useEffect } from 'react';
import useSystemStore from '../stores/useSystemStore';

const stateColors = {
  awake: 'text-rex-safe',
  patrol: 'text-red-400',
  alert_sleep: 'text-rex-warn',
  deep_sleep: 'text-rex-muted',
  off: 'text-rex-muted',
  unknown: 'text-rex-warn',
};

const stateMessages = {
  awake: '*WOOF WOOF!* REX is awake and protecting your network',
  patrol: '*ruff ruff* REX is on patrol! *sniff sniff* Inspecting the network...',
  alert_sleep: '*woof* ... zzz ... REX is sleeping with one ear open',
  deep_sleep: '*zzz* ... REX is in deep sleep',
  off: '*whimper* REX is off',
  unknown: '*ruff?* Connecting to REX backend...',
};

const stateAnimations = {
  awake: 'animate-breathe',
  patrol: 'animate-pulse',
  alert_sleep: 'animate-pulse-slow',
  deep_sleep: '',
  off: 'opacity-50',
  unknown: 'animate-pulse',
};

/* ------------------------------------------------------------------ */
/* Great Dane ASCII art - side profiles (left and right facing)       */
/* ------------------------------------------------------------------ */

/* The original Great Dane -- used everywhere */
const rexDog = {
  normal: `    ^
   / \\__
  (    @\\___
  /         O
 /   (_____/
/_____/   U`,

  alert: `    ^
   / \\__
  (!O @\\___
  /         O
 /   (\\____/
/_____/ | U
         |~~`,

  sleep: `    ^
   / \\__
  (  - @\\___  zzz
  /         O
 /   (_____/
/_____/   U`,

  happy: `    ^
   / \\__
  (  O @\\___
  /         O
 /   (_____/
/_____/   U~`,
};

const sideArt = {
  awake: rexDog.normal,
  patrol: rexDog.happy,
  alert_sleep: rexDog.sleep,
  deep_sleep: rexDog.sleep,
  off: rexDog.sleep,
  unknown: rexDog.normal,
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

/* Threat-active Great Dane */
const threatArtFrames = [
  rexDog.alert,
  rexDog.happy,
];

/* Junkyard Dog mode art */
const junkyardArt = `    ^
   / \\__
  (!O @\\___    *GRRRRR!*
  /         O  JUNKYARD DOG!
 /   (_____/
/_____/   U
|||||||`;

export default function RexGuardDog() {
  const { powerState, activeThreats } = useSystemStore();
  const hasThreat = activeThreats > 0;
  const color = hasThreat ? 'text-rex-threat' : stateColors[powerState] || 'text-rex-safe';
  const animation = hasThreat ? 'animate-pulse' : stateAnimations[powerState] || '';
  const message = hasThreat
    ? `*GRRRRR WOOF WOOF!* ${activeThreats} active threat${activeThreats > 1 ? 's' : ''} detected!`
    : stateMessages[powerState] || '*ruff* REX is ready';

  /* Tamagotchi animation: cycle through poses like a living pet
     The dog switches between side-profile poses and front-facing frames
  */
  const [frameIndex, setFrameIndex] = useState(0);
  const [showFront, setShowFront] = useState(false);

  useEffect(() => {
    /* Toggle between side profile and front view every 8 seconds */
    const viewToggle = setInterval(() => {
      setShowFront((prev) => !prev);
    }, 8000);
    return () => clearInterval(viewToggle);
  }, []);

  useEffect(() => {
    /* Animate front-facing frames */
    const frameSet = hasThreat
      ? frontFrames.alert
      : (powerState === 'deep_sleep' || powerState === 'alert_sleep')
        ? frontFrames.sleep
        : frontFrames.idle;

    const interval = setInterval(() => {
      setFrameIndex((prev) => (prev + 1) % frameSet.length);
    }, hasThreat ? 500 : 2500);
    return () => clearInterval(interval);
  }, [hasThreat, powerState]);

  /* Pick the right art */
  let art;
  if (hasThreat) {
    if (showFront) {
      const frames = frontFrames.alert;
      art = frames[frameIndex % frames.length];
    } else {
      art = threatArtFrames[frameIndex % threatArtFrames.length];
    }
  } else if (showFront) {
    const isSleeping = powerState === 'deep_sleep' || powerState === 'alert_sleep';
    const frameSet = isSleeping ? frontFrames.sleep : frontFrames.idle;
    art = frameSet[frameIndex % frameSet.length];
  } else {
    art = sideArt[powerState] || sideArt.awake;
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
