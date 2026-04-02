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
/* Great Dane ASCII art - side profiles (left and right facing)       */
/* ------------------------------------------------------------------ */

/* Facing right (looking out at the network) */
const rightFacing = {
  normal: `     /^\\
    /   \\___
   /      @\\____
  /              O
 /    (_________/
/______/     U`,

  alert: `     /^\\
    /   \\___
   /    ! @\\____
  /              O
 /    (____|____/
/______/ |  U
         |~~`,

  sleep: `     /^\\
    /   \\___
   /    - @\\____  zzz
  /              O
 /    (_________/
/______/     U`,
};

/* Facing left (mirrored, watching the other direction) */
const leftFacing = {
  normal: `         /^\\
    ___/   \\
 ____/@      \\
O              \\
 \\___________)  \\
          U  \\______\\`,

  alert: `         /^\\
    ___/   \\
 ____/@ !   \\
O              \\
 \\____|____)    \\
     U  | \\______\\
        ~~|`,

  sleep: `            /^\\
       ___/   \\
 ____/@  -     \\  zzz
O              \\
 \\___________)  \\
          U  \\______\\`,
};

const sideArt = {
  awake: rightFacing.normal,
  alert_sleep: leftFacing.sleep,
  deep_sleep: rightFacing.sleep,
  off: leftFacing.normal,
  unknown: rightFacing.normal,
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

/* Threat-active Great Dane: alternates facing to "look around" */
const threatArtFrames = [
  rightFacing.alert,
  leftFacing.alert,
];

/* Junkyard Dog mode art */
const junkyardArt = `     /^\\
    /   \\___
   /    ! @\\____    *GRRRRR!*
  /    _________O   JUNKYARD DOG!
 / ___/ ||||||||
/___/  ||||||| U
   CHAIN~~~~~~~`;

export default function RexGuardDog() {
  const { powerState, activeThreats } = useSystemStore();
  const hasThreat = activeThreats > 0;
  const color = hasThreat ? 'text-rex-threat' : stateColors[powerState] || 'text-rex-safe';
  const animation = hasThreat ? 'animate-pulse' : stateAnimations[powerState] || '';
  const message = hasThreat
    ? `*GRRRRR WOOF WOOF!* ${activeThreats} active threat${activeThreats > 1 ? 's' : ''} detected!`
    : stateMessages[powerState] || '*ruff* REX is ready';

  /* Tamagotchi animation: cycle through 3 views
     View 0: side profile (right-facing or left-facing)
     View 1: front-facing
     View 2: side profile (opposite direction)
  */
  const [frameIndex, setFrameIndex] = useState(0);
  const [viewIndex, setViewIndex] = useState(0);

  useEffect(() => {
    /* Rotate through views: right side -> front -> left side -> front */
    const viewToggle = setInterval(() => {
      setViewIndex((prev) => (prev + 1) % 4);
    }, 6000);
    return () => clearInterval(viewToggle);
  }, []);

  useEffect(() => {
    /* Animate frames within each view */
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

  /* Pick the right art based on current view */
  let art;
  const isSleeping = powerState === 'deep_sleep' || powerState === 'alert_sleep';

  if (hasThreat) {
    /* Threat mode: alternate between right-alert, front-alert, left-alert */
    if (viewIndex % 2 === 0) {
      art = threatArtFrames[viewIndex === 0 ? 0 : 1];
    } else {
      const frames = frontFrames.alert;
      art = frames[frameIndex % frames.length];
    }
  } else if (viewIndex === 0) {
    /* Right-facing side profile */
    art = isSleeping ? rightFacing.sleep : rightFacing.normal;
  } else if (viewIndex === 2) {
    /* Left-facing side profile */
    art = isSleeping ? leftFacing.sleep : leftFacing.normal;
  } else {
    /* Front-facing (views 1 and 3) */
    const frameSet = isSleeping ? frontFrames.sleep : frontFrames.idle;
    art = frameSet[frameIndex % frameSet.length];
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
