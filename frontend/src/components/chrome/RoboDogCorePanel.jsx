import React from 'react';
import { radius, colors } from '../../theme/tokens';

/* ------------------------------------------------------------------ */
/*  Posture-driven configuration                                      */
/* ------------------------------------------------------------------ */

const POSTURE_CONFIG = {
  nominal: {
    label: 'ALL CLEAR',
    bark: '*woof* All clear!',
    glowColor: 'rgba(34,211,238,0.12)',
    borderColor: 'border-cyan-500/20',
    accentColor: 'text-cyan-400',
    eyeColor: '#22D3EE',
    breathe: true,
    alert: false,
  },
  elevated: {
    label: 'ELEVATED',
    bark: '*GRRRRR* Something suspicious...',
    glowColor: 'rgba(251,191,36,0.14)',
    borderColor: 'border-amber-400/30',
    accentColor: 'text-amber-300',
    eyeColor: '#FBBF24',
    breathe: false,
    alert: true,
  },
  critical: {
    label: 'CRITICAL',
    bark: '*WOOF WOOF WOOF!* THREAT DETECTED!',
    glowColor: 'rgba(239,68,68,0.18)',
    borderColor: 'border-red-500/40',
    accentColor: 'text-red-400',
    eyeColor: '#EF4444',
    breathe: false,
    alert: true,
  },
  unknown: {
    label: 'UNKNOWN',
    bark: '*ruff?* Sniffing around...',
    glowColor: 'rgba(100,116,139,0.10)',
    borderColor: 'border-slate-700',
    accentColor: 'text-slate-400',
    eyeColor: '#64748B',
    breathe: false,
    alert: false,
  },
};

const POWER_LABELS = {
  awake: 'AWAKE',
  alert_sleep: 'LIGHT SLEEP',
  deep_sleep: 'DEEP SLEEP',
  off: 'OFFLINE',
  unknown: 'UNKNOWN',
};

const LLM_LABELS = {
  ready: 'LLM READY',
  loading: 'LLM LOADING',
  error: 'LLM ERROR',
  disabled: 'LLM OFF',
  unknown: 'LLM --',
};

/* ------------------------------------------------------------------ */
/*  Great Dane ASCII Art (posture-dependent, different angles)        */
/* ------------------------------------------------------------------ */

function DogArt({ posture, eyeColor }) {
  /* Each posture shows REX from a different angle */
  const art = {
    /* Front-facing alert: ears up, growling */
    critical: `    /^\\_
   (!O @\\___
   /         O
  /   (\\____/
 /_____/ | U
          |~~`,

    /* 3/4 view: ears perked, watching */
    elevated: `    /^\\_
   ( O @\\___
   /         O
  /   (_____/
 /_____/   U~`,

    /* Side profile: relaxed, happy */
    nominal: `    /^\\_
   (   @\\___
   /         O
  /   (_____/
 /_____/   U`,

    /* Lying down: sleepy */
    unknown: `      _/^\\
 ___/@  ? )
O         \\
 \\_____) _ \\
    U  \\____\\`,
  };

  return (
    <pre
      className="font-mono text-xs sm:text-sm md:text-base leading-snug select-none whitespace-pre"
      style={{ color: eyeColor }}
      aria-hidden="true"
    >
      {art[posture] || art.nominal}
    </pre>
  );
}

/* ------------------------------------------------------------------ */
/*  Main Component                                                    */
/* ------------------------------------------------------------------ */

/**
 * RoboDogCorePanel
 *
 * The signature REX Great Dane component -- a guard-dog whose visuals
 * and bark shift based on threat posture, power state, LLM status, and
 * connection health.  REX communicates in dog noises only.
 *
 * @param {{
 *   threatPosture: 'nominal'|'elevated'|'critical'|'unknown',
 *   powerState: string,
 *   llmStatus: string,
 *   connected: boolean,
 * }} props
 */
export default function RoboDogCorePanel({
  threatPosture = 'unknown',
  powerState = 'unknown',
  llmStatus = 'unknown',
  connected = false,
}) {
  const cfg = POSTURE_CONFIG[threatPosture] || POSTURE_CONFIG.unknown;
  const powerLabel = POWER_LABELS[powerState] || POWER_LABELS.unknown;
  const llmLabel = LLM_LABELS[llmStatus] || LLM_LABELS.unknown;

  return (
    <div
      className={`
        relative overflow-hidden
        ${radius.panel} border ${cfg.borderColor}
        bg-gradient-to-b from-[#0B1020] to-[#050816]
        p-6 flex flex-col items-center gap-4
        transition-all duration-500
      `}
      style={{
        boxShadow: `0 0 40px ${cfg.glowColor}, inset 0 1px 0 rgba(255,255,255,0.04)`,
      }}
      role="status"
      aria-label={`REX threat posture: ${cfg.label}`}
    >
      {/* Top-edge signal line */}
      <div
        className="absolute inset-x-0 top-0 h-px"
        style={{
          background: `linear-gradient(90deg, transparent, ${cfg.glowColor}, transparent)`,
        }}
      />

      {/* Posture badge */}
      <div className="flex items-center gap-2">
        <span
          className={`
            inline-block w-2 h-2 rounded-full
            ${cfg.alert ? 'animate-ping' : ''}
          `}
          style={{ backgroundColor: cfg.eyeColor }}
        />
        <span className={`text-xs font-bold tracking-widest uppercase ${cfg.accentColor}`}>
          {cfg.label}
        </span>
      </div>

      {/* Great Dane visualisation */}
      <div className={cfg.breathe ? 'animate-breathe' : cfg.alert ? 'animate-pulse' : ''}>
        <DogArt posture={threatPosture} eyeColor={cfg.eyeColor} />
      </div>

      {/* REX bark - dog speaks in dog noises */}
      <p className={`text-xs italic ${cfg.accentColor} text-center`}>
        {cfg.bark}
      </p>

      {/* Status strip */}
      <div className="flex flex-wrap items-center justify-center gap-x-4 gap-y-1 text-[11px] font-medium tracking-wide uppercase">
        <span className={powerState === 'awake' ? 'text-emerald-400' : 'text-slate-500'}>
          {powerLabel}
        </span>
        <span className="text-slate-700">|</span>
        <span className={llmStatus === 'ready' ? 'text-cyan-400' : llmStatus === 'error' ? 'text-red-400' : 'text-slate-500'}>
          {llmLabel}
        </span>
        <span className="text-slate-700">|</span>
        <span className={connected ? 'text-emerald-400' : 'text-red-400'}>
          {connected ? 'LINK UP' : 'LINK DOWN'}
        </span>
      </div>
    </div>
  );
}
