/**
 * TopCommandBar -- horizontal top bar across authenticated pages.
 *
 * Shows: page label, connection pill, mode/status summary,
 * active threat counter, logout button.
 *
 * Responsive: hides status summary on small screens.
 * Connection state: uses merged API + WS state for the pill.
 */

import React from 'react';
import useSystemStore from '../stores/useSystemStore';
import useConnectionStatus from '../hooks/useConnectionStatus';

/* ---------- sub-components ---------- */

function ConnectionStatusPill() {
  const { state, label } = useConnectionStatus();

  const config = PILL_CONFIG[state] || PILL_CONFIG.unknown;

  return (
    <span
      className={`inline-flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full border ${config.classes}`}
      role="status"
      aria-live="polite"
      aria-label={`Connection: ${label}`}
    >
      <span
        className={`w-1.5 h-1.5 rounded-full ${config.dot} ${config.pulse ? 'animate-pulse' : ''}`}
        aria-hidden="true"
      />
      <span className="hidden sm:inline">{label}</span>
    </span>
  );
}

const PILL_CONFIG = {
  unknown:      { classes: 'border-slate-600 bg-slate-800/60 text-slate-400',         dot: 'bg-slate-500',  pulse: false },
  connecting:   { classes: 'border-amber-500/30 bg-amber-500/10 text-amber-300',      dot: 'bg-amber-400',  pulse: true },
  connected:    { classes: 'border-cyan-500/30 bg-cyan-500/10 text-cyan-400',          dot: 'bg-cyan-400',   pulse: false },
  degraded:     { classes: 'border-amber-500/30 bg-amber-500/10 text-amber-200',      dot: 'bg-amber-400',  pulse: true },
  disconnected: { classes: 'border-rex-threat/30 bg-rex-threat/10 text-rex-threat',    dot: 'bg-rex-threat', pulse: true },
};

function AlertCounter() {
  const activeThreats = useSystemStore((s) => s.activeThreats);

  if (activeThreats === 0) return null;

  return (
    <span
      className="inline-flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full border border-rex-threat/30 bg-rex-threat/10 text-rex-threat font-medium"
      role="status"
      aria-label={`${activeThreats} active threat${activeThreats !== 1 ? 's' : ''}`}
    >
      <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} aria-hidden="true">
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126z" />
      </svg>
      <span>{activeThreats} active</span>
    </span>
  );
}

function StatusSummary() {
  const mode = useSystemStore((s) => s.mode);
  const status = useSystemStore((s) => s.status);
  const powerState = useSystemStore((s) => s.powerState);

  return (
    <div className="hidden lg:flex items-center gap-2 text-xs text-rex-muted" role="status" aria-label="System status summary">
      <span className="px-2 py-0.5 rounded bg-rex-card/50 capitalize">{mode}</span>
      <span className="text-rex-card" aria-hidden="true">|</span>
      <span className="capitalize">{status}</span>
      {powerState !== 'unknown' && (
        <>
          <span className="text-rex-card" aria-hidden="true">|</span>
          <span className="capitalize">{powerState}</span>
        </>
      )}
    </div>
  );
}

/* ---------- main component ---------- */

/**
 * @param {Object}  props
 * @param {string}  props.pageLabel  Current page name to display.
 */
export default function TopCommandBar({ pageLabel }) {
  const logout = useSystemStore((s) => s.logout);

  return (
    <header
      className="h-14 bg-rex-surface/80 backdrop-blur-sm border-b border-rex-card flex items-center justify-between px-3 sm:px-4 shrink-0"
      role="banner"
    >
      {/* Left: page label + connection */}
      <div className="flex items-center gap-2 sm:gap-3 min-w-0">
        <h1 className="text-sm font-semibold text-rex-text tracking-wide truncate">
          {pageLabel}
        </h1>
        <ConnectionStatusPill />
      </div>

      {/* Right: status summary + alerts + logout */}
      <div className="flex items-center gap-2 sm:gap-3 shrink-0">
        <StatusSummary />
        <AlertCounter />

        <button
          onClick={logout}
          className="flex items-center gap-1.5 px-2.5 sm:px-3 py-1.5 rounded-lg border border-rex-card
                     text-rex-muted hover:text-rex-threat hover:border-rex-threat/50
                     transition-colors text-xs
                     focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400"
          aria-label="Log out"
        >
          <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} aria-hidden="true">
            <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 9V5.25A2.25 2.25 0 0013.5 3h-6a2.25 2.25 0 00-2.25 2.25v13.5A2.25 2.25 0 007.5 21h6a2.25 2.25 0 002.25-2.25V15m3 0l3-3m0 0l-3-3m3 3H9" />
          </svg>
          <span className="hidden sm:inline">Logout</span>
        </button>
      </div>
    </header>
  );
}
