/**
 * BasicShell — simplified layout for basic mode.
 *
 * Reduced nav with fewer items. Same dark theme.
 * No features hidden behind faked states.
 */
import React from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import useSystemStore from '../stores/useSystemStore';
import { colors } from '../theme/tokens';

/* ---------- nav items for basic mode ---------- */

const BASIC_NAV = [
  { to: '/overview', label: 'Overview' },
  { to: '/settings', label: 'Settings' },
  { to: '/onboarding', label: 'Setup' },
];

/* ---------- component ---------- */

export default function BasicShell({ children, pageLabel }) {
  const connected = useSystemStore((s) => s.connected);
  const version = useSystemStore((s) => s.version);
  const logout = useSystemStore((s) => s.logout);

  return (
    <div className="flex flex-col h-screen overflow-hidden" style={{ backgroundColor: colors.bg.app }}>
      {/* Top bar */}
      <header className="h-14 bg-rex-surface/80 backdrop-blur-sm border-b border-rex-card flex items-center justify-between px-4 shrink-0">
        <div className="flex items-center gap-4">
          <span className="text-cyan-400 font-bold text-lg tracking-wider">REX</span>

          {/* Inline nav */}
          <nav className="hidden sm:flex items-center gap-1">
            {BASIC_NAV.map(({ to, label }) => (
              <NavLink
                key={to}
                to={to}
                className={({ isActive }) =>
                  `px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                    isActive
                      ? 'text-cyan-300 bg-cyan-500/10'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-white/[0.04]'
                  }`
                }
              >
                {label}
              </NavLink>
            ))}
          </nav>
        </div>

        <div className="flex items-center gap-3">
          {/* Connection indicator */}
          <span
            className={`inline-flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full border ${
              connected
                ? 'border-cyan-500/30 bg-cyan-500/10 text-cyan-400'
                : 'border-red-500/30 bg-red-500/10 text-red-400'
            }`}
            role="status"
          >
            <span
              className={`w-1.5 h-1.5 rounded-full ${
                connected ? 'bg-cyan-400 animate-pulse' : 'bg-red-400'
              }`}
            />
            {connected ? 'Connected' : 'Disconnected'}
          </span>

          <button
            onClick={logout}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-rex-card text-rex-muted hover:text-red-400 hover:border-red-500/50 transition-colors text-xs"
            title="Log out"
          >
            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 9V5.25A2.25 2.25 0 0013.5 3h-6a2.25 2.25 0 00-2.25 2.25v13.5A2.25 2.25 0 007.5 21h6a2.25 2.25 0 002.25-2.25V15m3 0l3-3m0 0l-3-3m3 3H9" />
            </svg>
            Logout
          </button>
        </div>
      </header>

      {/* Mobile nav (visible on small screens) */}
      <nav className="sm:hidden flex items-center gap-1 px-4 py-2 bg-rex-surface/60 border-b border-rex-card">
        {BASIC_NAV.map(({ to, label }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                isActive
                  ? 'text-cyan-300 bg-cyan-500/10'
                  : 'text-slate-400 hover:text-slate-200'
              }`
            }
          >
            {label}
          </NavLink>
        ))}
      </nav>

      {/* Content */}
      <main className="flex-1 overflow-y-auto" style={{ backgroundColor: colors.bg.app }}>
        {children}
      </main>

      {/* Footer */}
      <footer className="h-8 border-t border-rex-card flex items-center justify-center">
        <p className="text-[10px] text-slate-700 font-mono">
          REX v{version || '---'} -- basic mode
        </p>
      </footer>
    </div>
  );
}
