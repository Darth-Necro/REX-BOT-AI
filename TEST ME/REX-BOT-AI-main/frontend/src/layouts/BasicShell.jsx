/**
 * BasicShell -- simplified layout for basic mode.
 *
 * Responsive:
 *   - Desktop: top nav bar with inline links
 *   - Mobile: full-width content + fixed bottom nav bar (Overview, Threats, Devices, Settings)
 *   - Critical alerts always visible in top bar
 *
 * No features hidden behind faked states.
 */
import React from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import useSystemStore from '../stores/useSystemStore';
import { ToastContainer } from '../components/chrome/ActionFeedbackToast';
import { colors } from '../theme/tokens';

/* ---------- nav items ---------- */

const BASIC_NAV = [
  { to: '/overview',  label: 'Overview', icon: OverviewIcon },
  { to: '/threats',   label: 'Threats',  icon: ThreatsIcon },
  { to: '/devices',   label: 'Devices',  icon: DevicesIcon },
  { to: '/settings',  label: 'Settings', icon: SettingsIcon },
];

/* ---------- mini icons for bottom nav ---------- */

function OverviewIcon({ className }) {
  return (
    <svg className={className} width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5">
      <rect x="2" y="2" width="7" height="7" rx="2" />
      <rect x="11" y="2" width="7" height="7" rx="2" />
      <rect x="2" y="11" width="7" height="7" rx="2" />
      <rect x="11" y="11" width="7" height="7" rx="2" />
    </svg>
  );
}

function ThreatsIcon({ className }) {
  return (
    <svg className={className} width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5">
      <path d="M10 2L3 5.5V10C3 14.1 6 17.4 10 18.5C14 17.4 17 14.1 17 10V5.5L10 2Z" strokeLinejoin="round" />
    </svg>
  );
}

function DevicesIcon({ className }) {
  return (
    <svg className={className} width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5">
      <rect x="5" y="5" width="10" height="10" rx="1.5" />
      <path d="M8 2V5M12 2V5M8 15V18M12 15V18M2 8H5M2 12H5M15 8H18M15 12H18" strokeLinecap="round" />
    </svg>
  );
}

function SettingsIcon({ className }) {
  return (
    <svg className={className} width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5">
      <circle cx="10" cy="10" r="3" />
      <path d="M10 2V4M10 16V18M3.5 5.5L5 7M15 13L16.5 14.5M2 10H4M16 10H18M3.5 14.5L5 13M15 7L16.5 5.5" strokeLinecap="round" />
    </svg>
  );
}

/* ---------- critical alert banner ---------- */

function CriticalAlertBanner() {
  const activeThreats = useSystemStore((s) => s.activeThreats);
  const status = useSystemStore((s) => s.status);

  if (activeThreats === 0 && status !== 'critical') return null;

  return (
    <div
      className="px-4 py-2 text-xs font-medium flex items-center gap-2"
      role="alert"
      style={{ backgroundColor: 'rgba(239,68,68,0.12)', color: '#fca5a5' }}
    >
      <svg className="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126z" />
      </svg>
      {activeThreats > 0
        ? `${activeThreats} active threat${activeThreats !== 1 ? 's' : ''} detected`
        : 'System status: critical'}
    </div>
  );
}

/* ---------- component ---------- */

export default function BasicShell({ children }) {
  const connected = useSystemStore((s) => s.connected);
  const version = useSystemStore((s) => s.version);
  const logout = useSystemStore((s) => s.logout);

  return (
    <div className="flex flex-col h-screen overflow-hidden" style={{ backgroundColor: colors.bg.app }}>
      {/* Top bar */}
      <header className="h-14 bg-rex-surface/80 backdrop-blur-sm border-b border-rex-card flex items-center justify-between px-4 shrink-0">
        <div className="flex items-center gap-4">
          <span className="text-cyan-400 font-bold text-lg tracking-wider">REX</span>

          {/* Desktop inline nav (hidden on mobile) */}
          <nav className="hidden sm:flex items-center gap-1" aria-label="Main navigation">
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
            <span className="hidden sm:inline">{connected ? 'Connected' : 'Disconnected'}</span>
          </span>

          <button
            onClick={logout}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-rex-card text-rex-muted hover:text-red-400 hover:border-red-500/50 transition-colors text-xs"
            title="Log out"
          >
            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 9V5.25A2.25 2.25 0 0013.5 3h-6a2.25 2.25 0 00-2.25 2.25v13.5A2.25 2.25 0 007.5 21h6a2.25 2.25 0 002.25-2.25V15m3 0l3-3m0 0l-3-3m3 3H9" />
            </svg>
            <span className="hidden sm:inline">Logout</span>
          </button>
        </div>
      </header>

      {/* Critical alert banner -- always visible */}
      <CriticalAlertBanner />

      {/* Content -- full width, with bottom padding on mobile for nav bar */}
      <main className="flex-1 overflow-y-auto pb-16 sm:pb-0" style={{ backgroundColor: colors.bg.app }}>
        {children}
      </main>

      {/* Mobile bottom nav bar (visible on small screens only) */}
      <nav
        className="sm:hidden fixed bottom-0 left-0 right-0 z-40 border-t border-rex-card bg-rex-surface/95 backdrop-blur-sm"
        aria-label="Mobile navigation"
      >
        <div className="flex items-center justify-around h-14">
          {BASIC_NAV.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) =>
                `flex flex-col items-center gap-0.5 px-3 py-1.5 transition-colors ${
                  isActive
                    ? 'text-cyan-400'
                    : 'text-slate-500'
                }`
              }
            >
              {({ isActive }) => (
                <>
                  <Icon className={`w-5 h-5 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                  <span className="text-[10px] font-medium">{label}</span>
                </>
              )}
            </NavLink>
          ))}
        </div>
      </nav>

      {/* Desktop footer (hidden on mobile) */}
      <footer className="hidden sm:flex h-8 border-t border-rex-card items-center justify-center shrink-0">
        <p className="text-[10px] text-slate-700 font-mono">
          REX v{version || '---'} -- basic mode
        </p>
      </footer>

      {/* Toast overlay */}
      <ToastContainer />
    </div>
  );
}
