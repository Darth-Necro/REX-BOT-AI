/**
 * SidebarNav -- left-side navigation rail.
 *
 * Items: Overview, Devices, Threats.
 * Active state uses cyan highlight bar + text.
 * Disabled state for pages not yet implemented (grayed, no click).
 */

import React from 'react';
import { NavLink } from 'react-router-dom';

/* ---------- icon components ---------- */

function OverviewIcon({ className }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 6A2.25 2.25 0 016 3.75h2.25A2.25 2.25 0 0110.5 6v2.25a2.25 2.25 0 01-2.25 2.25H6a2.25 2.25 0 01-2.25-2.25V6zM3.75 15.75A2.25 2.25 0 016 13.5h2.25a2.25 2.25 0 012.25 2.25V18a2.25 2.25 0 01-2.25 2.25H6A2.25 2.25 0 013.75 18v-2.25zM13.5 6a2.25 2.25 0 012.25-2.25H18A2.25 2.25 0 0120.25 6v2.25A2.25 2.25 0 0118 10.5h-2.25a2.25 2.25 0 01-2.25-2.25V6zM13.5 15.75a2.25 2.25 0 012.25-2.25H18a2.25 2.25 0 012.25 2.25V18A2.25 2.25 0 0118 20.25h-2.25A2.25 2.25 0 0113.5 18v-2.25z" />
    </svg>
  );
}

function DevicesIcon({ className }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 17.25v1.007a3 3 0 01-.879 2.122L7.5 21h9l-.621-.621A3 3 0 0115 18.257V17.25m6-12V15a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 15V5.25A2.25 2.25 0 015.25 3h13.5A2.25 2.25 0 0121 5.25z" />
    </svg>
  );
}

function ThreatsIcon({ className }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
    </svg>
  );
}

/* ---------- nav items ---------- */

const NAV_ITEMS = [
  { to: '/overview', label: 'Overview', Icon: OverviewIcon, disabled: false },
  { to: '/devices',  label: 'Devices',  Icon: DevicesIcon,  disabled: false },
  { to: '/threats',  label: 'Threats',  Icon: ThreatsIcon,  disabled: false },
];

/* ---------- component ---------- */

export default function SidebarNav() {
  return (
    <nav
      className="w-56 shrink-0 bg-rex-surface border-r border-rex-card flex flex-col h-full"
      aria-label="Main navigation"
    >
      {/* Brand */}
      <div className="h-16 flex items-center gap-2 px-4 border-b border-rex-card">
        <span className="text-cyan-400 font-bold text-lg tracking-wider">REX</span>
        <span className="text-[10px] text-rex-muted font-mono bg-rex-card/50 px-1.5 py-0.5 rounded">v0.1</span>
      </div>

      {/* Navigation links */}
      <div className="flex-1 py-3 space-y-0.5 overflow-y-auto">
        {NAV_ITEMS.map(({ to, label, Icon, disabled }) => {
          if (disabled) {
            return (
              <div
                key={to}
                className="flex items-center gap-3 px-4 py-2.5 text-rex-muted/40 cursor-not-allowed select-none"
                title={`${label} (coming soon)`}
              >
                <Icon className="w-5 h-5" />
                <span className="text-sm">{label}</span>
              </div>
            );
          }

          return (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) =>
                `relative flex items-center gap-3 px-4 py-2.5 transition-colors group ${
                  isActive
                    ? 'text-cyan-400 bg-cyan-500/10'
                    : 'text-rex-muted hover:text-rex-text hover:bg-rex-card/30'
                }`
              }
            >
              {({ isActive }) => (
                <>
                  {/* Active indicator bar */}
                  {isActive && (
                    <span className="absolute left-0 top-1 bottom-1 w-[3px] rounded-r bg-cyan-400" />
                  )}
                  <Icon className={`w-5 h-5 ${isActive ? 'text-cyan-400' : ''}`} />
                  <span className="text-sm font-medium">{label}</span>
                </>
              )}
            </NavLink>
          );
        })}
      </div>

      {/* Bottom section */}
      <div className="border-t border-rex-card px-4 py-3">
        <p className="text-[10px] text-rex-muted/40 font-mono">REX-BOT-AI</p>
      </div>
    </nav>
  );
}
