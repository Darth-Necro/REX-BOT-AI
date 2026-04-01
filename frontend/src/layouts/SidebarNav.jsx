/**
 * SidebarNav -- left-side navigation rail.
 *
 * Items: Overview, Devices, Threats, Firewall, Knowledge Base, Scheduler, Plugins, Diagnostics.
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

function FirewallIcon({ className }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m0-10.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
    </svg>
  );
}

function KnowledgeBaseIcon({ className }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 6.042A8.967 8.967 0 006 3.75c-1.052 0-2.062.18-3 .512v14.25A8.987 8.987 0 016 18c2.305 0 4.408.867 6 2.292m0-14.25a8.966 8.966 0 016-2.292c1.052 0 2.062.18 3 .512v14.25A8.987 8.987 0 0018 18a8.967 8.967 0 00-6 2.292m0-14.25v14.25" />
    </svg>
  );
}

function SchedulerIcon({ className }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
  );
}

function PluginsIcon({ className }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M14.25 6.087c0-.355.186-.676.401-.959.221-.29.349-.634.349-1.003 0-1.036-1.007-1.875-2.25-1.875s-2.25.84-2.25 1.875c0 .369.128.713.349 1.003.215.283.401.604.401.959v0a.64.64 0 01-.657.643 48.39 48.39 0 01-4.163-.3c.186 1.613.293 3.25.315 4.907a.656.656 0 01-.658.663v0c-.355 0-.676-.186-.959-.401a1.647 1.647 0 00-1.003-.349c-1.036 0-1.875 1.007-1.875 2.25s.84 2.25 1.875 2.25c.369 0 .713-.128 1.003-.349.283-.215.604-.401.959-.401v0c.31 0 .555.26.532.57a48.039 48.039 0 01-.642 5.056c1.518.19 3.058.309 4.616.354a.64.64 0 00.657-.643v0c0-.355-.186-.676-.401-.959a1.647 1.647 0 01-.349-1.003c0-1.035 1.008-1.875 2.25-1.875 1.243 0 2.25.84 2.25 1.875 0 .369-.128.713-.349 1.003-.215.283-.4.604-.4.959v0c0 .333.277.599.61.58a48.1 48.1 0 005.427-.63 48.05 48.05 0 00.582-4.717.532.532 0 00-.533-.57v0c-.355 0-.676.186-.959.401-.29.221-.634.349-1.003.349-1.035 0-1.875-1.007-1.875-2.25s.84-2.25 1.875-2.25c.37 0 .713.128 1.003.349.283.215.604.401.96.401v0a.656.656 0 00.658-.663 48.422 48.422 0 00-.37-5.36c-1.886.342-3.81.574-5.766.689a.578.578 0 01-.61-.58z" />
    </svg>
  );
}

function DiagnosticsIcon({ className }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M9.75 3.104v5.714a2.25 2.25 0 01-.659 1.591L5 14.5M9.75 3.104c-.251.023-.501.05-.75.082m.75-.082a24.301 24.301 0 014.5 0m0 0v5.714c0 .597.237 1.17.659 1.591L19.8 15.3M14.25 3.104c.251.023.501.05.75.082M19.8 15.3l-1.57.393A9.065 9.065 0 0112 15a9.065 9.065 0 00-6.23.693L5 14.5m14.8.8l.8 2.4M5 14.5l-.8 2.4m.8 3.6h14" />
    </svg>
  );
}

/* ---------- nav items ---------- */

const NAV_ITEMS = [
  { to: '/overview', label: 'Overview',        Icon: OverviewIcon,       disabled: false },
  { to: '/devices',  label: 'Devices',         Icon: DevicesIcon,        disabled: false },
  { to: '/threats',  label: 'Threats',          Icon: ThreatsIcon,        disabled: false },
  { to: '/firewall', label: 'Firewall',         Icon: FirewallIcon,       disabled: false },
  { to: '/knowledge', label: 'Knowledge Base',  Icon: KnowledgeBaseIcon,  disabled: false },
  { to: '/scheduler', label: 'Scheduler',       Icon: SchedulerIcon,      disabled: false },
  { to: '/plugins',   label: 'Plugins',         Icon: PluginsIcon,        disabled: false },
  { to: '/diagnostics', label: 'Diagnostics',   Icon: DiagnosticsIcon,    disabled: false },
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
