import React, { useState, useEffect, useCallback } from 'react';
import { colors } from '../theme/tokens';
import ConnectionStatusPill from '../components/chrome/ConnectionStatusPill';
import { ToastContainer } from '../components/chrome/ActionFeedbackToast';
import useSystemStore from '../stores/useSystemStore';

/* ------------------------------------------------------------------ */
/*  Default nav items (can be overridden via props)                   */
/* ------------------------------------------------------------------ */

const DEFAULT_NAV = [
  { id: 'overview',    label: 'Overview',        icon: NavIconGrid },
  { id: 'threats',     label: 'Threats',         icon: NavIconShield },
  { id: 'devices',     label: 'Devices',         icon: NavIconCpu },
  { id: 'firewall',    label: 'Firewall',        icon: NavIconShield },
  { id: 'knowledge',   label: 'Knowledge Base',  icon: NavIconBook },
  { id: 'scheduler',   label: 'Scheduler',       icon: NavIconClock },
  { id: 'plugins',     label: 'Plugins',         icon: NavIconPlugin },
  { id: 'diagnostics', label: 'Diagnostics',     icon: NavIconDiag },
  { id: 'chat',        label: 'REX Chat',        icon: NavIconChat },
];

/* ------------------------------------------------------------------ */
/*  Minimal inline SVG nav icons (no external deps)                   */
/* ------------------------------------------------------------------ */

function NavIconGrid({ active }) {
  return (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" className={active ? 'text-cyan-400' : 'text-slate-500'}>
      <rect x="2" y="2" width="7" height="7" rx="2" stroke="currentColor" strokeWidth="1.5" />
      <rect x="11" y="2" width="7" height="7" rx="2" stroke="currentColor" strokeWidth="1.5" />
      <rect x="2" y="11" width="7" height="7" rx="2" stroke="currentColor" strokeWidth="1.5" />
      <rect x="11" y="11" width="7" height="7" rx="2" stroke="currentColor" strokeWidth="1.5" />
    </svg>
  );
}

function NavIconShield({ active }) {
  return (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" className={active ? 'text-cyan-400' : 'text-slate-500'}>
      <path d="M10 2L3 5.5V10C3 14.1 6 17.4 10 18.5C14 17.4 17 14.1 17 10V5.5L10 2Z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" />
    </svg>
  );
}

function NavIconCpu({ active }) {
  return (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" className={active ? 'text-cyan-400' : 'text-slate-500'}>
      <rect x="5" y="5" width="10" height="10" rx="1.5" stroke="currentColor" strokeWidth="1.5" />
      <path d="M8 2V5M12 2V5M8 15V18M12 15V18M2 8H5M2 12H5M15 8H18M15 12H18" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
    </svg>
  );
}

function NavIconChat({ active }) {
  return (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" className={active ? 'text-cyan-400' : 'text-slate-500'}>
      <path d="M4 4H16C16.6 4 17 4.4 17 5V13C17 13.6 16.6 14 16 14H7L3 17V5C3 4.4 3.4 4 4 4Z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" />
    </svg>
  );
}

function NavIconBook({ active }) {
  return (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" className={active ? 'text-cyan-400' : 'text-slate-500'}>
      <path d="M10 5A7 7 0 005 3C4.2 3 3.4 3.14 2.6 3.4V14.4C3.4 14.14 4.2 14 5 14C6.8 14 8.4 14.7 10 15.8M10 5A7 7 0 0115 3C15.8 3 16.6 3.14 17.4 3.4V14.4C16.6 14.14 15.8 14 15 14C13.2 14 11.6 14.7 10 15.8M10 5V15.8" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function NavIconClock({ active }) {
  return (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" className={active ? 'text-cyan-400' : 'text-slate-500'}>
      <circle cx="10" cy="10" r="7.5" stroke="currentColor" strokeWidth="1.5" />
      <path d="M10 5.5V10H13.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function NavIconPlugin({ active }) {
  return (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" className={active ? 'text-cyan-400' : 'text-slate-500'}>
      <path d="M11.5 4.5C11.5 3.67 10.83 3 10 3S8.5 3.67 8.5 4.5V6H6V8.5C5.17 8.5 4.5 9.17 4.5 10S5.17 11.5 6 11.5V14H8.5V15.5C8.5 16.33 9.17 17 10 17S11.5 16.33 11.5 15.5V14H14V11.5C14.83 11.5 15.5 10.83 15.5 10S14.83 8.5 14 8.5V6H11.5V4.5Z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" />
    </svg>
  );
}

function NavIconDiag({ active }) {
  return (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" className={active ? 'text-cyan-400' : 'text-slate-500'}>
      <path d="M3 10H6L8 5L12 15L14 10H17" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

/* ------------------------------------------------------------------ */
/*  Hamburger icon                                                     */
/* ------------------------------------------------------------------ */

function HamburgerIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
      <path d="M3 5H17M3 10H17M3 15H17" />
    </svg>
  );
}

function CloseIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
      <path d="M5 5L15 15M15 5L5 15" />
    </svg>
  );
}

/* ------------------------------------------------------------------ */
/*  AppShell                                                          */
/* ------------------------------------------------------------------ */

/**
 * Main app shell: left nav rail + content area.
 * Responsive: sidebar collapses to a drawer on mobile (< 768px).
 * Toast container included for feedback overlay.
 *
 * @param {{
 *   children: React.ReactNode,
 *   navItems?: Array<{ id: string, label: string, icon: React.ComponentType }>,
 *   currentPage?: string,
 *   onNavigate?: (id: string) => void,
 * }} props
 */
export default function AppShell({
  children,
  navItems = DEFAULT_NAV,
  currentPage = 'overview',
  onNavigate,
}) {
  const apiConnection = useSystemStore((s) => s.apiConnection);
  const wsConnection = useSystemStore((s) => s.wsConnection);
  const version = useSystemStore((s) => s.version);
  const logout = useSystemStore((s) => s.logout);
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  // Close mobile drawer on navigation
  const handleNavigate = useCallback(
    (id) => {
      setMobileOpen(false);
      onNavigate?.(id);
    },
    [onNavigate],
  );

  // Close drawer on Escape key
  useEffect(() => {
    if (!mobileOpen) return;
    const handleKey = (e) => {
      if (e.key === 'Escape') setMobileOpen(false);
    };
    document.addEventListener('keydown', handleKey);
    return () => document.removeEventListener('keydown', handleKey);
  }, [mobileOpen]);

  // Show worst-of API / WS as the pill state
  const connectionState = deriveConnectionPillState(apiConnection, wsConnection);

  /* -- Sidebar content shared between desktop rail and mobile drawer -- */
  const sidebarContent = (isMobile) => (
    <>
      {/* Brand header */}
      <div className="flex items-center gap-2 px-4 h-16 border-b" style={{ borderColor: colors.border.subtle }}>
        <span className="text-lg font-black tracking-tight" style={{ color: colors.accent.cyan }}>
          REX
        </span>
        {(!collapsed || isMobile) && (
          <span className="text-xs font-medium text-slate-500 tracking-wider">BOT-AI</span>
        )}
        {isMobile ? (
          <button
            onClick={() => setMobileOpen(false)}
            className="ml-auto text-slate-400 hover:text-slate-200 transition-colors p-1"
            aria-label="Close navigation"
          >
            <CloseIcon />
          </button>
        ) : (
          <button
            onClick={() => setCollapsed((c) => !c)}
            className="ml-auto text-slate-600 hover:text-slate-400 transition-colors p-1 hidden md:block"
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
              <path
                d={collapsed ? 'M6 3L11 8L6 13' : 'M10 3L5 8L10 13'}
                stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"
              />
            </svg>
          </button>
        )}
      </div>

      {/* Connection pill */}
      <div className="px-3 py-3">
        <ConnectionStatusPill state={connectionState} />
      </div>

      {/* Nav links */}
      <ul className="flex-1 px-2 space-y-1 mt-1 overflow-y-auto" role="navigation" aria-label="Main navigation">
        {navItems.map((item) => {
          const active = currentPage === item.id;
          const Icon = item.icon;
          return (
            <li key={item.id}>
              <button
                onClick={() => handleNavigate(item.id)}
                className={`
                  w-full flex items-center gap-3 px-3 py-2.5 rounded-xl
                  text-sm font-medium transition-colors duration-200
                  ${active
                    ? 'bg-cyan-500/10 text-cyan-300'
                    : 'text-slate-400 hover:bg-white/[0.04] hover:text-slate-200'
                  }
                `}
                aria-current={active ? 'page' : undefined}
              >
                <Icon active={active} />
                {(!collapsed || isMobile) && <span>{item.label}</span>}
              </button>
            </li>
          );
        })}
      </ul>

      {/* Footer */}
      <div className="px-3 py-3 space-y-2 border-t" style={{ borderColor: colors.border.subtle }}>
        <button
          onClick={logout}
          className="w-full flex items-center gap-2 px-3 py-2 rounded-xl text-xs text-slate-500 hover:text-red-400 hover:bg-red-500/5 transition-colors"
        >
          <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
            <path d="M5 1H2.5C1.67 1 1 1.67 1 2.5V11.5C1 12.33 1.67 13 2.5 13H5M9.5 10L13 7L9.5 4M5.5 7H12.5" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          {(!collapsed || isMobile) && <span>Logout</span>}
        </button>
        {(!collapsed || isMobile) && (
          <p className="text-[10px] text-slate-700 text-center tracking-wide">
            REX v{version || '---'}
          </p>
        )}
      </div>
    </>
  );

  return (
    <div className="flex h-screen overflow-hidden" style={{ backgroundColor: colors.bg.app }}>
      {/* ---- Mobile hamburger bar (visible < md) ---- */}
      <div
        className="md:hidden fixed top-0 left-0 right-0 z-40 h-14 flex items-center justify-between px-4 border-b backdrop-blur-sm"
        style={{
          backgroundColor: `${colors.bg.shell}ee`,
          borderColor: colors.border.subtle,
        }}
      >
        <button
          onClick={() => setMobileOpen(true)}
          className="text-slate-400 hover:text-slate-200 transition-colors p-1.5"
          aria-label="Open navigation menu"
        >
          <HamburgerIcon />
        </button>
        <span className="text-sm font-black tracking-tight" style={{ color: colors.accent.cyan }}>
          REX
        </span>
        <ConnectionStatusPill state={connectionState} compact />
      </div>

      {/* ---- Mobile drawer overlay ---- */}
      {mobileOpen && (
        <div
          className="md:hidden fixed inset-0 z-50 flex"
          role="dialog"
          aria-modal="true"
          aria-label="Navigation menu"
        >
          {/* Backdrop */}
          <div
            className="fixed inset-0 bg-black/60"
            onClick={() => setMobileOpen(false)}
            aria-hidden="true"
          />
          {/* Drawer */}
          <nav
            className="relative z-10 flex flex-col w-64 h-full"
            style={{ backgroundColor: colors.bg.shell }}
          >
            {sidebarContent(true)}
          </nav>
        </div>
      )}

      {/* ---- Desktop left nav rail (hidden on mobile) ---- */}
      <nav
        className={`
          hidden md:flex flex-col shrink-0 border-r
          transition-[width] duration-300 ease-in-out
          ${collapsed ? 'w-16' : 'w-56'}
        `}
        style={{
          backgroundColor: colors.bg.shell,
          borderColor: colors.border.subtle,
        }}
      >
        {sidebarContent(false)}
      </nav>

      {/* ---- Main Content ---- */}
      <main
        className="flex-1 overflow-y-auto pt-14 md:pt-0"
        style={{ backgroundColor: colors.bg.app }}
      >
        <div className="h-full max-w-7xl mx-auto">
          {children}
        </div>
      </main>

      {/* ---- Toast overlay ---- */}
      <ToastContainer />
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Helpers                                                           */
/* ------------------------------------------------------------------ */

function deriveConnectionPillState(api, ws) {
  if (api === 'disconnected' || ws === 'disconnected') return 'disconnected';
  if (api === 'connecting' || ws === 'connecting') return 'connecting';
  if (api === 'degraded' || ws === 'degraded') return 'degraded';
  if (api === 'connected' && ws === 'connected') return 'connected';
  return 'unknown';
}
