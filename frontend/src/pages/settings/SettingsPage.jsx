/**
 * SettingsPage — settings hub linking to sub-pages.
 *
 * Shows available settings sections as cards. Availability is derived
 * from mode (basic mode sees fewer links). Never fakes feature availability.
 */
import React from 'react';
import { Link } from 'react-router-dom';
import useModeGuard from '../../hooks/useModeGuard';

/* ---------- settings sections ---------- */

const SETTINGS_SECTIONS = [
  {
    path: '/settings/notifications',
    label: 'Notifications',
    description: 'Configure Discord, Telegram, Email, and Matrix alerts.',
    icon: 'bell',
    mode: 'advanced',
  },
  {
    path: '/settings/about',
    label: 'About',
    description: 'Version, build info, and system uptime.',
    icon: 'info',
    mode: 'basic',
  },
  {
    path: '/privacy',
    label: 'Privacy',
    description: 'Privacy signals, data retention, and audits.',
    icon: 'shield',
    mode: 'advanced',
  },
  {
    path: '/onboarding',
    label: 'Onboarding',
    description: 'Run or review the REX setup interview.',
    icon: 'chat',
    mode: 'basic',
  },
  {
    path: '/change-password',
    label: 'Change Password',
    description: 'Update your dashboard admin password.',
    icon: 'lock',
    mode: 'basic',
  },
];

/* ---------- icons ---------- */

function SectionIcon({ type }) {
  const cls = "w-6 h-6 text-slate-500";
  switch (type) {
    case 'bell':
      return (
        <svg className={cls} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M14.857 17.082a23.848 23.848 0 005.454-1.31A8.967 8.967 0 0118 9.75V9A6 6 0 006 9v.75a8.967 8.967 0 01-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31m5.714 0a24.255 24.255 0 01-5.714 0m5.714 0a3 3 0 11-5.714 0" />
        </svg>
      );
    case 'info':
      return (
        <svg className={cls} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M11.25 11.25l.041-.02a.75.75 0 011.063.852l-.708 2.836a.75.75 0 001.063.853l.041-.021M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9-3.75h.008v.008H12V8.25z" />
        </svg>
      );
    case 'shield':
      return (
        <svg className={cls} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
        </svg>
      );
    case 'chat':
      return (
        <svg className={cls} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M20.25 8.511c.884.284 1.5 1.128 1.5 2.097v4.286c0 1.136-.847 2.1-1.98 2.193-.34.027-.68.052-1.02.072v3.091l-3-3c-1.354 0-2.694-.055-4.02-.163a2.115 2.115 0 01-.825-.242m9.345-8.334a2.126 2.126 0 00-.476-.095 48.64 48.64 0 00-8.048 0c-1.131.094-1.976 1.057-1.976 2.192v4.286c0 .837.46 1.58 1.155 1.951m9.345-8.334V6.637c0-1.621-1.152-3.026-2.76-3.235A48.455 48.455 0 0011.25 3c-2.115 0-4.198.137-6.24.402-1.608.209-2.76 1.614-2.76 3.235v6.226c0 1.621 1.152 3.026 2.76 3.235.577.075 1.157.14 1.74.194V21l4.155-4.155" />
        </svg>
      );
    case 'lock':
      return (
        <svg className={cls} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z" />
        </svg>
      );
    default:
      return null;
  }
}

/* ---------- main page ---------- */

export default function SettingsPage() {
  const { isBasic, isRouteAvailable } = useModeGuard();

  const visibleSections = SETTINGS_SECTIONS.filter((section) => {
    if (isBasic && section.mode === 'advanced') return false;
    return true;
  });

  return (
    <div className="p-6 lg:p-8 max-w-4xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-slate-100 tracking-tight">
          Settings
        </h1>
        <p className="text-sm text-slate-500 mt-1">
          {isBasic
            ? 'Basic mode -- some settings are only available in advanced mode.'
            : 'Configure REX system settings.'}
        </p>
      </div>

      {/* Section cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {visibleSections.map((section) => {
          const available = isRouteAvailable(section.path);

          if (!available) {
            return (
              <div
                key={section.path}
                className="rounded-[26px] border border-white/[0.04] bg-slate-900/30 p-5 opacity-40 cursor-not-allowed"
              >
                <div className="flex items-center gap-3 mb-2">
                  <SectionIcon type={section.icon} />
                  <span className="text-sm font-medium text-slate-400">{section.label}</span>
                </div>
                <p className="text-xs text-slate-600">{section.description}</p>
                <p className="text-[10px] text-slate-700 mt-2">Not available in current mode</p>
              </div>
            );
          }

          return (
            <Link
              key={section.path}
              to={section.path}
              className="rounded-[26px] border border-white/[0.06] bg-gradient-to-br from-[#0B1020] to-[#11192C] p-5 hover:border-cyan-500/20 hover:shadow-[0_0_24px_rgba(34,211,238,0.04)] transition-all group"
            >
              <div className="flex items-center gap-3 mb-2">
                <SectionIcon type={section.icon} />
                <span className="text-sm font-medium text-slate-200 group-hover:text-cyan-300 transition-colors">
                  {section.label}
                </span>
              </div>
              <p className="text-xs text-slate-500">{section.description}</p>
            </Link>
          );
        })}
      </div>

      {/* Mode indicator */}
      {isBasic && (
        <div className="rounded-xl border border-white/[0.04] bg-slate-900/30 p-4 text-xs text-slate-600">
          You are in basic mode. Switch to advanced mode to access all settings.
        </div>
      )}
    </div>
  );
}
