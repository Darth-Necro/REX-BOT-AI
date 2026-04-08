/**
 * EmptyState -- unified placeholder for empty, loading, degraded,
 * unsupported, and disconnected states.
 *
 * Color is never the sole meaning carrier: each variant has a distinct
 * icon, heading, and accessible label.
 */

import React from 'react';

/* ---------- variant config ---------- */

const VARIANTS = {
  empty: {
    icon: EmptyIcon,
    heading: 'Nothing here yet',
    description: 'No data is available for this view.',
    ariaLabel: 'Empty state: no data available',
    borderClass: 'border-slate-700/40',
  },
  loading: {
    icon: LoadingIcon,
    heading: 'Loading',
    description: 'Fetching data from REX...',
    ariaLabel: 'Loading data',
    borderClass: 'border-red-500/20',
  },
  degraded: {
    icon: DegradedIcon,
    heading: 'Partial data',
    description: 'Some information could not be loaded. Showing what is available.',
    ariaLabel: 'Degraded state: partial data loaded',
    borderClass: 'border-amber-500/30',
  },
  unsupported: {
    icon: UnsupportedIcon,
    heading: 'Not supported',
    description: 'This feature is not available in the current configuration.',
    ariaLabel: 'Unsupported feature',
    borderClass: 'border-slate-600/40',
  },
  disconnected: {
    icon: DisconnectedIcon,
    heading: 'Disconnected',
    description: 'Cannot reach the REX backend. Data shown may be stale.',
    ariaLabel: 'Disconnected from backend',
    borderClass: 'border-red-500/30',
  },
  error: {
    icon: ErrorIcon,
    heading: 'Something went wrong',
    description: 'An error occurred while loading this data.',
    ariaLabel: 'Error loading data',
    borderClass: 'border-red-500/30',
  },
};

/* ---------- component ---------- */

/**
 * @param {Object} props
 * @param {'empty'|'loading'|'degraded'|'unsupported'|'disconnected'|'error'} [props.variant='empty']
 * @param {string} [props.heading]      Override heading text.
 * @param {string} [props.description]  Override description text.
 * @param {React.ReactNode} [props.action]  Optional action button / link.
 * @param {string} [props.className]    Extra classes.
 */
export default function EmptyState({
  variant = 'empty',
  heading,
  description,
  action,
  className = '',
}) {
  const config = VARIANTS[variant] || VARIANTS.empty;
  const Icon = config.icon;

  return (
    <div
      role="status"
      aria-label={config.ariaLabel}
      className={`flex flex-col items-center justify-center py-16 px-6 text-center border border-dashed rounded-2xl ${config.borderClass} ${className}`}
    >
      <Icon />
      <h3 className="mt-4 text-sm font-semibold text-slate-300">
        {heading || config.heading}
      </h3>
      <p className="mt-1 text-xs text-rex-muted max-w-xs">
        {description || config.description}
      </p>
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

/* ---------- icons ---------- */

function EmptyIcon() {
  return (
    <svg className="w-10 h-10 text-slate-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5} aria-hidden="true">
      <path strokeLinecap="round" strokeLinejoin="round" d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" />
    </svg>
  );
}

function LoadingIcon() {
  return (
    <svg className="w-10 h-10 text-red-400 animate-spin" fill="none" viewBox="0 0 24 24" aria-hidden="true">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
    </svg>
  );
}

function DegradedIcon() {
  return (
    <svg className="w-10 h-10 text-amber-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5} aria-hidden="true">
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
    </svg>
  );
}

function UnsupportedIcon() {
  return (
    <svg className="w-10 h-10 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5} aria-hidden="true">
      <path strokeLinecap="round" strokeLinejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
    </svg>
  );
}

function DisconnectedIcon() {
  return (
    <svg className="w-10 h-10 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5} aria-hidden="true">
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 013 12c0-1.605.42-3.113 1.157-4.418" />
    </svg>
  );
}

function ErrorIcon() {
  return (
    <svg className="w-10 h-10 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5} aria-hidden="true">
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
    </svg>
  );
}
