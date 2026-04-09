/**
 * Badge -- standardized pill/badge system for REX-BOT-AI.
 *
 * Supports color variants mapped to the design system, plus size options.
 * Accessible: always has visible text, never relies on color alone.
 */

import React from 'react';

/* ---------- variant tokens ---------- */

const VARIANT_MAP = {
  default: 'bg-slate-700/40 text-slate-300 border-slate-600/40',
  red:     'bg-red-500/10 text-red-300 border-red-500/30',
  emerald: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30',
  amber:   'bg-amber-500/10 text-amber-300 border-amber-500/30',
  orange:  'bg-orange-500/10 text-orange-300 border-orange-500/30',
  fuchsia: 'bg-fuchsia-500/10 text-fuchsia-300 border-fuchsia-500/30',

  // Semantic aliases
  success: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30',
  warning: 'bg-amber-500/10 text-amber-300 border-amber-500/30',
  danger:  'bg-red-500/10 text-red-300 border-red-500/30',
  info:    'bg-slate-700/40 text-slate-400 border-slate-600/40',
};

const SIZE_MAP = {
  sm: 'text-[10px] px-1.5 py-0.5',
  md: 'text-xs px-2.5 py-1',
  lg: 'text-sm px-3 py-1.5',
};

/**
 * @param {Object}  props
 * @param {string}  props.children       Badge text.
 * @param {'default'|'red'|'emerald'|'amber'|'orange'|'fuchsia'|'success'|'warning'|'danger'|'info'} [props.variant='default']
 * @param {'sm'|'md'|'lg'} [props.size='md']
 * @param {boolean} [props.dot]          Show leading status dot.
 * @param {string}  [props.dotColor]     Override dot color class.
 * @param {string}  [props.className]    Additional classes.
 */
export default function Badge({
  children,
  variant = 'default',
  size = 'md',
  dot = false,
  dotColor,
  className = '',
}) {
  const variantCls = VARIANT_MAP[variant] || VARIANT_MAP.default;
  const sizeCls = SIZE_MAP[size] || SIZE_MAP.md;

  // Derive dot color from variant if not explicitly provided
  const dotCls = dotColor || deriveDotColor(variant);

  return (
    <span
      className={`
        inline-flex items-center gap-1.5 rounded-full border font-medium
        ${variantCls} ${sizeCls} ${className}
      `}
    >
      {dot && (
        <span
          className={`w-1.5 h-1.5 rounded-full shrink-0 ${dotCls}`}
          aria-hidden="true"
        />
      )}
      {children}
    </span>
  );
}

/* ---------- semantic shorthand factories ---------- */

const SEVERITY_VARIANT = {
  critical: 'red',
  high: 'orange',
  medium: 'amber',
  low: 'red',
  info: 'default',
};

const STATUS_VARIANT = {
  operational: 'emerald',
  healthy: 'emerald',
  connected: 'emerald',
  degraded: 'amber',
  unknown: 'default',
  critical: 'red',
  disconnected: 'red',
  connecting: 'red',
};

/**
 * SeverityBadge -- renders a Badge coloured by threat severity.
 * @param {{ severity: string, className?: string }} props
 */
export function SeverityBadge({ severity, className }) {
  const variant = SEVERITY_VARIANT[severity] || 'default';
  return (
    <Badge variant={variant} dot className={className}>
      {severity || 'unknown'}
    </Badge>
  );
}

/**
 * StatusBadge -- renders a Badge coloured by system/service status.
 * @param {{ status: string, className?: string }} props
 */
export function StatusBadge({ status, className }) {
  const variant = STATUS_VARIANT[status] || 'default';
  return (
    <Badge variant={variant} dot className={className}>
      {status || 'unknown'}
    </Badge>
  );
}

/**
 * CapabilityBadge -- boolean on/off badge.
 * @param {{ enabled: boolean, label?: string, className?: string }} props
 */
export function CapabilityBadge({ enabled, label, className }) {
  return (
    <Badge variant={enabled ? 'emerald' : 'default'} className={className}>
      {label || (enabled ? 'Enabled' : 'Disabled')}
    </Badge>
  );
}

/* ---------- helpers ---------- */

function deriveDotColor(variant) {
  const map = {
    default: 'bg-slate-400',
    red: 'bg-red-400',
    emerald: 'bg-emerald-400',
    amber: 'bg-amber-400',
    orange: 'bg-orange-400',
    fuchsia: 'bg-fuchsia-400',
    success: 'bg-emerald-400',
    warning: 'bg-amber-400',
    danger: 'bg-red-400',
    info: 'bg-slate-400',
  };
  return map[variant] || map.default;
}
