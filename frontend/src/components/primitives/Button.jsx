/**
 * Button -- consistent button component with multiple variants.
 *
 * Variants: primary, secondary, ghost, danger
 * States:   disabled, loading
 * Accessibility: focus-visible ring, disabled aria, loading spinner + aria-busy
 */

import React from 'react';

/* ---------- variant styles ---------- */

const VARIANT_CLASSES = {
  primary:
    'bg-red-600 hover:bg-red-500 text-white border-red-500/30 shadow-sm',
  secondary:
    'bg-rex-surface hover:bg-slate-700/50 text-slate-200 border-slate-600/50',
  ghost:
    'bg-transparent hover:bg-slate-700/30 text-slate-300 border-transparent',
  danger:
    'bg-red-600/20 hover:bg-red-600/30 text-red-300 border-red-500/30',
};

const SIZE_CLASSES = {
  sm: 'text-xs px-3 py-1.5 rounded-lg',
  md: 'text-sm px-4 py-2 rounded-xl',
  lg: 'text-sm px-5 py-2.5 rounded-xl',
};

/**
 * @param {Object}  props
 * @param {React.ReactNode}  props.children
 * @param {'primary'|'secondary'|'ghost'|'danger'} [props.variant='secondary']
 * @param {'sm'|'md'|'lg'}   [props.size='md']
 * @param {boolean}  [props.loading=false]
 * @param {boolean}  [props.disabled=false]
 * @param {string}   [props.className]
 * @param {Function} [props.onClick]
 * @param {'button'|'submit'|'reset'} [props.type='button']
 * @param {string}   [props.ariaLabel]
 */
export default function Button({
  children,
  variant = 'secondary',
  size = 'md',
  loading = false,
  disabled = false,
  className = '',
  onClick,
  type = 'button',
  ariaLabel,
  ...rest
}) {
  const isDisabled = disabled || loading;
  const variantCls = VARIANT_CLASSES[variant] || VARIANT_CLASSES.secondary;
  const sizeCls = SIZE_CLASSES[size] || SIZE_CLASSES.md;

  return (
    <button
      type={type}
      disabled={isDisabled}
      aria-disabled={isDisabled || undefined}
      aria-busy={loading || undefined}
      aria-label={ariaLabel}
      onClick={isDisabled ? undefined : onClick}
      className={`
        inline-flex items-center justify-center gap-2 border font-medium
        transition-colors duration-200
        focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-400
        focus-visible:ring-offset-2 focus-visible:ring-offset-rex-bg
        disabled:opacity-40 disabled:cursor-not-allowed
        ${variantCls} ${sizeCls} ${className}
      `}
      {...rest}
    >
      {loading && <LoadingSpinner />}
      {children}
    </button>
  );
}

/* ---------- spinner ---------- */

function LoadingSpinner() {
  return (
    <svg
      className="w-4 h-4 animate-spin shrink-0"
      fill="none"
      viewBox="0 0 24 24"
      aria-hidden="true"
    >
      <circle
        className="opacity-25"
        cx="12" cy="12" r="10"
        stroke="currentColor" strokeWidth="4"
      />
      <path
        className="opacity-75"
        fill="currentColor"
        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
      />
    </svg>
  );
}
