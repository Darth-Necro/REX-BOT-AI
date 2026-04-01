/**
 * ActionFeedbackToast -- renders a single toast notification.
 * Types: success, warning, error, pending, unsupported.
 *
 * Icons:
 *   success  -> checkmark
 *   error    -> X circle
 *   warning  -> triangle
 *   pending  -> spinner
 *
 * Auto-dismiss: success after 5s, warnings after 8s, errors stay visible.
 * Screen reader: aria-live region on container; assertive for errors, polite otherwise.
 *
 * Also exports ToastContainer which renders all active toasts
 * from useUiStore in a fixed overlay.
 */
import React from 'react';
import useUiStore from '../../stores/useUiStore';

/* ---------- icon SVGs ---------- */

function CheckIcon() {
  return (
    <svg className="w-4 h-4 text-emerald-400 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5} aria-hidden="true">
      <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
    </svg>
  );
}

function WarningIcon() {
  return (
    <svg className="w-4 h-4 text-amber-400 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} aria-hidden="true">
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
    </svg>
  );
}

function ErrorIcon() {
  return (
    <svg className="w-4 h-4 text-red-400 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} aria-hidden="true">
      <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
    </svg>
  );
}

function SpinnerIcon() {
  return (
    <svg className="w-4 h-4 text-cyan-400 animate-spin shrink-0" fill="none" viewBox="0 0 24 24" aria-hidden="true">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
    </svg>
  );
}

function UnsupportedIcon() {
  return (
    <svg className="w-4 h-4 text-slate-400 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} aria-hidden="true">
      <path strokeLinecap="round" strokeLinejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
    </svg>
  );
}

const ICON_MAP = {
  check: CheckIcon,
  warning: WarningIcon,
  error: ErrorIcon,
  spinner: SpinnerIcon,
  unsupported: UnsupportedIcon,
};

const TYPE_STYLES = {
  success: 'border-emerald-500/30 bg-emerald-500/10',
  warning: 'border-amber-500/30 bg-amber-500/10',
  error: 'border-red-500/30 bg-red-500/10',
  pending: 'border-cyan-500/30 bg-cyan-500/10',
  unsupported: 'border-slate-600 bg-slate-800/60',
};

/* ---------- single toast ---------- */

export default function ActionFeedbackToast({ toast, onDismiss }) {
  const IconComponent = ICON_MAP[toast.icon] || CheckIcon;
  const style = TYPE_STYLES[toast.type] || TYPE_STYLES.success;

  return (
    <div
      className={`
        flex items-center gap-3 px-4 py-3 rounded-xl border
        ${style}
        shadow-lg shadow-black/20
        backdrop-blur-sm
        animate-[slideIn_0.2s_ease-out]
      `}
      role="alert"
      aria-atomic="true"
    >
      <IconComponent />
      <span className="text-sm text-slate-200 flex-1">{toast.message}</span>
      <button
        onClick={() => onDismiss(toast.id)}
        className="text-slate-500 hover:text-slate-300 transition-colors shrink-0"
        aria-label="Dismiss notification"
      >
        <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} aria-hidden="true">
          <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
        </svg>
      </button>
    </div>
  );
}

/* ---------- toast container overlay ---------- */

export function ToastContainer() {
  const toasts = useUiStore((s) => s.toasts);
  const dismissToast = useUiStore((s) => s.dismissToast);

  if (toasts.length === 0) return null;

  // Separate error toasts (assertive) from others (polite)
  const errorToasts = toasts.filter((t) => t.type === 'error');
  const otherToasts = toasts.filter((t) => t.type !== 'error');

  return (
    <div className="fixed bottom-4 right-4 sm:bottom-4 sm:right-4 bottom-20 z-50 flex flex-col gap-2 max-w-sm w-full pointer-events-none">
      {/* Assertive region for errors -- screen readers announce immediately */}
      <div aria-live="assertive" aria-atomic="true" className="contents">
        {errorToasts.map((toast) => (
          <div key={toast.id} className="pointer-events-auto">
            <ActionFeedbackToast toast={toast} onDismiss={dismissToast} />
          </div>
        ))}
      </div>

      {/* Polite region for non-errors */}
      <div aria-live="polite" aria-atomic="true" className="contents">
        {otherToasts.map((toast) => (
          <div key={toast.id} className="pointer-events-auto">
            <ActionFeedbackToast toast={toast} onDismiss={dismissToast} />
          </div>
        ))}
      </div>
    </div>
  );
}
