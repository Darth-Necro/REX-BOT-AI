/**
 * DangerConfirmModal — reusable confirmation modal for destructive actions.
 * Shows title, description, and impact summary before requiring explicit confirm.
 * Designed for use with useDangerConfirm hook.
 */
import React from 'react';

export default function DangerConfirmModal({
  isOpen = false,
  title = 'Confirm Action',
  description = '',
  impact = '',
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  onConfirm,
  onCancel,
}) {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/70 backdrop-blur-sm"
        onClick={onCancel}
      />

      {/* Dialog */}
      <div className="relative w-full max-w-md bg-[#0B1020] border border-red-500/30 rounded-2xl shadow-2xl shadow-red-500/10 p-6">
        {/* Icon */}
        <div className="flex justify-center mb-4">
          <div className="w-14 h-14 rounded-full bg-red-500/15 border border-red-500/30 flex items-center justify-center">
            <svg className="w-7 h-7 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
            </svg>
          </div>
        </div>

        {/* Title */}
        <h3 className="text-lg font-bold text-red-300 text-center mb-2">
          {title}
        </h3>

        {/* Description */}
        {description && (
          <p className="text-sm text-slate-300 text-center mb-3">
            {description}
          </p>
        )}

        {/* Impact summary */}
        {impact && (
          <div className="bg-red-500/10 border border-red-500/20 rounded-xl px-4 py-3 mb-5">
            <p className="text-xs font-medium text-red-300 uppercase tracking-wide mb-1">Impact</p>
            <p className="text-sm text-slate-300">{impact}</p>
          </div>
        )}

        {/* Actions */}
        <div className="flex items-center gap-3">
          <button
            onClick={onCancel}
            className="flex-1 px-4 py-2.5 bg-slate-800 text-slate-300 rounded-xl
                       hover:bg-slate-700 transition-colors text-sm font-medium"
          >
            {cancelLabel}
          </button>
          <button
            onClick={onConfirm}
            className="flex-1 px-4 py-2.5 bg-red-600 text-white rounded-xl
                       hover:bg-red-500 transition-colors text-sm font-bold"
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
