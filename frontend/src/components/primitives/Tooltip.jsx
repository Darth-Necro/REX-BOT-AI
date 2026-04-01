/**
 * Tooltip -- accessible, keyboard-friendly tooltip.
 *
 * Shows on hover and on focus (keyboard users).
 * Uses role="tooltip" and aria-describedby for screen readers.
 * Positioned above the trigger by default; auto-flips if near viewport top.
 */

import React, { useState, useRef, useId, useEffect, useCallback } from 'react';

/**
 * @param {Object} props
 * @param {string}           props.content    Tooltip text.
 * @param {React.ReactNode}  props.children   Trigger element (must accept ref forwarding or be a DOM element).
 * @param {'top'|'bottom'}   [props.position='top']
 * @param {string}           [props.className]  Extra classes on tooltip bubble.
 */
export default function Tooltip({
  content,
  children,
  position = 'top',
  className = '',
}) {
  const [visible, setVisible] = useState(false);
  const [flipped, setFlipped] = useState(false);
  const triggerRef = useRef(null);
  const tooltipId = useId();

  const show = useCallback(() => setVisible(true), []);
  const hide = useCallback(() => setVisible(false), []);

  // Flip direction if trigger is near viewport edge
  useEffect(() => {
    if (!visible || !triggerRef.current) return;
    const rect = triggerRef.current.getBoundingClientRect();
    if (position === 'top' && rect.top < 48) {
      setFlipped(true);
    } else if (position === 'bottom' && window.innerHeight - rect.bottom < 48) {
      setFlipped(true);
    } else {
      setFlipped(false);
    }
  }, [visible, position]);

  const pos = flipped ? (position === 'top' ? 'bottom' : 'top') : position;

  const positionClasses =
    pos === 'top'
      ? 'bottom-full left-1/2 -translate-x-1/2 mb-2'
      : 'top-full left-1/2 -translate-x-1/2 mt-2';

  // Handle Escape to dismiss
  const handleKeyDown = useCallback(
    (e) => {
      if (e.key === 'Escape' && visible) {
        hide();
      }
    },
    [visible, hide],
  );

  if (!content) {
    return <>{children}</>;
  }

  return (
    <span
      className="relative inline-flex"
      onMouseEnter={show}
      onMouseLeave={hide}
      onFocus={show}
      onBlur={hide}
      onKeyDown={handleKeyDown}
      ref={triggerRef}
    >
      {/* Trigger element with aria binding */}
      <span aria-describedby={visible ? tooltipId : undefined}>
        {children}
      </span>

      {/* Tooltip bubble */}
      {visible && (
        <span
          id={tooltipId}
          role="tooltip"
          className={`
            absolute z-50 ${positionClasses}
            whitespace-nowrap px-2.5 py-1.5 rounded-lg
            bg-slate-800 border border-slate-700 text-xs text-slate-200
            shadow-lg pointer-events-none
            animate-in fade-in duration-150
            ${className}
          `}
        >
          {content}
        </span>
      )}
    </span>
  );
}
