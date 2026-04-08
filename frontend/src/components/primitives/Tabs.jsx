/**
 * Tabs -- accessible, keyboard-navigable tab system.
 *
 * Implements WAI-ARIA Tabs pattern:
 *   - role="tablist" / role="tab" / role="tabpanel"
 *   - Arrow keys move focus between tabs
 *   - Home / End jump to first / last tab
 *   - Enter / Space selects the focused tab
 *   - Visible focus ring for keyboard users
 */

import React, { useState, useRef, useCallback } from 'react';

/**
 * @param {Object} props
 * @param {{ id: string, label: string, disabled?: boolean }[]} props.tabs
 * @param {string}   [props.activeId]      Controlled active tab id.
 * @param {Function} [props.onChange]       Called with tab id on selection.
 * @param {string}   [props.className]     Extra classes on the tablist wrapper.
 * @param {string}   [props.ariaLabel]     Accessible label for the tablist.
 */
export default function Tabs({
  tabs = [],
  activeId,
  onChange,
  className = '',
  ariaLabel = 'Tabs',
}) {
  const [internalActive, setInternalActive] = useState(tabs[0]?.id);
  const tabRefs = useRef([]);

  const currentId = activeId ?? internalActive;

  const select = useCallback(
    (id) => {
      if (activeId === undefined) setInternalActive(id);
      onChange?.(id);
    },
    [activeId, onChange],
  );

  const handleKeyDown = useCallback(
    (e) => {
      const enabledTabs = tabs.filter((t) => !t.disabled);
      const currentIndex = enabledTabs.findIndex((t) => t.id === currentId);
      let nextIndex = -1;

      switch (e.key) {
        case 'ArrowRight':
        case 'ArrowDown':
          e.preventDefault();
          nextIndex = (currentIndex + 1) % enabledTabs.length;
          break;
        case 'ArrowLeft':
        case 'ArrowUp':
          e.preventDefault();
          nextIndex = (currentIndex - 1 + enabledTabs.length) % enabledTabs.length;
          break;
        case 'Home':
          e.preventDefault();
          nextIndex = 0;
          break;
        case 'End':
          e.preventDefault();
          nextIndex = enabledTabs.length - 1;
          break;
        default:
          return;
      }

      if (nextIndex >= 0) {
        const nextTab = enabledTabs[nextIndex];
        select(nextTab.id);
        const globalIdx = tabs.indexOf(nextTab);
        tabRefs.current[globalIdx]?.focus();
      }
    },
    [tabs, currentId, select],
  );

  return (
    <div
      role="tablist"
      aria-label={ariaLabel}
      className={`flex gap-1 border-b border-slate-700/40 ${className}`}
      onKeyDown={handleKeyDown}
    >
      {tabs.map((tab, i) => {
        const isActive = tab.id === currentId;
        const isDisabled = tab.disabled === true;

        return (
          <button
            key={tab.id}
            ref={(el) => { tabRefs.current[i] = el; }}
            role="tab"
            id={`tab-${tab.id}`}
            aria-selected={isActive}
            aria-controls={`tabpanel-${tab.id}`}
            aria-disabled={isDisabled || undefined}
            tabIndex={isActive ? 0 : -1}
            disabled={isDisabled}
            onClick={() => !isDisabled && select(tab.id)}
            className={`
              relative px-4 py-2.5 text-sm font-medium transition-colors
              focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-400 focus-visible:ring-offset-2 focus-visible:ring-offset-rex-bg
              ${isDisabled
                ? 'text-slate-600 cursor-not-allowed'
                : isActive
                  ? 'text-red-300'
                  : 'text-rex-muted hover:text-slate-200'
              }
            `}
          >
            {tab.label}
            {/* Active indicator bar */}
            {isActive && (
              <span className="absolute bottom-0 left-2 right-2 h-0.5 rounded-full bg-red-400" />
            )}
          </button>
        );
      })}
    </div>
  );
}

/**
 * TabPanel -- renders the content for a tab.
 * @param {{ id: string, activeId: string, children: React.ReactNode, className?: string }} props
 */
export function TabPanel({ id, activeId, children, className = '' }) {
  if (id !== activeId) return null;

  return (
    <div
      role="tabpanel"
      id={`tabpanel-${id}`}
      aria-labelledby={`tab-${id}`}
      tabIndex={0}
      className={`focus-visible:outline-none ${className}`}
    >
      {children}
    </div>
  );
}
