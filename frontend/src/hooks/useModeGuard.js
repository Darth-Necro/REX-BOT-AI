/**
 * useModeGuard — derive route availability from the current view mode.
 *
 * Basic mode shows a reduced set of routes (Dashboard, Devices, Threats,
 * Scheduler, Settings, Diagnostics).  Advanced mode shows all pages
 * including Firewall, Plugins, Knowledge Base, Network Map, etc.
 *
 * The hook prefers viewMode (persisted to localStorage) from useUiStore.
 * Falls back to uiMode, then systemStore.mode.
 *
 * This does NOT fake features — unavailable routes are honestly hidden,
 * not shown as "coming soon".
 */
import { useMemo } from 'react';
import useSystemStore from '../stores/useSystemStore';
import useUiStore from '../stores/useUiStore';

/**
 * Routes always available regardless of mode.
 */
const UNIVERSAL_ROUTES = new Set([
  '/overview',
  '/login',
  '/settings',
  '/settings/about',
  '/onboarding',
  '/devices',
  '/threats',
  '/scheduler',
  '/diagnostics',
  '/diagnostics/services',
]);

/**
 * Routes only available in advanced mode.
 */
const ADVANCED_ONLY_ROUTES = new Set([
  '/firewall',
  '/plugins',
  '/knowledge',
  '/network',
  '/settings/notifications',
  '/privacy',
]);

/**
 * Full nav structure with metadata.
 * `mode` indicates minimum mode required.
 */
const ALL_NAV_ITEMS = [
  { path: '/overview', label: 'Overview', mode: 'basic' },
  { path: '/devices', label: 'Devices', mode: 'basic' },
  { path: '/threats', label: 'Threats', mode: 'basic' },
  { path: '/scheduler', label: 'Scheduler', mode: 'basic' },
  { path: '/diagnostics', label: 'Diagnostics', mode: 'basic' },
  { path: '/settings', label: 'Settings', mode: 'basic' },
  { path: '/network', label: 'Network', mode: 'advanced' },
  { path: '/firewall', label: 'Firewall', mode: 'advanced' },
  { path: '/knowledge', label: 'Knowledge Base', mode: 'advanced' },
  { path: '/plugins', label: 'Plugins', mode: 'advanced' },
  { path: '/privacy', label: 'Privacy', mode: 'advanced' },
  { path: '/onboarding', label: 'Setup', mode: 'basic' },
];

export default function useModeGuard() {
  // Prefer viewMode (persisted); fall back to uiMode, then system mode
  const viewMode = useUiStore((s) => s.viewMode);
  const uiMode = useUiStore((s) => s.uiMode);
  const systemMode = useSystemStore((s) => s.mode);
  const mode = viewMode || uiMode || systemMode || 'advanced';

  const isBasic = mode === 'basic';

  const isRouteAvailable = useMemo(() => {
    return (path) => {
      if (UNIVERSAL_ROUTES.has(path)) return true;
      if (isBasic && ADVANCED_ONLY_ROUTES.has(path)) return false;
      return true;
    };
  }, [isBasic]);

  const availableNavItems = useMemo(() => {
    if (!isBasic) return ALL_NAV_ITEMS;
    return ALL_NAV_ITEMS.filter((item) => item.mode === 'basic');
  }, [isBasic]);

  return {
    mode,
    isBasic,
    isRouteAvailable,
    availableNavItems,
    allNavItems: ALL_NAV_ITEMS,
  };
}
