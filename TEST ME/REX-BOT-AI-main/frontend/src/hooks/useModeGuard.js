/**
 * useModeGuard — derive route availability from the current UI mode.
 *
 * Basic mode shows a reduced set of routes. Advanced mode shows all.
 * Components call `isRouteAvailable(path)` to conditionally render links
 * and `getAvailableRoutes()` to build nav menus.
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
]);

/**
 * Routes only available in advanced mode.
 */
const ADVANCED_ONLY_ROUTES = new Set([
  '/devices',
  '/threats',
  '/settings/notifications',
  '/privacy',
  '/diagnostics',
]);

/**
 * Full nav structure with metadata.
 * `mode` indicates minimum mode required.
 */
const ALL_NAV_ITEMS = [
  { path: '/overview', label: 'Overview', mode: 'basic' },
  { path: '/devices', label: 'Devices', mode: 'advanced' },
  { path: '/threats', label: 'Threats', mode: 'advanced' },
  { path: '/privacy', label: 'Privacy', mode: 'advanced' },
  { path: '/settings', label: 'Settings', mode: 'basic' },
  { path: '/onboarding', label: 'Setup', mode: 'basic' },
];

export default function useModeGuard() {
  // Prefer useUiStore mode; fall back to system store mode
  const uiMode = useUiStore((s) => s.uiMode);
  const systemMode = useSystemStore((s) => s.mode);
  const mode = uiMode || systemMode || 'advanced';

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
