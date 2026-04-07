/**
 * useAuthStore -- Single source of truth for authentication state.
 *
 * Token is stored in localStorage keyed by the API base URL so that
 * multiple REX instances on different origins do not share tokens.
 * All auth checks should go through this store. The legacy token/setToken/logout
 * in useSystemStore have been removed.
 */

import { create } from 'zustand';

const SESSION_STATES = {
  ANONYMOUS: 'anonymous',
  AUTHENTICATING: 'authenticating',
  AUTHENTICATED: 'authenticated',
  EXPIRED: 'expired',
};

/**
 * Derive a per-instance localStorage key from the API base URL.
 * Multiple REX dashboards on different origins each get their own token slot.
 */
const _tokenKey = () => {
  const base = import.meta.env.VITE_API_URL || window.location.origin;
  return `rex-token-${btoa(base).slice(0, 16)}`;
};

/**
 * Decode a JWT payload and return its `exp` claim (seconds since epoch),
 * or null if the token is not a valid JWT.
 */
function _getExpiry(token) {
  try {
    const payload = JSON.parse(atob(token.split('.')[1]));
    return payload.exp || null;
  } catch {
    return null;
  }
}

/**
 * Try to restore a token from instance-aware localStorage on startup.
 */
function _loadPersistedToken() {
  try {
    const t = localStorage.getItem(_tokenKey());
    if (t && typeof t === 'string' && t.trim() !== '') return t;
  } catch { /* ignore */ }
  return null;
}

const _restoredToken = _loadPersistedToken();

const useAuthStore = create((set, get) => ({
  sessionState: _restoredToken ? SESSION_STATES.AUTHENTICATED : SESSION_STATES.ANONYMOUS,
  token: _restoredToken,
  error: null,

  /**
   * Store a token after successful login.
   * Persisted to localStorage keyed by instance URL.
   * Also clears any legacy localStorage token.
   */
  setToken: (token) => {
    localStorage.removeItem('rex_token');
    if (!token || typeof token !== 'string' || token.trim() === '') {
      try { localStorage.removeItem(_tokenKey()); } catch { /* ignore */ }
      set({ token: null, sessionState: SESSION_STATES.ANONYMOUS, error: 'Blank token rejected' });
      return;
    }
    try { localStorage.setItem(_tokenKey(), token); } catch { /* ignore */ }
    set({ token, sessionState: SESSION_STATES.AUTHENTICATED, error: null });
  },

  setSessionState: (sessionState) => set({ sessionState }),
  setError: (error) => set({ error }),

  /**
   * Begin a login attempt -- called before the API request fires.
   */
  beginLogin: () => set({ sessionState: SESSION_STATES.AUTHENTICATING, error: null }),

  /**
   * Full logout -- wipe token, clear legacy + instance storage, redirect to /login.
   */
  logout: () => {
    localStorage.removeItem('rex_token');
    try { localStorage.removeItem(_tokenKey()); } catch { /* ignore */ }
    set({
      token: null,
      sessionState: SESSION_STATES.ANONYMOUS,
      error: null,
    });
    // Redirect to login page. Use window.location so it works outside React
    // Router context (e.g. from an axios interceptor).
    if (typeof window !== 'undefined' && window.location.pathname !== '/login') {
      window.location.href = '/login';
    }
  },

  /**
   * Mark session as expired (e.g. 401 interceptor).
   */
  expire: () => {
    localStorage.removeItem('rex_token');
    try { localStorage.removeItem(_tokenKey()); } catch { /* ignore */ }
    set({
      token: null,
      sessionState: SESSION_STATES.EXPIRED,
      error: 'Session expired. Please log in again.',
    });
  },

  /**
   * Returns true if the current token's `exp` claim is in the past.
   * Returns false if there is no token or the token has no exp claim.
   */
  isExpired: () => {
    const { token } = get();
    if (!token) return false;
    const exp = _getExpiry(token);
    if (!exp) return false;
    return Date.now() / 1000 > exp;
  },

  /** Convenience selectors */
  isAuthenticated: () => get().sessionState === SESSION_STATES.AUTHENTICATED,
}));

export { SESSION_STATES };
export default useAuthStore;
