/**
 * useAuthStore -- Single source of truth for authentication state.
 *
 * Token is held in-memory only (never localStorage) to reduce XSS surface.
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

const useAuthStore = create((set, get) => ({
  sessionState: SESSION_STATES.ANONYMOUS,
  token: null,
  error: null,

  /**
   * Store a token after successful login.
   * Keeps token in JS memory -- not localStorage.
   * Also clears any legacy localStorage token.
   */
  setToken: (token) => {
    localStorage.removeItem('rex_token');
    if (!token || typeof token !== 'string' || token.trim() === '') {
      set({ token: null, sessionState: SESSION_STATES.ANONYMOUS, error: 'Blank token rejected' });
      return;
    }
    set({ token, sessionState: SESSION_STATES.AUTHENTICATED, error: null });
  },

  setSessionState: (sessionState) => set({ sessionState }),
  setError: (error) => set({ error }),

  /**
   * Begin a login attempt -- called before the API request fires.
   */
  beginLogin: () => set({ sessionState: SESSION_STATES.AUTHENTICATING, error: null }),

  /**
   * Full logout -- wipe token, clear legacy storage, and redirect to /login.
   */
  logout: () => {
    localStorage.removeItem('rex_token');
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
  expire: () => set({
    token: null,
    sessionState: SESSION_STATES.EXPIRED,
    error: 'Session expired. Please log in again.',
  }),

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

  /**
   * Placeholder for token refresh. Implementations should call the refresh
   * endpoint and feed the new token to setToken().
   */
  refreshToken: async () => {
    // TODO: call /api/auth/refresh and store the new token
  },

  /** Convenience selectors */
  isAuthenticated: () => get().sessionState === SESSION_STATES.AUTHENTICATED,
}));

export { SESSION_STATES };
export default useAuthStore;
