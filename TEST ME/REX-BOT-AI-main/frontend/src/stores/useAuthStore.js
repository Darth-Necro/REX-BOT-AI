/**
 * useAuthStore -- Authentication state management.
 *
 * Token is held in-memory only (never localStorage) to reduce XSS surface.
 * The system store's legacy token/setToken/logout remain wired for backward
 * compat but new code should go through this store.
 */

import { create } from 'zustand';

const SESSION_STATES = {
  ANONYMOUS: 'anonymous',
  AUTHENTICATING: 'authenticating',
  AUTHENTICATED: 'authenticated',
  EXPIRED: 'expired',
};

const useAuthStore = create((set, get) => ({
  sessionState: SESSION_STATES.ANONYMOUS,
  token: null,
  error: null,

  /**
   * Store a token after successful login.
   * Keeps token in JS memory -- not localStorage.
   */
  setToken: (token) => {
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
   * Full logout -- wipe token and reset to anonymous.
   */
  logout: () => set({
    token: null,
    sessionState: SESSION_STATES.ANONYMOUS,
    error: null,
  }),

  /**
   * Mark session as expired (e.g. 401 interceptor).
   */
  expire: () => set({
    token: null,
    sessionState: SESSION_STATES.EXPIRED,
    error: 'Session expired. Please log in again.',
  }),

  /** Convenience selectors */
  isAuthenticated: () => get().sessionState === SESSION_STATES.AUTHENTICATED,
}));

export { SESSION_STATES };
export default useAuthStore;
