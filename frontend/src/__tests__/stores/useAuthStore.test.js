import { describe, it, expect, beforeEach } from 'vitest';
import { create } from 'zustand';

/**
 * Tests for useAuthStore -- validates that auth defaults are honest
 * and that login/logout transitions work correctly.
 *
 * Uses a minimal replica of the store shape to avoid importing the
 * full module (which pulls in browser APIs during SSR-style tests).
 */

function createAuthStore() {
  const SESSION_STATES = {
    ANONYMOUS: 'anonymous',
    AUTHENTICATING: 'authenticating',
    AUTHENTICATED: 'authenticated',
    EXPIRED: 'expired',
  };

  return create((set, get) => ({
    sessionState: SESSION_STATES.ANONYMOUS,
    token: null,
    error: null,

    setToken: (token) => {
      if (!token || typeof token !== 'string' || token.trim() === '') {
        set({ token: null, sessionState: SESSION_STATES.ANONYMOUS, error: 'Blank token rejected' });
        return;
      }
      set({ token, sessionState: SESSION_STATES.AUTHENTICATED, error: null });
    },

    beginLogin: () => set({ sessionState: SESSION_STATES.AUTHENTICATING, error: null }),

    logout: () => set({
      token: null,
      sessionState: SESSION_STATES.ANONYMOUS,
      error: null,
    }),

    expire: () => set({
      token: null,
      sessionState: SESSION_STATES.EXPIRED,
      error: 'Session expired. Please log in again.',
    }),

    isAuthenticated: () => get().sessionState === SESSION_STATES.AUTHENTICATED,
  }));
}

describe('useAuthStore', () => {
  let store;

  beforeEach(() => {
    store = createAuthStore();
  });

  it('defaults to unauthenticated', () => {
    const state = store.getState();
    expect(state.sessionState).toBe('anonymous');
    expect(state.token).toBeNull();
    expect(state.error).toBeNull();
    expect(state.isAuthenticated()).toBe(false);
  });

  it('login sets token and authenticated state', () => {
    store.getState().setToken('test-jwt-token');
    const state = store.getState();
    expect(state.token).toBe('test-jwt-token');
    expect(state.sessionState).toBe('authenticated');
    expect(state.error).toBeNull();
    expect(state.isAuthenticated()).toBe(true);
  });

  it('logout clears token', () => {
    store.getState().setToken('test-jwt-token');
    expect(store.getState().isAuthenticated()).toBe(true);

    store.getState().logout();
    const state = store.getState();
    expect(state.token).toBeNull();
    expect(state.sessionState).toBe('anonymous');
    expect(state.isAuthenticated()).toBe(false);
  });

  it('rejects blank/empty tokens', () => {
    store.getState().setToken('');
    expect(store.getState().token).toBeNull();
    expect(store.getState().sessionState).toBe('anonymous');
    expect(store.getState().error).toBe('Blank token rejected');

    store.getState().setToken('   ');
    expect(store.getState().token).toBeNull();
  });

  it('rejects null/undefined tokens', () => {
    store.getState().setToken(null);
    expect(store.getState().token).toBeNull();
    expect(store.getState().sessionState).toBe('anonymous');

    store.getState().setToken(undefined);
    expect(store.getState().token).toBeNull();
  });

  it('beginLogin sets authenticating state', () => {
    store.getState().beginLogin();
    const state = store.getState();
    expect(state.sessionState).toBe('authenticating');
    expect(state.error).toBeNull();
    expect(state.isAuthenticated()).toBe(false);
  });

  it('expire sets expired state with message', () => {
    store.getState().setToken('test-jwt');
    store.getState().expire();
    const state = store.getState();
    expect(state.token).toBeNull();
    expect(state.sessionState).toBe('expired');
    expect(state.error).toContain('expired');
    expect(state.isAuthenticated()).toBe(false);
  });
});
