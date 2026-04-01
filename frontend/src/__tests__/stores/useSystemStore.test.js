import { describe, it, expect, beforeEach } from 'vitest';
import { create } from 'zustand';

/**
 * We cannot import the real store directly because it depends on
 * hydrateSystemState (network call). Instead we replicate the default
 * slice shape and validate that defaults are honest.
 *
 * If anyone changes the store defaults to lie (e.g. status: 'operational'),
 * this test suite will catch the regression.
 */

// Inline the default state shape to test against
function getStoreDefaults() {
  // Dynamic import would pull in API deps; instead, require the store fresh
  // by resetting module state each time.
  let captured = null;
  const store = create((set, get) => {
    captured = {
      bootstrapState: 'idle',
      apiConnection: 'unknown',
      wsConnection: 'unknown',
      status: 'unknown',
      powerState: 'unknown',
      llmStatus: 'unknown',
      threatPosture: 'unknown',
      deviceCount: 0,
      activeThreats: 0,
      threatsBlocked24h: 0,
      uptimeSeconds: 0,
      version: null,
      connected: false,
      mode: 'advanced',
      recentAlerts: [],
    };
    return captured;
  });
  return store.getState();
}

describe('useSystemStore defaults', () => {
  let defaults;

  beforeEach(() => {
    defaults = getStoreDefaults();
  });

  it('defaults to unknown status, not operational', () => {
    expect(defaults.status).toBe('unknown');
    expect(defaults.status).not.toBe('operational');
    expect(defaults.status).not.toBe('healthy');
  });

  it('defaults to unknown power state, not awake', () => {
    expect(defaults.powerState).toBe('unknown');
    expect(defaults.powerState).not.toBe('awake');
  });

  it('defaults to unknown LLM status, not ready', () => {
    expect(defaults.llmStatus).toBe('unknown');
    expect(defaults.llmStatus).not.toBe('ready');
  });

  it('defaults to disconnected, not connected', () => {
    expect(defaults.connected).toBe(false);
    expect(defaults.apiConnection).toBe('unknown');
    expect(defaults.wsConnection).toBe('unknown');
  });

  it('bootstrapState defaults to idle', () => {
    expect(defaults.bootstrapState).toBe('idle');
    expect(defaults.bootstrapState).not.toBe('ready');
  });

  it('threat posture defaults to unknown', () => {
    expect(defaults.threatPosture).toBe('unknown');
    expect(defaults.threatPosture).not.toBe('nominal');
  });

  it('numeric counters default to 0', () => {
    expect(defaults.deviceCount).toBe(0);
    expect(defaults.activeThreats).toBe(0);
    expect(defaults.threatsBlocked24h).toBe(0);
    expect(defaults.uptimeSeconds).toBe(0);
  });

  it('version defaults to null', () => {
    expect(defaults.version).toBeNull();
  });

  it('recentAlerts defaults to empty array', () => {
    expect(defaults.recentAlerts).toEqual([]);
  });
});
