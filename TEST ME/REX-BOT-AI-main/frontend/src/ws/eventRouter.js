/**
 * eventRouter -- routes incoming WebSocket events to the correct Zustand stores.
 *
 * Event types handled:
 *   new_device / device.new        -> useDeviceStore.applyDeviceDelta
 *   device_departed / device.departed -> useDeviceStore.applyDeviceDelta
 *   device_update / device.update  -> useDeviceStore.applyDeviceDelta
 *   threat_detected / threat.new   -> useThreatStore.applyThreatDelta
 *   threat_resolved / threat.resolved -> useThreatStore.applyThreatDelta
 *   status_change / status.update  -> useSystemStore.updateFromStatus
 */

import useDeviceStore from '../stores/useDeviceStore';
import useThreatStore from '../stores/useThreatStore';
import useSystemStore from '../stores/useSystemStore';

/* Map of event type -> handler */
const ROUTES = {
  // Device events
  'new_device':       (d) => useDeviceStore.getState().applyDeviceDelta('new_device', d.payload || d),
  'device.new':       (d) => useDeviceStore.getState().applyDeviceDelta('device.new', d.payload || d),
  'device_departed':  (d) => useDeviceStore.getState().applyDeviceDelta('device_departed', d.payload || d),
  'device.departed':  (d) => useDeviceStore.getState().applyDeviceDelta('device.departed', d.payload || d),
  'device_update':    (d) => useDeviceStore.getState().applyDeviceDelta('device_update', d.payload || d),
  'device.update':    (d) => useDeviceStore.getState().applyDeviceDelta('device.update', d.payload || d),

  // Threat events
  'threat_detected':  (d) => useThreatStore.getState().applyThreatDelta('threat_detected', d.payload || d),
  'threat.new':       (d) => useThreatStore.getState().applyThreatDelta('threat.new', d.payload || d),
  'threat_resolved':  (d) => useThreatStore.getState().applyThreatDelta('threat_resolved', d.payload || d),
  'threat.resolved':  (d) => useThreatStore.getState().applyThreatDelta('threat.resolved', d.payload || d),

  // System status events
  'status_change':    (d) => useSystemStore.getState().updateFromStatus(d.payload || d),
  'status.update':    (d) => useSystemStore.getState().updateFromStatus(d.payload || d),
};

/**
 * Route a single WS message to the appropriate store(s).
 * @param {Object} message  Parsed WS message with a `type` field.
 */
export function routeEvent(message) {
  const type = message?.type;
  if (!type) return;

  const handler = ROUTES[type];
  if (handler) {
    try {
      handler(message);
    } catch (err) {
      console.error(`[eventRouter] failed to handle "${type}":`, err);
    }
  }
}

/**
 * Returns the list of event types we handle (for subscription).
 */
export function getSubscribedTypes() {
  return Object.keys(ROUTES);
}
