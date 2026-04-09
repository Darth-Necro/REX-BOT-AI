/**
 * Network API -- derive topology from device and system data.
 *
 * There is no dedicated /network endpoint on the backend.
 * Instead we assemble a topology graph from the devices list and
 * system status.  Nodes are real devices; edges represent shared
 * subnet membership.  No fake traffic or synthetic telemetry.
 */

import { getDevices } from './devices';
import { getStatus } from './system';

/**
 * Fetch device list + system status and derive a topology object.
 *
 * Uses Promise.allSettled so partial failure still returns what we can.
 *
 * @returns {Promise<{
 *   nodes: Array<{ id: string, label: string, ip: string, mac: string, type: string, trust: string, status: string, segment: string }>,
 *   segments: string[],
 *   gateway: string|null,
 *   fetchedAt: string,
 *   degraded: boolean,
 * }>}
 */
export async function getNetworkTopology() {
  const [devicesRes, statusRes] = await Promise.allSettled([
    getDevices(),
    getStatus(),
  ]);

  const devices =
    devicesRes.status === 'fulfilled' ? devicesRes.value : [];
  const status =
    statusRes.status === 'fulfilled' ? statusRes.value : null;

  // Derive segment from IP subnet (first 3 octets) or vendor grouping
  const nodes = devices.map((d) => {
    const ip = d.ip_address || d.ip || '';
    const segment = deriveSegment(ip, d);

    return {
      id: d.mac_address || d.mac || ip || `device-${Math.random().toString(36).slice(2, 8)}`,
      label: d.hostname || d.name || ip || 'Unknown',
      ip,
      mac: d.mac_address || d.mac || '',
      type: d.device_type || d.type || 'unknown',
      trust: d.trust_level || d.trust || 'unknown',
      status: d.status || 'unknown',
      segment,
      vendor: d.vendor || null,
      os: d.os || d.operating_system || null,
    };
  });

  // Collect unique segments
  const segmentSet = new Set(nodes.map((n) => n.segment));
  const segments = [...segmentSet].sort();

  // Identify likely gateway (router type, or lowest IP on most common subnet)
  const gateway = findGateway(nodes);

  const degraded =
    devicesRes.status === 'rejected' || statusRes.status === 'rejected';

  return {
    nodes,
    segments,
    gateway,
    fetchedAt: new Date().toISOString(),
    degraded,
  };
}

/* ---------- helpers ---------- */

function deriveSegment(ip, device) {
  if (device.segment || device.network_segment) {
    return device.segment || device.network_segment;
  }
  if (!ip || typeof ip !== 'string') return 'unknown';
  const parts = ip.split('.');
  if (parts.length !== 4) return 'unknown';
  return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
}

function findGateway(nodes) {
  // Prefer nodes explicitly typed as router / gateway
  const router = nodes.find(
    (n) =>
      n.type === 'router' ||
      n.type === 'gateway' ||
      (n.label && /gateway|router/i.test(n.label)),
  );
  if (router) return router.id;

  // Fallback: node ending in .1
  const dotOne = nodes.find(
    (n) => n.ip && n.ip.endsWith('.1'),
  );
  return dotOne ? dotOne.id : null;
}
