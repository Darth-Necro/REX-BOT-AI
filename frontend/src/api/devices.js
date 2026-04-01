/**
 * Device API -- fetch device list and individual device details.
 *
 * Response normalization ensures downstream code always gets an array
 * regardless of backend envelope shape.
 */

import api from './client';

/**
 * Fetch all discovered devices.
 * @returns {Promise<Array>}
 */
export async function getDevices() {
  const res = await api.get('/devices/');
  const data = res.data;
  const list = data?.devices || data || [];
  return Array.isArray(list) ? list : [];
}

/**
 * Fetch a single device by MAC address.
 * @param {string} mac  URL-safe MAC address.
 * @returns {Promise<Object>}
 */
export async function getDevice(mac) {
  if (!mac) throw new Error('MAC address is required');
  const res = await api.get(`/devices/${encodeURIComponent(mac)}`);
  return res.data;
}
