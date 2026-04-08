/**
 * Federation API -- peer-to-peer threat intelligence sharing endpoints.
 */
import api from './client';

export async function getFederationStatus() {
  const res = await api.get('/federation/status');
  const d = res.data || {};
  return {
    enabled: d.enabled ?? false,
    peerCount: d.peer_count ?? 0,
    sharedIocCount: d.shared_ioc_count ?? 0,
  };
}

export async function getFederationPeers() {
  const res = await api.get('/federation/peers');
  const d = res.data || {};
  return {
    peers: Array.isArray(d.peers) ? d.peers : [],
    count: d.count ?? 0,
  };
}

export async function enableFederation() {
  const res = await api.post('/federation/enable');
  return res.data;
}

export async function disableFederation() {
  const res = await api.post('/federation/disable');
  return res.data;
}
