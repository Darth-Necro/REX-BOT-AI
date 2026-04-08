/**
 * FederationPage -- peer-to-peer threat intelligence sharing.
 *
 * Shows federation status, peer list, and enable/disable toggle.
 */
import React, { useEffect } from 'react';
import useFederationStore from '../../stores/useFederationStore';
import { SkeletonCard } from '../../components/primitives/Skeleton';

function StatCard({ label, value }) {
  return (
    <div className="rounded-2xl border border-white/[0.06] bg-gradient-to-br from-[#0a0a0a] to-[#141414] p-5">
      <p className="text-xs text-slate-500 uppercase tracking-widest mb-1">{label}</p>
      <p className="text-2xl font-bold text-slate-100 tabular-nums">{value}</p>
    </div>
  );
}

function PeerCard({ peer }) {
  return (
    <div className="rounded-xl border border-white/[0.06] bg-rex-surface p-4 space-y-2">
      <div className="flex items-center justify-between">
        <span className="text-sm font-medium text-slate-200 font-mono">
          {peer.peer_id || peer.id || 'Unknown'}
        </span>
        <span className={`text-xs px-2 py-0.5 rounded-full ${
          peer.status === 'connected' || peer.active
            ? 'bg-emerald-500/20 text-emerald-300'
            : 'bg-slate-700/50 text-slate-400'
        }`}>
          {peer.status || (peer.active ? 'connected' : 'inactive')}
        </span>
      </div>
      {peer.last_seen && (
        <p className="text-xs text-slate-500">
          Last seen: {new Date(peer.last_seen).toLocaleString()}
        </p>
      )}
      {peer.shared_iocs != null && (
        <p className="text-xs text-slate-500">
          Shared IOCs: {peer.shared_iocs}
        </p>
      )}
    </div>
  );
}

export default function FederationPage() {
  const {
    enabled, peerCount, sharedIocCount, peers,
    loading, toggling, error,
    fetchStatus, enable, disable,
  } = useFederationStore();

  useEffect(() => {
    fetchStatus();
  }, [fetchStatus]);

  if (loading) {
    return (
      <div className="p-6 lg:p-8 max-w-4xl mx-auto space-y-4">
        <SkeletonCard />
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <SkeletonCard /><SkeletonCard /><SkeletonCard />
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 lg:p-8 max-w-4xl mx-auto space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 tracking-tight">Federation</h1>
          <p className="text-sm text-slate-500 mt-1">
            Peer-to-peer threat intelligence sharing between REX instances.
          </p>
        </div>
        <button
          onClick={enabled ? disable : enable}
          disabled={toggling}
          className={`px-5 py-2 rounded-xl text-sm font-medium border transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${
            enabled
              ? 'bg-red-500/20 text-red-300 border-red-500/30 hover:bg-red-500/30'
              : 'bg-red-500/20 text-red-300 border-red-500/30 hover:bg-red-500/30'
          }`}
        >
          {toggling ? 'Updating...' : enabled ? 'Disable Federation' : 'Enable Federation'}
        </button>
      </div>

      {/* Error */}
      {error && (
        <div className="rounded-xl border border-red-500/30 bg-red-500/5 p-3 text-sm text-red-300">
          {error}
        </div>
      )}

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <StatCard label="Status" value={enabled ? 'Enabled' : 'Disabled'} />
        <StatCard label="Connected Peers" value={peerCount} />
        <StatCard label="Shared IOCs" value={sharedIocCount} />
      </div>

      {/* Peers */}
      <section>
        <h2 className="text-sm font-bold tracking-widest uppercase text-slate-400 mb-3">
          Peers
        </h2>
        {peers.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {peers.map((peer, i) => (
              <PeerCard key={peer.peer_id || peer.id || i} peer={peer} />
            ))}
          </div>
        ) : (
          <div className="flex items-center justify-center py-8 text-sm text-slate-600">
            {enabled
              ? 'No peers discovered yet. Other REX instances on the network will appear here.'
              : 'Enable federation to discover peers.'}
          </div>
        )}
      </section>
    </div>
  );
}
