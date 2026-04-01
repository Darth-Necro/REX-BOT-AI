/**
 * NetworkMapPage -- full page: topology map + summary + selected node detail.
 *
 * Hydrates from API on mount. Shows honest loading / empty / error states.
 * No fabricated data.
 */

import React, { useEffect, useCallback, useMemo } from 'react';
import useNetworkStore from '../../stores/useNetworkStore';
import NetworkMap from '../../components/network/NetworkMap';
import NetworkNodeCard from '../../components/network/NetworkNodeCard';
import Badge from '../../components/primitives/Badge';
import Button from '../../components/primitives/Button';
import { timeAgo } from '../../lib/formatters';

/* ---------- summary stats ---------- */

function TopologySummary({ nodes, segments, fetchedAt }) {
  const online = nodes.filter(
    (n) => n.status === 'online' || n.status === 'trusted',
  ).length;

  const trustDistribution = useMemo(() => {
    const dist = { trusted: 0, known: 0, new: 0, untrusted: 0, blocked: 0, unknown: 0 };
    nodes.forEach((n) => {
      const key = n.trust || 'unknown';
      const mapped = dist.hasOwnProperty(key) ? key : 'unknown';
      dist[mapped]++;
    });
    return dist;
  }, [nodes]);

  return (
    <div
      className="grid grid-cols-2 sm:grid-cols-4 gap-3"
      role="region"
      aria-label="Network summary"
    >
      <SummaryCard label="Total Devices" value={nodes.length} />
      <SummaryCard label="Online" value={online} accent />
      <SummaryCard label="Segments" value={segments.length} />
      <SummaryCard
        label="Last Scanned"
        value={fetchedAt ? timeAgo(fetchedAt) : '--'}
        small
      />
    </div>
  );
}

function SummaryCard({ label, value, accent, small }) {
  return (
    <div className="bg-rex-surface border border-rex-card rounded-xl px-4 py-3">
      <p className="text-xs text-rex-muted uppercase tracking-wide">{label}</p>
      <p
        className={`mt-1 font-bold tabular-nums ${
          small ? 'text-sm text-slate-300' : 'text-lg text-slate-100'
        } ${accent ? 'text-cyan-300' : ''}`}
      >
        {value}
      </p>
    </div>
  );
}

/* ---------- page ---------- */

export default function NetworkMapPage() {
  const nodes = useNetworkStore((s) => s.nodes);
  const segments = useNetworkStore((s) => s.segments);
  const selectedNode = useNetworkStore((s) => s.selectedNode);
  const selectNode = useNetworkStore((s) => s.selectNode);
  const clearSelection = useNetworkStore((s) => s.clearSelection);
  const loading = useNetworkStore((s) => s.loading);
  const fetchedAt = useNetworkStore((s) => s.fetchedAt);
  const fetchTopology = useNetworkStore((s) => s.fetchTopology);

  useEffect(() => {
    fetchTopology();
  }, [fetchTopology]);

  const handleSelectNode = useCallback(
    (node) => {
      if (selectedNode?.id === node.id) {
        clearSelection();
      } else {
        selectNode(node);
      }
    },
    [selectedNode, selectNode, clearSelection],
  );

  return (
    <div className="flex h-full">
      {/* Main content */}
      <div className="flex-1 overflow-y-auto p-4 md:p-6 space-y-6">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <div>
            <h1 className="text-xl font-bold text-slate-100">Network Map</h1>
            <p className="text-sm text-slate-500 mt-0.5">
              Topology derived from discovered devices
            </p>
          </div>
          <Button
            onClick={fetchTopology}
            loading={loading}
            variant="secondary"
            size="sm"
            ariaLabel="Refresh network topology"
          >
            {loading ? 'Scanning...' : 'Refresh'}
          </Button>
        </div>

        {/* Summary */}
        {nodes.length > 0 && (
          <TopologySummary
            nodes={nodes}
            segments={segments}
            fetchedAt={fetchedAt}
          />
        )}

        {/* Map */}
        <NetworkMap
          onSelectNode={handleSelectNode}
          selectedNodeId={selectedNode?.id}
        />
      </div>

      {/* Selected node detail panel */}
      {selectedNode && (
        <aside className="w-80 shrink-0 border-l border-rex-card overflow-y-auto hidden md:block">
          <NetworkNodeCard
            node={selectedNode}
            selected
            onClose={clearSelection}
          />
        </aside>
      )}

      {/* Mobile: selected node as bottom sheet overlay */}
      {selectedNode && (
        <div className="md:hidden fixed inset-x-0 bottom-0 z-40 max-h-[60vh] overflow-y-auto bg-rex-surface border-t border-rex-card rounded-t-2xl shadow-xl">
          <NetworkNodeCard
            node={selectedNode}
            selected
            onClose={clearSelection}
          />
        </div>
      )}
    </div>
  );
}
