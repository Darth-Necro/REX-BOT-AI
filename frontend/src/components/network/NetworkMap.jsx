/**
 * NetworkMap -- visual network topology built from real device data.
 *
 * Renders nodes from the network store grouped by segment.
 * Trust-based coloring: each node's ring color reflects its trust tier.
 * Click to select a node. Keyboard accessible (Tab + Enter).
 *
 * NO fake traffic animations. NO synthetic data.
 * Honest loading / empty / degraded / error states.
 */

import React, { useMemo, useCallback } from 'react';
import useNetworkStore from '../../stores/useNetworkStore';
import { trustTokens, normalizeTrust, trustTier } from '../../lib/trust';
import SegmentBadge from './SegmentBadge';
import EmptyState from '../primitives/EmptyState';

/* ---------- node color by trust ---------- */

const TRUST_RING_COLORS = {
  trusted: 'ring-emerald-400/60 border-emerald-500/30',
  known: 'ring-red-400/60 border-red-500/30',
  new: 'ring-amber-400/60 border-amber-500/30',
  untrusted: 'ring-orange-400/60 border-orange-500/30',
  blocked: 'ring-red-400/60 border-red-500/30',
  unknown: 'ring-slate-500/40 border-slate-600/30',
};

const STATUS_DOT = {
  online: 'bg-emerald-400',
  trusted: 'bg-emerald-400',
  offline: 'bg-slate-500',
  departed: 'bg-slate-500',
  new: 'bg-amber-400',
};

/* ---------- component ---------- */

/**
 * @param {Object}   props
 * @param {Function} [props.onSelectNode]  Called with node object.
 * @param {string}   [props.selectedNodeId]
 * @param {string}   [props.className]
 */
export default function NetworkMap({ onSelectNode, selectedNodeId, className = '' }) {
  const nodes = useNetworkStore((s) => s.nodes);
  const segments = useNetworkStore((s) => s.segments);
  const gateway = useNetworkStore((s) => s.gateway);
  const loading = useNetworkStore((s) => s.loading);
  const error = useNetworkStore((s) => s.error);
  const degraded = useNetworkStore((s) => s.degraded);

  // Group nodes by segment
  const grouped = useMemo(() => {
    const map = {};
    nodes.forEach((n) => {
      const seg = n.segment || 'unknown';
      if (!map[seg]) map[seg] = [];
      map[seg].push(n);
    });
    return map;
  }, [nodes]);

  const handleSelect = useCallback(
    (node) => {
      onSelectNode?.(node);
    },
    [onSelectNode],
  );

  const handleKeyDown = useCallback(
    (e, node) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        handleSelect(node);
      }
    },
    [handleSelect],
  );

  /* ---------- state branches ---------- */

  if (loading && nodes.length === 0) {
    return <EmptyState variant="loading" heading="Mapping network" description="Discovering devices and building topology..." />;
  }

  if (error && nodes.length === 0) {
    return (
      <EmptyState
        variant="error"
        heading="Topology unavailable"
        description={error}
      />
    );
  }

  if (!loading && nodes.length === 0) {
    return (
      <EmptyState
        variant="empty"
        heading="No devices found"
        description="REX has not discovered any devices yet. Run a network scan to populate the map."
      />
    );
  }

  return (
    <div className={`space-y-6 ${className}`} role="region" aria-label="Network topology map">
      {/* Degraded banner */}
      {degraded && (
        <div
          className="bg-amber-500/10 border border-amber-500/30 rounded-xl px-4 py-2 text-xs text-amber-300"
          role="alert"
        >
          Some data could not be loaded. The map may be incomplete.
        </div>
      )}

      {/* Segments */}
      {segments.map((seg) => {
        const segNodes = grouped[seg] || [];
        if (segNodes.length === 0) return null;

        return (
          <div key={seg}>
            <div className="flex items-center gap-2 mb-3">
              <SegmentBadge segment={seg} />
              <span className="text-xs text-rex-muted">
                {segNodes.length} device{segNodes.length !== 1 ? 's' : ''}
              </span>
            </div>

            <div
              className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-3"
              role="list"
              aria-label={`Devices in segment ${seg}`}
            >
              {segNodes.map((node) => {
                const score = normalizeTrust(node.trust);
                const tier = trustTier(score);
                const ringCls = TRUST_RING_COLORS[tier] || TRUST_RING_COLORS.unknown;
                const dotCls = STATUS_DOT[node.status] || 'bg-slate-500';
                const isGateway = node.id === gateway;
                const isSelected = node.id === selectedNodeId;
                const tTokens = trustTokens(node.trust);

                return (
                  <div
                    key={node.id}
                    role="listitem"
                    tabIndex={0}
                    onClick={() => handleSelect(node)}
                    onKeyDown={(e) => handleKeyDown(e, node)}
                    className={`
                      relative flex flex-col items-center gap-2 p-3 rounded-xl
                      border ring-2 cursor-pointer
                      transition-all duration-200
                      focus-visible:outline-none focus-visible:ring-red-400 focus-visible:ring-offset-2 focus-visible:ring-offset-rex-bg
                      hover:bg-slate-700/20
                      ${ringCls}
                      ${isSelected ? 'bg-red-500/5 border-red-500/40 ring-red-400/50' : 'bg-rex-surface'}
                    `}
                    aria-label={`${node.label}, ${node.ip || 'no IP'}, trust: ${tTokens.label}, status: ${node.status || 'unknown'}`}
                    aria-selected={isSelected}
                  >
                    {/* Gateway indicator */}
                    {isGateway && (
                      <span className="absolute -top-1.5 -right-1.5 text-[8px] font-bold bg-red-500 text-rex-bg px-1.5 py-0.5 rounded-full">
                        GW
                      </span>
                    )}

                    {/* Status dot */}
                    <span className="relative flex h-2.5 w-2.5">
                      <span className={`relative inline-flex h-2.5 w-2.5 rounded-full ${dotCls}`} />
                    </span>

                    {/* Node label */}
                    <span className="text-xs font-medium text-rex-text text-center truncate w-full">
                      {node.label}
                    </span>

                    {/* IP */}
                    {node.ip && (
                      <span className="text-[10px] font-mono text-rex-muted truncate w-full text-center">
                        {node.ip}
                      </span>
                    )}

                    {/* Trust tier label */}
                    <span className={`text-[10px] font-medium ${tTokens.text}`}>
                      {tTokens.label}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        );
      })}
    </div>
  );
}
