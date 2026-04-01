/**
 * NetworkNodeCard -- displays details for a single network node.
 *
 * Shows: name, IP, MAC, device type, trust level, online status.
 * No fabricated telemetry -- only data the backend actually provides.
 */

import React from 'react';
import Badge from '../primitives/Badge';
import SegmentBadge from './SegmentBadge';
import TrustRing from './TrustRing';
import { trustTokens } from '../../lib/trust';

/* ---------- status helpers ---------- */

function statusBadgeVariant(status) {
  switch (status) {
    case 'online':
    case 'trusted':
      return 'emerald';
    case 'offline':
    case 'departed':
      return 'red';
    case 'new':
      return 'amber';
    default:
      return 'default';
  }
}

function typeLabel(type) {
  if (!type || type === 'unknown') return 'Unknown type';
  return type.charAt(0).toUpperCase() + type.slice(1);
}

/* ---------- component ---------- */

/**
 * @param {Object}  props
 * @param {Object}  props.node           Node data from useNetworkStore.
 * @param {boolean} [props.selected=false]
 * @param {Function} [props.onClose]     Close callback for panel mode.
 * @param {string}  [props.className]
 */
export default function NetworkNodeCard({
  node,
  selected = false,
  onClose,
  className = '',
}) {
  if (!node) return null;

  const tTokens = trustTokens(node.trust);

  return (
    <div
      className={`
        bg-rex-surface border rounded-2xl overflow-hidden transition-colors
        ${selected ? 'border-cyan-500/40' : 'border-rex-card'}
        ${className}
      `}
      role="region"
      aria-label={`Device details: ${node.label}`}
    >
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-rex-card">
        <div className="flex items-center gap-2 min-w-0">
          <DeviceTypeIcon type={node.type} />
          <h3 className="text-sm font-semibold text-rex-text truncate">
            {node.label}
          </h3>
        </div>
        {onClose && (
          <button
            onClick={onClose}
            className="text-rex-muted hover:text-rex-text transition-colors shrink-0"
            aria-label="Close device details"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        )}
      </div>

      {/* Body */}
      <div className="p-4 space-y-4">
        {/* Trust ring + badges row */}
        <div className="flex items-center gap-4">
          <TrustRing trust={node.trust} size={52} />
          <div className="flex flex-col gap-1.5">
            <Badge variant={statusBadgeVariant(node.status)} size="sm" dot>
              {node.status || 'unknown'}
            </Badge>
            <span className={`text-xs font-medium ${tTokens.text}`}>
              {tTokens.label}
            </span>
          </div>
        </div>

        {/* Details */}
        <div className="space-y-2">
          <Field label="IP Address" value={node.ip} mono />
          <Field label="MAC Address" value={node.mac} mono />
          <Field label="Type" value={typeLabel(node.type)} />
          {node.vendor && <Field label="Vendor" value={node.vendor} />}
          {node.os && <Field label="OS" value={node.os} />}
        </div>

        {/* Segment */}
        <div>
          <span className="text-xs text-rex-muted uppercase tracking-wide block mb-1.5">
            Segment
          </span>
          <SegmentBadge segment={node.segment} />
        </div>
      </div>
    </div>
  );
}

/* ---------- sub-components ---------- */

function Field({ label, value, mono }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-xs text-rex-muted">{label}</span>
      <span className={`text-xs text-rex-text ${mono ? 'font-mono' : ''}`}>
        {value || '--'}
      </span>
    </div>
  );
}

function DeviceTypeIcon({ type }) {
  const cls = 'w-5 h-5 text-rex-muted shrink-0';

  if (type === 'router' || type === 'gateway') {
    return (
      <svg className={cls} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5} aria-hidden="true">
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 013 12c0-1.605.42-3.113 1.157-4.418" />
      </svg>
    );
  }

  return (
    <svg className={cls} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5} aria-hidden="true">
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 17.25v1.007a3 3 0 01-.879 2.122L7.5 21h9l-.621-.621A3 3 0 0115 18.257V17.25m6-12V15a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 15V5.25A2.25 2.25 0 015.25 3h13.5A2.25 2.25 0 0121 5.25z" />
    </svg>
  );
}
