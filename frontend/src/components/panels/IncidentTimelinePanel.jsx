/**
 * IncidentTimelinePanel -- chronological event timeline.
 *
 * Events are tagged as OBSERVED, INFERRED, or EXECUTED so the user
 * can distinguish facts from analysis from actions.  Color + icon +
 * text label all convey the category (never color alone).
 */

import React from 'react';
import Badge from '../primitives/Badge';
import EmptyState from '../primitives/EmptyState';
import { formatDateTime, timeAgo } from '../../lib/formatters';

/* ---------- event kind config ---------- */

const KIND_CONFIG = {
  observed: {
    label: 'Observed',
    variant: 'red',
    icon: ObservedIcon,
    description: 'Directly captured by REX sensors.',
  },
  inferred: {
    label: 'Inferred',
    variant: 'amber',
    icon: InferredIcon,
    description: 'Analysis by REX -- not a direct observation.',
  },
  executed: {
    label: 'Executed',
    variant: 'emerald',
    icon: ExecutedIcon,
    description: 'Action taken by REX or the operator.',
  },
};

/* ---------- component ---------- */

/**
 * @param {Object}  props
 * @param {Array}   props.events     Array of { kind, timestamp, title, detail? }.
 * @param {boolean} [props.loading=false]
 * @param {string}  [props.className]
 */
export default function IncidentTimelinePanel({
  events = [],
  loading = false,
  className = '',
}) {
  if (loading) {
    return <EmptyState variant="loading" heading="Loading timeline" />;
  }

  if (events.length === 0) {
    return (
      <EmptyState
        variant="empty"
        heading="No events"
        description="No incident events are available for this item."
      />
    );
  }

  // Sort chronologically (oldest first)
  const sorted = [...events].sort(
    (a, b) => new Date(a.timestamp) - new Date(b.timestamp),
  );

  return (
    <div
      className={`space-y-0 ${className}`}
      role="list"
      aria-label="Incident timeline"
    >
      {sorted.map((event, i) => {
        const config = KIND_CONFIG[event.kind] || KIND_CONFIG.observed;
        const Icon = config.icon;
        const isLast = i === sorted.length - 1;

        return (
          <div
            key={i}
            role="listitem"
            className="relative flex gap-3 pb-6"
          >
            {/* Vertical connector line */}
            {!isLast && (
              <span
                className="absolute left-[11px] top-7 bottom-0 w-px bg-slate-700/50"
                aria-hidden="true"
              />
            )}

            {/* Icon */}
            <div className="shrink-0 mt-0.5">
              <Icon />
            </div>

            {/* Content */}
            <div className="min-w-0 flex-1 space-y-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-sm font-medium text-rex-text">
                  {event.title || 'Event'}
                </span>
                <Badge variant={config.variant} size="sm">
                  {config.label}
                </Badge>
              </div>

              {event.detail && (
                <p className="text-xs text-slate-400 leading-relaxed">
                  {event.detail}
                </p>
              )}

              <p className="text-[10px] text-rex-muted font-mono">
                {formatDateTime(event.timestamp)}
                {event.timestamp && (
                  <span className="ml-2 text-slate-600">
                    ({timeAgo(event.timestamp)})
                  </span>
                )}
              </p>
            </div>
          </div>
        );
      })}
    </div>
  );
}

/* ---------- icons ---------- */

function ObservedIcon() {
  return (
    <svg className="w-6 h-6 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5} aria-hidden="true">
      <path strokeLinecap="round" strokeLinejoin="round" d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z" />
      <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
    </svg>
  );
}

function InferredIcon() {
  return (
    <svg className="w-6 h-6 text-amber-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5} aria-hidden="true">
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 18v-5.25m0 0a6.01 6.01 0 001.5-.189m-1.5.189a6.01 6.01 0 01-1.5-.189m3.75 7.478a12.06 12.06 0 01-4.5 0m3.75 2.383a14.406 14.406 0 01-3 0M14.25 18v-.192c0-.983.658-1.823 1.508-2.316a7.5 7.5 0 10-7.517 0c.85.493 1.509 1.333 1.509 2.316V18" />
    </svg>
  );
}

function ExecutedIcon() {
  return (
    <svg className="w-6 h-6 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5} aria-hidden="true">
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
  );
}
