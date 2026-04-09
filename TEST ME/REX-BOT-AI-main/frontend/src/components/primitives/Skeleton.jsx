/**
 * Skeleton -- loading placeholder primitives.
 *
 * Provides Card, Row, and Text variants that pulse to indicate loading.
 * All skeletons are aria-hidden so screen readers skip them.
 */

import React from 'react';

/* ---------- base shimmer ---------- */

function Shimmer({ className = '' }) {
  return (
    <div
      aria-hidden="true"
      className={`animate-pulse rounded bg-slate-700/40 ${className}`}
    />
  );
}

/* ---------- card skeleton ---------- */

/**
 * Placeholder for a card-shaped component.
 * @param {{ className?: string }} props
 */
export function SkeletonCard({ className = '' }) {
  return (
    <div
      aria-hidden="true"
      className={`animate-pulse rounded-2xl border border-slate-700/30 bg-rex-surface p-4 space-y-3 ${className}`}
    >
      <Shimmer className="h-4 w-3/5" />
      <Shimmer className="h-3 w-4/5" />
      <Shimmer className="h-3 w-2/5" />
    </div>
  );
}

/* ---------- table row skeleton ---------- */

/**
 * Placeholder for a table row.
 * @param {{ cols?: number, className?: string }} props
 */
export function SkeletonRow({ cols = 5, className = '' }) {
  return (
    <tr aria-hidden="true" className={className}>
      {Array.from({ length: cols }, (_, i) => (
        <td key={i} className="px-4 py-3">
          <Shimmer className="h-3 w-full" />
        </td>
      ))}
    </tr>
  );
}

/**
 * Multiple skeleton rows for a loading table.
 * @param {{ rows?: number, cols?: number }} props
 */
export function SkeletonTable({ rows = 5, cols = 5 }) {
  return (
    <tbody aria-hidden="true">
      {Array.from({ length: rows }, (_, i) => (
        <SkeletonRow key={i} cols={cols} />
      ))}
    </tbody>
  );
}

/* ---------- text line skeleton ---------- */

/**
 * Placeholder for a text line.
 * @param {{ width?: string, className?: string }} props
 */
export function SkeletonText({ width = 'w-3/4', className = '' }) {
  return <Shimmer className={`h-3 ${width} ${className}`} />;
}

/* ---------- panel skeleton ---------- */

/**
 * Placeholder for a side panel.
 * @param {{ className?: string }} props
 */
export function SkeletonPanel({ className = '' }) {
  return (
    <div
      aria-hidden="true"
      className={`animate-pulse space-y-4 p-4 ${className}`}
    >
      <Shimmer className="h-5 w-2/5" />
      <Shimmer className="h-3 w-full" />
      <Shimmer className="h-3 w-4/5" />
      <div className="pt-2 space-y-2">
        <Shimmer className="h-3 w-3/5" />
        <Shimmer className="h-3 w-2/5" />
      </div>
      <div className="pt-2 space-y-2">
        <Shimmer className="h-3 w-4/5" />
        <Shimmer className="h-3 w-1/2" />
      </div>
    </div>
  );
}

/* ---------- default export ---------- */

export default Shimmer;
