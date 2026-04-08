/**
 * SegmentBadge -- identifies a network segment with a colored pill.
 *
 * Color is derived deterministically from the segment string so
 * the same subnet always gets the same hue. Text label is always
 * present alongside color for accessibility.
 */

import React from 'react';

/* ---------- color palette ---------- */

const PALETTE = [
  { bg: 'bg-red-500/10',    text: 'text-red-300',    border: 'border-red-500/30' },
  { bg: 'bg-fuchsia-500/10', text: 'text-fuchsia-300', border: 'border-fuchsia-500/30' },
  { bg: 'bg-amber-500/10',   text: 'text-amber-300',   border: 'border-amber-500/30' },
  { bg: 'bg-emerald-500/10', text: 'text-emerald-300', border: 'border-emerald-500/30' },
  { bg: 'bg-sky-500/10',     text: 'text-sky-300',     border: 'border-sky-500/30' },
  { bg: 'bg-orange-500/10',  text: 'text-orange-300',  border: 'border-orange-500/30' },
  { bg: 'bg-indigo-500/10',  text: 'text-indigo-300',  border: 'border-indigo-500/30' },
];

function hashSegment(segment) {
  let hash = 0;
  for (let i = 0; i < segment.length; i++) {
    hash = ((hash << 5) - hash + segment.charCodeAt(i)) | 0;
  }
  return Math.abs(hash);
}

/**
 * @param {Object}  props
 * @param {string}  props.segment   Segment identifier (e.g. "192.168.1.0/24").
 * @param {string}  [props.className]
 */
export default function SegmentBadge({ segment, className = '' }) {
  if (!segment || segment === 'unknown') {
    return (
      <span
        className={`inline-flex items-center text-[10px] font-medium px-2 py-0.5 rounded-full border bg-slate-800/60 text-slate-400 border-slate-700 ${className}`}
      >
        Unknown segment
      </span>
    );
  }

  const palette = PALETTE[hashSegment(segment) % PALETTE.length];

  return (
    <span
      className={`inline-flex items-center text-[10px] font-mono font-medium px-2 py-0.5 rounded-full border ${palette.bg} ${palette.text} ${palette.border} ${className}`}
      title={`Network segment: ${segment}`}
    >
      {segment}
    </span>
  );
}
