/**
 * TrustRing -- circular trust score visualization.
 *
 * Renders an SVG ring that fills proportionally to the trust score (0-100).
 * Color changes with trust tier for visual clarity, but the numeric value
 * and tier label are always shown for accessibility.
 *
 * Accessible: aria-label + visible text label so color is never sole carrier.
 */

import React from 'react';
import { normalizeTrust, trustTier, trustStrokeColor, TRUST_TOKENS } from '../../lib/trust';

const RADIUS = 18;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

/**
 * @param {Object}   props
 * @param {string|number|null} props.trust  Raw trust value from backend.
 * @param {number}   [props.size=48]        SVG width/height in px.
 * @param {string}   [props.className]
 */
export default function TrustRing({ trust, size = 48, className = '' }) {
  const score = normalizeTrust(trust);
  const tier = trustTier(score);
  const tokens = TRUST_TOKENS[tier] || TRUST_TOKENS.unknown;
  const strokeClass = trustStrokeColor(tier);

  // Arc length
  const isKnown = score >= 0;
  const pct = isKnown ? score / 100 : 0;
  const dashArray = `${pct * CIRCUMFERENCE} ${CIRCUMFERENCE}`;

  return (
    <div
      className={`inline-flex flex-col items-center gap-1 ${className}`}
      role="img"
      aria-label={isKnown ? `Trust score: ${score} out of 100, tier: ${tokens.label}` : 'Trust score: unknown'}
    >
      <svg
        width={size}
        height={size}
        viewBox="0 0 44 44"
        className="transform -rotate-90"
        aria-hidden="true"
      >
        {/* Background ring */}
        <circle
          cx="22" cy="22" r={RADIUS}
          fill="none"
          strokeWidth="3"
          className="stroke-slate-700/50"
        />
        {/* Foreground arc */}
        {isKnown && (
          <circle
            cx="22" cy="22" r={RADIUS}
            fill="none"
            strokeWidth="3"
            strokeLinecap="round"
            strokeDasharray={dashArray}
            className={`${strokeClass} transition-all duration-500`}
          />
        )}
      </svg>

      {/* Center label */}
      <span className={`text-[10px] font-medium ${tokens.text}`}>
        {isKnown ? `${score}` : '?'}
      </span>
    </div>
  );
}
