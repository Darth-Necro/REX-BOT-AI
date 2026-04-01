/**
 * ReasoningPanel -- shows REX's analysis chain for a threat or incident.
 *
 * Critical design rule: every inference is explicitly labeled as
 * "REX Analysis" -- never presented as fact.  This prevents the UI
 * from creating false confidence in automated conclusions.
 */

import React from 'react';
import Badge from '../primitives/Badge';
import EmptyState from '../primitives/EmptyState';

/* ---------- component ---------- */

/**
 * @param {Object}   props
 * @param {Array}    [props.steps]       Array of { summary, detail?, confidence?, sources? }.
 * @param {string}   [props.conclusion]  Final conclusion text.
 * @param {boolean}  [props.loading=false]
 * @param {string}   [props.className]
 */
export default function ReasoningPanel({
  steps = [],
  conclusion,
  loading = false,
  className = '',
}) {
  if (loading) {
    return <EmptyState variant="loading" heading="Analyzing" />;
  }

  if (steps.length === 0 && !conclusion) {
    return (
      <EmptyState
        variant="empty"
        heading="No analysis available"
        description="REX has not produced reasoning data for this item."
      />
    );
  }

  return (
    <div
      className={`space-y-4 ${className}`}
      role="region"
      aria-label="REX analysis reasoning"
    >
      {/* Disclaimer banner */}
      <div className="flex items-start gap-2 bg-amber-500/5 border border-amber-500/20 rounded-xl px-4 py-3">
        <svg className="w-4 h-4 text-amber-400 mt-0.5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5} aria-hidden="true">
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
        </svg>
        <div>
          <p className="text-xs font-semibold text-amber-300">
            REX Analysis -- Not Verified Fact
          </p>
          <p className="text-[10px] text-amber-200/70 mt-0.5">
            The following is automated reasoning by REX. It represents inference, not direct observation. Verify before acting on conclusions.
          </p>
        </div>
      </div>

      {/* Reasoning steps */}
      {steps.length > 0 && (
        <ol className="space-y-3" aria-label="Reasoning steps">
          {steps.map((step, i) => (
            <li key={i} className="flex gap-3">
              {/* Step number */}
              <span
                className="shrink-0 w-6 h-6 rounded-full bg-slate-700/50 flex items-center justify-center text-[10px] font-bold text-slate-400"
                aria-hidden="true"
              >
                {i + 1}
              </span>

              <div className="min-w-0 flex-1 space-y-1">
                <p className="text-sm text-slate-200">{step.summary}</p>

                {step.detail && (
                  <p className="text-xs text-slate-400 leading-relaxed">
                    {step.detail}
                  </p>
                )}

                <div className="flex flex-wrap items-center gap-2">
                  <Badge variant="amber" size="sm">Inference</Badge>

                  {step.confidence != null && (
                    <span className="text-[10px] text-rex-muted">
                      Confidence: {formatConfidence(step.confidence)}
                    </span>
                  )}

                  {step.sources && step.sources.length > 0 && (
                    <span className="text-[10px] text-rex-muted">
                      Sources: {step.sources.join(', ')}
                    </span>
                  )}
                </div>
              </div>
            </li>
          ))}
        </ol>
      )}

      {/* Conclusion */}
      {conclusion && (
        <div className="bg-slate-800/40 border border-slate-700/40 rounded-xl px-4 py-3">
          <div className="flex items-center gap-2 mb-1.5">
            <Badge variant="amber" size="sm">Inferred Conclusion</Badge>
          </div>
          <p className="text-sm text-slate-200 leading-relaxed">{conclusion}</p>
        </div>
      )}
    </div>
  );
}

/* ---------- helpers ---------- */

function formatConfidence(value) {
  if (typeof value === 'number') {
    return value <= 1
      ? `${Math.round(value * 100)}%`
      : `${Math.round(value)}%`;
  }
  return String(value);
}
