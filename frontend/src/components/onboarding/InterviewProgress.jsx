/**
 * InterviewProgress — step/total progress bar for the onboarding interview.
 *
 * Renders an honest progress bar: 0% when no steps are known,
 * actual fraction when totalSteps > 0.
 * Never fakes completion.
 */
import React from 'react';
import useInterviewStore from '../../stores/useInterviewStore';

export default function InterviewProgress() {
  const state = useInterviewStore((s) => s.state);
  const currentStep = useInterviewStore((s) => s.currentStep);
  const totalSteps = useInterviewStore((s) => s.totalSteps);

  const isCompleted = state === 'completed';
  const hasSteps = totalSteps > 0;
  const pct = hasSteps
    ? Math.min(100, Math.round((currentStep / totalSteps) * 100))
    : 0;

  // Display fraction only if we have real data
  const label = isCompleted
    ? 'Complete'
    : hasSteps
      ? `Step ${currentStep} of ${totalSteps}`
      : state === 'unknown'
        ? 'Progress unknown'
        : 'Waiting...';

  return (
    <div className="space-y-2">
      {/* Header */}
      <div className="flex items-center justify-between">
        <span className="text-xs font-bold tracking-widest uppercase text-slate-400">
          Interview Progress
        </span>
        <span className="text-xs text-slate-500 tabular-nums">
          {label}
        </span>
      </div>

      {/* Progress bar */}
      <div className="h-2 rounded-full bg-slate-800/60 border border-white/[0.04] overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-500 ease-out ${
            isCompleted
              ? 'bg-emerald-400'
              : pct > 0
                ? 'bg-cyan-400'
                : 'bg-slate-700'
          }`}
          style={{ width: `${isCompleted ? 100 : pct}%` }}
        />
      </div>

      {/* Percentage text */}
      {hasSteps && !isCompleted && (
        <p className="text-[10px] text-slate-600 text-right tabular-nums">
          {pct}%
        </p>
      )}
    </div>
  );
}
