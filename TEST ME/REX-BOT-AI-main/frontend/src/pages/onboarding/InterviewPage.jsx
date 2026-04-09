/**
 * InterviewPage — onboarding interview chat + progress + completion CTA.
 *
 * Fetches interview status on mount. Renders InterviewChat and
 * InterviewProgress. Honest about unknown/error states.
 */
import React, { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import useInterviewStore from '../../stores/useInterviewStore';
import InterviewChat from '../../components/onboarding/InterviewChat';
import InterviewProgress from '../../components/onboarding/InterviewProgress';

export default function InterviewPage() {
  const { state, fetchStatus, completedAt } = useInterviewStore();
  const navigate = useNavigate();

  useEffect(() => {
    fetchStatus();
  }, [fetchStatus]);

  return (
    <div className="p-6 lg:p-8 max-w-3xl mx-auto space-y-6 h-full flex flex-col">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-slate-100 tracking-tight">
          REX Onboarding
        </h1>
        <p className="text-sm text-slate-500 mt-1">
          {state === 'completed'
            ? 'Onboarding has been completed.'
            : state === 'in_progress'
              ? 'Answer the questions below to configure REX for your environment.'
              : state === 'not_started'
                ? 'Start the interview to configure REX.'
                : 'Checking onboarding status...'}
        </p>
      </div>

      {/* Progress bar */}
      <InterviewProgress />

      {/* Chat area */}
      <div className="flex-1 min-h-0 rounded-[26px] border border-white/[0.06] bg-gradient-to-br from-[#0B1020] to-[#11192C] overflow-hidden flex flex-col">
        <InterviewChat />
      </div>

      {/* Completion CTA */}
      {state === 'completed' && (
        <div className="flex items-center justify-between rounded-[26px] border border-emerald-500/20 bg-emerald-500/5 p-5">
          <div>
            <p className="text-sm font-medium text-emerald-300">Setup complete</p>
            <p className="text-xs text-slate-500 mt-0.5">
              {completedAt
                ? `Finished ${new Date(completedAt).toLocaleString()}`
                : 'REX is configured and ready.'}
            </p>
          </div>
          <button
            onClick={() => navigate('/overview')}
            className="px-5 py-2 rounded-xl bg-cyan-500/20 text-cyan-300 text-sm font-medium border border-cyan-500/30 hover:bg-cyan-500/30 transition-colors"
          >
            Go to Dashboard
          </button>
        </div>
      )}
    </div>
  );
}
