/**
 * InterviewChat — REX onboarding interview conversation UI.
 *
 * Shows REX prompts and user response options/chips.
 * Displays honest loading/empty/completed states.
 * Never fakes questions or progress.
 */
import React, { useRef, useEffect, useState } from 'react';
import useInterviewStore from '../../stores/useInterviewStore';

/* ---------- message bubble ---------- */

function ChatBubble({ role, text }) {
  const isRex = role === 'rex';
  return (
    <div className={`flex ${isRex ? 'justify-start' : 'justify-end'}`}>
      <div
        className={`
          max-w-[80%] px-4 py-3 rounded-2xl text-sm leading-relaxed
          ${isRex
            ? 'bg-slate-800/60 border border-white/[0.06] text-slate-200'
            : 'bg-red-500/15 border border-red-500/20 text-red-100'
          }
        `}
      >
        {isRex && (
          <span className="text-[10px] font-bold text-red-400 tracking-widest uppercase block mb-1">
            REX
          </span>
        )}
        {text}
      </div>
    </div>
  );
}

/* ---------- option chip ---------- */

function OptionChip({ label, onClick, disabled }) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className="px-4 py-2 rounded-xl bg-slate-800/60 border border-white/[0.06] text-sm text-slate-200 hover:bg-red-500/10 hover:border-red-500/20 hover:text-red-200 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
    >
      {label}
    </button>
  );
}

/* ---------- main component ---------- */

export default function InterviewChat() {
  const {
    state,
    currentQuestion,
    loading,
    submitting,
    error,
    history,
    submitAnswer,
  } = useInterviewStore();

  const scrollRef = useRef(null);
  const [freeText, setFreeText] = useState('');

  // Auto-scroll to bottom on new messages
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [history, currentQuestion]);

  /* ---------- loading state ---------- */

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="flex items-center gap-3 text-sm text-slate-500">
          <svg className="w-5 h-5 animate-spin text-red-400" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
          </svg>
          Loading interview...
        </div>
      </div>
    );
  }

  /* ---------- completed state ---------- */

  if (state === 'completed') {
    return (
      <div className="flex flex-col items-center justify-center py-12 gap-3">
        <div className="w-12 h-12 rounded-full bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center">
          <svg className="w-6 h-6 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
          </svg>
        </div>
        <p className="text-sm text-slate-300 font-medium">Onboarding complete</p>
        <p className="text-xs text-slate-500">REX has been configured based on your answers.</p>
      </div>
    );
  }

  /* ---------- unknown / error state ---------- */

  if (state === 'unknown' && !loading) {
    return (
      <div className="flex flex-col items-center justify-center py-12 gap-2">
        <p className="text-sm text-slate-500">
          Interview status unknown -- backend may not support onboarding yet.
        </p>
        {error && (
          <p className="text-xs text-red-400">{error}</p>
        )}
      </div>
    );
  }

  /* ---------- active interview ---------- */

  const hasOptions = currentQuestion?.options?.length > 0;
  const isTextType = currentQuestion?.type === 'text' || (!hasOptions && currentQuestion);

  const handleSubmitFreeText = () => {
    if (!freeText.trim() || submitting) return;
    submitAnswer(freeText.trim());
    setFreeText('');
  };

  return (
    <div className="flex flex-col h-full">
      {/* Chat history */}
      <div
        ref={scrollRef}
        className="flex-1 overflow-y-auto space-y-3 p-4"
      >
        {history.map((msg, i) => (
          <ChatBubble key={i} role={msg.role} text={msg.text} />
        ))}

        {/* Current question prompt */}
        {currentQuestion?.prompt && (
          <ChatBubble role="rex" text={currentQuestion.prompt} />
        )}

        {/* No question available */}
        {!currentQuestion && state === 'in_progress' && (
          <div className="text-xs text-slate-600 text-center py-2">
            Waiting for next question...
          </div>
        )}
      </div>

      {/* Error banner */}
      {error && (
        <div className="mx-4 mb-2 rounded-xl border border-red-500/30 bg-red-500/5 p-2 text-xs text-red-300">
          {error}
        </div>
      )}

      {/* Response area */}
      {currentQuestion && (
        <div className="border-t border-white/[0.06] p-4">
          {/* Option chips */}
          {hasOptions && (
            <div className="flex flex-wrap gap-2">
              {currentQuestion.options.map((opt, i) => (
                <OptionChip
                  key={i}
                  label={typeof opt === 'string' ? opt : opt.label || opt.value || String(opt)}
                  onClick={() => submitAnswer(typeof opt === 'string' ? opt : opt.value || String(opt))}
                  disabled={submitting}
                />
              ))}
            </div>
          )}

          {/* Free text input */}
          {isTextType && !hasOptions && (
            <div className="flex gap-2">
              <input
                type="text"
                value={freeText}
                onChange={(e) => setFreeText(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleSubmitFreeText()}
                placeholder="Type your answer..."
                disabled={submitting}
                className="flex-1 bg-slate-900/60 border border-white/[0.06] rounded-xl px-3 py-2 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-red-500/40 focus:ring-1 focus:ring-red-500/20 disabled:opacity-40 transition-colors"
              />
              <button
                onClick={handleSubmitFreeText}
                disabled={submitting || !freeText.trim()}
                className="px-4 py-2 rounded-xl bg-red-500/20 text-red-300 text-sm font-medium border border-red-500/30 hover:bg-red-500/30 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
              >
                {submitting ? 'Sending...' : 'Send'}
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
