/**
 * useInterviewStore — onboarding interview state.
 *
 * Tracks progress, current question, and submission lifecycle.
 * state starts as 'unknown' until backend confirms actual interview state.
 */
import { create } from 'zustand';
import {
  getInterviewStatus,
  getCurrentQuestion,
  submitInterviewAnswer,
} from '../api/interview';

const useInterviewStore = create((set, get) => ({
  // Interview status
  state: 'unknown', // 'unknown' | 'not_started' | 'in_progress' | 'completed'
  currentStep: 0,
  totalSteps: 0,
  completedAt: null,

  // Current question
  currentQuestion: null, // { id, prompt, options, type } | null

  // Lifecycle
  loading: false,
  submitting: false,
  error: null,

  // Chat history for display
  history: [],

  /* ---------- hydration ---------- */

  fetchStatus: async () => {
    if (get().loading) return;
    set({ loading: true, error: null });
    try {
      const status = await getInterviewStatus();
      set({
        state: status.state,
        currentStep: status.currentStep,
        totalSteps: status.totalSteps,
        completedAt: status.completedAt,
        loading: false,
      });

      // If in progress, also fetch the current question
      if (status.state === 'in_progress' || status.state === 'not_started') {
        try {
          const question = await getCurrentQuestion();
          set({ currentQuestion: question });
        } catch {
          // Question fetch failure is non-fatal; show the interview state anyway
          set({ currentQuestion: null });
        }
      }
    } catch (err) {
      set({
        error: err.message || 'Failed to fetch interview status',
        loading: false,
      });
    }
  },

  /* ---------- answer submission ---------- */

  submitAnswer: async (answer) => {
    const { currentQuestion, submitting } = get();
    if (submitting || !currentQuestion?.id) return false;

    set({ submitting: true, error: null });

    // Record the user answer in history
    set((s) => ({
      history: [
        ...s.history,
        { role: 'rex', text: currentQuestion.prompt },
        { role: 'user', text: answer },
      ],
    }));

    try {
      const result = await submitInterviewAnswer(currentQuestion.id, answer);

      if (result.accepted) {
        set((s) => ({
          currentStep: result.nextStep ?? s.currentStep + 1,
          submitting: false,
        }));

        // Fetch next question or detect completion
        try {
          const status = await getInterviewStatus();
          set({
            state: status.state,
            currentStep: status.currentStep,
            totalSteps: status.totalSteps,
            completedAt: status.completedAt,
          });

          if (status.state === 'in_progress') {
            const question = await getCurrentQuestion();
            set({ currentQuestion: question });
          } else {
            set({ currentQuestion: null });
          }
        } catch {
          // Non-fatal: question fetch can fail without breaking state
        }

        return true;
      }

      set({ submitting: false, error: 'Answer was not accepted' });
      return false;
    } catch (err) {
      set({
        error: err.message || 'Failed to submit answer',
        submitting: false,
      });
      return false;
    }
  },

  /* ---------- local setters ---------- */

  clearError: () => set({ error: null }),
  resetHistory: () => set({ history: [] }),
}));

export default useInterviewStore;
