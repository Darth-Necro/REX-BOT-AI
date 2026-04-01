/**
 * Interview / Onboarding API module.
 * Drives the REX onboarding interview flow.
 * Every function returns normalised data with honest defaults.
 */
import api from './client';

const ALLOWED_INTERVIEW_STATES = new Set([
  'not_started',
  'in_progress',
  'completed',
]);

/**
 * GET /api/onboarding/status — interview progress.
 * @returns {Promise<{ state: string, currentStep: number, totalSteps: number, completedAt: string|null }>}
 */
export async function getInterviewStatus() {
  const res = await api.get('/onboarding/status');
  const raw = res.data;

  if (!raw || typeof raw !== 'object') {
    return {
      state: 'unknown',
      currentStep: 0,
      totalSteps: 0,
      completedAt: null,
    };
  }

  const rawState = typeof raw.state === 'string' ? raw.state.toLowerCase().trim() : '';

  return {
    state: ALLOWED_INTERVIEW_STATES.has(rawState) ? rawState : 'unknown',
    currentStep: typeof raw.current_step === 'number' ? raw.current_step : (typeof raw.currentStep === 'number' ? raw.currentStep : 0),
    totalSteps: typeof raw.total_steps === 'number' ? raw.total_steps : (typeof raw.totalSteps === 'number' ? raw.totalSteps : 0),
    completedAt: typeof raw.completed_at === 'string' ? raw.completed_at : (typeof raw.completedAt === 'string' ? raw.completedAt : null),
  };
}

/**
 * GET /api/onboarding/question — current interview question.
 * @returns {Promise<{ id: string|null, prompt: string, options: Array, type: string }>}
 */
export async function getCurrentQuestion() {
  const res = await api.get('/onboarding/question');
  const raw = res.data;

  if (!raw || typeof raw !== 'object') {
    return { id: null, prompt: '', options: [], type: 'text' };
  }

  return {
    id: raw.id ?? null,
    prompt: typeof raw.prompt === 'string' ? raw.prompt : '',
    options: Array.isArray(raw.options) ? raw.options : [],
    type: typeof raw.type === 'string' ? raw.type : 'text',
  };
}

/**
 * POST /api/onboarding/answer — submit an answer to the current question.
 * @param {string} questionId
 * @param {string} answer
 * @returns {Promise<{ accepted: boolean, nextStep: number|null }>}
 */
export async function submitInterviewAnswer(questionId, answer) {
  const res = await api.post('/onboarding/answer', {
    question_id: questionId,
    answer,
  });
  const raw = res.data;

  if (!raw || typeof raw !== 'object') {
    return { accepted: false, nextStep: null };
  }

  return {
    accepted: raw.accepted === true,
    nextStep: typeof raw.next_step === 'number' ? raw.next_step : (typeof raw.nextStep === 'number' ? raw.nextStep : null),
  };
}
