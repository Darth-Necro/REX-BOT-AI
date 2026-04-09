/**
 * Centralized motion / animation tokens for REX-BOT-AI.
 *
 * All durations in milliseconds.  Easing curves use CSS cubic-bezier values.
 * Import these in components instead of hard-coding timing values so the
 * entire UI can be tuned from one place (or reduced-motion can be applied).
 */

/* ---------- durations ---------- */

export const duration = {
  instant: 75,
  fast: 150,
  normal: 250,
  slow: 400,
  page: 500,
};

/* ---------- easing ---------- */

export const easing = {
  /** Smooth deceleration -- good for enter/appear animations. */
  out: 'cubic-bezier(0.16, 1, 0.3, 1)',
  /** Smooth acceleration -- good for exit/dismiss animations. */
  in: 'cubic-bezier(0.55, 0, 1, 0.45)',
  /** Standard ease for most transitions. */
  inOut: 'cubic-bezier(0.4, 0, 0.2, 1)',
  /** Slight bounce at the end. Use sparingly. */
  bounce: 'cubic-bezier(0.34, 1.56, 0.64, 1)',
};

/* ---------- Tailwind-friendly class fragments ---------- */

export const transition = {
  fast: `transition-all duration-[${duration.fast}ms] ease-[${easing.inOut}]`,
  normal: `transition-all duration-[${duration.normal}ms] ease-[${easing.inOut}]`,
  slow: `transition-all duration-[${duration.slow}ms] ease-[${easing.out}]`,
  color: 'transition-colors duration-200 ease-in-out',
};

/**
 * Helper: returns true when the user prefers reduced motion.
 * Call at runtime (not at import time) so SSR does not throw.
 */
export function prefersReducedMotion() {
  if (typeof window === 'undefined') return false;
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}
