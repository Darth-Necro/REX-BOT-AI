/**
 * Centralized shadow and glow tokens for REX-BOT-AI dark theme.
 *
 * Shadows are intentionally subtle in a dark UI -- most depth cues come
 * from background-color layering rather than drop shadows.
 * Glows are the primary accent; they map to the cyan / red / amber palette.
 */

/* ---------- box shadows (CSS values) ---------- */

export const shadow = {
  none: 'none',
  sm: '0 1px 2px 0 rgba(0, 0, 0, 0.3)',
  md: '0 4px 6px -1px rgba(0, 0, 0, 0.4), 0 2px 4px -2px rgba(0, 0, 0, 0.3)',
  lg: '0 10px 15px -3px rgba(0, 0, 0, 0.5), 0 4px 6px -4px rgba(0, 0, 0, 0.4)',
  xl: '0 20px 25px -5px rgba(0, 0, 0, 0.6), 0 8px 10px -6px rgba(0, 0, 0, 0.5)',
};

/* ---------- glows (box-shadow style) ---------- */

export const glow = {
  cyan: '0 0 12px rgba(34, 211, 238, 0.25)',
  cyanStrong: '0 0 20px rgba(34, 211, 238, 0.45)',
  red: '0 0 12px rgba(239, 68, 68, 0.30)',
  amber: '0 0 12px rgba(234, 179, 8, 0.25)',
  emerald: '0 0 12px rgba(16, 185, 129, 0.25)',
};

/* ---------- Tailwind utility class fragments ---------- */

export const glowClass = {
  cyan: 'shadow-[0_0_12px_rgba(34,211,238,0.25)]',
  cyanStrong: 'shadow-[0_0_20px_rgba(34,211,238,0.45)]',
  red: 'shadow-[0_0_12px_rgba(239,68,68,0.30)]',
  amber: 'shadow-[0_0_12px_rgba(234,179,8,0.25)]',
  emerald: 'shadow-[0_0_12px_rgba(16,185,129,0.25)]',
};
