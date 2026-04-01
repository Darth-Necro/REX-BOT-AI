/**
 * Type-scale helpers for REX-BOT-AI.
 *
 * Tailwind already provides a solid type scale; this module defines
 * named semantic presets so pages stay consistent without hunting for
 * the right combination of classes.
 *
 * Every preset returns a className string.
 */

export const type = {
  /** Page heading (e.g. "Network Map"). */
  pageTitle: 'text-xl font-bold text-slate-100 tracking-tight',

  /** Section heading inside a page. */
  sectionTitle: 'text-sm font-semibold text-slate-300 tracking-wide',

  /** Card title. */
  cardTitle: 'text-sm font-medium text-slate-200',

  /** Small label text (uppercase). */
  label: 'text-xs text-rex-muted uppercase tracking-wide font-medium',

  /** Body / description text. */
  body: 'text-sm text-slate-300 leading-relaxed',

  /** Muted helper text. */
  caption: 'text-xs text-rex-muted',

  /** Mono-spaced data values (IPs, MACs, IDs). */
  mono: 'text-xs font-mono text-slate-300',

  /** Large stat number on a card. */
  stat: 'text-2xl font-bold tabular-nums text-slate-100',

  /** Inline code / KB reference. */
  code: 'text-xs font-mono bg-slate-800/60 px-1.5 py-0.5 rounded text-slate-300',
};
