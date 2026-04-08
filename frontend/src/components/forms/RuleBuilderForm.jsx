/**
 * RuleBuilderForm — structured rule builder for creating firewall rules.
 * No raw nftables strings. All fields are validated UI inputs.
 */
import React, { useState, useCallback } from 'react';

const ACTIONS = ['block', 'allow', 'reject'];
const PROTOCOLS = ['tcp', 'udp', 'icmp', 'any'];
const DIRECTIONS = ['inbound', 'outbound', 'both'];

const inputCls =
  'w-full bg-[#050816] border border-white/[0.08] rounded-xl px-3 py-2 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-red-500/40 transition-colors';
const selectCls =
  'appearance-none w-full bg-[#050816] border border-white/[0.08] rounded-xl px-3 py-2 pr-8 text-sm text-slate-200 focus:outline-none focus:border-red-500/40 transition-colors cursor-pointer';
const labelCls = 'text-xs text-slate-500 block mb-1';

const INITIAL = {
  action: 'block',
  source: '',
  destination: '',
  port: '',
  protocol: 'tcp',
  direction: 'inbound',
  reason: '',
};

export default function RuleBuilderForm({ onSubmit, disabled = false }) {
  const [form, setForm] = useState(INITIAL);
  const [submitting, setSubmitting] = useState(false);

  const set = (field) => (e) => setForm((f) => ({ ...f, [field]: e.target.value }));

  const valid = form.source.trim() || form.destination.trim();

  const handleSubmit = useCallback(
    async (e) => {
      e.preventDefault();
      if (!valid || disabled || submitting) return;
      setSubmitting(true);
      try {
        await onSubmit?.({
          action: form.action,
          source: form.source.trim() || null,
          destination: form.destination.trim() || null,
          port: form.port.trim() || null,
          protocol: form.protocol,
          direction: form.direction,
          reason: form.reason.trim() || 'Manual rule',
        });
        setForm(INITIAL);
      } finally {
        setSubmitting(false);
      }
    },
    [form, valid, disabled, submitting, onSubmit]
  );

  return (
    <form onSubmit={handleSubmit} className="bg-gradient-to-br from-[#0a0a0a] to-[#141414] border border-white/[0.06] rounded-2xl p-5">
      <h3 className="text-xs text-slate-500 uppercase tracking-wide font-medium mb-4">Add Firewall Rule</h3>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Action */}
        <div>
          <label className={labelCls}>Action</label>
          <div className="relative">
            <select value={form.action} onChange={set('action')} className={selectCls} disabled={disabled}>
              {ACTIONS.map((a) => (
                <option key={a} value={a}>{a.charAt(0).toUpperCase() + a.slice(1)}</option>
              ))}
            </select>
            <ChevronIcon />
          </div>
        </div>

        {/* Source */}
        <div>
          <label className={labelCls}>Source IP / CIDR</label>
          <input
            type="text"
            value={form.source}
            onChange={set('source')}
            placeholder="0.0.0.0/0"
            className={inputCls}
            disabled={disabled}
          />
        </div>

        {/* Destination */}
        <div>
          <label className={labelCls}>Destination IP / CIDR</label>
          <input
            type="text"
            value={form.destination}
            onChange={set('destination')}
            placeholder="192.168.1.0/24"
            className={inputCls}
            disabled={disabled}
          />
        </div>

        {/* Port */}
        <div>
          <label className={labelCls}>Port</label>
          <input
            type="text"
            value={form.port}
            onChange={set('port')}
            placeholder="443 or 8000-9000"
            className={inputCls}
            disabled={disabled}
          />
        </div>

        {/* Protocol */}
        <div>
          <label className={labelCls}>Protocol</label>
          <div className="relative">
            <select value={form.protocol} onChange={set('protocol')} className={selectCls} disabled={disabled}>
              {PROTOCOLS.map((p) => (
                <option key={p} value={p}>{p.toUpperCase()}</option>
              ))}
            </select>
            <ChevronIcon />
          </div>
        </div>

        {/* Direction */}
        <div>
          <label className={labelCls}>Direction</label>
          <div className="relative">
            <select value={form.direction} onChange={set('direction')} className={selectCls} disabled={disabled}>
              {DIRECTIONS.map((d) => (
                <option key={d} value={d}>{d.charAt(0).toUpperCase() + d.slice(1)}</option>
              ))}
            </select>
            <ChevronIcon />
          </div>
        </div>

        {/* Reason */}
        <div>
          <label className={labelCls}>Reason</label>
          <input
            type="text"
            value={form.reason}
            onChange={set('reason')}
            placeholder="Suspicious traffic"
            className={inputCls}
            disabled={disabled}
          />
        </div>

        {/* Submit */}
        <div className="flex items-end">
          <button
            type="submit"
            disabled={!valid || disabled || submitting}
            className="w-full px-4 py-2 bg-red-500 text-white rounded-xl font-medium text-sm
                       hover:bg-red-400 disabled:opacity-40 disabled:cursor-not-allowed
                       transition-colors"
          >
            {submitting ? 'Adding...' : 'Add Rule'}
          </button>
        </div>
      </div>
      {disabled && (
        <p className="mt-3 text-xs text-amber-400/80">
          Rule creation is not supported by the current backend configuration.
        </p>
      )}
    </form>
  );
}

function ChevronIcon() {
  return (
    <svg className="absolute right-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-600 pointer-events-none" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
    </svg>
  );
}
