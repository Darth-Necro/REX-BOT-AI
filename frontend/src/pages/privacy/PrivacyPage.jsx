/**
 * PrivacyPage — privacy signal cards + audit + data retention info.
 *
 * Fetches from usePrivacyStore. Renders honest states for each signal.
 * Audit button gated on capabilities.
 */
import React, { useEffect } from 'react';
import usePrivacyStore from '../../stores/usePrivacyStore';
import PrivacySignalCard from '../../components/cards/PrivacySignalCard';
import useSafeMutation from '../../hooks/useSafeMutation';
import { can } from '../../lib/permissions';

/* ---------- sub-components ---------- */

function SectionHeader({ title, subtitle }) {
  return (
    <div className="mb-3">
      <h2 className="text-sm font-bold tracking-widest uppercase text-slate-400">
        {title}
      </h2>
      {subtitle && (
        <p className="text-xs text-slate-600 mt-0.5">{subtitle}</p>
      )}
    </div>
  );
}

function RetentionCard({ retention }) {
  const policyLabel = retention.policy === 'unknown'
    ? 'Not reported'
    : retention.policy;

  return (
    <div className="rounded-[26px] border border-white/[0.06] bg-gradient-to-br from-[#0B1020] to-[#11192C] p-5">
      <h3 className="text-xs font-bold tracking-widest uppercase text-slate-400 mb-2">
        Data Retention
      </h3>
      <div className="space-y-2">
        <div className="flex justify-between items-center">
          <span className="text-sm text-slate-500">Policy</span>
          <span className="text-sm text-slate-200 capitalize">{policyLabel}</span>
        </div>
        {retention.days !== null && (
          <div className="flex justify-between items-center">
            <span className="text-sm text-slate-500">Duration</span>
            <span className="text-sm text-slate-200">
              {retention.days} day{retention.days !== 1 ? 's' : ''}
            </span>
          </div>
        )}
        {retention.days === null && retention.policy === 'unknown' && (
          <p className="text-xs text-slate-600">
            Retention settings not available from backend.
          </p>
        )}
      </div>
    </div>
  );
}

function AuditResultPanel({ result }) {
  if (!result) return null;

  return (
    <div className="rounded-[26px] border border-white/[0.06] bg-gradient-to-br from-[#0B1020] to-[#11192C] p-5 space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-xs font-bold tracking-widest uppercase text-slate-400">
          Audit Result
        </h3>
        <span className="text-[10px] text-slate-600">
          {result.ranAt ? new Date(result.ranAt).toLocaleString() : ''}
        </span>
      </div>

      {result.score !== null && (
        <div className="flex items-center gap-3">
          <span className="text-2xl font-bold text-slate-100 tabular-nums">
            {result.score}
          </span>
          <span className="text-xs text-slate-500">/100</span>
        </div>
      )}

      {result.findings.length > 0 ? (
        <ul className="space-y-1.5">
          {result.findings.map((f, i) => (
            <li
              key={i}
              className={`text-sm px-3 py-2 rounded-xl border ${
                f.severity === 'critical'
                  ? 'border-red-500/30 bg-red-500/5 text-red-300'
                  : f.severity === 'warning'
                    ? 'border-amber-500/30 bg-amber-500/5 text-amber-300'
                    : 'border-white/[0.06] bg-slate-800/40 text-slate-300'
              }`}
            >
              {f.message || f.description || JSON.stringify(f)}
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-xs text-slate-600">No findings reported.</p>
      )}
    </div>
  );
}

/* ---------- main page ---------- */

export default function PrivacyPage() {
  const {
    signals,
    retention,
    capabilities,
    loading,
    error,
    auditResult,
    auditing,
    auditError,
    fetchPrivacyState,
    runAudit,
  } = usePrivacyStore();

  const canAudit = can(capabilities, 'audit');

  useEffect(() => {
    fetchPrivacyState();
  }, [fetchPrivacyState]);

  const { mutate: handleAudit, isPending } = useSafeMutation(
    runAudit,
    { pending: 'Running privacy audit...', success: 'Audit complete', error: 'Audit failed' }
  );

  /* ---------- loading ---------- */

  if (loading) {
    return (
      <div className="p-6 lg:p-8 max-w-4xl mx-auto">
        <div className="flex items-center justify-center py-16">
          <div className="flex items-center gap-3 text-sm text-slate-500">
            <svg className="w-5 h-5 animate-spin text-cyan-400" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
            </svg>
            Loading privacy data...
          </div>
        </div>
      </div>
    );
  }

  /* ---------- render ---------- */

  return (
    <div className="p-6 lg:p-8 max-w-4xl mx-auto space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-slate-100 tracking-tight">
          Privacy
        </h1>
        <p className="text-sm text-slate-500 mt-1">
          Privacy signals, data retention, and audit controls.
        </p>
      </div>

      {/* Error banner */}
      {error && (
        <div className="rounded-xl border border-red-500/30 bg-red-500/5 p-3 text-sm text-red-300">
          {error}
        </div>
      )}

      {/* Privacy signals */}
      <section>
        <SectionHeader
          title="Privacy Signals"
          subtitle={signals.length > 0 ? `${signals.length} signal${signals.length !== 1 ? 's' : ''} reported` : 'No signals available from backend'}
        />

        {signals.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {signals.map((signal, i) => (
              <PrivacySignalCard
                key={signal.id || i}
                title={signal.title || signal.name || `Signal ${i + 1}`}
                value={signal.value ?? signal.status ?? null}
                verification={signal.verification || signal.state || 'unknown'}
                description={signal.description || null}
              />
            ))}
          </div>
        ) : (
          <div className="flex items-center justify-center py-8 text-sm text-slate-600">
            No privacy signals reported by backend.
          </div>
        )}
      </section>

      {/* Data retention */}
      <section>
        <SectionHeader title="Data Retention" />
        <RetentionCard retention={retention} />
      </section>

      {/* Audit */}
      <section>
        <SectionHeader
          title="Privacy Audit"
          subtitle={canAudit ? 'Run a privacy compliance check' : 'Audit capability not reported by backend'}
        />

        <div className="flex items-center gap-3">
          <button
            onClick={handleAudit}
            disabled={isPending || !canAudit}
            className="px-5 py-2 rounded-xl bg-cyan-500/20 text-cyan-300 text-sm font-medium border border-cyan-500/30 hover:bg-cyan-500/30 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            {isPending ? 'Running...' : 'Run Audit'}
          </button>

          {!canAudit && (
            <span className="text-xs text-slate-600">
              Not available -- backend does not report audit capability.
            </span>
          )}
        </div>

        {auditError && (
          <div className="mt-3 rounded-xl border border-red-500/30 bg-red-500/5 p-3 text-sm text-red-300">
            {auditError}
          </div>
        )}

        <div className="mt-4">
          <AuditResultPanel result={auditResult} />
        </div>
      </section>
    </div>
  );
}
