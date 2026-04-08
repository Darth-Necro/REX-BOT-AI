/**
 * ThreatDetailsPage -- full drilldown into a single threat.
 *
 * Shows three cards: Facts (observed data), Analysis (REX inference),
 * and Actions (what was/can be done).
 *
 * No fabricated data. Sections degrade gracefully when fields are absent.
 */

import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { getThreat } from '../../api/threats';
import useThreatStore from '../../stores/useThreatStore';
import Badge from '../../components/primitives/Badge';
import Button from '../../components/primitives/Button';
import EmptyState from '../../components/primitives/EmptyState';
import { SkeletonCard } from '../../components/primitives/Skeleton';
import { severityTokens, normalizeSeverity } from '../../lib/severity';
import { formatDateTime, timeAgo } from '../../lib/formatters';

/* ---------- page ---------- */

export default function ThreatDetailsPage() {
  const { id } = useParams();
  const [threat, setThreat] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!id) return;
    let cancelled = false;

    setLoading(true);
    setError(null);

    getThreat(id)
      .then((data) => {
        if (!cancelled) {
          setThreat(data);
          setLoading(false);
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setError(err.message || 'Failed to load threat details');
          setLoading(false);
        }
      });

    return () => { cancelled = true; };
  }, [id]);

  if (loading) {
    return (
      <div className="p-4 md:p-6 space-y-4">
        <SkeletonCard />
        <SkeletonCard />
        <SkeletonCard />
      </div>
    );
  }

  if (error || !threat) {
    return (
      <div className="p-4 md:p-6">
        <EmptyState
          variant="error"
          heading="Threat not found"
          description={error || `Could not load threat ${id}.`}
          action={
            <Link to="/threats" className="text-xs text-cyan-400 hover:underline">
              Back to Threats
            </Link>
          }
        />
      </div>
    );
  }

  const sev = normalizeSeverity(threat.severity);
  const sevTokens = severityTokens(threat.severity);
  const isResolved = threat.resolved || threat.status === 'resolved';

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-4xl">
      {/* Breadcrumb */}
      <nav aria-label="Breadcrumb" className="text-xs text-rex-muted">
        <Link to="/threats" className="hover:text-cyan-400 transition-colors">
          Threats
        </Link>
        <span className="mx-2">/</span>
        <span className="text-slate-300">{threat.id || id}</span>
      </nav>

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div className="flex items-center gap-3">
          <h1 className="text-xl font-bold text-slate-100">
            {threat.title || threat.category || 'Threat Details'}
          </h1>
          <Badge variant={sevTokens.text.includes('red') ? 'red' : sevTokens.text.includes('orange') ? 'orange' : sevTokens.text.includes('amber') ? 'amber' : 'default'} dot>
            {sev}
          </Badge>
          {isResolved && (
            <Badge variant="emerald" dot>Resolved</Badge>
          )}
        </div>
      </div>

      {/* Facts card */}
      <section
        className="bg-rex-surface border border-rex-card rounded-2xl p-5 space-y-4"
        aria-label="Observed facts"
      >
        <h2 className="text-sm font-semibold text-slate-300 flex items-center gap-2">
          <ObservedIcon />
          Facts (Observed)
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <Field label="Severity" value={sev} capitalize />
          <Field label="Status" value={isResolved ? 'Resolved' : (threat.status || 'Active')} capitalize />
          <Field label="Category" value={threat.category} capitalize />
          <Field label="Source Device" value={threat.source_device} />
          <Field label="Source IP" value={threat.source_ip} mono />
          <Field label="Source MAC" value={threat.source_mac} mono />
          <Field label="Detected At" value={formatDateTime(threat.timestamp)} />
          {threat.timestamp && (
            <Field label="Time Ago" value={timeAgo(threat.timestamp)} />
          )}
        </div>
        {threat.description && (
          <div>
            <span className="text-xs text-rex-muted block mb-1">Description</span>
            <p className="text-sm text-slate-200 leading-relaxed">{threat.description}</p>
          </div>
        )}
      </section>

      {/* Analysis card */}
      <section
        className="bg-rex-surface border border-amber-500/20 rounded-2xl p-5 space-y-4"
        aria-label="REX analysis"
      >
        <h2 className="text-sm font-semibold text-amber-300 flex items-center gap-2">
          <InferredIcon />
          Analysis (REX Inference)
        </h2>
        <div className="bg-amber-500/5 border border-amber-500/15 rounded-xl px-3 py-2">
          <p className="text-[10px] text-amber-200/70">
            The following is automated analysis. It represents inference, not verified fact.
          </p>
        </div>
        {threat.analysis || threat.reasoning ? (
          <p className="text-sm text-slate-300 leading-relaxed">
            {threat.analysis || threat.reasoning}
          </p>
        ) : (
          <p className="text-xs text-rex-muted italic">
            No automated analysis is available for this threat.
          </p>
        )}
        {threat.confidence != null && (
          <Field label="Confidence" value={formatConfidence(threat.confidence)} />
        )}
      </section>

      {/* Actions card */}
      <section
        className="bg-rex-surface border border-rex-card rounded-2xl p-5 space-y-4"
        aria-label="Actions taken"
      >
        <h2 className="text-sm font-semibold text-slate-300 flex items-center gap-2">
          <ActionIcon />
          Actions
        </h2>
        {threat.action_taken ? (
          <div className="bg-emerald-500/5 border border-emerald-500/20 rounded-xl px-4 py-3">
            <p className="text-sm text-emerald-300">{threat.action_taken}</p>
          </div>
        ) : (
          <p className="text-xs text-rex-muted italic">
            No automated action has been taken for this threat.
          </p>
        )}
        {!isResolved && (
          <ThreatActions threatId={threat.id || id} onResolved={(t) => setThreat({ ...threat, ...t })} />
        )}
        {threat.recommended_actions && threat.recommended_actions.length > 0 && (
          <div>
            <span className="text-xs text-rex-muted block mb-2">Recommended Actions</span>
            <ul className="space-y-1">
              {threat.recommended_actions.map((action, i) => (
                <li key={i} className="text-sm text-slate-300 flex items-start gap-2">
                  <span className="text-cyan-400 mt-1 shrink-0" aria-hidden="true">-</span>
                  {action}
                </li>
              ))}
            </ul>
          </div>
        )}
      </section>

      {/* ID */}
      {threat.id && (
        <p className="text-[10px] text-rex-muted font-mono break-all">
          ID: {threat.id}
        </p>
      )}
    </div>
  );
}

/* ---------- sub-components ---------- */

function ThreatActions({ threatId, onResolved }) {
  const { resolveThreat, markFalsePositive } = useThreatStore();
  const [acting, setActing] = useState(null);

  const handle = async (action) => {
    setActing(action);
    try {
      if (action === 'resolve') {
        await resolveThreat(threatId);
        onResolved({ resolved: true, status: 'resolved' });
      } else {
        await markFalsePositive(threatId);
        onResolved({ resolved: true, status: 'false_positive' });
      }
    } finally {
      setActing(null);
    }
  };

  return (
    <div className="flex flex-wrap gap-2 pt-2">
      <button
        onClick={() => handle('resolve')}
        disabled={!!acting}
        className="px-4 py-2 rounded-xl bg-emerald-500/20 text-emerald-300 text-xs font-medium border border-emerald-500/30 hover:bg-emerald-500/30 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
      >
        {acting === 'resolve' ? 'Resolving...' : 'Resolve'}
      </button>
      <button
        onClick={() => handle('false_positive')}
        disabled={!!acting}
        className="px-4 py-2 rounded-xl bg-amber-500/20 text-amber-300 text-xs font-medium border border-amber-500/30 hover:bg-amber-500/30 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
      >
        {acting === 'false_positive' ? 'Marking...' : 'Mark False Positive'}
      </button>
    </div>
  );
}

function Field({ label, value, mono, capitalize: cap }) {
  return (
    <div className="flex items-center justify-between gap-2">
      <span className="text-xs text-rex-muted shrink-0">{label}</span>
      <span
        className={`text-xs text-rex-text text-right ${mono ? 'font-mono' : ''} ${cap ? 'capitalize' : ''}`}
      >
        {value || '--'}
      </span>
    </div>
  );
}

function formatConfidence(value) {
  if (typeof value === 'number') {
    return value <= 1 ? `${Math.round(value * 100)}%` : `${Math.round(value)}%`;
  }
  return String(value);
}

function ObservedIcon() {
  return (
    <svg className="w-4 h-4 text-cyan-400 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5} aria-hidden="true">
      <path strokeLinecap="round" strokeLinejoin="round" d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z" />
      <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
    </svg>
  );
}

function InferredIcon() {
  return (
    <svg className="w-4 h-4 text-amber-400 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5} aria-hidden="true">
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 18v-5.25m0 0a6.01 6.01 0 001.5-.189m-1.5.189a6.01 6.01 0 01-1.5-.189m3.75 7.478a12.06 12.06 0 01-4.5 0m3.75 2.383a14.406 14.406 0 01-3 0M14.25 18v-.192c0-.983.658-1.823 1.508-2.316a7.5 7.5 0 10-7.517 0c.85.493 1.509 1.333 1.509 2.316V18" />
    </svg>
  );
}

function ActionIcon() {
  return (
    <svg className="w-4 h-4 text-emerald-400 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5} aria-hidden="true">
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
  );
}
