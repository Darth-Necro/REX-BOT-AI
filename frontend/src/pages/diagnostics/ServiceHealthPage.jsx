/**
 * ServiceHealthPage -- service health cards with dependency chains.
 *
 * Each service card shows its status and its upstream dependencies.
 * All data comes from /health + /status via the diagnostics store.
 * No fabricated health data.
 */

import React, { useEffect } from 'react';
import useDiagnosticsStore from '../../stores/useDiagnosticsStore';
import Badge from '../../components/primitives/Badge';
import Button from '../../components/primitives/Button';
import EmptyState from '../../components/primitives/EmptyState';
import { SkeletonCard } from '../../components/primitives/Skeleton';
import { formatUptime } from '../../lib/formatters';

/* ---------- dependency chain config ---------- */

/**
 * Known service dependencies (upstream).
 * Key = service name (from diagnostics store).
 * Value = list of services this one depends on.
 */
const DEPENDENCY_MAP = {
  'System':      ['API', 'Database'],
  'LLM Engine':  ['API', 'Database'],
  'WebSocket':   ['API'],
  'API':         ['Database'],
  'Database':    [],
  'Power State': [],
};

/* ---------- status helpers ---------- */

const STATUS_VARIANT = {
  healthy: 'emerald',
  operational: 'emerald',
  ready: 'emerald',
  connected: 'emerald',
  awake: 'emerald',
  degraded: 'amber',
  loading: 'amber',
  alert_sleep: 'amber',
  critical: 'red',
  error: 'red',
  disconnected: 'red',
  disabled: 'red',
  off: 'red',
  deep_sleep: 'default',
  unknown: 'default',
};

function statusVariant(status) {
  return STATUS_VARIANT[(status || '').toLowerCase()] || 'default';
}

/* ---------- page ---------- */

export default function ServiceHealthPage() {
  const {
    snapshot,
    serviceHealth,
    loading,
    error,
    fetchedAt,
    fetchDiagnostics,
  } = useDiagnosticsStore();

  useEffect(() => {
    fetchDiagnostics();
  }, [fetchDiagnostics]);

  const status = snapshot?.status ?? {};

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-5xl">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100">Service Health</h1>
          <p className="text-sm text-slate-500 mt-0.5">
            {loading
              ? 'Fetching service status...'
              : fetchedAt
                ? `Last checked ${new Date(fetchedAt).toLocaleTimeString()}`
                : 'No data yet'}
          </p>
        </div>
        <Button
          onClick={fetchDiagnostics}
          loading={loading}
          variant="secondary"
          size="sm"
          ariaLabel="Refresh service health"
        >
          {loading ? 'Refreshing...' : 'Refresh'}
        </Button>
      </div>

      {/* Error banner */}
      {error && (
        <div
          className="bg-red-500/10 border border-red-500/30 rounded-xl px-4 py-3"
          role="alert"
        >
          <p className="text-sm text-red-300">{error}</p>
        </div>
      )}

      {/* Loading skeletons */}
      {loading && serviceHealth.length === 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {Array.from({ length: 6 }, (_, i) => (
            <SkeletonCard key={i} />
          ))}
        </div>
      )}

      {/* Empty state */}
      {!loading && serviceHealth.length === 0 && !error && (
        <EmptyState
          variant="disconnected"
          heading="No service data"
          description="Cannot retrieve service health. The backend may not be reachable."
        />
      )}

      {/* Service cards with dependency chains */}
      {serviceHealth.length > 0 && (
        <div
          className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4"
          role="list"
          aria-label="Service health cards"
        >
          {serviceHealth.map((svc) => {
            const deps = DEPENDENCY_MAP[svc.name] || [];
            const upstreamHealth = deps.map((depName) => {
              const dep = serviceHealth.find((s) => s.name === depName);
              return { name: depName, status: dep?.status || 'unknown' };
            });

            return (
              <ServiceHealthCard
                key={svc.name}
                name={svc.name}
                status={svc.status}
                dependencies={upstreamHealth}
                isMeta={svc.isMeta}
              />
            );
          })}
        </div>
      )}

      {/* Uptime */}
      {status.uptimeSeconds > 0 && (
        <div className="text-xs text-rex-muted">
          System uptime: {formatUptime(status.uptimeSeconds)}
        </div>
      )}
    </div>
  );
}

/* ---------- service card ---------- */

function ServiceHealthCard({ name, status, dependencies = [], isMeta }) {
  const variant = statusVariant(status);
  const statusLabel = status || 'unknown';

  return (
    <div
      role="listitem"
      className="bg-rex-surface border border-rex-card rounded-2xl p-4 space-y-3 transition-shadow hover:shadow-md"
      aria-label={`${name}: ${statusLabel}`}
    >
      {/* Name + status */}
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium text-slate-200">{name}</h3>
        <Badge variant={variant} size="sm" dot>
          {statusLabel}
        </Badge>
      </div>

      {/* Dependency chain */}
      {dependencies.length > 0 && (
        <div className="space-y-1.5">
          <span className="text-[10px] text-rex-muted uppercase tracking-wide">
            Depends on
          </span>
          <div className="flex flex-wrap gap-1.5">
            {dependencies.map((dep) => (
              <span
                key={dep.name}
                className="flex items-center gap-1 text-[10px] text-slate-400"
              >
                <span
                  className={`w-1.5 h-1.5 rounded-full ${
                    statusVariant(dep.status) === 'emerald'
                      ? 'bg-emerald-400'
                      : statusVariant(dep.status) === 'amber'
                        ? 'bg-amber-400'
                        : statusVariant(dep.status) === 'red'
                          ? 'bg-red-400'
                          : 'bg-slate-500'
                  }`}
                  aria-hidden="true"
                />
                {dep.name}
                <span className="sr-only">: {dep.status || 'unknown'}</span>
              </span>
            ))}
          </div>

          {/* Chain visualization */}
          <div className="flex items-center gap-1 text-[10px] text-slate-600" aria-hidden="true">
            {dependencies.map((dep, i) => (
              <React.Fragment key={dep.name}>
                <span className="text-slate-500">{dep.name}</span>
                {i < dependencies.length - 1 && <span>+</span>}
              </React.Fragment>
            ))}
            <span className="mx-1">&rarr;</span>
            <span className="text-slate-400 font-medium">{name}</span>
          </div>
        </div>
      )}

      {/* Meta indicator */}
      {isMeta && (
        <span className="text-[10px] text-rex-muted italic">
          Metadata only -- not a runtime service
        </span>
      )}
    </div>
  );
}
