/**
 * AgentActionsPage -- displays the REX agent action registry and scope.
 *
 * Shows all whitelisted actions grouped by domain with risk levels,
 * confirmation requirements, and parameter details.
 */
import React, { useEffect, useMemo, useState } from 'react';
import useAgentStore from '../../stores/useAgentStore';
import { SkeletonCard } from '../../components/primitives/Skeleton';

const RISK_COLORS = {
  low: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30',
  medium: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
  high: 'bg-orange-500/20 text-orange-300 border-orange-500/30',
  critical: 'bg-red-500/20 text-red-300 border-red-500/30',
};

function ActionCard({ action }) {
  const [expanded, setExpanded] = useState(false);
  const riskCls = RISK_COLORS[action.risk_level] || RISK_COLORS.low;
  const hasParams = action.parameters && (
    Array.isArray(action.parameters) ? action.parameters.length > 0 : Object.keys(action.parameters).length > 0
  );

  return (
    <div className="rounded-xl border border-white/[0.06] bg-rex-surface p-4 space-y-3">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="text-sm font-mono font-medium text-slate-200 break-all">
            {action.action_id}
          </p>
          <p className="text-xs text-slate-400 mt-1">{action.description || 'No description'}</p>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        {action.domain && (
          <span className="text-[10px] px-2 py-0.5 rounded-full bg-cyan-500/15 text-cyan-300 border border-cyan-500/20">
            {action.domain}
          </span>
        )}
        <span className={`text-[10px] px-2 py-0.5 rounded-full border ${riskCls}`}>
          {action.risk_level || 'low'}
        </span>
        {action.requires_confirmation && (
          <span className="text-[10px] px-2 py-0.5 rounded-full bg-amber-500/10 text-amber-300 border border-amber-500/20">
            Confirm required
          </span>
        )}
      </div>

      {hasParams && (
        <div>
          <button
            onClick={() => setExpanded(!expanded)}
            className="text-[10px] text-slate-500 hover:text-cyan-400 transition-colors"
          >
            {expanded ? 'Hide parameters' : 'Show parameters'}
          </button>
          {expanded && (
            <pre className="mt-2 text-[10px] text-slate-400 bg-rex-bg rounded-lg p-3 overflow-x-auto font-mono">
              {JSON.stringify(action.parameters, null, 2)}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}

export default function AgentActionsPage() {
  const {
    actions, count, scope, loading, error, domainFilter,
    fetchActions, filterByDomain,
  } = useAgentStore();

  useEffect(() => {
    fetchActions();
  }, [fetchActions]);

  // Derive domain list from all actions (when unfiltered)
  const domains = useMemo(() => {
    if (domainFilter) return [];
    const set = new Set(actions.map((a) => a.domain).filter(Boolean));
    return Array.from(set).sort();
  }, [actions, domainFilter]);

  // Keep stable domain list for tabs
  const [allDomains, setAllDomains] = useState([]);
  useEffect(() => {
    if (domains.length > 0) setAllDomains(domains);
  }, [domains]);

  if (loading && actions.length === 0) {
    return (
      <div className="p-6 lg:p-8 max-w-4xl mx-auto space-y-4">
        <SkeletonCard />
        <SkeletonCard />
        <SkeletonCard />
      </div>
    );
  }

  return (
    <div className="p-6 lg:p-8 max-w-4xl mx-auto space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-slate-100 tracking-tight">Agent Actions</h1>
        <p className="text-sm text-slate-500 mt-1">
          Whitelisted actions REX can execute. {count} action{count !== 1 ? 's' : ''} registered.
        </p>
      </div>

      {/* Scope info */}
      {scope && (
        <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-4 space-y-2">
          <p className="text-sm text-cyan-200">{scope.description || 'Agent scope information'}</p>
          <div className="flex gap-4 text-xs text-slate-400">
            <span>{scope.securityKeywordsCount} security keywords</span>
            <span>{scope.outOfScopePatternsCount} out-of-scope patterns</span>
          </div>
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="rounded-xl border border-red-500/30 bg-red-500/5 p-3 text-sm text-red-300">
          {error}
        </div>
      )}

      {/* Domain filter tabs */}
      {allDomains.length > 0 && (
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => filterByDomain(null)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
              !domainFilter
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                : 'bg-rex-surface text-slate-400 border border-white/[0.06] hover:text-slate-200'
            }`}
          >
            All
          </button>
          {allDomains.map((domain) => (
            <button
              key={domain}
              onClick={() => filterByDomain(domain)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                domainFilter === domain
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                  : 'bg-rex-surface text-slate-400 border border-white/[0.06] hover:text-slate-200'
              }`}
            >
              {domain}
            </button>
          ))}
        </div>
      )}

      {/* Action cards */}
      {actions.length > 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {actions.map((action) => (
            <ActionCard key={action.action_id} action={action} />
          ))}
        </div>
      ) : (
        <div className="flex items-center justify-center py-8 text-sm text-slate-600">
          No actions registered.
        </div>
      )}
    </div>
  );
}
