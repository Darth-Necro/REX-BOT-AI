/**
 * PluginCard — displays a single plugin with name, state, description,
 * permissions, and action button (install/remove).
 */
import React from 'react';

function StateBadge({ state }) {
  const styles = {
    installed: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
    active: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
    enabled: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
    disabled: 'bg-slate-700/40 text-slate-400 border-slate-600',
    available: 'bg-red-500/15 text-red-300 border-red-500/30',
    error: 'bg-red-500/15 text-red-300 border-red-500/30',
  };
  const cls = styles[(state || '').toLowerCase()] || 'bg-slate-700/40 text-slate-400 border-slate-600';
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full font-medium border ${cls}`}>
      {state || 'unknown'}
    </span>
  );
}

export default function PluginCard({
  plugin,
  isInstalled = false,
  canInstall = false,
  canRemove = false,
  actionInProgress = false,
  onInstall,
  onRemove,
}) {
  if (!plugin) return null;

  const permissions = plugin.permissions ?? plugin.required_permissions ?? [];

  return (
    <div className="bg-gradient-to-br from-[#0a0a0a] to-[#141414] border border-white/[0.06] rounded-2xl p-5 flex flex-col gap-3 transition-shadow hover:shadow-[0_0_24px_rgba(220,38,38,0.06)]">
      {/* Header */}
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-slate-100 truncate">{plugin.name ?? plugin.id ?? 'Unnamed Plugin'}</h3>
          {plugin.author && (
            <p className="text-xs text-slate-500 mt-0.5">by {plugin.author}</p>
          )}
        </div>
        <StateBadge state={isInstalled ? (plugin.state ?? 'installed') : 'available'} />
      </div>

      {/* Description */}
      <p className="text-xs text-slate-400 leading-relaxed line-clamp-3">
        {plugin.description || 'No description provided.'}
      </p>

      {/* Version */}
      {plugin.version && (
        <p className="text-xs text-slate-500 font-mono">v{plugin.version}</p>
      )}

      {/* Permissions */}
      {Array.isArray(permissions) && permissions.length > 0 && (
        <div>
          <p className="text-xs text-slate-500 mb-1">Permissions:</p>
          <div className="flex flex-wrap gap-1">
            {permissions.map((perm, i) => (
              <span
                key={i}
                className="text-xs px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-white/[0.06]"
              >
                {perm}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Action */}
      <div className="mt-auto pt-2">
        {isInstalled ? (
          <button
            onClick={() => onRemove?.(plugin.id)}
            disabled={!canRemove || actionInProgress}
            className="w-full px-3 py-2 text-xs font-medium rounded-xl
                       bg-red-500/10 text-red-300 border border-red-500/30
                       hover:bg-red-500/20 disabled:opacity-40 disabled:cursor-not-allowed
                       transition-colors"
          >
            {actionInProgress ? 'Removing...' : 'Remove'}
          </button>
        ) : (
          <button
            onClick={() => onInstall?.(plugin.id)}
            disabled={!canInstall || actionInProgress}
            className="w-full px-3 py-2 text-xs font-medium rounded-xl
                       bg-red-500/10 text-red-300 border border-red-500/30
                       hover:bg-red-500/20 disabled:opacity-40 disabled:cursor-not-allowed
                       transition-colors"
          >
            {actionInProgress ? 'Installing...' : 'Install'}
          </button>
        )}
        {!canInstall && !isInstalled && (
          <p className="text-xs text-amber-400/70 mt-1.5">
            Plugin installation not supported by backend.
          </p>
        )}
      </div>
    </div>
  );
}
