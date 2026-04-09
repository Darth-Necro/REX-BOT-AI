/**
 * PluginsPage — installed and available plugins, with install/remove actions.
 * Mutations gated on capabilities.
 */
import React, { useEffect, useState } from 'react';
import usePluginStore from '../../stores/usePluginStore';
import { pluginPermissions } from '../../lib/permissions';
import PluginCard from '../../components/cards/PluginCard';

export default function PluginsPage() {
  const {
    installed, available, loading, actionInProgress, error, capabilities,
    fetchPlugins, installPlugin, removePlugin,
  } = usePluginStore();

  const perms = pluginPermissions(capabilities);
  const [tab, setTab] = useState('installed');

  useEffect(() => {
    fetchPlugins();
  }, [fetchPlugins]);

  // Filter available to exclude already-installed
  const installedIds = new Set(installed.map((p) => p.id));
  const filteredAvailable = available.filter((p) => !installedIds.has(p.id));

  const activeList = tab === 'installed' ? installed : filteredAvailable;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100">Plugins</h1>
          <p className="text-sm text-slate-500 mt-0.5">
            {loading
              ? 'Loading...'
              : `${installed.length} installed \u00B7 ${filteredAvailable.length} available`}
          </p>
        </div>
        {/* Tab switcher */}
        <div className="flex items-center gap-1 bg-[#0B1020] rounded-xl border border-white/[0.06] p-0.5">
          <button
            onClick={() => setTab('installed')}
            className={`px-4 py-1.5 text-xs font-medium rounded-lg transition-colors ${
              tab === 'installed' ? 'bg-cyan-500/15 text-cyan-300' : 'text-slate-500 hover:text-slate-300'
            }`}
          >
            Installed ({installed.length})
          </button>
          <button
            onClick={() => setTab('available')}
            className={`px-4 py-1.5 text-xs font-medium rounded-lg transition-colors ${
              tab === 'available' ? 'bg-cyan-500/15 text-cyan-300' : 'text-slate-500 hover:text-slate-300'
            }`}
          >
            Available ({filteredAvailable.length})
          </button>
        </div>
      </div>

      {/* Error banner */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-2xl px-4 py-3">
          <p className="text-sm text-red-300">{error}</p>
        </div>
      )}

      {/* Loading state */}
      {loading && (
        <div className="flex items-center justify-center py-16 text-slate-500 text-sm">
          <svg className="w-4 h-4 animate-spin mr-2" viewBox="0 0 24 24" fill="none">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
          </svg>
          Loading plugins...
        </div>
      )}

      {/* Empty state */}
      {!loading && activeList.length === 0 && (
        <div className="flex flex-col items-center justify-center py-16 text-center">
          <p className="text-slate-500 text-sm">
            {tab === 'installed'
              ? 'No plugins installed. Browse available plugins to get started.'
              : 'No additional plugins available.'}
          </p>
        </div>
      )}

      {/* Plugin grid */}
      {!loading && activeList.length > 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {activeList.map((plugin) => (
            <PluginCard
              key={plugin.id}
              plugin={plugin}
              isInstalled={tab === 'installed'}
              canInstall={perms.canInstall}
              canRemove={perms.canRemove}
              actionInProgress={actionInProgress === plugin.id}
              onInstall={installPlugin}
              onRemove={removePlugin}
            />
          ))}
        </div>
      )}
    </div>
  );
}
