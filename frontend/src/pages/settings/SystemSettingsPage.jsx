/**
 * SystemSettingsPage -- form for system-wide configuration.
 *
 * Exposes scan_interval, protection_mode, sleep_time, wake_time,
 * data_retention_days, and telemetry_enabled.
 */
import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import useConfigStore from '../../stores/useConfigStore';
import { SkeletonCard } from '../../components/primitives/Skeleton';

const PROTECTION_MODES = [
  { value: 'alert_only', label: 'Alert Only (ruff)' },
  { value: 'auto_block_critical', label: 'Auto Block Critical (woof)' },
  { value: 'auto_block_all', label: 'Auto Block All (WOOF!)' },
  { value: 'junkyard_dog', label: 'Junkyard Dog (GRRRRR!)' },
];

export default function SystemSettingsPage() {
  const { config, loading, saving, error, saveError, fetchConfig, saveConfig } = useConfigStore();
  const [form, setForm] = useState(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    fetchConfig();
  }, [fetchConfig]);

  useEffect(() => {
    if (config && !form) {
      setForm({
        scan_interval: config.scan_interval ?? 60,
        protection_mode: config.protection_mode ?? 'auto_block_critical',
        sleep_time: config.sleep_time ?? '',
        wake_time: config.wake_time ?? '',
        data_retention_days: config.data_retention_days ?? 30,
        telemetry_enabled: config.telemetry_enabled ?? false,
      });
    }
  }, [config, form]);

  const handleChange = (field, value) => {
    setForm((prev) => ({ ...prev, [field]: value }));
    setSaved(false);
  };

  const handleSave = async () => {
    if (!form) return;
    const result = await saveConfig(form);
    if (result) {
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    }
  };

  if (loading || !form) {
    return (
      <div className="p-6 lg:p-8 max-w-2xl mx-auto space-y-4">
        <SkeletonCard />
        <SkeletonCard />
      </div>
    );
  }

  return (
    <div className="p-6 lg:p-8 max-w-2xl mx-auto space-y-6">
      {/* Breadcrumb */}
      <nav className="text-xs text-rex-muted">
        <Link to="/settings" className="hover:text-red-400 transition-colors">Settings</Link>
        <span className="mx-2">/</span>
        <span className="text-slate-300">System Configuration</span>
      </nav>

      <div>
        <h1 className="text-xl font-bold text-slate-100 tracking-tight">System Configuration</h1>
        <p className="text-sm text-slate-500 mt-1">Scan interval, protection mode, schedule, and data retention.</p>
      </div>

      {(error || saveError) && (
        <div className="rounded-xl border border-red-500/30 bg-red-500/5 p-3 text-sm text-red-300">
          {error || saveError}
        </div>
      )}

      <div className="rounded-[26px] border border-white/[0.06] bg-gradient-to-br from-[#0a0a0a] to-[#141414] p-6 space-y-5">
        {/* Scan Interval */}
        <div className="space-y-1.5">
          <label className="text-xs text-slate-400 font-medium" htmlFor="scan_interval">
            Scan Interval (seconds)
          </label>
          <input
            id="scan_interval"
            type="number"
            min={10}
            value={form.scan_interval}
            onChange={(e) => handleChange('scan_interval', parseInt(e.target.value, 10) || 10)}
            className="w-full bg-rex-bg border border-rex-card rounded-xl px-4 py-2.5 text-sm text-rex-text focus:outline-none focus:border-red-500/50 transition-colors"
          />
          <p className="text-[10px] text-slate-600">Minimum 10 seconds between scans.</p>
        </div>

        {/* Protection Mode */}
        <div className="space-y-1.5">
          <label className="text-xs text-slate-400 font-medium" htmlFor="protection_mode">
            Protection Mode
          </label>
          <select
            id="protection_mode"
            value={form.protection_mode}
            onChange={(e) => handleChange('protection_mode', e.target.value)}
            className="w-full bg-rex-bg border border-rex-card rounded-xl px-4 py-2.5 text-sm text-rex-text focus:outline-none focus:border-red-500/50 transition-colors"
          >
            {PROTECTION_MODES.map((m) => (
              <option key={m.value} value={m.value}>{m.label}</option>
            ))}
          </select>
        </div>

        {/* Sleep / Wake Times */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div className="space-y-1.5">
            <label className="text-xs text-slate-400 font-medium" htmlFor="sleep_time">
              Sleep Time (HH:MM)
            </label>
            <input
              id="sleep_time"
              type="time"
              value={form.sleep_time}
              onChange={(e) => handleChange('sleep_time', e.target.value)}
              className="w-full bg-rex-bg border border-rex-card rounded-xl px-4 py-2.5 text-sm text-rex-text focus:outline-none focus:border-red-500/50 transition-colors"
            />
          </div>
          <div className="space-y-1.5">
            <label className="text-xs text-slate-400 font-medium" htmlFor="wake_time">
              Wake Time (HH:MM)
            </label>
            <input
              id="wake_time"
              type="time"
              value={form.wake_time}
              onChange={(e) => handleChange('wake_time', e.target.value)}
              className="w-full bg-rex-bg border border-rex-card rounded-xl px-4 py-2.5 text-sm text-rex-text focus:outline-none focus:border-red-500/50 transition-colors"
            />
          </div>
        </div>

        {/* Data Retention */}
        <div className="space-y-1.5">
          <label className="text-xs text-slate-400 font-medium" htmlFor="data_retention_days">
            Data Retention (days)
          </label>
          <input
            id="data_retention_days"
            type="number"
            min={1}
            value={form.data_retention_days}
            onChange={(e) => handleChange('data_retention_days', parseInt(e.target.value, 10) || 1)}
            className="w-full bg-rex-bg border border-rex-card rounded-xl px-4 py-2.5 text-sm text-rex-text focus:outline-none focus:border-red-500/50 transition-colors"
          />
        </div>

        {/* Telemetry */}
        <div className="flex items-center justify-between">
          <div>
            <p className="text-xs text-slate-400 font-medium">Telemetry</p>
            <p className="text-[10px] text-slate-600 mt-0.5">Send anonymous usage data to help improve REX.</p>
          </div>
          <button
            onClick={() => handleChange('telemetry_enabled', !form.telemetry_enabled)}
            className={`relative w-11 h-6 rounded-full transition-colors ${
              form.telemetry_enabled ? 'bg-red-500' : 'bg-rex-card'
            }`}
            role="switch"
            aria-checked={form.telemetry_enabled}
          >
            <span className={`absolute top-0.5 left-0.5 w-5 h-5 rounded-full bg-white transition-transform ${
              form.telemetry_enabled ? 'translate-x-5' : ''
            }`} />
          </button>
        </div>
      </div>

      {/* Save */}
      <div className="flex items-center gap-3">
        <button
          onClick={handleSave}
          disabled={saving}
          className="px-6 py-2.5 rounded-xl bg-red-500/20 text-red-300 text-sm font-medium border border-red-500/30 hover:bg-red-500/30 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
        >
          {saving ? 'Saving...' : 'Save Changes'}
        </button>
        {saved && (
          <span className="text-xs text-emerald-400">Settings saved successfully.</span>
        )}
      </div>
    </div>
  );
}
