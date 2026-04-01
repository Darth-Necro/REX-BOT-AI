import React, { useState, useCallback, useEffect } from 'react';
import useSystemStore from '../../stores/useSystemStore';
import api from '../../api/client';

function Section({ title, children }) {
  return (
    <div className="bg-rex-surface border border-rex-card rounded-xl p-5">
      <h3 className="text-sm font-semibold text-rex-text mb-4">{title}</h3>
      {children}
    </div>
  );
}

function Toggle({ label, description, checked, onChange, disabled = false }) {
  return (
    <div className="flex items-center justify-between py-2">
      <div className="mr-4">
        <p className="text-sm text-rex-text">{label}</p>
        {description && <p className="text-xs text-rex-muted mt-0.5">{description}</p>}
      </div>
      <button
        role="switch"
        aria-checked={checked}
        onClick={() => !disabled && onChange(!checked)}
        disabled={disabled}
        className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 focus:outline-none disabled:opacity-50 disabled:cursor-not-allowed ${
          checked ? 'bg-rex-accent' : 'bg-rex-card'
        }`}
      >
        <span
          className={`pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow transform transition-transform duration-200 ${
            checked ? 'translate-x-5' : 'translate-x-0'
          }`}
        />
      </button>
    </div>
  );
}

function SliderSetting({ label, description, value, min, max, step, unit, onChange }) {
  return (
    <div className="py-2">
      <div className="flex items-center justify-between mb-2">
        <div>
          <p className="text-sm text-rex-text">{label}</p>
          {description && <p className="text-xs text-rex-muted mt-0.5">{description}</p>}
        </div>
        <span className="text-sm font-medium text-rex-accent">
          {value}{unit}
        </span>
      </div>
      <input
        type="range"
        min={min}
        max={max}
        step={step}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        className="w-full h-2 rounded-full appearance-none cursor-pointer bg-rex-card accent-rex-accent"
      />
      <div className="flex justify-between text-xs text-rex-muted mt-1">
        <span>{min}{unit}</span>
        <span>{max}{unit}</span>
      </div>
    </div>
  );
}

function NotificationChannel({ name, type, configured, onTest }) {
  const [testing, setTesting] = useState(false);

  const handleTest = useCallback(async () => {
    setTesting(true);
    try {
      await onTest(type);
    } finally {
      setTimeout(() => setTesting(false), 2000);
    }
  }, [type, onTest]);

  return (
    <div className="flex items-center justify-between py-2 border-b border-rex-card/50 last:border-0">
      <div className="flex items-center gap-3">
        <span className={`w-2 h-2 rounded-full ${configured ? 'bg-rex-safe' : 'bg-rex-muted'}`} />
        <div>
          <p className="text-sm text-rex-text">{name}</p>
          <p className="text-xs text-rex-muted">{configured ? 'Configured' : 'Not configured'}</p>
        </div>
      </div>
      {configured && (
        <button
          onClick={handleTest}
          disabled={testing}
          className="text-xs px-3 py-1.5 bg-rex-card text-rex-text rounded-lg hover:bg-rex-card/80 disabled:opacity-50 transition-colors"
        >
          {testing ? 'Sent!' : 'Test'}
        </button>
      )}
    </div>
  );
}

export default function SettingsPanel() {
  const { mode, toggleMode, version, uptimeSeconds } = useSystemStore();

  const [settings, setSettings] = useState({
    protection_mode: 'auto_block_critical',
    scan_interval: 30,
    sleep_time: '23:00',
    wake_time: '07:00',
    data_retention_days: 90,
    telemetry_enabled: false,
  });
  const [notifications, setNotifications] = useState([
    { name: 'Discord Webhook', type: 'discord', configured: false },
    { name: 'Email Alerts', type: 'email', configured: false },
    { name: 'Pushover', type: 'pushover', configured: false },
    { name: 'Gotify', type: 'gotify', configured: false },
  ]);
  const [saving, setSaving] = useState(false);

  // Fetch settings on mount
  useEffect(() => {
    api.get('/config/')
      .then((res) => {
        const cfg = res.data?.config || res.data || {};
        setSettings((prev) => ({
          ...prev,
          protection_mode: cfg.protection_mode || prev.protection_mode,
          scan_interval: cfg.scan_interval_minutes || cfg.scan_interval || prev.scan_interval,
          sleep_time: cfg.sleep_time || prev.sleep_time,
          wake_time: cfg.wake_time || prev.wake_time,
          data_retention_days: cfg.data_retention_days || prev.data_retention_days,
          telemetry_enabled: cfg.telemetry_enabled ?? prev.telemetry_enabled,
        }));
        if (cfg.notifications) {
          setNotifications((prev) =>
            prev.map((n) => ({
              ...n,
              configured: !!(cfg.notifications[n.type]?.enabled),
            }))
          );
        }
      })
      .catch(() => {/* Use defaults */});
  }, []);

  const updateSetting = useCallback((key, value) => {
    setSettings((prev) => ({ ...prev, [key]: value }));
  }, []);

  const handleSave = useCallback(async () => {
    setSaving(true);
    try {
      await api.put('/config/', settings);
    } catch (err) {
      console.error('Failed to save settings:', err);
    } finally {
      setTimeout(() => setSaving(false), 1000);
    }
  }, [settings]);

  const handleTestNotification = useCallback(async (type) => {
    try {
      await api.post(`/config/notifications/${type}/test`);
    } catch (err) {
      console.error('Notification test failed:', err);
    }
  }, []);

  const formatUptime = (seconds) => {
    if (!seconds) return 'Unknown';
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const parts = [];
    if (d > 0) parts.push(`${d}d`);
    if (h > 0) parts.push(`${h}h`);
    parts.push(`${m}m`);
    return parts.join(' ');
  };

  return (
    <div className="space-y-4 max-w-3xl">
      {/* Mode Toggle */}
      <Section title="Display Mode">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm text-rex-text">
              Currently in <span className="font-semibold text-rex-accent capitalize">{mode}</span> mode
            </p>
            <p className="text-xs text-rex-muted mt-0.5">
              Basic mode shows a simplified overview. Advanced mode shows full controls.
            </p>
          </div>
          <button
            onClick={toggleMode}
            className="px-4 py-2 bg-rex-accent text-white rounded-lg hover:bg-rex-accent/80 transition-colors text-sm font-medium"
          >
            Switch to {mode === 'basic' ? 'Advanced' : 'Basic'}
          </button>
        </div>
      </Section>

      {/* Protection Mode */}
      <Section title="Protection Mode">
        <div className="space-y-2">
          {[
            { value: 'auto_block_all', label: 'Auto-Block All', desc: 'Block all detected threats automatically' },
            { value: 'auto_block_critical', label: 'Auto-Block Critical', desc: 'Only auto-block critical and high severity threats' },
            { value: 'alert_only', label: 'Alert Only', desc: 'Only send alerts, never auto-block' },
          ].map((opt) => (
            <label
              key={opt.value}
              className={`flex items-start gap-3 p-3 rounded-lg cursor-pointer transition-colors ${
                settings.protection_mode === opt.value
                  ? 'bg-rex-accent/10 border border-rex-accent/30'
                  : 'bg-rex-bg border border-rex-card hover:border-rex-card/80'
              }`}
            >
              <input
                type="radio"
                name="protection_mode"
                value={opt.value}
                checked={settings.protection_mode === opt.value}
                onChange={() => updateSetting('protection_mode', opt.value)}
                className="mt-0.5 accent-rex-accent"
              />
              <div>
                <p className="text-sm font-medium text-rex-text">{opt.label}</p>
                <p className="text-xs text-rex-muted">{opt.desc}</p>
              </div>
            </label>
          ))}
        </div>
      </Section>

      {/* Notification Channels */}
      <Section title="Notification Channels">
        <div className="divide-y divide-rex-card/30">
          {notifications.map((n) => (
            <NotificationChannel
              key={n.type}
              name={n.name}
              type={n.type}
              configured={n.configured}
              onTest={handleTestNotification}
            />
          ))}
        </div>
      </Section>

      {/* Scan Interval */}
      <Section title="Scan Configuration">
        <SliderSetting
          label="Scan Interval"
          description="How often REX scans your network for new devices and threats"
          value={settings.scan_interval}
          min={5}
          max={120}
          step={5}
          unit="m"
          onChange={(v) => updateSetting('scan_interval', v)}
        />
      </Section>

      {/* Power Schedule */}
      <Section title="Power Schedule">
        <p className="text-xs text-rex-muted mb-3">
          Set sleep and wake times to reduce resource usage during quiet hours. REX stays alert for critical threats during sleep.
        </p>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="text-xs text-rex-muted block mb-1">Sleep Time</label>
            <input
              type="time"
              value={settings.sleep_time}
              onChange={(e) => updateSetting('sleep_time', e.target.value)}
              className="w-full bg-rex-bg border border-rex-card rounded-lg px-3 py-2 text-sm text-rex-text focus:outline-none focus:border-rex-accent transition-colors"
            />
          </div>
          <div>
            <label className="text-xs text-rex-muted block mb-1">Wake Time</label>
            <input
              type="time"
              value={settings.wake_time}
              onChange={(e) => updateSetting('wake_time', e.target.value)}
              className="w-full bg-rex-bg border border-rex-card rounded-lg px-3 py-2 text-sm text-rex-text focus:outline-none focus:border-rex-accent transition-colors"
            />
          </div>
        </div>
      </Section>

      {/* Data Retention */}
      <Section title="Data Retention">
        <SliderSetting
          label="Retention Period"
          description="How long to keep threat and device logs before purging"
          value={settings.data_retention_days}
          min={7}
          max={365}
          step={7}
          unit=" days"
          onChange={(v) => updateSetting('data_retention_days', v)}
        />
      </Section>

      {/* Privacy */}
      <Section title="Privacy">
        <Toggle
          label="Anonymous Telemetry"
          description="Send anonymous usage stats to help improve REX. No personal or network data is ever shared."
          checked={settings.telemetry_enabled}
          onChange={(v) => updateSetting('telemetry_enabled', v)}
        />
        <div className="mt-3 p-3 bg-rex-bg rounded-lg">
          <p className="text-xs text-rex-muted font-medium mb-2">Data Inventory</p>
          <ul className="text-xs text-rex-muted space-y-1">
            <li>Device metadata (IP, MAC, hostname) -- stored locally only</li>
            <li>Threat logs -- stored locally, purged per retention policy</li>
            <li>Firewall rules -- stored locally only</li>
            <li>Chat history -- in-memory only, not persisted</li>
          </ul>
        </div>
      </Section>

      {/* About */}
      <Section title="About REX-BOT-AI">
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-sm text-rex-muted">Version</span>
            <span className="text-sm text-rex-text font-mono">{version || '1.0.0'}</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-sm text-rex-muted">Uptime</span>
            <span className="text-sm text-rex-text">{formatUptime(uptimeSeconds)}</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-sm text-rex-muted">Platform</span>
            <span className="text-sm text-rex-text">Raspberry Pi / Linux</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-sm text-rex-muted">License</span>
            <span className="text-sm text-rex-text">MIT</span>
          </div>
        </div>
      </Section>

      {/* Save button */}
      <div className="flex justify-end">
        <button
          onClick={handleSave}
          disabled={saving}
          className="flex items-center gap-2 px-6 py-2.5 bg-rex-accent text-white rounded-lg hover:bg-rex-accent/80 disabled:opacity-50 transition-colors text-sm font-medium"
        >
          {saving ? (
            <>
              <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              Saving...
            </>
          ) : (
            'Save Settings'
          )}
        </button>
      </div>
    </div>
  );
}
