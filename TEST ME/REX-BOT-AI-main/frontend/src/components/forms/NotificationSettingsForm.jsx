/**
 * NotificationSettingsForm — Discord/Telegram/Email/Matrix fields with save/test.
 *
 * Reads from useNotificationStore. Disables mutations when capabilities
 * deny them. Shows honest loading/saving/testing states.
 */
import React, { useEffect, useState } from 'react';
import useNotificationStore from '../../stores/useNotificationStore';
import useSafeMutation from '../../hooks/useSafeMutation';
import { can } from '../../lib/permissions';

/* ---------- field group ---------- */

function FieldGroup({ label, children, disabled }) {
  return (
    <fieldset className={`space-y-3 ${disabled ? 'opacity-40 pointer-events-none' : ''}`} disabled={disabled}>
      <legend className="text-xs font-bold tracking-widest uppercase text-slate-400 mb-2">
        {label}
      </legend>
      {children}
    </fieldset>
  );
}

function TextInput({ label, value, onChange, type = 'text', placeholder = '', disabled = false }) {
  return (
    <label className="block">
      <span className="text-xs text-slate-500 mb-1 block">{label}</span>
      <input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        disabled={disabled}
        className="w-full bg-slate-900/60 border border-white/[0.06] rounded-xl px-3 py-2 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/40 focus:ring-1 focus:ring-cyan-500/20 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
      />
    </label>
  );
}

function ChannelToggle({ channel, enabled, onToggle, disabled }) {
  return (
    <label className="flex items-center gap-3 cursor-pointer select-none">
      <div className="relative">
        <input
          type="checkbox"
          checked={enabled}
          onChange={() => onToggle(channel)}
          disabled={disabled}
          className="sr-only"
        />
        <div
          className={`w-9 h-5 rounded-full transition-colors ${
            enabled ? 'bg-cyan-500/60' : 'bg-slate-700'
          } ${disabled ? 'opacity-40' : ''}`}
        />
        <div
          className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white transition-transform ${
            enabled ? 'translate-x-4' : ''
          }`}
        />
      </div>
      <span className="text-sm text-slate-300 capitalize">{channel}</span>
    </label>
  );
}

/* ---------- main component ---------- */

export default function NotificationSettingsForm() {
  const {
    settings,
    capabilities,
    loading,
    saving,
    testing,
    error,
    testResult,
    fetchSettings,
    saveSettings,
    testNotifications,
    updateSettingsLocal,
  } = useNotificationStore();

  const canSave = can(capabilities, 'save');
  const canTest = can(capabilities, 'test');

  // Local draft to avoid writing to store on every keystroke
  const [draft, setDraft] = useState(settings);

  useEffect(() => {
    fetchSettings();
  }, [fetchSettings]);

  // Sync draft when store settings change (e.g. after fetch)
  useEffect(() => {
    setDraft(settings);
  }, [settings]);

  const { mutate: handleSave, isPending: isSaving } = useSafeMutation(
    () => saveSettings(draft),
    { pending: 'Saving notifications...', success: 'Notification settings saved', error: 'Failed to save settings' }
  );

  const { mutate: handleTest, isPending: isTesting } = useSafeMutation(
    testNotifications,
    { pending: 'Sending test notification...', success: 'Test sent', error: 'Test notification failed' }
  );

  const updateDraft = (patch) => setDraft((d) => ({ ...d, ...patch }));

  const toggleChannel = (channel) => {
    setDraft((d) => {
      const channels = d.enabled_channels.includes(channel)
        ? d.enabled_channels.filter((c) => c !== channel)
        : [...d.enabled_channels, channel];
      return { ...d, enabled_channels: channels };
    });
  };

  /* ---------- loading state ---------- */

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="flex items-center gap-3 text-sm text-slate-500">
          <svg className="w-5 h-5 animate-spin text-cyan-400" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
          </svg>
          Loading notification settings...
        </div>
      </div>
    );
  }

  /* ---------- render ---------- */

  return (
    <div className="space-y-6">
      {/* Error banner */}
      {error && (
        <div className="rounded-xl border border-red-500/30 bg-red-500/5 p-3 text-sm text-red-300">
          {error}
        </div>
      )}

      {/* Channel toggles */}
      <div className="flex flex-wrap gap-4">
        {['discord', 'telegram', 'email', 'matrix'].map((ch) => (
          <ChannelToggle
            key={ch}
            channel={ch}
            enabled={draft.enabled_channels.includes(ch)}
            onToggle={toggleChannel}
            disabled={!canSave}
          />
        ))}
      </div>

      {/* Discord */}
      <FieldGroup label="Discord" disabled={!draft.enabled_channels.includes('discord')}>
        <TextInput
          label="Webhook URL"
          value={draft.discord_webhook}
          onChange={(v) => updateDraft({ discord_webhook: v })}
          placeholder="https://discord.com/api/webhooks/..."
          disabled={!canSave}
        />
      </FieldGroup>

      {/* Telegram */}
      <FieldGroup label="Telegram" disabled={!draft.enabled_channels.includes('telegram')}>
        <TextInput
          label="Bot Token"
          value={draft.telegram_bot_token}
          onChange={(v) => updateDraft({ telegram_bot_token: v })}
          placeholder="123456789:ABCdef..."
          disabled={!canSave}
        />
        <TextInput
          label="Chat ID"
          value={draft.telegram_chat_id}
          onChange={(v) => updateDraft({ telegram_chat_id: v })}
          placeholder="-100..."
          disabled={!canSave}
        />
      </FieldGroup>

      {/* Email */}
      <FieldGroup label="Email" disabled={!draft.enabled_channels.includes('email')}>
        <TextInput
          label="Recipient"
          value={draft.email_to}
          onChange={(v) => updateDraft({ email_to: v })}
          type="email"
          placeholder="alerts@example.com"
          disabled={!canSave}
        />
        <TextInput
          label="SMTP Host"
          value={draft.email_smtp_host}
          onChange={(v) => updateDraft({ email_smtp_host: v })}
          placeholder="smtp.example.com"
          disabled={!canSave}
        />
      </FieldGroup>

      {/* Matrix */}
      <FieldGroup label="Matrix" disabled={!draft.enabled_channels.includes('matrix')}>
        <TextInput
          label="Homeserver"
          value={draft.matrix_homeserver}
          onChange={(v) => updateDraft({ matrix_homeserver: v })}
          placeholder="https://matrix.org"
          disabled={!canSave}
        />
        <TextInput
          label="Room ID"
          value={draft.matrix_room_id}
          onChange={(v) => updateDraft({ matrix_room_id: v })}
          placeholder="!room:matrix.org"
          disabled={!canSave}
        />
        <TextInput
          label="Access Token"
          value={draft.matrix_token}
          onChange={(v) => updateDraft({ matrix_token: v })}
          type="password"
          placeholder="syt_..."
          disabled={!canSave}
        />
      </FieldGroup>

      {/* Actions */}
      <div className="flex items-center gap-3 pt-2">
        <button
          onClick={handleSave}
          disabled={isSaving || !canSave}
          className="px-5 py-2 rounded-xl bg-cyan-500/20 text-cyan-300 text-sm font-medium border border-cyan-500/30 hover:bg-cyan-500/30 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
        >
          {isSaving ? 'Saving...' : 'Save Settings'}
        </button>

        <button
          onClick={handleTest}
          disabled={isTesting || !canTest || draft.enabled_channels.length === 0}
          className="px-5 py-2 rounded-xl bg-slate-800/60 text-slate-300 text-sm font-medium border border-white/[0.06] hover:bg-slate-700/60 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
        >
          {isTesting ? 'Testing...' : 'Send Test'}
        </button>

        {!canSave && (
          <span className="text-xs text-slate-600">
            Save not available -- backend does not report this capability.
          </span>
        )}
      </div>

      {/* Test result */}
      {testResult && (
        <div
          className={`rounded-xl border p-3 text-sm ${
            testResult.success
              ? 'border-emerald-500/30 bg-emerald-500/5 text-emerald-300'
              : 'border-red-500/30 bg-red-500/5 text-red-300'
          }`}
        >
          {testResult.success
            ? 'Test notification sent successfully.'
            : `Test failed: ${testResult.details?.error || 'Unknown error'}`}
        </div>
      )}
    </div>
  );
}
