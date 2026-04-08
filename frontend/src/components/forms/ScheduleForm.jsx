/**
 * ScheduleForm — mode selector and frequency inputs for REX power scheduling.
 * Does not manage its own API state; receives current values + onSave callback.
 */
import React, { useState, useEffect, useCallback } from 'react';

const MODES = [
  { value: 'always_on',  label: 'Always On',    desc: 'REX stays awake at all times.' },
  { value: 'scheduled',  label: 'Scheduled',    desc: 'REX follows a wake/sleep schedule.' },
  { value: 'adaptive',   label: 'Adaptive',     desc: 'REX adjusts based on threat activity.' },
  { value: 'manual',     label: 'Manual',       desc: 'Power state is controlled manually.' },
];

const inputCls =
  'w-full bg-[#050816] border border-white/[0.08] rounded-xl px-3 py-2 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-red-500/40 transition-colors';
const labelCls = 'text-xs text-slate-500 block mb-1';

export default function ScheduleForm({
  currentMode = 'unknown',
  currentWakeTime = '',
  currentSleepTime = '',
  saving = false,
  disabled = false,
  onSave,
}) {
  const [mode, setMode] = useState(currentMode);
  const [wakeTime, setWakeTime] = useState(currentWakeTime);
  const [sleepTime, setSleepTime] = useState(currentSleepTime);

  useEffect(() => {
    setMode(currentMode);
    setWakeTime(currentWakeTime);
    setSleepTime(currentSleepTime);
  }, [currentMode, currentWakeTime, currentSleepTime]);

  const dirty =
    mode !== currentMode || wakeTime !== currentWakeTime || sleepTime !== currentSleepTime;

  const handleSubmit = useCallback(
    (e) => {
      e.preventDefault();
      if (!dirty || saving || disabled) return;
      onSave?.({
        mode,
        wake_time: wakeTime || null,
        sleep_time: sleepTime || null,
      });
    },
    [mode, wakeTime, sleepTime, dirty, saving, disabled, onSave]
  );

  return (
    <form
      onSubmit={handleSubmit}
      className="bg-gradient-to-br from-[#0a0a0a] to-[#141414] border border-white/[0.06] rounded-2xl p-5"
    >
      <h3 className="text-xs text-slate-500 uppercase tracking-wide font-medium mb-4">
        Power Schedule
      </h3>

      {/* Mode selector */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 mb-5">
        {MODES.map((m) => {
          const selected = mode === m.value;
          return (
            <button
              key={m.value}
              type="button"
              onClick={() => !disabled && setMode(m.value)}
              disabled={disabled}
              className={`text-left p-3 rounded-xl border transition-colors ${
                selected
                  ? 'border-red-500/40 bg-red-500/10'
                  : 'border-white/[0.06] bg-[#050816] hover:border-white/[0.12]'
              } ${disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}`}
            >
              <p className={`text-sm font-medium ${selected ? 'text-red-300' : 'text-slate-300'}`}>
                {m.label}
              </p>
              <p className="text-xs text-slate-500 mt-0.5">{m.desc}</p>
            </button>
          );
        })}
      </div>

      {/* Schedule times (visible when mode is 'scheduled') */}
      {mode === 'scheduled' && (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-5">
          <div>
            <label className={labelCls}>Wake Time</label>
            <input
              type="time"
              value={wakeTime}
              onChange={(e) => setWakeTime(e.target.value)}
              className={inputCls}
              disabled={disabled}
            />
          </div>
          <div>
            <label className={labelCls}>Sleep Time</label>
            <input
              type="time"
              value={sleepTime}
              onChange={(e) => setSleepTime(e.target.value)}
              className={inputCls}
              disabled={disabled}
            />
          </div>
        </div>
      )}

      {/* Save */}
      <div className="flex items-center gap-3">
        <button
          type="submit"
          disabled={!dirty || saving || disabled}
          className="px-5 py-2 bg-red-500 text-white rounded-xl font-medium text-sm
                     hover:bg-red-400 disabled:opacity-40 disabled:cursor-not-allowed
                     transition-colors"
        >
          {saving ? 'Saving...' : 'Save Schedule'}
        </button>
        {dirty && (
          <span className="text-xs text-amber-300">Unsaved changes</span>
        )}
      </div>

      {disabled && (
        <p className="mt-3 text-xs text-amber-400/80">
          Schedule updates are not supported by the current backend configuration.
        </p>
      )}
    </form>
  );
}
