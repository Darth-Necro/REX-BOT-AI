/**
 * SchedulerPage — power state display, job history table, schedule form.
 * Mutations gated on backend capabilities.
 */
import React, { useEffect, useState } from 'react';
import useSchedulerStore from '../../stores/useSchedulerStore';
import { schedulerPermissions } from '../../lib/permissions';
import api from '../../api/client';
import JobHistoryTable from '../../components/tables/JobHistoryTable';
import ScheduleForm from '../../components/forms/ScheduleForm';

const POWER_STATE_STYLES = {
  awake:       { bg: 'bg-emerald-500/10', text: 'text-emerald-300', border: 'border-emerald-500/30', label: 'Awake' },
  alert_sleep: { bg: 'bg-amber-500/10',   text: 'text-amber-300',   border: 'border-amber-500/30',   label: 'Alert Sleep' },
  deep_sleep:  { bg: 'bg-slate-800/60',   text: 'text-slate-400',   border: 'border-slate-600',       label: 'Deep Sleep' },
  off:         { bg: 'bg-red-500/10',     text: 'text-red-300',     border: 'border-red-500/30',     label: 'Off' },
  unknown:     { bg: 'bg-slate-800/60',   text: 'text-slate-400',   border: 'border-slate-600',       label: 'Unknown' },
};

export default function SchedulerPage() {
  const {
    powerState, mode, jobs, loading, saving, error, capabilities,
    fetchSchedule, saveSchedule,
  } = useSchedulerStore();

  const perms = schedulerPermissions(capabilities);
  const [patrolling, setPatrolling] = useState(false);
  const [patrolError, setPatrolError] = useState(null);

  useEffect(() => {
    fetchSchedule();
  }, [fetchSchedule]);

  const handlePatrolNow = async () => {
    setPatrolling(true);
    setPatrolError(null);
    try {
      // Trigger an immediate deep scan (patrol) via the devices/scan endpoint
      await api.post('/devices/scan', { scan_type: 'deep' });
      // Re-fetch schedule to reflect any new jobs
      await fetchSchedule();
    } catch (err) {
      setPatrolError(err?.response?.data?.detail || err.message || 'Failed to trigger patrol');
    } finally {
      setPatrolling(false);
    }
  };

  const psStyle = POWER_STATE_STYLES[powerState] || POWER_STATE_STYLES.unknown;

  // Extract wake/sleep times from jobs or mode config if available
  const wakeJob = jobs.find((j) => (j.name || j.job || '').toLowerCase().includes('wake'));
  const sleepJob = jobs.find((j) => (j.name || j.job || '').toLowerCase().includes('sleep'));

  return (
    <div className="p-4 sm:p-6 lg:p-8 space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100">Scheduler</h1>
          <p className="text-sm text-slate-500 mt-0.5">
            {loading ? 'Loading...' : `${jobs.length} scheduled job${jobs.length !== 1 ? 's' : ''}`}
          </p>
        </div>
        <div className="flex items-center gap-3">
          {/* Patrol Now button */}
          <button
            onClick={handlePatrolNow}
            disabled={patrolling}
            className="px-4 py-2.5 text-sm font-medium rounded-xl bg-red-500/10 text-red-300
                       border border-red-500/30 hover:bg-red-500/20 disabled:opacity-40
                       disabled:cursor-not-allowed transition-colors flex items-center gap-2"
          >
            {patrolling ? (
              <>
                <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                Patrolling...
              </>
            ) : (
              'Patrol Now'
            )}
          </button>

          {/* Power state badge */}
          <div className={`${psStyle.bg} ${psStyle.border} border rounded-2xl px-5 py-3 flex items-center gap-3`}>
          <div className={`w-3 h-3 rounded-full ${
            powerState === 'awake' ? 'bg-emerald-400 animate-pulse' :
            powerState === 'alert_sleep' ? 'bg-amber-400' :
            powerState === 'off' ? 'bg-red-400' : 'bg-slate-500'
          }`} />
          <div>
            <p className="text-xs text-slate-500 uppercase tracking-wide">Power State</p>
            <p className={`text-sm font-semibold ${psStyle.text}`}>{psStyle.label}</p>
          </div>
        </div>
        </div>
      </div>

      {/* Patrol error banner */}
      {patrolError && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-2xl px-4 py-3">
          <p className="text-sm text-red-300">{patrolError}</p>
        </div>
      )}

      {/* Error banner */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-2xl px-4 py-3">
          <p className="text-sm text-red-300">{error}</p>
        </div>
      )}

      {/* Schedule configuration */}
      <ScheduleForm
        currentMode={mode}
        currentWakeTime={wakeJob?.time ?? ''}
        currentSleepTime={sleepJob?.time ?? ''}
        saving={saving}
        disabled={!perms.canUpdateSchedule}
        onSave={saveSchedule}
      />

      {/* Job history */}
      <div>
        <h2 className="text-sm font-semibold text-slate-300 mb-3">Scheduled Jobs</h2>
        <JobHistoryTable jobs={jobs} loading={loading} />
      </div>
    </div>
  );
}
