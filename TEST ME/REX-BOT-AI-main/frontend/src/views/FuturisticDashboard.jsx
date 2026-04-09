import React from 'react';
import useSystemStore from '../stores/useSystemStore';
import useThreatStore from '../stores/useThreatStore';
import useDeviceStore from '../stores/useDeviceStore';

const severityClasses = {
  critical: "border-red-500/50 bg-red-500/10 text-red-200",
  high: "border-amber-400/50 bg-amber-400/10 text-amber-100",
  medium: "border-cyan-400/40 bg-cyan-400/10 text-cyan-100",
  low: "border-sky-400/30 bg-sky-400/10 text-sky-100",
  info: "border-slate-600/40 bg-slate-600/10 text-slate-200",
};

const trustBar = (trust) => {
  if (trust >= 85) return "from-emerald-400 to-cyan-400";
  if (trust >= 50) return "from-amber-300 to-cyan-400";
  return "from-red-400 to-fuchsia-500";
};

function StatCard({ label, value, meta }) {
  return (
    <div className="rounded-3xl border border-cyan-400/20 bg-slate-950/70 p-5 backdrop-blur-xl shadow-[0_0_30px_rgba(34,211,238,0.06)]">
      <div className="text-[11px] uppercase tracking-[0.28em] text-slate-400">{label}</div>
      <div className="mt-4 flex items-end justify-between">
        <div className="text-4xl font-semibold tracking-tight text-white">{value}</div>
        <div className="rounded-full border border-cyan-400/20 bg-cyan-400/10 px-3 py-1 text-xs text-cyan-200">
          {meta}
        </div>
      </div>
      <div className="mt-4 h-1.5 rounded-full bg-slate-800">
        <div className="h-1.5 w-4/5 rounded-full bg-gradient-to-r from-cyan-400 via-sky-400 to-fuchsia-500" />
      </div>
    </div>
  );
}

function AlertCard({ alert }) {
  const cls = severityClasses[alert.severity] || severityClasses.info;
  return (
    <div className={`rounded-2xl border p-4 ${cls}`}>
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-sm font-semibold text-white">{alert.title || alert.description}</div>
          <div className="mt-1 text-xs uppercase tracking-[0.2em] text-slate-300/80">
            {alert.device || alert.source_ip || 'unknown'}
          </div>
        </div>
        <div className="whitespace-nowrap text-xs text-slate-300/80">{alert.time || ''}</div>
      </div>
      <p className="mt-3 text-sm leading-6 text-slate-200/90">{alert.detail || alert.description}</p>
      <div className="mt-4 flex gap-2">
        <button className="rounded-full border border-white/15 bg-white/10 px-3 py-1.5 text-xs text-white">
          Investigate
        </button>
        <button className="rounded-full border border-white/15 bg-white/5 px-3 py-1.5 text-xs text-white/90">
          Contain
        </button>
      </div>
    </div>
  );
}

function DeviceCard({ device }) {
  const trust = device.trust_level || device.trust || 50;
  const state = device.status || device.state || 'unknown';
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-4">
      <div className="flex items-center justify-between">
        <div>
          <div className="text-sm font-medium text-white">{device.hostname || device.name || 'Unknown'}</div>
          <div className="mt-1 text-xs uppercase tracking-[0.22em] text-slate-500">{device.ip_address || device.ip}</div>
        </div>
        <div className="rounded-full border border-slate-700 bg-slate-950 px-2.5 py-1 text-[10px] uppercase tracking-[0.25em] text-slate-300">
          {state}
        </div>
      </div>
      <div className="mt-4 flex items-center justify-between text-xs text-slate-400">
        <span>Trust level</span>
        <span className="text-white">{trust}%</span>
      </div>
      <div className="mt-2 h-2 rounded-full bg-slate-800">
        <div
          className={`h-2 rounded-full bg-gradient-to-r ${trustBar(trust)}`}
          style={{ width: `${trust}%` }}
        />
      </div>
    </div>
  );
}

function RexAvatar({ connected, activeThreats }) {
  const eyeColor = activeThreats > 0 ? 'bg-red-400 shadow-[0_0_22px_rgba(248,113,113,0.9)]' : 'bg-cyan-400 shadow-[0_0_22px_rgba(34,211,238,0.9)]';
  const statusText = !connected ? 'Connecting to neural mesh...' : activeThreats > 0 ? 'Threat posture: Elevated' : 'Autonomous defense online';
  const statusBorder = activeThreats > 0 ? 'border-red-400/20 bg-red-500/10 text-red-200' : 'border-emerald-400/25 bg-emerald-400/10 text-emerald-200';

  return (
    <div className="relative flex min-h-[330px] items-center justify-center rounded-[2rem] border border-cyan-400/15 bg-[radial-gradient(circle_at_center,rgba(34,211,238,0.16),transparent_42%),linear-gradient(to_bottom_right,rgba(15,23,42,0.95),rgba(2,6,23,0.95))]">
      <div className="absolute inset-0 rounded-[2rem] shadow-[inset_0_0_80px_rgba(34,211,238,0.08)]" />
      <div className={`absolute top-5 left-5 rounded-full border px-3 py-1 text-[10px] uppercase tracking-[0.28em] ${connected ? 'border-cyan-400/20 bg-cyan-400/10 text-cyan-200' : 'border-amber-400/20 bg-amber-400/10 text-amber-200'}`}>
        {connected ? 'Core Neural Mesh Stable' : 'Connecting...'}
      </div>
      <div className={`absolute bottom-5 right-5 rounded-full border px-3 py-1 text-[10px] uppercase tracking-[0.28em] ${statusBorder}`}>
        {statusText}
      </div>
      <div className="relative">
        <div className="absolute -inset-8 rounded-full bg-cyan-400/10 blur-3xl" />
        <div className="relative h-64 w-64 rounded-full border border-cyan-300/30 bg-slate-900/90 shadow-[0_0_80px_rgba(34,211,238,0.14)]">
          <div className="absolute inset-6 rounded-full border border-cyan-300/20" />
          <div className="absolute left-10 top-12 h-16 w-16 rounded-2xl border border-cyan-300/30 bg-slate-950/80 rotate-[-18deg]" />
          <div className="absolute right-10 top-12 h-16 w-16 rounded-2xl border border-cyan-300/30 bg-slate-950/80 rotate-[18deg]" />
          <div className={`absolute left-[74px] top-[92px] h-6 w-6 rounded-full ${eyeColor}`} />
          <div className={`absolute right-[74px] top-[92px] h-6 w-6 rounded-full ${eyeColor}`} />
          <div className="absolute left-1/2 top-[118px] h-16 w-24 -translate-x-1/2 rounded-[40px] border border-cyan-300/25 bg-slate-950/80" />
          <div className="absolute left-1/2 top-[145px] h-1.5 w-14 -translate-x-1/2 rounded-full bg-gradient-to-r from-cyan-400 to-fuchsia-500" />
          <div className="absolute left-1/2 bottom-12 flex -translate-x-1/2 items-center gap-2 text-[10px] uppercase tracking-[0.25em] text-slate-400">
            <span className={`h-2 w-2 rounded-full ${connected ? 'bg-emerald-400 shadow-[0_0_10px_rgba(74,222,128,0.8)]' : 'bg-amber-400 animate-pulse'}`} />
            {statusText}
          </div>
        </div>
      </div>
    </div>
  );
}

export default function FuturisticDashboard() {
  const { status, powerState, mode, deviceCount, activeThreats, threatsBlocked24h, llmStatus, connected } = useSystemStore();
  const { threats } = useThreatStore();
  const { devices } = useDeviceStore();

  const recentAlerts = threats.slice(0, 3);
  const topDevices = devices.slice(0, 4);

  return (
    <div className="min-h-screen bg-[#050816] text-slate-100 overflow-hidden">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_right,rgba(0,255,255,0.12),transparent_28%),radial-gradient(circle_at_bottom_left,rgba(255,0,128,0.10),transparent_26%),linear-gradient(to_bottom,rgba(255,255,255,0.03),transparent)]" />
      <div className="absolute inset-0 opacity-20 [background-image:linear-gradient(rgba(56,189,248,0.12)_1px,transparent_1px),linear-gradient(90deg,rgba(56,189,248,0.12)_1px,transparent_1px)] bg-[size:44px_44px]" />

      <div className="relative mx-auto max-w-7xl px-6 py-6">
        <header className="mb-6 rounded-3xl border border-cyan-400/20 bg-slate-950/70 backdrop-blur-xl shadow-[0_0_40px_rgba(34,211,238,0.08)]">
          <div className="flex flex-col gap-5 p-6 lg:flex-row lg:items-center lg:justify-between">
            <div className="flex items-center gap-4">
              <div className="relative flex h-16 w-16 items-center justify-center rounded-2xl border border-cyan-300/30 bg-cyan-400/10 shadow-[0_0_30px_rgba(34,211,238,0.18)]">
                <div className="absolute inset-1 rounded-2xl border border-cyan-300/20" />
                <span className="text-2xl" role="img" aria-label="guard dog">&#x1F43A;</span>
              </div>
              <div>
                <div className="text-xs uppercase tracking-[0.35em] text-cyan-300/80">REX-BOT-AI</div>
                <h1 className="text-3xl font-semibold tracking-tight">Autonomous Cyber Defense Console</h1>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              {[
                ["Mode", mode || 'unknown'],
                ["Status", status || 'unknown'],
                ["State", powerState || 'unknown'],
                ["LLM", llmStatus || 'unknown'],
              ].map(([k, v]) => (
                <div key={k} className="rounded-2xl border border-slate-800 bg-slate-900/80 px-4 py-3">
                  <div className="text-[10px] uppercase tracking-[0.28em] text-slate-500">{k}</div>
                  <div className="mt-2 text-sm font-medium text-slate-100">{v}</div>
                </div>
              ))}
            </div>
          </div>
        </header>

        <div className="grid gap-6 lg:grid-cols-[1.35fr_0.95fr]">
          <section className="space-y-6">
            <div className="grid gap-4 md:grid-cols-3">
              <StatCard label="Devices Protected" value={deviceCount} meta={connected ? 'live' : 'offline'} />
              <StatCard label="Threats Blocked" value={threatsBlocked24h} meta={`${activeThreats} active`} />
              <StatCard label="Network Health" value={status === 'operational' ? '100' : status === 'degraded' ? '72' : '--'} meta={status || 'unknown'} />
            </div>

            <div className="grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
              <div className="rounded-3xl border border-cyan-400/20 bg-slate-950/70 p-5 backdrop-blur-xl">
                <div className="mb-4 flex items-center justify-between">
                  <div>
                    <div className="text-[11px] uppercase tracking-[0.28em] text-slate-400">Guard Dog Core Status</div>
                    <h2 className="mt-1 text-xl font-semibold">REX Sentinel Avatar</h2>
                  </div>
                  <div className={`rounded-full border px-3 py-1 text-xs ${connected ? 'border-emerald-400/25 bg-emerald-400/10 text-emerald-200' : 'border-amber-400/25 bg-amber-400/10 text-amber-200'}`}>
                    {connected ? 'Active Defense' : 'Connecting...'}
                  </div>
                </div>
                <RexAvatar connected={connected} activeThreats={activeThreats} />
              </div>

              <div className="rounded-3xl border border-cyan-400/20 bg-slate-950/70 p-5 backdrop-blur-xl">
                <div className="mb-4 flex items-center justify-between">
                  <div>
                    <div className="text-[11px] uppercase tracking-[0.28em] text-slate-400">Recent Alerts</div>
                    <h2 className="mt-1 text-xl font-semibold">Threat Feed</h2>
                  </div>
                </div>
                <div className="space-y-3">
                  {recentAlerts.length === 0 ? (
                    <div className="py-8 text-center text-sm text-slate-500">
                      {connected ? 'No recent alerts.' : 'Waiting for backend connection...'}
                    </div>
                  ) : (
                    recentAlerts.map((alert, i) => <AlertCard key={alert.id || i} alert={alert} />)
                  )}
                </div>
              </div>
            </div>
          </section>

          <aside className="space-y-6">
            <div className="rounded-3xl border border-cyan-400/20 bg-slate-950/70 p-5 backdrop-blur-xl">
              <div className="mb-4">
                <div className="text-[11px] uppercase tracking-[0.28em] text-slate-400">Device Trust Matrix</div>
                <h2 className="mt-1 text-xl font-semibold">Risk Surface</h2>
              </div>
              <div className="space-y-4">
                {topDevices.length === 0 ? (
                  <div className="py-8 text-center text-sm text-slate-500">
                    {connected ? 'No devices discovered yet.' : 'Waiting for scan...'}
                  </div>
                ) : (
                  topDevices.map((device, i) => <DeviceCard key={device.mac_address || i} device={device} />)
                )}
              </div>
            </div>

            <div className="rounded-3xl border border-cyan-400/20 bg-slate-950/70 p-5 backdrop-blur-xl">
              <div className="mb-4 flex items-center justify-between">
                <div>
                  <div className="text-[11px] uppercase tracking-[0.28em] text-slate-400">Power State</div>
                  <h2 className="mt-1 text-xl font-semibold">Wake / Sleep Control</h2>
                </div>
                <div className={`h-3 w-3 rounded-full ${connected ? 'bg-emerald-400 shadow-[0_0_14px_rgba(74,222,128,0.9)]' : 'bg-amber-400 animate-pulse'}`} />
              </div>
              <div className="rounded-[2rem] border border-slate-800 bg-slate-900/80 p-4">
                <div className="mb-4 flex items-center justify-between text-sm">
                  <span className="text-slate-400">Current posture</span>
                  <span className="font-medium text-white">{powerState === 'awake' ? 'Awake / Active Defense' : powerState || 'Unknown'}</span>
                </div>
                <button className="w-full rounded-2xl border border-cyan-300/30 bg-gradient-to-r from-cyan-400/20 via-sky-400/15 to-fuchsia-500/20 px-4 py-3 text-sm font-semibold text-white shadow-[0_0_24px_rgba(34,211,238,0.12)]">
                  {powerState === 'awake' ? 'Put REX to Alert-Sleep' : 'Wake REX'}
                </button>
              </div>
            </div>
          </aside>
        </div>
      </div>
    </div>
  );
}
