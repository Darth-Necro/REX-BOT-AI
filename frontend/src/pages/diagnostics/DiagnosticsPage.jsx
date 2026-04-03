/**
 * DiagnosticsPage -- system diagnostics, dependency status, and log viewer.
 *
 * Combines data from:
 *   - /api/diagnostics  (full system snapshot)
 *   - /api/health + /api/status  (via diagnostics store, for service health grid)
 *
 * No fake data. Everything comes from live backend endpoints.
 */
import React, { useEffect, useState, useCallback } from 'react';
import useDiagnosticsStore from '../../stores/useDiagnosticsStore';
import ServiceCard from '../../components/cards/ServiceCard';
import LogViewer from '../../components/LogViewer';
import Badge from '../../components/primitives/Badge';
import Button from '../../components/primitives/Button';
import { SkeletonCard } from '../../components/primitives/Skeleton';
import api from '../../api/client';

/* ---------- helpers ---------- */

function formatUptime_local(seconds) {
  if (!seconds || seconds <= 0) return '--';
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const parts = [];
  if (d > 0) parts.push(`${d}d`);
  if (h > 0) parts.push(`${h}h`);
  parts.push(`${m}m`);
  return parts.join(' ');
}

function statusVariant(ok) {
  if (ok === true) return 'emerald';
  if (ok === false) return 'red';
  return 'default';
}

function statusLabel(ok) {
  if (ok === true) return 'Connected';
  if (ok === false) return 'Unreachable';
  return 'Unknown';
}

/* ---------- page ---------- */

export default function DiagnosticsPage() {
  const { snapshot, serviceHealth, loading, error, fetchedAt, fetchDiagnostics } =
    useDiagnosticsStore();

  const [diag, setDiag] = useState(null);
  const [diagLoading, setDiagLoading] = useState(false);
  const [diagError, setDiagError] = useState(null);
  const [copied, setCopied] = useState(false);

  const fetchFullDiagnostics = useCallback(async () => {
    setDiagLoading(true);
    setDiagError(null);
    try {
      const resp = await api.get('/diagnostics');
      setDiag(resp.data);
    } catch (err) {
      setDiagError(err.response?.data?.detail || err.message || 'Failed to fetch diagnostics');
    } finally {
      setDiagLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchDiagnostics();
    fetchFullDiagnostics();
    const interval = setInterval(() => {
      fetchDiagnostics();
      fetchFullDiagnostics();
    }, 30_000);
    return () => clearInterval(interval);
  }, [fetchDiagnostics, fetchFullDiagnostics]);

  const status = snapshot?.status ?? {};

  /* -- Copy diagnostics text to clipboard -- */
  const copyDiagnostics = useCallback(async () => {
    if (!diag) return;
    const lines = [
      '=== REX Diagnostics Report ===',
      '',
      `REX Version:       ${diag.rex_version || '--'}`,
      `Python Version:    ${diag.python_version || '--'}`,
      `OS:                ${diag.os_info?.name || '--'} ${diag.os_info?.version || ''}`,
      `Architecture:      ${diag.os_info?.architecture || '--'}`,
      `WSL:               ${diag.os_info?.is_wsl ? 'Yes' : 'No'}`,
      `Docker:            ${diag.os_info?.is_docker ? 'Yes' : 'No'}`,
      `VM:                ${diag.os_info?.is_vm ? 'Yes' : 'No'}`,
      '',
      '--- Configuration ---',
      `Data Dir:          ${diag.data_dir?.path || '--'}`,
      `Data Dir Writable: ${diag.data_dir?.writable ? 'Yes' : 'No'}`,
      `Protection Mode:   ${diag.protection_mode || '--'}`,
      `Power State:       ${diag.power_state || '--'}`,
      `Uptime:            ${formatUptime_local(diag.uptime_seconds)}`,
      '',
      '--- Dependencies ---',
      `Redis:             ${diag.services?.redis?.connected ? 'Connected' : 'Unreachable'} (${diag.services?.redis?.url || '--'})`,
      `Ollama:            ${diag.services?.ollama?.reachable ? 'Reachable' : 'Unreachable'} (${diag.services?.ollama?.url || '--'})`,
      `ChromaDB:          ${diag.services?.chromadb?.reachable ? 'Reachable' : 'Unreachable'} (${diag.services?.chromadb?.url || '--'})`,
      '',
      '--- Infrastructure ---',
      `TLS Configured:    ${diag.tls?.configured ? 'Yes' : 'No'}`,
      `Frontend Dist:     ${diag.frontend_dist_present ? 'Present' : 'Missing'}`,
      `PID File:          ${diag.pid_file?.exists ? `Yes (PID ${diag.pid_file.pid})` : 'Not found'}`,
      '',
      '--- Resources ---',
      `Disk Usage:        ${diag.resources?.disk_pct ?? '--'}%`,
      `Memory Usage:      ${diag.resources?.mem_pct ?? '--'}%`,
      '',
      `--- Service Summary ---`,
      `Total Services:    ${diag.service_summary?.total ?? '--'}`,
      `Healthy:           ${diag.service_summary?.healthy ?? '--'}`,
      `Unhealthy:         ${diag.service_summary?.unhealthy ?? '--'}`,
    ];

    try {
      await navigator.clipboard.writeText(lines.join('\n'));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback for non-secure contexts
      const textarea = document.createElement('textarea');
      textarea.value = lines.join('\n');
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }, [diag]);

  const handleRefresh = useCallback(() => {
    fetchDiagnostics();
    fetchFullDiagnostics();
  }, [fetchDiagnostics, fetchFullDiagnostics]);

  return (
    <div className="p-4 sm:p-6 lg:p-8 space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100">Diagnostics</h1>
          <p className="text-sm text-slate-500 mt-0.5">
            {loading || diagLoading
              ? 'Fetching runtime state...'
              : fetchedAt
                ? `Last updated ${new Date(fetchedAt).toLocaleTimeString()}`
                : 'No data yet'}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            onClick={copyDiagnostics}
            disabled={!diag}
            variant="secondary"
            size="sm"
            ariaLabel="Copy diagnostics to clipboard"
          >
            {copied ? 'Copied!' : 'Copy Diagnostics'}
          </Button>
          <Button
            onClick={handleRefresh}
            loading={loading || diagLoading}
            variant="secondary"
            size="sm"
            ariaLabel="Refresh diagnostics"
          >
            {loading || diagLoading ? 'Refreshing...' : 'Refresh'}
          </Button>
        </div>
      </div>

      {/* Error banners */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-2xl px-4 py-3">
          <p className="text-sm text-red-300">{error}</p>
        </div>
      )}
      {diagError && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-2xl px-4 py-3">
          <p className="text-sm text-red-300">{diagError}</p>
        </div>
      )}

      {/* System Info Section */}
      {diag && (
        <div>
          <h2 className="text-sm font-semibold text-slate-300 mb-3">System Information</h2>
          <div className="bg-gradient-to-br from-[#0B1020] to-[#11192C] border border-white/[0.06] rounded-2xl overflow-hidden">
            <table className="w-full text-sm">
              <tbody className="divide-y divide-white/[0.04]">
                <DiagRow label="REX Version" value={diag.rex_version} />
                <DiagRow label="Python Version" value={diag.python_version} />
                <DiagRow label="OS" value={`${diag.os_info?.name || '--'} ${diag.os_info?.version || ''}`} />
                <DiagRow label="Architecture" value={diag.os_info?.architecture} />
                <DiagRow label="Protection Mode" value={diag.protection_mode} />
                <DiagRow label="Power State" value={diag.power_state} />
                <DiagRow label="Uptime" value={formatUptime_local(diag.uptime_seconds)} />
                {diag.os_info?.is_wsl && <DiagRow label="Environment" value="WSL" />}
                {diag.os_info?.is_docker && <DiagRow label="Environment" value="Docker" />}
                {diag.os_info?.is_vm && <DiagRow label="Environment" value="Virtual Machine" />}
                {diag.os_info?.is_raspberry_pi && <DiagRow label="Environment" value="Raspberry Pi" />}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Dependency Status Section */}
      {diag && (
        <div>
          <h2 className="text-sm font-semibold text-slate-300 mb-3">Dependency Status</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {/* Redis */}
            <DependencyCard
              name="Redis"
              healthy={diag.services?.redis?.connected}
              detail={diag.services?.redis?.url}
            />
            {/* Ollama */}
            <DependencyCard
              name="Ollama (LLM)"
              healthy={diag.services?.ollama?.reachable}
              detail={diag.services?.ollama?.url}
            />
            {/* ChromaDB */}
            <DependencyCard
              name="ChromaDB"
              healthy={diag.services?.chromadb?.reachable}
              detail={diag.services?.chromadb?.url}
            />
            {/* TLS */}
            <DependencyCard
              name="TLS Certificates"
              healthy={diag.tls?.configured}
              detail={diag.tls?.configured
                ? `${diag.tls.cert_count} cert(s), ${diag.tls.key_count} key(s)`
                : 'Not configured'}
            />
            {/* Frontend Dist */}
            <DependencyCard
              name="Frontend Build"
              healthy={diag.frontend_dist_present}
              detail={diag.frontend_dist_present ? 'dist/ present' : 'dist/ missing'}
            />
            {/* Data Dir */}
            <DependencyCard
              name="Data Directory"
              healthy={diag.data_dir?.writable}
              detail={diag.data_dir?.path || '--'}
            />
          </div>
        </div>
      )}

      {/* Diagnostics loading skeletons */}
      {diagLoading && !diag && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {Array.from({ length: 6 }, (_, i) => (
            <SkeletonCard key={i} />
          ))}
        </div>
      )}

      {/* Service health grid */}
      <div>
        <h2 className="text-sm font-semibold text-slate-300 mb-3">Service Health</h2>
        {loading && serviceHealth.length === 0 ? (
          <div className="flex items-center justify-center py-12 text-slate-500 text-sm">
            <svg className="w-4 h-4 animate-spin mr-2" viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
            </svg>
            Loading service health...
          </div>
        ) : serviceHealth.length === 0 ? (
          <div className="py-12 text-center text-slate-500 text-sm">
            No service health data available. The backend may not be reachable.
          </div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {serviceHealth.map((svc) => (
              <ServiceCard key={svc.name} name={svc.name} status={svc.status} />
            ))}
          </div>
        )}
      </div>

      {/* Runtime truth (resource overview) */}
      {diag && (
        <div>
          <h2 className="text-sm font-semibold text-slate-300 mb-3">Resources</h2>
          <div className="bg-gradient-to-br from-[#0B1020] to-[#11192C] border border-white/[0.06] rounded-2xl overflow-hidden">
            <table className="w-full text-sm">
              <tbody className="divide-y divide-white/[0.04]">
                <DiagRow
                  label="Disk Usage"
                  value={`${diag.resources?.disk_pct ?? '--'}%`}
                  warn={!diag.resources?.disk_ok}
                />
                <DiagRow
                  label="Memory Usage"
                  value={`${diag.resources?.mem_pct ?? '--'}%`}
                  warn={!diag.resources?.mem_ok}
                />
                <DiagRow
                  label="PID File"
                  value={
                    diag.pid_file?.exists
                      ? `PID ${diag.pid_file.pid} (${diag.pid_file.process_alive ? 'running' : 'stale'})`
                      : 'Not found'
                  }
                  warn={diag.pid_file?.exists && !diag.pid_file?.process_alive}
                />
                <DiagRow
                  label="Services"
                  value={`${diag.service_summary?.healthy ?? 0}/${diag.service_summary?.total ?? 0} healthy`}
                  warn={(diag.service_summary?.unhealthy ?? 0) > 0}
                />
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Runtime State from status endpoint */}
      {snapshot && (
        <div>
          <h2 className="text-sm font-semibold text-slate-300 mb-3">Runtime State</h2>
          <div className="bg-gradient-to-br from-[#0B1020] to-[#11192C] border border-white/[0.06] rounded-2xl overflow-hidden">
            <table className="w-full text-sm">
              <tbody className="divide-y divide-white/[0.04]">
                <DiagRow label="System Status" value={status.status} />
                <DiagRow label="Power State" value={status.powerState} />
                <DiagRow label="LLM Engine" value={status.llmStatus} />
                <DiagRow label="Devices" value={status.deviceCount} />
                <DiagRow label="Active Threats" value={status.activeThreats} warn={status.activeThreats > 0} />
                <DiagRow label="Threats Blocked (24h)" value={status.threatsBlocked24h} />
                <DiagRow label="Uptime" value={formatUptime_local(status.uptimeSeconds)} />
                <DiagRow label="Version" value={status.version ?? '--'} />
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Log Viewer */}
      <div>
        <h2 className="text-sm font-semibold text-slate-300 mb-3">Application Logs</h2>
        <LogViewer />
      </div>
    </div>
  );
}

/* ---------- sub-components ---------- */

function DiagRow({ label, value, warn = false }) {
  const display = value === 0 ? '0' : value || '--';
  return (
    <tr className="hover:bg-white/[0.02]">
      <td className="px-5 py-3 text-xs text-slate-500 font-medium uppercase tracking-wide w-1/3">
        {label}
      </td>
      <td className={`px-5 py-3 text-sm font-medium ${
        warn ? 'text-red-300' :
        display === 'unknown' || display === '--' ? 'text-slate-500' :
        'text-slate-200'
      }`}>
        {display}
      </td>
    </tr>
  );
}

function DependencyCard({ name, healthy, detail }) {
  const variant = statusVariant(healthy);
  const label = statusLabel(healthy);

  return (
    <div
      className="bg-gradient-to-br from-[#0B1020] to-[#11192C] border border-white/[0.06]
                 rounded-2xl p-4 space-y-2 transition-shadow hover:shadow-md"
      role="listitem"
      aria-label={`${name}: ${label}`}
    >
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium text-slate-200">{name}</h3>
        <Badge variant={variant} size="sm" dot>
          {label}
        </Badge>
      </div>
      {detail && (
        <p className="text-[11px] text-slate-500 font-mono truncate" title={detail}>
          {detail}
        </p>
      )}
    </div>
  );
}
