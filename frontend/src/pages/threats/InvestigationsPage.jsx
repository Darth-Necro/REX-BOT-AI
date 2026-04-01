/**
 * InvestigationsPage -- combined timeline + reasoning + device context
 * for a threat investigation.
 *
 * Composes IncidentTimelinePanel and ReasoningPanel alongside
 * device context from the device store.
 *
 * No fabricated data. Every section degrades honestly when data is missing.
 */

import React, { useEffect, useState, useMemo } from 'react';
import { useParams, Link } from 'react-router-dom';
import { getThreat } from '../../api/threats';
import useDeviceStore from '../../stores/useDeviceStore';
import IncidentTimelinePanel from '../../components/panels/IncidentTimelinePanel';
import ReasoningPanel from '../../components/panels/ReasoningPanel';
import Tabs, { TabPanel } from '../../components/primitives/Tabs';
import Badge from '../../components/primitives/Badge';
import EmptyState from '../../components/primitives/EmptyState';
import { SkeletonCard } from '../../components/primitives/Skeleton';
import { severityTokens, normalizeSeverity } from '../../lib/severity';
import { formatDateTime } from '../../lib/formatters';

const INVESTIGATION_TABS = [
  { id: 'timeline', label: 'Timeline' },
  { id: 'reasoning', label: 'Analysis' },
  { id: 'context', label: 'Device Context' },
];

/* ---------- page ---------- */

export default function InvestigationsPage() {
  const { id } = useParams();
  const [threat, setThreat] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('timeline');

  const devices = useDeviceStore((s) => s.devices);
  const fetchDevices = useDeviceStore((s) => s.fetchDevices);

  // Hydrate threat
  useEffect(() => {
    if (!id) return;
    let cancelled = false;
    setLoading(true);
    setError(null);

    getThreat(id)
      .then((data) => {
        if (!cancelled) {
          setThreat(data);
          setLoading(false);
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setError(err.message || 'Failed to load investigation');
          setLoading(false);
        }
      });

    return () => { cancelled = true; };
  }, [id]);

  // Ensure devices are loaded for context tab
  useEffect(() => {
    if (devices.length === 0) fetchDevices();
  }, [devices.length, fetchDevices]);

  // Derive timeline events from threat data
  const timelineEvents = useMemo(() => {
    if (!threat) return [];
    const events = [];

    if (threat.timestamp) {
      events.push({
        kind: 'observed',
        timestamp: threat.timestamp,
        title: 'Threat detected',
        detail: threat.description || threat.category || undefined,
      });
    }

    if (threat.analysis || threat.reasoning) {
      events.push({
        kind: 'inferred',
        timestamp: threat.analyzed_at || threat.timestamp,
        title: 'REX analysis completed',
        detail: threat.analysis || threat.reasoning,
      });
    }

    if (threat.action_taken) {
      events.push({
        kind: 'executed',
        timestamp: threat.action_at || threat.timestamp,
        title: 'Automated action taken',
        detail: threat.action_taken,
      });
    }

    if (threat.resolved || threat.status === 'resolved') {
      events.push({
        kind: 'observed',
        timestamp: threat.resolved_at || threat.timestamp,
        title: 'Threat resolved',
      });
    }

    // Append any explicit events array from the backend
    if (Array.isArray(threat.events)) {
      threat.events.forEach((e) => events.push(e));
    }

    return events;
  }, [threat]);

  // Derive reasoning steps
  const reasoningSteps = useMemo(() => {
    if (!threat) return [];
    if (Array.isArray(threat.reasoning_steps)) return threat.reasoning_steps;
    if (threat.analysis || threat.reasoning) {
      return [{ summary: threat.analysis || threat.reasoning }];
    }
    return [];
  }, [threat]);

  // Find related device
  const relatedDevice = useMemo(() => {
    if (!threat) return null;
    const mac = threat.source_mac;
    const ip = threat.source_ip;
    return devices.find(
      (d) =>
        (mac && d.mac_address === mac) ||
        (ip && d.ip_address === ip),
    ) || null;
  }, [threat, devices]);

  /* ---------- render ---------- */

  if (loading) {
    return (
      <div className="p-4 md:p-6 space-y-4">
        <SkeletonCard />
        <SkeletonCard />
      </div>
    );
  }

  if (error || !threat) {
    return (
      <div className="p-4 md:p-6">
        <EmptyState
          variant="error"
          heading="Investigation not found"
          description={error || `Could not load investigation for ${id}.`}
          action={
            <Link to="/threats" className="text-xs text-cyan-400 hover:underline">
              Back to Threats
            </Link>
          }
        />
      </div>
    );
  }

  const sev = normalizeSeverity(threat.severity);

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-5xl">
      {/* Breadcrumb */}
      <nav aria-label="Breadcrumb" className="text-xs text-rex-muted">
        <Link to="/threats" className="hover:text-cyan-400 transition-colors">Threats</Link>
        <span className="mx-2">/</span>
        <span className="text-slate-300">Investigation: {threat.id || id}</span>
      </nav>

      {/* Header */}
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="text-xl font-bold text-slate-100">
          {threat.title || threat.category || 'Investigation'}
        </h1>
        <Badge variant={sev === 'critical' ? 'red' : sev === 'high' ? 'orange' : sev === 'medium' ? 'amber' : 'default'} dot>
          {sev}
        </Badge>
        {(threat.resolved || threat.status === 'resolved') && (
          <Badge variant="emerald" dot>Resolved</Badge>
        )}
        {threat.timestamp && (
          <span className="text-xs text-rex-muted font-mono">
            {formatDateTime(threat.timestamp)}
          </span>
        )}
      </div>

      {/* Tabs */}
      <Tabs
        tabs={INVESTIGATION_TABS}
        activeId={activeTab}
        onChange={setActiveTab}
        ariaLabel="Investigation sections"
      />

      {/* Tab panels */}
      <TabPanel id="timeline" activeId={activeTab}>
        <IncidentTimelinePanel events={timelineEvents} />
      </TabPanel>

      <TabPanel id="reasoning" activeId={activeTab}>
        <ReasoningPanel
          steps={reasoningSteps}
          conclusion={threat.conclusion || null}
        />
      </TabPanel>

      <TabPanel id="context" activeId={activeTab}>
        {relatedDevice ? (
          <DeviceContextCard device={relatedDevice} />
        ) : (
          <EmptyState
            variant="empty"
            heading="No device context"
            description="Could not find a matching device for this threat's source."
          />
        )}
      </TabPanel>
    </div>
  );
}

/* ---------- device context card ---------- */

function DeviceContextCard({ device }) {
  return (
    <div
      className="bg-rex-surface border border-rex-card rounded-2xl p-5 space-y-3"
      role="region"
      aria-label={`Device context: ${device.hostname || device.ip_address}`}
    >
      <h3 className="text-sm font-semibold text-slate-200">
        {device.hostname || device.ip_address || 'Unknown Device'}
      </h3>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
        <CtxField label="IP" value={device.ip_address} mono />
        <CtxField label="MAC" value={device.mac_address} mono />
        <CtxField label="Type" value={device.device_type} capitalize />
        <CtxField label="Trust" value={device.trust_level} capitalize />
        <CtxField label="Status" value={device.status} capitalize />
        <CtxField label="Vendor" value={device.vendor} />
        <CtxField label="OS" value={device.os || device.operating_system} />
      </div>
      {device.mac_address && (
        <Link
          to={`/devices/${encodeURIComponent(device.mac_address)}`}
          className="inline-block text-xs text-cyan-400 hover:underline mt-2"
        >
          View full device details
        </Link>
      )}
    </div>
  );
}

function CtxField({ label, value, mono, capitalize: cap }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-xs text-rex-muted">{label}</span>
      <span className={`text-xs text-rex-text ${mono ? 'font-mono' : ''} ${cap ? 'capitalize' : ''}`}>
        {value || '--'}
      </span>
    </div>
  );
}
