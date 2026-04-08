/**
 * DeviceDetailsPage -- full drilldown for a single device.
 *
 * Fetches by MAC from the API. Falls back to store if available.
 * Shows network info, classification, ports, services, traffic stats.
 * No fabricated telemetry.
 */

import React, { useEffect, useState, useMemo } from 'react';
import { useParams, Link } from 'react-router-dom';
import { getDevice } from '../../api/devices';
import useDeviceStore from '../../stores/useDeviceStore';
import useThreatStore from '../../stores/useThreatStore';
import Badge from '../../components/primitives/Badge';
import Button from '../../components/primitives/Button';
import EmptyState from '../../components/primitives/EmptyState';
import { SkeletonCard } from '../../components/primitives/Skeleton';
import TrustRing from '../../components/network/TrustRing';
import SegmentBadge from '../../components/network/SegmentBadge';
import { trustTokens } from '../../lib/trust';
import { formatDateTime, timeAgo, formatBytes } from '../../lib/formatters';

/* ---------- page ---------- */

export default function DeviceDetailsPage() {
  const { id } = useParams(); // MAC address
  const [device, setDevice] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Try store first for instant display
  const storeDevices = useDeviceStore((s) => s.devices);
  const threats = useThreatStore((s) => s.threats);

  useEffect(() => {
    if (!id) return;
    let cancelled = false;

    // Check store first
    const cached = storeDevices.find((d) => d.mac_address === id);
    if (cached) {
      setDevice(cached);
      setLoading(false);
    }

    // Always fetch fresh data
    getDevice(id)
      .then((data) => {
        if (!cancelled) {
          setDevice(data);
          setLoading(false);
        }
      })
      .catch((err) => {
        if (!cancelled && !cached) {
          setError(err.message || 'Failed to load device');
          setLoading(false);
        }
      });

    return () => { cancelled = true; };
  }, [id, storeDevices]);

  // Related threats
  const relatedThreats = useMemo(() => {
    if (!device) return [];
    return threats.filter(
      (t) =>
        t.source_mac === device.mac_address ||
        t.source_ip === device.ip_address,
    );
  }, [device, threats]);

  if (loading && !device) {
    return (
      <div className="p-4 md:p-6 space-y-4">
        <SkeletonCard />
        <SkeletonCard />
      </div>
    );
  }

  if (error && !device) {
    return (
      <div className="p-4 md:p-6">
        <EmptyState
          variant="error"
          heading="Device not found"
          description={error}
          action={
            <Link to="/devices" className="text-xs text-red-400 hover:underline">
              Back to Devices
            </Link>
          }
        />
      </div>
    );
  }

  if (!device) return null;

  const ports = device.open_ports || device.ports || [];
  const services = device.services || [];
  const tTokens = trustTokens(device.trust_level || device.trust);

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-4xl">
      {/* Breadcrumb */}
      <nav aria-label="Breadcrumb" className="text-xs text-rex-muted">
        <Link to="/devices" className="hover:text-red-400 transition-colors">Devices</Link>
        <span className="mx-2">/</span>
        <span className="text-slate-300">{device.hostname || device.mac_address}</span>
      </nav>

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div className="flex items-center gap-4">
          <TrustRing trust={device.trust_level || device.trust} size={56} />
          <div>
            <h1 className="text-xl font-bold text-slate-100">
              {device.hostname || 'Unknown Device'}
            </h1>
            <div className="flex flex-wrap items-center gap-2 mt-1">
              <Badge
                variant={device.status === 'online' || device.status === 'trusted' ? 'emerald' : device.status === 'offline' ? 'red' : 'default'}
                size="sm"
                dot
              >
                {device.status || 'unknown'}
              </Badge>
              <span className={`text-xs font-medium ${tTokens.text}`}>
                {tTokens.label}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Network info */}
      <Section title="Network" ariaLabel="Network information">
        <FieldGrid>
          <Field label="IP Address" value={device.ip_address} mono />
          <Field label="MAC Address" value={device.mac_address} mono />
          <Field label="Vendor" value={device.vendor} />
          <Field label="Segment" custom>
            <SegmentBadge segment={device.segment || deriveSegment(device.ip_address)} />
          </Field>
        </FieldGrid>
      </Section>

      {/* Classification */}
      <Section title="Classification" ariaLabel="Device classification">
        <FieldGrid>
          <Field label="Type" value={device.device_type} capitalize />
          <Field label="OS" value={device.os || device.operating_system} />
          <Field label="Trust Level" value={device.trust_level} capitalize />
          <Field label="Status" value={device.status} capitalize />
        </FieldGrid>
      </Section>

      {/* Ports */}
      {ports.length > 0 && (
        <Section title="Open Ports" ariaLabel="Open ports">
          <div className="flex flex-wrap gap-1.5">
            {ports.map((p, i) => (
              <span
                key={i}
                className="text-xs bg-rex-card/60 border border-rex-card px-2.5 py-1 rounded-lg font-mono text-rex-text"
              >
                {typeof p === 'object' ? `${p.port}/${p.protocol || 'tcp'}` : p}
              </span>
            ))}
          </div>
        </Section>
      )}

      {/* Services */}
      {services.length > 0 && (
        <Section title="Services" ariaLabel="Running services">
          <div className="flex flex-wrap gap-1.5">
            {services.map((s, i) => (
              <Badge key={i} variant="red" size="sm">
                {typeof s === 'object' ? s.name : s}
              </Badge>
            ))}
          </div>
        </Section>
      )}

      {/* Traffic */}
      {(device.bytes_sent != null || device.bytes_recv != null) && (
        <Section title="Traffic" ariaLabel="Traffic statistics">
          <FieldGrid>
            <Field label="Bytes Sent" value={formatBytes(device.bytes_sent)} />
            <Field label="Bytes Received" value={formatBytes(device.bytes_recv)} />
          </FieldGrid>
        </Section>
      )}

      {/* Timestamps */}
      <Section title="Timestamps" ariaLabel="Device timestamps">
        <FieldGrid>
          {device.first_seen && (
            <Field label="First Seen" value={`${formatDateTime(device.first_seen)} (${timeAgo(device.first_seen)})`} />
          )}
          {device.last_seen && (
            <Field label="Last Seen" value={`${formatDateTime(device.last_seen)} (${timeAgo(device.last_seen)})`} />
          )}
        </FieldGrid>
      </Section>

      {/* Related threats */}
      <Section title={`Related Threats (${relatedThreats.length})`} ariaLabel="Related threats">
        {relatedThreats.length === 0 ? (
          <p className="text-xs text-rex-muted italic">No threats associated with this device.</p>
        ) : (
          <div className="space-y-2">
            {relatedThreats.slice(0, 10).map((t) => (
              <Link
                key={t.id}
                to={`/threats/${encodeURIComponent(t.id)}`}
                className="flex items-center justify-between bg-rex-card/20 border border-rex-card rounded-xl px-4 py-2 hover:bg-rex-card/30 transition-colors group"
              >
                <div className="min-w-0">
                  <p className="text-xs text-rex-text truncate group-hover:text-red-300 transition-colors">
                    {t.category || t.title || t.id}
                  </p>
                  <p className="text-[10px] text-rex-muted font-mono">
                    {formatDateTime(t.timestamp)}
                  </p>
                </div>
                <Badge
                  variant={t.severity === 'critical' ? 'red' : t.severity === 'high' ? 'orange' : 'default'}
                  size="sm"
                >
                  {t.severity || 'unknown'}
                </Badge>
              </Link>
            ))}
          </div>
        )}
      </Section>

      {/* MAC address footer */}
      <p className="text-[10px] text-rex-muted font-mono break-all">
        MAC: {device.mac_address}
      </p>
    </div>
  );
}

/* ---------- sub-components ---------- */

function Section({ title, ariaLabel, children }) {
  return (
    <section
      className="bg-rex-surface border border-rex-card rounded-2xl p-5 space-y-3"
      aria-label={ariaLabel}
    >
      <h2 className="text-sm font-semibold text-slate-300">{title}</h2>
      {children}
    </section>
  );
}

function FieldGrid({ children }) {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
      {children}
    </div>
  );
}

function Field({ label, value, mono, capitalize: cap, custom, children }) {
  return (
    <div className="flex items-center justify-between gap-2">
      <span className="text-xs text-rex-muted shrink-0">{label}</span>
      {custom ? (
        children
      ) : (
        <span className={`text-xs text-rex-text text-right ${mono ? 'font-mono' : ''} ${cap ? 'capitalize' : ''}`}>
          {value || '--'}
        </span>
      )}
    </div>
  );
}

function deriveSegment(ip) {
  if (!ip || typeof ip !== 'string') return 'unknown';
  const parts = ip.split('.');
  if (parts.length !== 4) return 'unknown';
  return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
}
