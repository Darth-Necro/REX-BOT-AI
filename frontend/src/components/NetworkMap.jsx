import React, { useState, useMemo } from 'react';
import useDeviceStore from '../stores/useDeviceStore';

const STATUS_FILL = {
  online: '#22c55e',
  offline: '#6b7280',
  quarantined: '#ef4444',
  trusted: '#3b82f6',
};

const DEVICE_ICONS = {
  router: (x, y, fill) => (
    <g transform={`translate(${x - 12}, ${y - 12})`}>
      <rect x="2" y="8" width="20" height="8" rx="2" fill={fill} opacity="0.2" stroke={fill} strokeWidth="1.5" />
      <circle cx="7" cy="12" r="1.5" fill={fill} />
      <circle cx="12" cy="12" r="1.5" fill={fill} />
      <circle cx="17" cy="12" r="1.5" fill={fill} />
      <line x1="4" y1="5" x2="8" y2="8" stroke={fill} strokeWidth="1.2" />
      <line x1="12" y1="3" x2="12" y2="8" stroke={fill} strokeWidth="1.2" />
      <line x1="20" y1="5" x2="16" y2="8" stroke={fill} strokeWidth="1.2" />
    </g>
  ),
  laptop: (x, y, fill) => (
    <g transform={`translate(${x - 10}, ${y - 8})`}>
      <rect x="3" y="1" width="14" height="10" rx="1.5" fill={fill} opacity="0.15" stroke={fill} strokeWidth="1.2" />
      <rect x="3" y="3" width="14" height="6" rx="0.5" fill={fill} opacity="0.1" />
      <path d="M1 13h18l-1 3H2l-1-3z" fill={fill} opacity="0.25" stroke={fill} strokeWidth="1" />
    </g>
  ),
  phone: (x, y, fill) => (
    <g transform={`translate(${x - 6}, ${y - 10})`}>
      <rect x="1" y="1" width="10" height="18" rx="2" fill={fill} opacity="0.15" stroke={fill} strokeWidth="1.2" />
      <line x1="4" y1="16" x2="8" y2="16" stroke={fill} strokeWidth="1" strokeLinecap="round" />
    </g>
  ),
  camera: (x, y, fill) => (
    <g transform={`translate(${x - 10}, ${y - 8})`}>
      <rect x="1" y="5" width="18" height="11" rx="2" fill={fill} opacity="0.15" stroke={fill} strokeWidth="1.2" />
      <circle cx="10" cy="10.5" r="3.5" fill={fill} opacity="0.2" stroke={fill} strokeWidth="1" />
      <path d="M6 5V3h3v2" fill={fill} opacity="0.3" />
    </g>
  ),
  tv: (x, y, fill) => (
    <g transform={`translate(${x - 11}, ${y - 8})`}>
      <rect x="1" y="1" width="20" height="13" rx="1.5" fill={fill} opacity="0.15" stroke={fill} strokeWidth="1.2" />
      <line x1="7" y1="16" x2="15" y2="16" stroke={fill} strokeWidth="1.5" strokeLinecap="round" />
    </g>
  ),
  printer: (x, y, fill) => (
    <g transform={`translate(${x - 10}, ${y - 9})`}>
      <rect x="5" y="1" width="10" height="5" rx="0.5" fill={fill} opacity="0.2" stroke={fill} strokeWidth="1" />
      <rect x="1" y="6" width="18" height="8" rx="1.5" fill={fill} opacity="0.15" stroke={fill} strokeWidth="1.2" />
      <rect x="5" y="14" width="10" height="4" rx="0.5" fill={fill} opacity="0.1" stroke={fill} strokeWidth="1" />
    </g>
  ),
  server: (x, y, fill) => (
    <g transform={`translate(${x - 8}, ${y - 10})`}>
      <rect x="1" y="1" width="14" height="5" rx="1" fill={fill} opacity="0.15" stroke={fill} strokeWidth="1.2" />
      <rect x="1" y="8" width="14" height="5" rx="1" fill={fill} opacity="0.15" stroke={fill} strokeWidth="1.2" />
      <rect x="1" y="15" width="14" height="5" rx="1" fill={fill} opacity="0.15" stroke={fill} strokeWidth="1.2" />
      <circle cx="4" cy="3.5" r="1" fill={fill} />
      <circle cx="4" cy="10.5" r="1" fill={fill} />
      <circle cx="4" cy="17.5" r="1" fill={fill} />
    </g>
  ),
  unknown: (x, y, fill) => (
    <g transform={`translate(${x - 8}, ${y - 8})`}>
      <circle cx="8" cy="8" r="7" fill={fill} opacity="0.15" stroke={fill} strokeWidth="1.2" />
      <text x="8" y="12" textAnchor="middle" fill={fill} fontSize="10" fontWeight="bold">?</text>
    </g>
  ),
};

function getDeviceIcon(type) {
  const t = (type || 'unknown').toLowerCase();
  if (t.includes('router') || t.includes('gateway')) return 'router';
  if (t.includes('laptop') || t.includes('computer') || t.includes('desktop') || t.includes('pc')) return 'laptop';
  if (t.includes('phone') || t.includes('mobile') || t.includes('tablet')) return 'phone';
  if (t.includes('camera') || t.includes('cam')) return 'camera';
  if (t.includes('tv') || t.includes('display') || t.includes('chromecast') || t.includes('roku')) return 'tv';
  if (t.includes('printer') || t.includes('print')) return 'printer';
  if (t.includes('server') || t.includes('nas') || t.includes('raspberry')) return 'server';
  return 'unknown';
}

function Tooltip({ device, x, y, viewBox }) {
  const tooltipWidth = 180;
  const tooltipHeight = 70;
  // Keep tooltip within viewBox bounds
  let tx = x + 20;
  let ty = y - 35;
  if (tx + tooltipWidth > viewBox) tx = x - tooltipWidth - 10;
  if (ty < 5) ty = 5;
  if (ty + tooltipHeight > viewBox) ty = viewBox - tooltipHeight - 5;

  return (
    <g>
      <rect
        x={tx} y={ty}
        width={tooltipWidth} height={tooltipHeight}
        rx="6"
        fill="#16213e"
        stroke="#0f3460"
        strokeWidth="1"
        filter="url(#shadow)"
      />
      <text x={tx + 10} y={ty + 18} fill="#e2e8f0" fontSize="11" fontWeight="600">
        {device.hostname || 'Unknown Device'}
      </text>
      <text x={tx + 10} y={ty + 34} fill="#94a3b8" fontSize="10">
        {device.ip_address || 'No IP'}
      </text>
      <text x={tx + 10} y={ty + 50} fill="#94a3b8" fontSize="10">
        Type: {device.device_type || 'Unknown'}
      </text>
      <text x={tx + 10} y={ty + 63} fill={STATUS_FILL[device.status] || '#6b7280'} fontSize="9" textTransform="capitalize">
        {device.status || 'unknown'}
      </text>
    </g>
  );
}

export default function NetworkMap() {
  const { devices } = useDeviceStore();
  const [hoveredMac, setHoveredMac] = useState(null);
  const viewBox = 500;
  const center = viewBox / 2;

  const gateway = useMemo(() => {
    return devices.find(
      (d) =>
        (d.device_type || '').toLowerCase().includes('router') ||
        (d.device_type || '').toLowerCase().includes('gateway') ||
        (d.is_gateway)
    );
  }, [devices]);

  const peripherals = useMemo(() => {
    if (!gateway) return devices;
    return devices.filter((d) => d.mac_address !== gateway.mac_address);
  }, [devices, gateway]);

  const positions = useMemo(() => {
    const pos = new Map();
    if (gateway) {
      pos.set(gateway.mac_address, { x: center, y: center });
    }
    const count = peripherals.length;
    const radius = Math.min(viewBox * 0.35, 170);
    peripherals.forEach((d, i) => {
      const angle = (2 * Math.PI * i) / Math.max(count, 1) - Math.PI / 2;
      pos.set(d.mac_address, {
        x: center + radius * Math.cos(angle),
        y: center + radius * Math.sin(angle),
      });
    });
    return pos;
  }, [peripherals, gateway, center, viewBox]);

  const hoveredDevice = hoveredMac
    ? devices.find((d) => d.mac_address === hoveredMac)
    : null;
  const hoveredPos = hoveredMac ? positions.get(hoveredMac) : null;

  if (devices.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-rex-muted">
        <svg className="w-16 h-16 mb-4 opacity-30" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
            d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064" />
        </svg>
        <p>No devices discovered yet.</p>
        <p className="text-xs mt-1">Run a network scan to populate the map.</p>
      </div>
    );
  }

  return (
    <div className="w-full aspect-square max-w-2xl mx-auto">
      <svg
        viewBox={`0 0 ${viewBox} ${viewBox}`}
        className="w-full h-full"
        role="img"
        aria-label="Network topology map"
      >
        <defs>
          <filter id="shadow" x="-10%" y="-10%" width="130%" height="130%">
            <feDropShadow dx="0" dy="2" stdDeviation="4" floodOpacity="0.4" />
          </filter>
          <filter id="glow">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {/* Background circle */}
        <circle cx={center} cy={center} r={viewBox * 0.45} fill="none" stroke="#0f3460" strokeWidth="0.5" strokeDasharray="4 4" opacity="0.4" />

        {/* Connection lines from gateway to peripherals */}
        {gateway && peripherals.map((d) => {
          const from = positions.get(gateway.mac_address);
          const to = positions.get(d.mac_address);
          if (!from || !to) return null;
          const fill = STATUS_FILL[d.status] || '#6b7280';
          return (
            <line
              key={`line-${d.mac_address}`}
              x1={from.x} y1={from.y}
              x2={to.x} y2={to.y}
              stroke={fill}
              strokeWidth={hoveredMac === d.mac_address ? 2 : 0.8}
              opacity={hoveredMac === d.mac_address ? 0.8 : 0.3}
              strokeDasharray={d.status === 'offline' ? '4 4' : 'none'}
            />
          );
        })}

        {/* If no gateway, connect first device to all others */}
        {!gateway && devices.length > 1 && devices.slice(1).map((d) => {
          const from = positions.get(devices[0].mac_address);
          const to = positions.get(d.mac_address);
          if (!from || !to) return null;
          return (
            <line
              key={`line-${d.mac_address}`}
              x1={from.x} y1={from.y}
              x2={to.x} y2={to.y}
              stroke="#0f3460"
              strokeWidth="0.8"
              opacity="0.3"
            />
          );
        })}

        {/* Gateway node (rendered large, in center) */}
        {gateway && (() => {
          const pos = positions.get(gateway.mac_address);
          const fill = STATUS_FILL[gateway.status] || '#22c55e';
          return (
            <g
              className="cursor-pointer"
              onMouseEnter={() => setHoveredMac(gateway.mac_address)}
              onMouseLeave={() => setHoveredMac(null)}
            >
              <circle cx={pos.x} cy={pos.y} r="28" fill={fill} opacity="0.08" />
              <circle cx={pos.x} cy={pos.y} r="22" fill={fill} opacity="0.12" stroke={fill} strokeWidth="1.5" />
              {DEVICE_ICONS.router(pos.x, pos.y, fill)}
              <text x={pos.x} y={pos.y + 35} textAnchor="middle" fill="#94a3b8" fontSize="9">
                {gateway.hostname || 'Gateway'}
              </text>
            </g>
          );
        })()}

        {/* Peripheral device nodes */}
        {peripherals.map((d) => {
          const pos = positions.get(d.mac_address);
          if (!pos) return null;
          const fill = STATUS_FILL[d.status] || '#6b7280';
          const iconType = getDeviceIcon(d.device_type);
          const iconFn = DEVICE_ICONS[iconType] || DEVICE_ICONS.unknown;
          const isHovered = hoveredMac === d.mac_address;

          return (
            <g
              key={d.mac_address}
              className="cursor-pointer"
              onMouseEnter={() => setHoveredMac(d.mac_address)}
              onMouseLeave={() => setHoveredMac(null)}
            >
              <circle
                cx={pos.x} cy={pos.y} r="18"
                fill={fill} opacity={isHovered ? 0.15 : 0.06}
                stroke={fill} strokeWidth={isHovered ? 1.5 : 0.5}
              />
              {iconFn(pos.x, pos.y, fill)}
              <text x={pos.x} y={pos.y + 28} textAnchor="middle" fill="#94a3b8" fontSize="8">
                {(d.hostname || d.ip_address || '').slice(0, 16)}
              </text>
            </g>
          );
        })}

        {/* Tooltip */}
        {hoveredDevice && hoveredPos && (
          <Tooltip device={hoveredDevice} x={hoveredPos.x} y={hoveredPos.y} viewBox={viewBox} />
        )}
      </svg>
    </div>
  );
}
