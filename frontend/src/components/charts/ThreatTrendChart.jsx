/**
 * ThreatTrendChart -- area chart showing threats over time (24h by hour).
 *
 * Derives time buckets from the threat list passed as props.
 * Empty state when no data.
 */
import React, { useMemo } from 'react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from 'recharts';

function bucketByHour(threats) {
  const now = Date.now();
  const buckets = [];
  for (let i = 23; i >= 0; i--) {
    const start = now - (i + 1) * 3600000;
    const end = now - i * 3600000;
    const label = new Date(end).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const count = threats.filter((t) => {
      const ts = new Date(t.timestamp || t.detected_at).getTime();
      return ts >= start && ts < end;
    }).length;
    buckets.push({ time: label, threats: count });
  }
  return buckets;
}

function CustomTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-rex-surface border border-rex-card rounded-lg px-3 py-2 text-xs shadow-lg">
      <p className="text-slate-400 mb-1">{label}</p>
      <p className="text-red-300 font-medium">{payload[0].value} threat{payload[0].value !== 1 ? 's' : ''}</p>
    </div>
  );
}

export default function ThreatTrendChart({ threats = [] }) {
  const data = useMemo(() => bucketByHour(threats), [threats]);
  const hasData = data.some((d) => d.threats > 0);

  if (!hasData) {
    return (
      <div className="flex items-center justify-center h-48 text-xs text-slate-600">
        No threat data in the last 24 hours.
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={200}>
      <AreaChart data={data} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
        <defs>
          <linearGradient id="trendFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#DC2626" stopOpacity={0.3} />
            <stop offset="95%" stopColor="#DC2626" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
        <XAxis
          dataKey="time"
          tick={{ fill: '#64748b', fontSize: 10 }}
          tickLine={false}
          axisLine={false}
          interval="preserveStartEnd"
        />
        <YAxis
          tick={{ fill: '#64748b', fontSize: 10 }}
          tickLine={false}
          axisLine={false}
          allowDecimals={false}
        />
        <Tooltip content={<CustomTooltip />} />
        <Area
          type="monotone"
          dataKey="threats"
          stroke="#DC2626"
          strokeWidth={2}
          fill="url(#trendFill)"
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}
