/**
 * SeverityBreakdownChart -- pie chart showing threat distribution by severity.
 */
import React, { useMemo } from 'react';
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
} from 'recharts';

const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#f59e0b',
  low: '#22d3ee',
  info: '#64748b',
};

function CustomTooltip({ active, payload }) {
  if (!active || !payload?.length) return null;
  const d = payload[0];
  return (
    <div className="bg-rex-surface border border-rex-card rounded-lg px-3 py-2 text-xs shadow-lg">
      <p className="capitalize" style={{ color: d.payload.fill }}>{d.name}</p>
      <p className="text-slate-200 font-medium">{d.value} threat{d.value !== 1 ? 's' : ''}</p>
    </div>
  );
}

export default function SeverityBreakdownChart({ threats = [] }) {
  const data = useMemo(() => {
    const counts = {};
    threats.forEach((t) => {
      const sev = (t.severity || 'info').toLowerCase();
      counts[sev] = (counts[sev] || 0) + 1;
    });
    return Object.entries(counts)
      .map(([name, value]) => ({ name, value }))
      .sort((a, b) => b.value - a.value);
  }, [threats]);

  if (data.length === 0) {
    return (
      <div className="flex items-center justify-center h-48 text-xs text-slate-600">
        No threat data available.
      </div>
    );
  }

  return (
    <div className="flex items-center gap-4">
      <ResponsiveContainer width={140} height={140}>
        <PieChart>
          <Pie
            data={data}
            dataKey="value"
            nameKey="name"
            cx="50%"
            cy="50%"
            innerRadius={35}
            outerRadius={60}
            paddingAngle={2}
            strokeWidth={0}
          >
            {data.map((entry) => (
              <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name] || SEVERITY_COLORS.info} />
            ))}
          </Pie>
          <Tooltip content={<CustomTooltip />} />
        </PieChart>
      </ResponsiveContainer>
      <div className="space-y-1.5">
        {data.map((entry) => (
          <div key={entry.name} className="flex items-center gap-2 text-xs">
            <span
              className="w-2.5 h-2.5 rounded-full shrink-0"
              style={{ backgroundColor: SEVERITY_COLORS[entry.name] || SEVERITY_COLORS.info }}
            />
            <span className="text-slate-400 capitalize">{entry.name}</span>
            <span className="text-slate-200 font-medium ml-auto tabular-nums">{entry.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
