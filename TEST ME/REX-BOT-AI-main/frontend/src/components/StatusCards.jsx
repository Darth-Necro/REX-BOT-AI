import React from 'react';
import useSystemStore from '../stores/useSystemStore';

function Card({ label, value, color = 'text-rex-text' }) {
  return (
    <div className="bg-rex-card rounded-xl p-4 flex flex-col items-center">
      <span className={`text-3xl font-bold ${color}`}>{value}</span>
      <span className="text-sm text-rex-muted mt-1">{label}</span>
    </div>
  );
}

export default function StatusCards() {
  const { deviceCount, threatsBlocked24h, activeThreats } = useSystemStore();
  const healthLabel = activeThreats === 0 ? 'Good' : activeThreats < 5 ? 'Fair' : 'Needs Attention';
  const healthColor = activeThreats === 0 ? 'text-rex-safe' : activeThreats < 5 ? 'text-rex-warn' : 'text-rex-threat';

  return (
    <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 w-full max-w-xl">
      <Card label="Devices Protected" value={deviceCount} color="text-rex-accent" />
      <Card label="Threats Blocked (24h)" value={threatsBlocked24h} color="text-rex-safe" />
      <Card label="Network Health" value={healthLabel} color={healthColor} />
    </div>
  );
}
