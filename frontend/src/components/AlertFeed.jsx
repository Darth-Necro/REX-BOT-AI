import React from 'react';
import useThreatStore from '../stores/useThreatStore';

const severityColors = {
  critical: 'border-rex-threat bg-rex-threat/10',
  high: 'border-orange-500 bg-orange-500/10',
  medium: 'border-rex-warn bg-rex-warn/10',
  low: 'border-rex-accent bg-rex-accent/10',
  info: 'border-rex-muted bg-rex-muted/10',
};

function timeAgo(timestamp) {
  if (!timestamp) return '';
  const diff = Date.now() - new Date(timestamp).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins} min ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

export default function AlertFeed() {
  const { threats } = useThreatStore();
  const recent = threats.slice(0, 5);

  if (recent.length === 0) {
    return (
      <div className="w-full max-w-xl text-center text-rex-muted py-8">
        All quiet. No recent alerts.
      </div>
    );
  }

  return (
    <div className="w-full max-w-xl space-y-2">
      <h3 className="text-sm font-semibold text-rex-muted uppercase tracking-wide">Recent Alerts</h3>
      {recent.map((t, i) => (
        <div
          key={t.id || i}
          className={`border-l-4 rounded-r-lg p-3 ${severityColors[t.severity] || severityColors.info}`}
        >
          <div className="flex justify-between items-start">
            <p className="text-sm">{t.description || 'Security event detected'}</p>
            <span className="text-xs text-rex-muted ml-2 whitespace-nowrap">
              {timeAgo(t.timestamp)}
            </span>
          </div>
        </div>
      ))}
    </div>
  );
}
