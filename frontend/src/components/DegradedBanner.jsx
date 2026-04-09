import React from 'react';

/**
 * DegradedBanner -- shows only when critical services are actually down.
 *
 * Only Redis and Ollama are shown here because they are the core services
 * that affect REX's functionality. ChromaDB (optional), TLS (normal for
 * local dev), and frontend completeness are not shown as degraded.
 */
export default function DegradedBanner({ services }) {
  const issues = [];
  if (services && services.redis === false) {
    issues.push('Redis unavailable — event bus degraded');
  }
  if (services && services.ollama === false) {
    issues.push('Ollama unavailable — AI analysis disabled, rules-only mode');
  }

  if (issues.length === 0) return null;

  return (
    <div className="rounded-xl border border-amber-500/30 bg-amber-500/5 p-3 mb-4">
      <p className="text-amber-300 text-sm font-bold mb-1">Degraded Mode</p>
      {issues.map((msg, i) => (
        <p key={i} className="text-amber-200/80 text-xs">{msg}</p>
      ))}
    </div>
  );
}
