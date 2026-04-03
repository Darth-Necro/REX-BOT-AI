import React from 'react';

export default function DegradedBanner({ services }) {
  const issues = [];
  if (services && !services.redis) issues.push('Redis unavailable — event bus degraded');
  if (services && !services.ollama) issues.push('Ollama unavailable — AI analysis disabled, rules-only mode');
  if (services && !services.chromadb) issues.push('ChromaDB unavailable — vector memory disabled');
  if (services && !services.tls) issues.push('No TLS certificates — running HTTP only');
  if (services && !services.frontend) issues.push('Some GUI pages may be incomplete');

  if (issues.length === 0) return null;

  return (
    <div className="bg-red-50 border-l-4 border-red-400 p-3 mb-4 rounded">
      <p className="text-red-700 text-sm font-bold mb-1">Degraded Mode</p>
      {issues.map((msg, i) => (
        <p key={i} className="text-red-600 text-xs">{msg}</p>
      ))}
    </div>
  );
}
