/**
 * LoginPage -- full-screen login with REX identity and LoginForm.
 *
 * Dark, futuristic aesthetic. ASCII REX dog, version badge,
 * connection hint. No fake data.
 */

import React, { useState, useEffect } from 'react';
import LoginForm from '../../components/auth/LoginForm';
import api from '../../api/client';

const _apiBase = import.meta.env.VITE_API_URL || window.location.origin;

export default function LoginPage() {
  const [version, setVersion] = useState(null);

  useEffect(() => {
    api.get('/status').then(res => {
      if (res.data?.version) setVersion(res.data.version);
    }).catch(() => { /* backend unreachable */ });
  }, []);

  return (
    <div className="min-h-screen bg-rex-bg flex items-center justify-center px-4">
      {/* Subtle background grid */}
      <div className="absolute inset-0 opacity-[0.03] pointer-events-none"
           style={{
             backgroundImage:
               'linear-gradient(rgba(0,255,255,.3) 1px, transparent 1px), linear-gradient(90deg, rgba(0,255,255,.3) 1px, transparent 1px)',
             backgroundSize: '40px 40px',
           }}
      />

      <div className="relative w-full max-w-sm">
        {/* Card */}
        <div className="bg-rex-surface/90 backdrop-blur-sm border border-rex-card rounded-2xl p-8 shadow-2xl shadow-red-500/5">
          {/* REX ASCII identity */}
          <pre
            className="text-red-400 text-center text-xl leading-tight mb-2 select-none font-mono"
            aria-hidden="true"
          >
{`  /\\_/\\
 ( o.o )
  > ^ <`}
          </pre>

          <h1 className="text-xl font-bold text-center text-rex-text tracking-wide mb-1">
            REX-BOT-AI
          </h1>
          <p className="text-xs text-rex-muted text-center mb-6">
            Network Security Console
          </p>

          {/* Login form */}
          <LoginForm />

          {/* Footer */}
          <div className="mt-6 pt-4 border-t border-rex-card/50 space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-[10px] text-rex-muted/50 font-mono">{version || 'loading...'}</span>
              <span className="text-[10px] text-rex-muted/50">Local auth only</span>
            </div>
            <div className="text-[10px] text-rex-muted/40 font-mono truncate" title={_apiBase}>
              {_apiBase}
            </div>
          </div>
        </div>

        {/* Subtle glow beneath the card */}
        <div className="absolute -bottom-4 left-1/2 -translate-x-1/2 w-3/4 h-8 bg-red-500/10 rounded-full blur-2xl pointer-events-none" />
      </div>
    </div>
  );
}
