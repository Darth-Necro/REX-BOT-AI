import React, { useEffect } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import useSystemStore from './stores/useSystemStore';
import { connect, on, disconnect } from './ws/socket';
import BasicView from './views/BasicView';
import AdvancedView from './views/AdvancedView';

function ModeToggle() {
  const { mode, toggleMode } = useSystemStore();
  return (
    <button
      onClick={toggleMode}
      className="flex items-center gap-2 px-3 py-1.5 rounded-full border border-rex-card hover:border-rex-accent transition-colors text-sm"
      aria-label={`Switch to ${mode === 'basic' ? 'Advanced' : 'Basic'} mode`}
    >
      <span className={mode === 'basic' ? 'text-rex-accent font-semibold' : 'text-rex-muted'}>Basic</span>
      <span className="text-rex-muted">|</span>
      <span className={mode === 'advanced' ? 'text-rex-accent font-semibold' : 'text-rex-muted'}>Advanced</span>
    </button>
  );
}

function TopBar() {
  const { connected, powerState } = useSystemStore();
  return (
    <header className="h-16 bg-rex-surface border-b border-rex-card flex items-center justify-between px-4">
      <div className="flex items-center gap-3">
        <span className="font-bold text-lg text-rex-accent">REX</span>
        <span className={`w-2 h-2 rounded-full ${connected ? 'bg-rex-safe' : 'bg-rex-threat'}`}
              title={connected ? 'Connected' : 'Disconnected'} />
        <span className="text-xs text-rex-muted capitalize">{powerState}</span>
      </div>
      <ModeToggle />
    </header>
  );
}

export default function App() {
  const { mode, setConnected, updateFromStatus } = useSystemStore();

  useEffect(() => {
    connect();
    on('__open', () => setConnected(true));
    on('__close', () => setConnected(false));
    on('rex.status', (data) => updateFromStatus(data.payload || data));
    on('threat.new', (data) => {
      // Import dynamically to avoid circular deps
      import('./stores/useThreatStore').then(({ default: store }) => {
        store.getState().addThreat(data.payload || data);
      });
    });
    return () => disconnect();
  }, []);

  return (
    <BrowserRouter>
      <div className="min-h-screen bg-rex-bg">
        <TopBar />
        <main>
          <Routes>
            <Route path="/*" element={mode === 'basic' ? <BasicView /> : <AdvancedView />} />
          </Routes>
        </main>
        <footer className="text-center text-xs text-rex-muted py-4 border-t border-rex-card">
          Network monitoring active | REX-BOT-AI v1.0.0 | MIT License
        </footer>
      </div>
    </BrowserRouter>
  );
}
