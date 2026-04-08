/**
 * ChatPage -- dedicated page for the REX AI chat interface.
 *
 * Wraps the existing RexChat component in a full-page layout
 * with an alpha banner since this feature depends on Ollama availability.
 */
import React from 'react';
import RexChat from '../../components/RexChat';
import AlphaBanner from '../../components/AlphaBanner';

export default function ChatPage() {
  return (
    <div className="p-4 md:p-6 max-w-4xl mx-auto space-y-4">
      <AlphaBanner feature="REX Chat" />

      <div>
        <h1 className="text-xl font-bold text-slate-100 tracking-tight">
          REX Chat
        </h1>
        <p className="text-sm text-slate-500 mt-1">
          Talk to REX about your network security. Requires Ollama to be running.
        </p>
      </div>

      <RexChat />
    </div>
  );
}
