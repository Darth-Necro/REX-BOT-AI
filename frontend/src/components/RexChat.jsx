import React, { useState, useRef, useEffect, useCallback } from 'react';
import api from '../api/client';

const REX_AVATAR = (
  <div className="w-8 h-8 rounded-full bg-rex-accent/20 border border-rex-accent/30 flex items-center justify-center shrink-0">
    <svg className="w-5 h-5 text-rex-accent" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
      <path d="M4.5 9c0-3.5 3-6.5 7.5-6.5s7.5 3 7.5 6.5c0 2-1 3.5-1.5 4l1 3.5-3-1.5c-1.2.6-2.5 1-4 1s-2.8-.4-4-1l-3 1.5 1-3.5c-.5-.5-1.5-2-1.5-4z" />
      <circle cx="9" cy="9" r="1" fill="currentColor" />
      <circle cx="15" cy="9" r="1" fill="currentColor" />
      <path d="M9.5 13c.8.7 1.5 1 2.5 1s1.7-.3 2.5-1" strokeLinecap="round" />
    </svg>
  </div>
);

const WELCOME_MESSAGE = {
  role: 'rex',
  text: "Woof! I'm REX, your network guard dog. I watch over your devices 24/7 and keep the bad guys out. Ask me anything about your network, devices, threats, or tell me to run a scan. I'm always on alert!",
  timestamp: new Date().toISOString(),
};

function TypingIndicator() {
  return (
    <div className="flex items-end gap-2 max-w-[80%]">
      {REX_AVATAR}
      <div className="bg-rex-surface border border-rex-card rounded-2xl rounded-bl-md px-4 py-3">
        <div className="flex gap-1.5 items-center">
          <span className="w-2 h-2 rounded-full bg-rex-accent animate-bounce" style={{ animationDelay: '0ms' }} />
          <span className="w-2 h-2 rounded-full bg-rex-accent animate-bounce" style={{ animationDelay: '150ms' }} />
          <span className="w-2 h-2 rounded-full bg-rex-accent animate-bounce" style={{ animationDelay: '300ms' }} />
        </div>
      </div>
    </div>
  );
}

function ChatBubble({ message }) {
  const isRex = message.role === 'rex';

  return (
    <div className={`flex items-end gap-2 ${isRex ? '' : 'flex-row-reverse'} max-w-[85%] ${isRex ? '' : 'ml-auto'}`}>
      {isRex && REX_AVATAR}
      <div
        className={`rounded-2xl px-4 py-2.5 text-sm leading-relaxed ${
          isRex
            ? 'bg-rex-surface border border-rex-card rounded-bl-md text-rex-text'
            : 'bg-rex-accent text-white rounded-br-md'
        }`}
      >
        <p className="whitespace-pre-wrap">{message.text}</p>
        <span className={`text-xs mt-1 block ${isRex ? 'text-rex-muted' : 'text-white/60'}`}>
          {new Date(message.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
        </span>
      </div>
    </div>
  );
}

export default function RexChat({ compact = false }) {
  const [messages, setMessages] = useState([WELCOME_MESSAGE]);
  const [input, setInput] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const messagesEndRef = useRef(null);
  const inputRef = useRef(null);

  const scrollToBottom = useCallback(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, []);

  useEffect(() => {
    scrollToBottom();
  }, [messages, isTyping, scrollToBottom]);

  const sendMessage = useCallback(async () => {
    const text = input.trim();
    if (!text || isTyping) return;

    const userMsg = { role: 'user', text, timestamp: new Date().toISOString() };
    setMessages((prev) => [...prev, userMsg]);
    setInput('');
    setIsTyping(true);

    try {
      const res = await api.post('/chat', { message: text });
      const reply = res.data?.reply || res.data?.message || res.data?.response || "Hmm, I couldn't process that. Try asking differently!";
      setMessages((prev) => [
        ...prev,
        { role: 'rex', text: reply, timestamp: new Date().toISOString() },
      ]);
    } catch (err) {
      const errorMsg =
        err.response?.status === 503
          ? "My brain is still warming up... give me a moment and try again!"
          : "Woof! Something went wrong. My connection might be down. I'll keep trying!";
      setMessages((prev) => [
        ...prev,
        { role: 'rex', text: errorMsg, timestamp: new Date().toISOString() },
      ]);
    } finally {
      setIsTyping(false);
    }
  }, [input, isTyping]);

  const handleKeyDown = useCallback(
    (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
      }
    },
    [sendMessage]
  );

  const containerHeight = compact ? 'h-[400px]' : 'h-[calc(100vh-16rem)]';

  return (
    <div className={`flex flex-col ${containerHeight} max-h-[700px] bg-rex-bg rounded-xl border border-rex-card overflow-hidden`}>
      {/* Header */}
      <div className="flex items-center gap-3 px-4 py-3 bg-rex-surface border-b border-rex-card shrink-0">
        {REX_AVATAR}
        <div>
          <h3 className="text-sm font-semibold text-rex-text">REX</h3>
          <p className="text-xs text-rex-safe">Online - Ready to help</p>
        </div>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4 scrollbar-thin">
        {messages.map((msg, i) => (
          <ChatBubble key={i} message={msg} />
        ))}
        {isTyping && <TypingIndicator />}
        <div ref={messagesEndRef} />
      </div>

      {/* Input */}
      <div className="border-t border-rex-card bg-rex-surface p-3 shrink-0">
        <div className="flex items-end gap-2">
          <textarea
            ref={inputRef}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Ask REX anything..."
            rows={1}
            className="flex-1 bg-rex-bg border border-rex-card rounded-xl px-4 py-2.5 text-sm text-rex-text placeholder-rex-muted resize-none focus:outline-none focus:border-rex-accent transition-colors max-h-24"
            disabled={isTyping}
          />
          <button
            onClick={sendMessage}
            disabled={!input.trim() || isTyping}
            className="shrink-0 w-10 h-10 rounded-xl bg-rex-accent text-white flex items-center justify-center hover:bg-rex-accent/80 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            aria-label="Send message"
          >
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 19V5m0 0l-7 7m7-7l7 7" />
            </svg>
          </button>
        </div>
      </div>
    </div>
  );
}
