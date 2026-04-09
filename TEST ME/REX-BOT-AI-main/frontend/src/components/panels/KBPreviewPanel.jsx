/**
 * KBPreviewPanel — safe rendered preview of knowledge base content.
 * Renders plain text with basic line-break preservation.
 * No dangerouslySetInnerHTML. No markdown parser (intentionally minimal).
 */
import React from 'react';

export default function KBPreviewPanel({ content = '', loading = false }) {
  if (loading) {
    return (
      <div className="flex flex-col h-full">
        <Header />
        <div className="flex-1 flex items-center justify-center text-slate-500 text-sm">
          Loading preview...
        </div>
      </div>
    );
  }

  if (!content) {
    return (
      <div className="flex flex-col h-full">
        <Header />
        <div className="flex-1 flex items-center justify-center text-slate-500 text-sm">
          No content to preview. Start writing in the editor.
        </div>
      </div>
    );
  }

  // Split into paragraphs (double newline) and lines (single newline)
  const paragraphs = content.split(/\n{2,}/);

  return (
    <div className="flex flex-col h-full">
      <Header />
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {paragraphs.map((para, i) => {
          const lines = para.split('\n');
          // Detect heading-like lines (start with # in markdown convention)
          if (lines[0]?.startsWith('# ')) {
            return (
              <div key={i}>
                <h2 className="text-base font-bold text-slate-100 mb-1">
                  {lines[0].replace(/^#+\s*/, '')}
                </h2>
                {lines.slice(1).map((line, j) => (
                  <p key={j} className="text-sm text-slate-300 leading-relaxed">{line || '\u00A0'}</p>
                ))}
              </div>
            );
          }
          if (lines[0]?.startsWith('## ')) {
            return (
              <div key={i}>
                <h3 className="text-sm font-semibold text-slate-200 mb-1">
                  {lines[0].replace(/^#+\s*/, '')}
                </h3>
                {lines.slice(1).map((line, j) => (
                  <p key={j} className="text-sm text-slate-300 leading-relaxed">{line || '\u00A0'}</p>
                ))}
              </div>
            );
          }
          // Detect list-like lines (start with - or *)
          const isList = lines.every((l) => /^\s*[-*]\s/.test(l) || l.trim() === '');
          if (isList) {
            return (
              <ul key={i} className="list-disc list-inside space-y-0.5">
                {lines.filter((l) => l.trim()).map((line, j) => (
                  <li key={j} className="text-sm text-slate-300">
                    {line.replace(/^\s*[-*]\s*/, '')}
                  </li>
                ))}
              </ul>
            );
          }
          // Regular paragraph
          return (
            <p key={i} className="text-sm text-slate-300 leading-relaxed whitespace-pre-wrap">
              {para}
            </p>
          );
        })}
      </div>
    </div>
  );
}

function Header() {
  return (
    <div className="px-4 py-2 border-b border-white/[0.06] bg-[#0B1020]">
      <span className="text-xs font-medium text-slate-500 uppercase tracking-wide">Preview</span>
    </div>
  );
}
