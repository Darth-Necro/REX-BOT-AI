/**
 * KBEditorPanel — textarea editor for the knowledge base with dirty/save state.
 * Does not hold its own API state; receives content + callbacks from parent.
 */
import React, { useState, useEffect, useCallback } from 'react';

export default function KBEditorPanel({
  content = '',
  saving = false,
  disabled = false,
  onSave,
}) {
  const [draft, setDraft] = useState(content);
  const dirty = draft !== content;

  // Sync when upstream content changes (e.g. after save or revert)
  useEffect(() => {
    setDraft(content);
  }, [content]);

  const handleSave = useCallback(() => {
    if (!dirty || saving || disabled) return;
    onSave?.(draft);
  }, [draft, dirty, saving, disabled, onSave]);

  const handleKeyDown = useCallback(
    (e) => {
      // Ctrl/Cmd + S to save
      if ((e.ctrlKey || e.metaKey) && e.key === 's') {
        e.preventDefault();
        handleSave();
      }
    },
    [handleSave]
  );

  return (
    <div className="flex flex-col h-full">
      {/* Toolbar */}
      <div className="flex items-center justify-between px-4 py-2 border-b border-white/[0.06] bg-[#0B1020]">
        <div className="flex items-center gap-2">
          <span className="text-xs font-medium text-slate-500 uppercase tracking-wide">Editor</span>
          {dirty && (
            <span className="text-xs px-2 py-0.5 rounded-full bg-amber-500/15 text-amber-300 border border-amber-500/30">
              Unsaved changes
            </span>
          )}
        </div>
        <button
          onClick={handleSave}
          disabled={!dirty || saving || disabled}
          className="px-3 py-1.5 text-xs font-medium rounded-lg bg-cyan-500 text-white
                     hover:bg-cyan-400 disabled:opacity-40 disabled:cursor-not-allowed
                     transition-colors"
        >
          {saving ? 'Saving...' : 'Save'}
        </button>
      </div>

      {/* Editor area */}
      <textarea
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        onKeyDown={handleKeyDown}
        disabled={disabled}
        placeholder={disabled ? 'Editing is not available for this backend.' : 'Enter knowledge base content...'}
        className="flex-1 w-full resize-none bg-[#050816] text-slate-200 text-sm font-mono
                   p-4 focus:outline-none placeholder-slate-600 disabled:opacity-50
                   disabled:cursor-not-allowed"
        spellCheck={false}
      />

      {disabled && (
        <div className="px-4 py-2 bg-amber-500/5 border-t border-amber-500/20">
          <p className="text-xs text-amber-400/80">
            Knowledge base editing is not supported by the current backend.
          </p>
        </div>
      )}
    </div>
  );
}
