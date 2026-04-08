/**
 * KnowledgeBasePage — editor/preview split layout with version history.
 * All edits flow through the store. Revert is gated on capabilities.
 */
import React, { useEffect, useState } from 'react';
import useKnowledgeBaseStore from '../../stores/useKnowledgeBaseStore';
import { kbPermissions } from '../../lib/permissions';
import useDangerConfirm from '../../hooks/useDangerConfirm';
import KBEditorPanel from '../../components/panels/KBEditorPanel';
import KBPreviewPanel from '../../components/panels/KBPreviewPanel';
import KBHistoryTable from '../../components/tables/KBHistoryTable';
import DangerConfirmModal from '../../components/modals/DangerConfirmModal';

export default function KnowledgeBasePage() {
  const {
    content, version, updatedAt, history,
    loading, historyLoading, saving, error, capabilities,
    fetchKB, fetchHistory, saveKB, revertKB,
  } = useKnowledgeBaseStore();

  const perms = kbPermissions(capabilities);
  const danger = useDangerConfirm();
  const [tab, setTab] = useState('editor'); // 'editor' | 'history'

  useEffect(() => {
    fetchKB();
    fetchHistory();
  }, [fetchKB, fetchHistory]);

  const handleSave = async (newContent) => {
    await saveKB(newContent);
    fetchHistory();
  };

  const handleRevert = (targetVersion) => {
    danger.open({
      title: `Revert to Version ${targetVersion}`,
      description: 'This will replace the current knowledge base content with a previous version.',
      impact: 'Any unsaved changes in the editor will be lost. This action creates a new version entry.',
      onConfirm: async () => {
        await revertKB(targetVersion);
        fetchHistory();
      },
    });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100">Knowledge Base</h1>
          <p className="text-sm text-slate-500 mt-0.5">
            {loading
              ? 'Loading...'
              : `Version ${version}${updatedAt ? ` \u00B7 Updated ${new Date(updatedAt).toLocaleDateString()}` : ''}`}
          </p>
        </div>
        <div className="flex items-center gap-1 bg-[#0B1020] rounded-xl border border-white/[0.06] p-0.5">
          <button
            onClick={() => setTab('editor')}
            className={`px-4 py-1.5 text-xs font-medium rounded-lg transition-colors ${
              tab === 'editor' ? 'bg-red-500/15 text-red-300' : 'text-slate-500 hover:text-slate-300'
            }`}
          >
            Editor
          </button>
          <button
            onClick={() => setTab('history')}
            className={`px-4 py-1.5 text-xs font-medium rounded-lg transition-colors ${
              tab === 'history' ? 'bg-red-500/15 text-red-300' : 'text-slate-500 hover:text-slate-300'
            }`}
          >
            History ({history.length})
          </button>
        </div>
      </div>

      {/* Error banner */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-2xl px-4 py-3">
          <p className="text-sm text-red-300">{error}</p>
        </div>
      )}

      {tab === 'editor' ? (
        /* Editor / Preview split */
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-0 rounded-2xl border border-white/[0.06] overflow-hidden min-h-[500px]">
          <div className="border-r border-white/[0.06]">
            <KBEditorPanel
              content={content}
              saving={saving}
              disabled={!perms.canEdit}
              onSave={handleSave}
            />
          </div>
          <div>
            <KBPreviewPanel content={content} loading={loading} />
          </div>
        </div>
      ) : (
        /* History tab */
        <KBHistoryTable
          history={history}
          loading={historyLoading}
          canRevert={perms.canRevert}
          currentVersion={version}
          onRevert={handleRevert}
        />
      )}

      {/* Danger confirmation modal */}
      <DangerConfirmModal
        isOpen={danger.isOpen}
        title={danger.title}
        description={danger.description}
        impact={danger.impact}
        confirmLabel="Revert"
        onConfirm={danger.confirm}
        onCancel={danger.close}
      />
    </div>
  );
}
