/**
 * FirewallPage — full firewall management page.
 * Rules table, structured rule builder, panic restore with DangerConfirmModal.
 * All mutations gated on backend capabilities.
 */
import React, { useEffect, useState } from 'react';
import useFirewallStore from '../../stores/useFirewallStore';
import { firewallPermissions } from '../../lib/permissions';
import useDangerConfirm from '../../hooks/useDangerConfirm';
import FirewallRulesTable from '../../components/tables/FirewallRulesTable';
import RuleBuilderForm from '../../components/forms/RuleBuilderForm';
import DangerConfirmModal from '../../components/modals/DangerConfirmModal';

export default function FirewallPage() {
  const {
    rules, loading, error, capabilities,
    fetchRules, createRule, deleteRule, panicRestore,
  } = useFirewallStore();

  const perms = firewallPermissions(capabilities);
  const danger = useDangerConfirm();
  const [deletingId, setDeletingId] = useState(null);

  useEffect(() => {
    fetchRules();
  }, [fetchRules]);

  const handleCreate = async (rule) => {
    await createRule(rule);
  };

  const handleDelete = (id) => {
    danger.open({
      title: 'Delete Firewall Rule',
      description: 'This will permanently remove the rule from the active firewall configuration.',
      impact: 'Traffic previously matched by this rule will no longer be filtered.',
      onConfirm: async () => {
        setDeletingId(id);
        try {
          await deleteRule(id);
        } finally {
          setDeletingId(null);
        }
      },
    });
  };

  const handlePanicActivate = () => {
    danger.open({
      title: 'ACTIVATE PANIC MODE',
      description: 'This will immediately block ALL inbound and outbound network traffic except essential system services.',
      impact: 'All network connectivity will be severed. You will need to manually restore normal operation afterward.',
      onConfirm: () => panicRestore('activate'),
    });
  };

  const handlePanicRestore = () => {
    danger.open({
      title: 'Restore Normal Operation',
      description: 'This will remove all panic-mode firewall rules and restore normal traffic flow.',
      impact: 'Network traffic will resume. Ensure threats have been resolved before restoring.',
      onConfirm: () => panicRestore('restore'),
    });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100">Firewall</h1>
          <p className="text-sm text-slate-500 mt-0.5">
            {loading ? 'Loading...' : `${rules.length} active rule${rules.length !== 1 ? 's' : ''}`}
          </p>
        </div>
        <div className="flex items-center gap-3">
          {perms.canRestore && (
            <button
              onClick={handlePanicRestore}
              className="px-4 py-2.5 text-sm font-medium rounded-xl bg-amber-500/10 text-amber-300
                         border border-amber-500/30 hover:bg-amber-500/20 transition-colors"
            >
              Restore Normal
            </button>
          )}
          {perms.canPanic && (
            <button
              onClick={handlePanicActivate}
              className="flex items-center gap-2 px-5 py-2.5 bg-red-600 text-white rounded-xl
                         hover:bg-red-500 transition-colors text-sm font-bold
                         shadow-lg shadow-red-600/20"
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
              </svg>
              PANIC
            </button>
          )}
        </div>
      </div>

      {/* Error banner */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-2xl px-4 py-3">
          <p className="text-sm text-red-300">{error}</p>
        </div>
      )}

      {/* Rule builder */}
      <RuleBuilderForm onSubmit={handleCreate} disabled={!perms.canCreate} />

      {/* Rules table */}
      <FirewallRulesTable
        rules={rules}
        loading={loading}
        canDelete={perms.canDelete}
        onDelete={handleDelete}
        deletingId={deletingId}
      />

      {/* Danger confirmation modal */}
      <DangerConfirmModal
        isOpen={danger.isOpen}
        title={danger.title}
        description={danger.description}
        impact={danger.impact}
        confirmLabel="Confirm"
        onConfirm={danger.confirm}
        onCancel={danger.close}
      />
    </div>
  );
}
