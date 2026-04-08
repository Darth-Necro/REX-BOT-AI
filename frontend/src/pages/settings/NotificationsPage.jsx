/**
 * NotificationsPage — notification settings form + test + last result.
 *
 * Delegates form rendering to NotificationSettingsForm.
 * Shows honest capability-gated UI -- never shows features the backend
 * has not reported as available.
 */
import React from 'react';
import NotificationSettingsForm from '../../components/forms/NotificationSettingsForm';

export default function NotificationsPage() {
  return (
    <div className="p-6 lg:p-8 max-w-3xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-slate-100 tracking-tight">
          Notification Settings
        </h1>
        <p className="text-sm text-slate-500 mt-1">
          Configure how REX alerts you about threats and system events.
        </p>
      </div>

      {/* Form */}
      <div className="rounded-[26px] border border-white/[0.06] bg-gradient-to-br from-[#0a0a0a] to-[#141414] p-6">
        <NotificationSettingsForm />
      </div>
    </div>
  );
}
