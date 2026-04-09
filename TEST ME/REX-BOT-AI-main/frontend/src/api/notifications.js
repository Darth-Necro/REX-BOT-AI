/**
 * Notifications API module.
 * Thin wrappers around the axios client for notification settings.
 * Every function returns normalised data; callers handle errors themselves.
 */
import api from './client';

/**
 * GET /api/notifications/settings — current notification config + capabilities.
 * @returns {Promise<{ settings: Object, capabilities: Object }>}
 */
export async function getNotificationSettings() {
  const res = await api.get('/notifications/settings');
  const raw = res.data;

  if (!raw || typeof raw !== 'object') {
    return {
      settings: {
        discord_webhook: '',
        telegram_bot_token: '',
        telegram_chat_id: '',
        email_to: '',
        email_smtp_host: '',
        matrix_homeserver: '',
        matrix_room_id: '',
        matrix_token: '',
        enabled_channels: [],
      },
      capabilities: {},
    };
  }

  return {
    settings: {
      discord_webhook: raw.settings?.discord_webhook ?? raw.discord_webhook ?? '',
      telegram_bot_token: raw.settings?.telegram_bot_token ?? raw.telegram_bot_token ?? '',
      telegram_chat_id: raw.settings?.telegram_chat_id ?? raw.telegram_chat_id ?? '',
      email_to: raw.settings?.email_to ?? raw.email_to ?? '',
      email_smtp_host: raw.settings?.email_smtp_host ?? raw.email_smtp_host ?? '',
      matrix_homeserver: raw.settings?.matrix_homeserver ?? raw.matrix_homeserver ?? '',
      matrix_room_id: raw.settings?.matrix_room_id ?? raw.matrix_room_id ?? '',
      matrix_token: raw.settings?.matrix_token ?? raw.matrix_token ?? '',
      enabled_channels: Array.isArray(raw.settings?.enabled_channels ?? raw.enabled_channels)
        ? (raw.settings?.enabled_channels ?? raw.enabled_channels)
        : [],
    },
    capabilities: raw.capabilities ?? {},
  };
}

/**
 * PUT /api/notifications/settings — persist notification config.
 * @param {Object} settings
 * @returns {Promise<Object>}
 */
export async function updateNotificationSettings(settings) {
  const res = await api.put('/notifications/settings', settings);
  return res.data;
}

/**
 * POST /api/notifications/test/{channel} — fire a test notification on a specific channel.
 * @param {string} channel  Channel name (discord, email, telegram, etc).
 * @returns {Promise<{ results: Object }>}
 */
export async function testNotification(channel) {
  if (!channel) throw new Error('Channel is required');
  const res = await api.post(`/notifications/test/${encodeURIComponent(channel)}`);
  return res.data;
}

/**
 * POST /api/notifications/test/{channel} — alias for backward compat.
 * @param {string} [channel='all']  Channel name.
 * @returns {Promise<{ results: Object }>}
 */
export async function testNotifications(channel = 'all') {
  return testNotification(channel);
}
