/**
 * WebSocket client singleton.
 *
 * - Authenticates via token query param on connect.
 * - Exponential backoff with jitter on disconnect.
 * - Clean disconnect on logout (no reconnect loop).
 * - Connection state exposed via handler callbacks.
 * - Reconnect always reads the *current* auth token from stores
 *   so a relogin during a backoff window is picked up automatically.
 */

import useAuthStore from '../stores/useAuthStore';
import useSystemStore from '../stores/useSystemStore';

let ws = null;
let reconnectTimer = null;
let reconnectDelay = 1000;
let intentionalClose = false;

const MAX_DELAY = 30000;
const BASE_DELAY = 1000;
const handlers = new Map();

/* ---------- connection state constants ---------- */

export const WS_STATES = {
  CONNECTING: 'connecting',
  OPEN: 'open',
  CLOSING: 'closing',
  CLOSED: 'closed',
};

/* ---------- public API ---------- */

/**
 * Open a WebSocket connection.
 * @param {string} [token]  Auth token. Falls back to in-memory lookup.
 * @param {string} [url]    Override WS URL (testing).
 */
export function connect(token, url) {
  if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
    return;
  }

  intentionalClose = false;
  reconnectDelay = BASE_DELAY;

  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = url || `${protocol}//${window.location.host}/ws${token ? `?token=${token}` : ''}`;

  emit('__state', WS_STATES.CONNECTING);
  ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    reconnectDelay = BASE_DELAY;
    emit('__state', WS_STATES.OPEN);
    emit('__open');

    // Subscribe to channels the backend expects
    send({
      type: 'subscribe',
      channels: [
        'status.update',
        'threat.new',
        'threat.resolved',
        'device.new',
        'device.update',
        'device.departed',
        'scan.complete',
        'status_change',
      ],
    });
  };

  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      const type = data.type || 'unknown';

      // Specific handler
      const handler = handlers.get(type);
      if (handler) handler(data);

      // Wildcard
      const wildcard = handlers.get('*');
      if (wildcard) wildcard(data);
    } catch (e) {
      console.error('[WS] parse error:', e);
    }
  };

  ws.onclose = () => {
    emit('__state', WS_STATES.CLOSED);
    emit('__close');

    // Only reconnect if the close was NOT intentional (logout / unmount)
    if (!intentionalClose) {
      const jitter = Math.random() * 1000;
      reconnectTimer = setTimeout(() => {
        reconnectDelay = Math.min(reconnectDelay * 2, MAX_DELAY);
        // Read the *current* token from stores so a relogin during
        // the backoff window is picked up (avoids stale closure capture).
        const currentToken =
          useAuthStore.getState().token || useSystemStore.getState().token;
        connect(currentToken, url);
      }, reconnectDelay + jitter);
    }
  };

  ws.onerror = () => {
    // onclose will fire after this -- let that handle reconnect
    ws.close();
  };
}

/**
 * Clean disconnect -- suppresses the reconnect loop.
 */
export function disconnect() {
  intentionalClose = true;
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }
  if (ws) {
    ws.close();
    ws = null;
  }
  emit('__state', WS_STATES.CLOSED);
}

/**
 * Send a JSON payload over the socket.
 * @param {Object} data
 */
export function send(data) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(data));
  }
}

/**
 * Register an event handler.
 * @param {string}   type     Event type or '__open' / '__close' / '__state' / '*'.
 * @param {Function} handler  Callback.
 */
export function on(type, handler) {
  handlers.set(type, handler);
}

/**
 * Unregister an event handler.
 * @param {string} type
 */
export function off(type) {
  handlers.delete(type);
}

/* ---------- internal ---------- */

function emit(type, data) {
  const handler = handlers.get(type);
  if (handler) handler(data);
}
