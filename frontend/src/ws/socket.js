/**
 * WebSocket client singleton.
 *
 * - Authenticates via first-message auth (JWT sent after connect, NOT in URL).
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
/** @type {Map<string, Set<Function>>} */
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
  // Connect WITHOUT token in URL to avoid leaking JWT in server/proxy logs.
  // Auth is sent as the first message after the connection opens.
  const wsUrl = url || `${protocol}//${window.location.host}/ws`;

  emit('__state', WS_STATES.CONNECTING);
  ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    reconnectDelay = BASE_DELAY;

    // Send auth as first message (preferred method — no JWT in URL)
    const authToken = token
      || useAuthStore.getState().token
      || useSystemStore.getState().token;
    if (authToken) {
      ws.send(JSON.stringify({ type: 'auth', token: authToken }));
    }

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

      // Specific handlers
      const typeHandlers = handlers.get(type);
      if (typeHandlers) typeHandlers.forEach((h) => h(data));

      // Wildcard handlers
      const wildcardHandlers = handlers.get('*');
      if (wildcardHandlers) wildcardHandlers.forEach((h) => h(data));
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
 * Multiple handlers per event type are supported.
 * @param {string}   type     Event type or '__open' / '__close' / '__state' / '*'.
 * @param {Function} handler  Callback.
 */
export function on(type, handler) {
  if (!handlers.has(type)) handlers.set(type, new Set());
  handlers.get(type).add(handler);
}

/**
 * Unregister a specific handler for an event type.
 * If handler is omitted, all handlers for that type are removed.
 * @param {string}    type
 * @param {Function}  [handler]
 */
export function off(type, handler) {
  if (!handler) {
    handlers.delete(type);
  } else {
    const set = handlers.get(type);
    if (set) {
      set.delete(handler);
      if (set.size === 0) handlers.delete(type);
    }
  }
}

/* ---------- internal ---------- */

function emit(type, data) {
  const set = handlers.get(type);
  if (set) set.forEach((h) => h(data));
}
