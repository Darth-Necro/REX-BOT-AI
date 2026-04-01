/** WebSocket singleton with reconnect logic. */

let ws = null;
let reconnectTimer = null;
let reconnectDelay = 1000;
const MAX_DELAY = 30000;
const handlers = new Map();

export function connect(url) {
  if (ws && ws.readyState === WebSocket.OPEN) return;

  const token = localStorage.getItem('rex_token');
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = url || `${protocol}//${window.location.host}/ws?token=${token || ''}`;
  ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    reconnectDelay = 1000;
    handlers.forEach((fn, type) => {
      if (type === '__open') fn();
    });
    // Subscribe to default channels (dotted event names)
    send({ type: 'subscribe', channels: ['status.update', 'threat.new', 'device.new', 'device.update', 'scan.complete'] });
  };

  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      const type = data.type || 'unknown';
      const handler = handlers.get(type);
      if (handler) handler(data);
      // Also call wildcard handler
      const wildcard = handlers.get('*');
      if (wildcard) wildcard(data);
    } catch (e) {
      console.error('WS parse error:', e);
    }
  };

  ws.onclose = () => {
    const closeHandler = handlers.get('__close');
    if (closeHandler) closeHandler();
    // Reconnect with exponential backoff + jitter
    const jitter = Math.random() * 1000;
    reconnectTimer = setTimeout(() => {
      reconnectDelay = Math.min(reconnectDelay * 2, MAX_DELAY);
      connect(url);
    }, reconnectDelay + jitter);
  };

  ws.onerror = () => {
    ws.close();
  };
}

export function disconnect() {
  if (reconnectTimer) clearTimeout(reconnectTimer);
  if (ws) ws.close();
  ws = null;
}

export function send(data) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(data));
  }
}

export function on(type, handler) {
  handlers.set(type, handler);
}

export function off(type) {
  handlers.delete(type);
}
