import { WebSocketServer, WebSocket } from 'ws';
import { Server } from 'http';

interface ExtendedWebSocket extends WebSocket {
  subscriptions?: Set<string>;
  isAlive?: boolean;
}

let wss: WebSocketServer | null = null;

export function initWebSocketServer(httpServer: Server) {
  wss = new WebSocketServer({ server: httpServer, path: '/ws/telemetry' });

  wss.on('connection', (ws: ExtendedWebSocket) => {
    ws.subscriptions = new Set(['ALL']);
    ws.isAlive = true;
    console.log('[WebSocket] Telemetry client connected to live SOC stream.');

    ws.on('pong', () => {
      ws.isAlive = true;
    });

    // Handshake message
    ws.send(JSON.stringify({
      type: 'HANDSHAKE',
      status: 'CONNECTED',
      channel: 'SOC_LIVE_TELEMETRY',
      availableChannels: ['NETFLOW', 'SIEM', 'DISCOVERY', 'CORRELATION', 'ALL'],
      timestamp: new Date().toISOString()
    }));

    ws.on('message', (data: string) => {
      try {
        const payload = JSON.parse(data.toString());
        if (payload.action === 'SUBSCRIBE' && payload.channel) {
          ws.subscriptions?.add(payload.channel);
          ws.send(JSON.stringify({ type: 'SUBSCRIBED', channel: payload.channel, timestamp: new Date().toISOString() }));
        }
      } catch (e) {
        // Ignore unparseable messages
      }
    });

    ws.on('close', () => {
      console.log('[WebSocket] Telemetry client disconnected.');
    });
  });

  // Regular heartbeat ping (15s) with Ping/Pong keepalive
  const interval = setInterval(() => {
    if (!wss) return;
    const memoryUsageMb = (process.memoryUsage().rss / (1024 * 1024)).toFixed(1);

    wss.clients.forEach((ws: ExtendedWebSocket) => {
      if (ws.isAlive === false) {
        return ws.terminate();
      }
      ws.isAlive = false;
      ws.ping();
    });

    broadcastTelemetryEvent({
      type: 'HEARTBEAT',
      timestamp: new Date().toISOString(),
      activeSensors: 12,
      memoryUsageMb,
      status: 'HEALTHY'
    });
  }, 15000);

  wss.on('close', () => {
    clearInterval(interval);
  });
}

export function broadcastTelemetryEvent(data: any, channel = 'ALL') {
  if (!wss) return;
  const message = JSON.stringify(data);
  wss.clients.forEach((client: ExtendedWebSocket) => {
    if (client.readyState === WebSocket.OPEN) {
      if (!client.subscriptions || client.subscriptions.has('ALL') || client.subscriptions.has(channel)) {
        client.send(message);
      }
    }
  });
}
